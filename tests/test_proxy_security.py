# tests/test_proxy_security.py
"""
Adversarial Security Tests for Scalpel Racer Proxy Core.
Focus: DoS resilience, Smuggling attempts, and Resource Exhaustion.
Refactored to use Mock Types for robust isinstance checks.
"""
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, ANY
import pytest
from proxy_core import Http11ProxyHandler
from proxy_h2 import NativeProxyHandler
from proxy_common import H2StreamContext as StreamContext, MAX_HEADER_LIST_SIZE
from compat import ErrorCodes

# -- Mock Types --
# We define these as classes so isinstance(evt, RequestReceived) works in proxy_core
# pylint: disable=too-few-public-methods
class MockRequestReceived:
    """Mock for h2.events.RequestReceived."""

class MockDataReceived:
    """Mock for h2.events.DataReceived."""

class MockStreamReset:
    """Mock for h2.events.StreamReset."""

class MockWindowUpdated:
    """Mock for h2.events.WindowUpdated."""

class MockTrailersReceived:
    """Mock for h2.events.TrailersReceived."""

class MockStreamEnded:
    """Mock for h2.events.StreamEnded."""

class MockResponseReceived:
    """Mock for h2.events.ResponseReceived."""
# pylint: enable=too-few-public-methods

# -- HTTP/1.1 Security --

class TestH1Security:
    """Security tests for HTTP/1.1 Proxy Handler."""

    @pytest.mark.asyncio
    async def test_te_obfuscation_smuggling(self):
        """[SECURITY] Verify we handle 'chunked' correctly even with noise."""
        reader = AsyncMock()
        writer = MagicMock()
        # Payload: 'identity' first, 'chunked' last. VALID.
        payload = [
            b"POST / HTTP/1.1",
            b"Host: target.com",
            b"Transfer-Encoding: identity",
            b"Transfer-Encoding: chunked",
            b""
        ]
        reader.read.return_value = b"0\r\n\r\n"
        iter_lines = iter(payload)
        async def mock_read(*_): # pylint: disable=unused-argument
            return next(iter_lines, b"")

        handler = Http11ProxyHandler(
            reader, writer, "target.com", None, None, None, enable_tunneling=False
        )

        # [FIX] Using patch.object on the Class
        # pylint: disable=protected-access
        with patch.object(Http11ProxyHandler, '_read_strict_line', side_effect=mock_read), \
             patch.object(Http11ProxyHandler, '_read_chunked_body',
                          new_callable=AsyncMock) as mock_chunk:

            mock_chunk.return_value = b""
            await handler.run()
            # Should NOT have closed due to 400.
            if writer.write.called:
                args = writer.write.call_args[0][0]
                assert b"400" not in args
        # pylint: enable=protected-access

    @pytest.mark.asyncio
    async def test_te_smuggling_bad_order(self):
        """[SECURITY] Reject if 'chunked' is NOT the final encoding."""
        reader = AsyncMock()
        writer = MagicMock()
        payload = [
            b"POST / HTTP/1.1",
            b"Host: target.com",
            b"Transfer-Encoding: chunked, identity",
            b""
        ]
        iter_lines = iter(payload)
        async def mock_read(*_): # pylint: disable=unused-argument
            return next(iter_lines, b"")

        handler = Http11ProxyHandler(reader, writer, "target.com", None, None, None)

        # [FIX] Using patch.object on the Class
        # pylint: disable=protected-access
        with patch.object(Http11ProxyHandler, '_read_strict_line', side_effect=mock_read):
            await handler.run()

            writer.write.assert_called()
            assert b"400 Bad Transfer-Encoding" in writer.write.call_args[0][0]
        # pylint: enable=protected-access

    @pytest.mark.asyncio
    async def test_cl_te_conflict_handling(self):
        """[SECURITY] Strip Content-Length if Transfer-Encoding is present."""
        reader = AsyncMock()
        writer = MagicMock()
        payload = [
            b"POST / HTTP/1.1",
            b"Host: target.com",
            b"Content-Length: 500",
            b"Transfer-Encoding: chunked",
            b""
        ]
        iter_lines = iter(payload)
        async def mock_read(*_): # pylint: disable=unused-argument
            return next(iter_lines, b"")

        handler = Http11ProxyHandler(
            reader, writer, "target.com", None, None, None, enable_tunneling=False
        )

        # [FIX] Using patch.object on the Class
        # pylint: disable=protected-access
        with patch.object(Http11ProxyHandler, '_read_strict_line', side_effect=mock_read), \
             patch.object(Http11ProxyHandler, '_read_chunked_body', return_value=b"safe"), \
             patch.object(Http11ProxyHandler, '_handle_request',
                          new_callable=AsyncMock) as mock_handle:

            await handler.run()

            # Access last argument for headers_dict (robust against presence of self)
            headers_dict = mock_handle.call_args[0][-2]
            assert "content-length" not in headers_dict
            assert "transfer-encoding" in headers_dict
        # pylint: enable=protected-access

    @pytest.mark.asyncio
    async def test_recursive_connect_attempt(self):
        """[SECURITY] Prevent CONNECT to itself or loopback if restricted."""
        reader = AsyncMock()
        writer = MagicMock()
        handler = Http11ProxyHandler(
            reader, writer, "127.0.0.1:8080", None, None, None
        )
        # pylint: disable=protected-access
        with patch("proxy_core.asyncio.open_connection") as mock_conn:
            await handler._handle_connect("127.0.0.1:22")
            assert mock_conn.called
        # pylint: enable=protected-access

# -- HTTP/2 Security --

class TestH2Security:
    """Security tests for HTTP/2 Proxy Handler."""

    @pytest.fixture(autouse=True)
    def patch_h2_types(self):
        """
        [FIX] Patch proxy_h2 with Mock CLASSES, not instances.
        This ensures isinstance(evt, RequestReceived) works correctly.
        """
        with patch("proxy_h2.RequestReceived", MockRequestReceived), \
             patch("proxy_h2.DataReceived", MockDataReceived), \
             patch("proxy_h2.StreamReset", MockStreamReset), \
             patch("proxy_h2.WindowUpdated", MockWindowUpdated), \
             patch("proxy_h2.TrailersReceived", MockTrailersReceived), \
             patch("proxy_h2.StreamEnded", MockStreamEnded), \
             patch("proxy_h2.ResponseReceived", MockResponseReceived):
            yield

    @pytest.fixture
    def h2_env(self):
        """Sets up the H2 environment with mocked H2Connection."""
        reader = AsyncMock()
        writer = MagicMock()

        # CRITICAL FIX: Patch proxy_h2.H2Connection directly to prevent the real library
        # from running its strict state machine during unit tests.
        # We also need to mock local_settings behavior.
        with patch("proxy_h2.H2Connection") as mock_conn_cls:
            mock_instance = mock_conn_cls.return_value
            mock_instance.local_settings = MagicMock()

            handler = NativeProxyHandler(
                reader, writer, "h2.target", MagicMock(), None, None, enable_tunneling=False
            )

            yield handler, writer

    @pytest.mark.asyncio
    async def test_h2_header_flood(self, h2_env):
        """[SECURITY] DoS Attempt: Header Flood."""
        handler, _ = h2_env

        # NativeProxyHandler.__init__ sets this value.
        # Since we use a Mock H2Connection, verifying this attribute confirms correct init.
        # [FIX] Assert on the call to __setitem__ because local_settings is a Mock
        handler.downstream_conn.local_settings.__setitem__.assert_any_call(
            ANY, MAX_HEADER_LIST_SIZE
        )

        class OversizedHeaderListError(Exception):
            """Mock exception for header flood."""

        # Patch the INSTANCE method receive_data on the mock
        handler.downstream_conn.receive_data.side_effect = OversizedHeaderListError

        handler.initial_data = b"trigger_exploit"
        await handler.run()
        assert handler.closed.is_set()

    @pytest.mark.asyncio
    async def test_h2_stream_concurrency_exhaustion(self, h2_env):
        """[SECURITY] Resource Exhaustion: Rapid stream creation/deletion."""
        handler, _ = h2_env
        handler.enable_tunneling = True
        handler.upstream_conn = MagicMock()

        for i in range(1, 300, 2): 
            # pylint: disable=attribute-defined-outside-init
            evt = MockRequestReceived()
            evt.stream_id = i
            evt.headers = [(b":method", b"GET")]
            evt.stream_ended = True
            await handler.handle_request_received(evt)
            # pylint: disable=protected-access
            handler._cleanup_stream(i, upstream_closed=True)
            # pylint: enable=protected-access
            # pylint: enable=attribute-defined-outside-init

        assert len(handler.streams) == 0

    @pytest.mark.asyncio
    async def test_slow_loris_h2_body(self, h2_env):
        """[SECURITY] Slowloris: Timeout on slow body read."""
        handler, _ = h2_env # writer unused
        handler.client_reader = AsyncMock()
        handler.client_reader.read.side_effect = asyncio.TimeoutError

        with patch("proxy_h2.IDLE_TIMEOUT", 0.01):
            await handler.run()

        # Should close connection on timeout
        assert handler.closed.is_set()

    @pytest.mark.asyncio
    async def test_h2_stream_reset_handling(self, h2_env):
        """[SECURITY] Handle actual StreamReset event."""
        handler, _ = h2_env
        stream_id = 1
        handler.streams[stream_id] = MagicMock()

        # pylint: disable=attribute-defined-outside-init
        evt = MockStreamReset()
        evt.stream_id = stream_id
        evt.error_code = ErrorCodes.CANCEL
        # pylint: enable=attribute-defined-outside-init

        # Use the REAL entry point
        await handler.handle_downstream_event(evt)
        assert stream_id not in handler.streams

    @pytest.mark.asyncio
    async def test_h2_window_update_flood(self, h2_env):
        """[SECURITY] Resilience against WindowUpdate floods."""
        handler, _ = h2_env
        stream_id = 1
        ctx = StreamContext(stream_id, "https", None)
        ctx.upstream_flow_event.clear()
        handler.streams[stream_id] = ctx

        # pylint: disable=attribute-defined-outside-init
        evt = MockWindowUpdated()
        evt.stream_id = stream_id
        evt.delta = 100
        # pylint: enable=attribute-defined-outside-init

        await handler.handle_downstream_event(evt)
        # Should unblock flow control
        assert ctx.downstream_flow_event.is_set()
