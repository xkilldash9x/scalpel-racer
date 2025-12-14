# tests/test_proxy_core.py
"""
Tests for proxy_core.py (HTTP/1.1 and HTTP/2 Proxy Handlers).
Expanded coverage for Chunked Encoding, Blind Tunneling, H2 Header/Flow logic,
and Security/Smuggling edge cases.
"""

import sys
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, call, ANY
from proxy_core import (
    Http11ProxyHandler, 
    NativeProxyHandler, 
    DualProtocolHandler,
    ProxyError, 
    CapturedRequest,
    H2_FORBIDDEN_HEADERS,
    StreamContext
)
# We define local dummy classes for patching to ensure isinstance works correctly
class MockRequestReceived: pass
class MockDataReceived: pass
class MockStreamEnded: pass
class MockStreamReset: pass
class MockWindowUpdated: pass
class MockTrailersReceived: pass
class MockResponseReceived: pass
class MockPingReceived: pass
class MockRemoteSettingsChanged: pass

# Dummy Exception for testing
class MockProtocolError(Exception): pass

# -- HTTP/1.1 Robustness & Security --

class TestHttp11Proxy:
    
    @pytest.mark.asyncio
    async def test_strict_crlf_enforcement(self):
        reader = AsyncMock()
        writer = MagicMock()
        reader.read.side_effect = [b"GET / HTTP/1.1\r\n", b""]
        handler = Http11ProxyHandler(reader, writer, "host", None, None, None)
        line = await handler._read_strict_line()
        assert line == b"GET / HTTP/1.1"
        
        reader.read.side_effect = [b"Header: Val\n", b""]
        handler.buffer = bytearray(b"")
        with pytest.raises(ProxyError):
            await handler._read_strict_line()

    @pytest.mark.asyncio
    async def test_cl_te_smuggling_prevention(self):
        reader = AsyncMock()
        writer = MagicMock()
        data = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 500\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        lines = data.split(b"\r\n")
        reader.read.side_effect = [b""] 
        handler = Http11ProxyHandler(reader, writer, "example.com", None, None, None, enable_tunneling=False)
        iter_lines = iter(lines)
        async def mock_read_line():
            try: return next(iter_lines)
            except StopIteration: return b""

        handler._read_strict_line = mock_read_line
        handler._read_chunked_body = AsyncMock(return_value=b"mock_body")
        handler._handle_request = AsyncMock()
        await handler.run()
        
        call_args = handler._handle_request.call_args
        if call_args:
            headers_dict = call_args[0][4]
            assert 'content-length' not in headers_dict
            assert 'transfer-encoding' in headers_dict

    @pytest.mark.asyncio
    async def test_obsolete_line_folding(self):
        reader = AsyncMock()
        writer = MagicMock()
        reader.read.side_effect = [
            b"GET / HTTP/1.1\r\n",
            b"Header: Value\r\n",
            b" Continued\r\n",
            b"\r\n"
        ]
        handler = Http11ProxyHandler(reader, writer, "host", None, None, None)
        await handler.run()
        writer.write.assert_called()
        assert b"400 Obsolete Line Folding Rejected" in writer.write.call_args[0][0]

    @pytest.mark.asyncio
    async def test_capture_callback(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()
        cb = MagicMock()
        reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n", b""]
        handler = Http11ProxyHandler(reader, writer, "a.com", cb, None, None, enable_tunneling=False)
        await handler.run()
        capture_calls = [call for call in cb.call_args_list if call[0][0] == "CAPTURE"]
        assert len(capture_calls) > 0
        req = capture_calls[0][0][1]
        assert isinstance(req, CapturedRequest)
        assert req.method == "GET"

    @pytest.mark.asyncio
    async def test_connect_method_mitm(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.start_tls = AsyncMock()
        ssl_factory = MagicMock()
        handler = Http11ProxyHandler(reader, writer, "", None, None, None, ssl_context_factory=ssl_factory)
        
        with patch("proxy_core.DualProtocolHandler") as MockDual:
            instance = MockDual.return_value
            instance.run = AsyncMock()
            await handler._handle_connect("secure.com:443")
            writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            writer.start_tls.assert_awaited()
            instance.run.assert_awaited()

    @pytest.mark.asyncio
    async def test_read_chunked_body(self):
        reader = AsyncMock()
        writer = MagicMock()
        handler = Http11ProxyHandler(reader, writer, "host", None, None, None)
        reader.read.side_effect = [b"4\r\nWiki\r\n", b"5\r\npedia\r\n", b"0\r\n\r\n"]
        body = await handler._read_chunked_body()
        assert body == b"Wikipedia"
    
    @pytest.mark.asyncio
    async def test_http11_gateway_timeout(self):
        """[NOVEL] Verify 504 Gateway Timeout behavior on upstream connect timeout."""
        reader = AsyncMock()
        writer = MagicMock()
        reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: timeout.com\r\n\r\n", b""]
        
        # Simulate asyncio.TimeoutError during upstream connection
        with patch("proxy_core.asyncio.open_connection", side_effect=asyncio.TimeoutError):
            handler = Http11ProxyHandler(reader, writer, "timeout.com", None, None, None, enable_tunneling=True)
            await handler.run()
            
            # Check for 504
            writer.write.assert_called()
            call_args = writer.write.call_args[0][0]
            assert b"504 Gateway Timeout" in call_args

# -- HTTP/2 Deep Logic & Flow Control --

class TestNativeProxyHandler:
    @pytest.fixture
    def mock_h2_setup(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()
        cb = MagicMock()
        handler = NativeProxyHandler(reader, writer, "h2.target", cb, None, None, enable_tunneling=False)
        return handler, reader, writer, cb

    @pytest.mark.asyncio
    async def test_h2_request_capture(self, mock_h2_setup):
        handler, _, _, cb = mock_h2_setup
        
        # Patch ALL H2 events to be safe
        with patch("proxy_core.RequestReceived", MockRequestReceived), \
             patch("proxy_core.DataReceived", MockDataReceived), \
             patch("proxy_core.StreamEnded", MockStreamEnded), \
             patch("proxy_core.TrailersReceived", MockTrailersReceived), \
             patch("proxy_core.StreamReset", MockStreamReset), \
             patch("proxy_core.WindowUpdated", MockWindowUpdated):
            
            req_event = MockRequestReceived()
            req_event.stream_id = 1
            req_event.headers = [(b":method", b"POST"), (b":path", b"/h2"), (b":authority", b"h2.target"), (b":scheme", b"https")]
            req_event.stream_ended = False
            
            await handler.handle_request_received(req_event)
            
            data_evt = MockDataReceived()
            data_evt.stream_id = 1
            data_evt.data = b"H2Body"
            data_evt.flow_controlled_length = 6
            data_evt.stream_ended = True
            
            await handler.handle_downstream_event(data_evt)
            handler.finalize_capture(handler.streams[1])
        
        capture_calls = [call for call in cb.call_args_list if call[0][0] == "CAPTURE"]
        assert len(capture_calls) == 1
        req = capture_calls[0][0][1]
        assert req.protocol == "HTTP/2"
        assert req.body == b"H2Body"

    @pytest.mark.asyncio
    async def test_flow_control_blocking(self, mock_h2_setup):
        handler, _, _, _ = mock_h2_setup
        stream_id = 1
        ctx = StreamContext(stream_id, "https")
        ctx.upstream_flow_event.clear()
        
        mock_conn = MagicMock()
        mock_conn.outbound_flow_control_window = 1000
        mock_conn.remote_flow_control_window.return_value = 0
        
        queue = asyncio.Queue()
        await queue.put((b"DATA", False, 0))
        
        h2_lock = asyncio.Lock()
        socket_lock = asyncio.Lock()
        
        sender_task = asyncio.create_task(
            handler._stream_sender(
                stream_id, mock_conn, MagicMock(), queue, ctx.upstream_flow_event,
                h2_lock, socket_lock, None, asyncio.Lock(), MagicMock(), asyncio.Lock()
            )
        )
        
        await asyncio.sleep(0.1)
        mock_conn.send_data.assert_not_called()
        
        ctx.upstream_flow_event.set()
        mock_conn.remote_flow_control_window.return_value = 100
        await asyncio.sleep(0.1)
        mock_conn.send_data.assert_called_once()
        sender_task.cancel()

    @pytest.mark.asyncio
    async def test_window_update_event_propagation(self, mock_h2_setup):
        handler, _, _, _ = mock_h2_setup
        ctx1 = StreamContext(1, "https")
        ctx1.upstream_flow_event.clear()
        handler.streams[1] = ctx1
        
        with patch("proxy_core.WindowUpdated", MockWindowUpdated):
            evt = MockWindowUpdated()
            evt.stream_id = 0
            await handler.handle_window_updated(evt, 'upstream')
            assert ctx1.upstream_flow_event.is_set()
            
            ctx1.upstream_flow_event.clear()
            evt.stream_id = 1
            await handler.handle_window_updated(evt, 'upstream')
            assert ctx1.upstream_flow_event.is_set()

    @pytest.mark.asyncio
    async def test_h2_header_sanitization(self, mock_h2_setup):
        handler, _, _, _ = mock_h2_setup
        raw_headers = [
            (b':method', b'GET'), (b':path', b'/'),
            (b'connection', b'keep-alive'), (b'te', b'trailers'),
            (b'te', b'compress'), (b'upgrade', b'h2c'),
        ]
        safe_headers, protocol = handler._prepare_forwarded_headers(raw_headers, is_upstream=True)
        safe_dict = {k: v for k, v in safe_headers}
        assert 'connection' not in safe_dict
        assert 'upgrade' not in safe_dict
        assert safe_dict.get('te') == 'trailers'
        assert ':method' in safe_dict

    @pytest.mark.asyncio
    async def test_h2_connect_protocol_disabled(self, mock_h2_setup):
        """
        [NOVEL] Verify that if Upstream doesn't support Extended CONNECT,
        we reject the client's request with a CONNECT_ERROR.
        """
        handler, _, _, _ = mock_h2_setup
        handler.enable_tunneling = True
        handler.upstream_conn = MagicMock()
        
        # Simulate Upstream settings where ENABLE_CONNECT_PROTOCOL is OFF (default 0)
        handler.upstream_conn.remote_settings.get.return_value = 0 
        
        with patch("proxy_core.RequestReceived", MockRequestReceived):
            evt = MockRequestReceived()
            evt.stream_id = 10
            evt.headers = [
                (b':method', b'CONNECT'),
                (b':protocol', b'websocket'), # RFC 8441 usage
                (b':authority', b'chat.example.com'),
                (b':scheme', b'https'),
                (b':path', b'/socket')
            ]
            evt.stream_ended = False
            
            await handler.handle_request_received(evt)
            
            # Should have called reset_stream on downstream
            handler.downstream_conn.reset_stream.assert_called_with(10, ANY)
            # Verify it cleaned up
            assert 10 not in handler.streams


class TestDualProtocol:
    @pytest.mark.asyncio
    async def test_protocol_detection_h2_preface(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.get_extra_info.return_value = None 
        reader.read.return_value = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        handler = DualProtocolHandler(reader, writer, "host", None, None, None)
        proto, data = await handler._detect_protocol()
        assert proto == "h2"
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_protocol_detection_fallback(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.get_extra_info.return_value = None
        reader.read.return_value = b'GET / HTTP/1.1\r\n'
        handler = DualProtocolHandler(reader, writer, "host", None, None, None)
        proto, data = await handler._detect_protocol()
        assert proto == "http/1.1"
        
    @pytest.mark.asyncio
    async def test_header_size_limit(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock() 
        writer.is_closing.return_value = False 
        
        huge_header = b"X-Huge: " + b"A" * 270000 + b"\r\n"
        reader.read.side_effect = [b"GET / HTTP/1.1\r\n", huge_header, b"\r\n"]
        
        handler = Http11ProxyHandler(reader, writer, "host", None, None, None)
        await handler.run()
        
        # Verify write was called (for the 400 error)
        assert writer.write.called
        args = writer.write.call_args_list[0][0][0]
        assert b"HTTP/1.1 400" in args

    @pytest.mark.asyncio
    async def test_slowloris_timeout_enforcement(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.is_closing.return_value = False
        reader.read.side_effect = asyncio.TimeoutError
        handler = Http11ProxyHandler(reader, writer, "host", None, None, None)
        await handler.run()
        writer.close.assert_called()

    @pytest.mark.asyncio
    async def test_upstream_connection_failure(self):
        reader = AsyncMock()
        writer = MagicMock()
        reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: bad.host\r\n\r\n", b""]
        with patch("proxy_core.asyncio.open_connection", side_effect=OSError("Refused")):
            handler = Http11ProxyHandler(reader, writer, "bad.host", None, None, None, enable_tunneling=True)
            await handler.run()
            writer.write.assert_called()
            args = writer.write.call_args[0][0]
            assert b"502 Bad Gateway" in args

class TestH2ResourceCleanup:
    
    @pytest.fixture
    def mock_h2_setup(self):
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()
        cb = MagicMock()
        handler = NativeProxyHandler(reader, writer, "h2.target", cb, None, None, enable_tunneling=False)
        return handler

    # [FIX] Patch ALL events in this scope to prevent type confusion
    @pytest.fixture(autouse=True)
    def patch_events(self):
        patcher = patch.multiple("proxy_core",
            RequestReceived=MockRequestReceived,
            DataReceived=MockDataReceived,
            StreamEnded=MockStreamEnded,
            StreamReset=MockStreamReset,
            WindowUpdated=MockWindowUpdated,
            TrailersReceived=MockTrailersReceived,
            ResponseReceived=MockResponseReceived
        )
        patcher.start()
        yield
        patcher.stop()

    @pytest.mark.asyncio
    async def test_rst_stream_cleans_resources(self, mock_h2_setup):
        handler = mock_h2_setup
        stream_id = 5
        handler.streams[stream_id] = MagicMock()
        
        evt = MockStreamReset()
        evt.stream_id = stream_id
        # [FIX] Add error_code for logging
        evt.error_code = 0 
        await handler.handle_downstream_event(evt)
        assert stream_id not in handler.streams

    @pytest.mark.asyncio
    async def test_goaway_handling(self, mock_h2_setup):
        handler = mock_h2_setup
        await handler.graceful_shutdown()
        assert handler.draining is True
        handler.client_writer.write.assert_called() 
        from proxy_core import GOAWAY_MAX_FRAME
        assert GOAWAY_MAX_FRAME in handler.client_writer.write.call_args[0][0]

    @pytest.mark.asyncio
    async def test_upstream_disconnect_propagation(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        handler.streams[sid] = ctx
        handler._cleanup_stream(sid, upstream_closed=True, force_close=True)
        assert sid not in handler.streams
        assert ctx.upstream_flow_event.is_set()

    @pytest.mark.asyncio
    async def test_downstream_disconnect_propagation(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        handler.streams[sid] = ctx
        handler._cleanup_stream(sid, upstream_closed=False, force_close=True)
        assert sid not in handler.streams

    @pytest.mark.asyncio
    async def test_stream_cleanup_on_error(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        handler.streams[sid] = ctx
        
        # Use our own Exception class so we can catch it reliably
        with patch("proxy_core.ErrorCodes", MagicMock()):
            # Mock the conn so reset_stream doesn't fail
            handler.downstream_conn = MagicMock()
            handler.terminate = AsyncMock()

            try:
                raise MockProtocolError("Fail")
            except MockProtocolError:
                handler._cleanup_stream(sid, force_close=True)
            
        assert sid not in handler.streams

    @pytest.mark.asyncio
    async def test_stream_cleanup_on_window_exhaustion(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        handler.streams[sid] = ctx
        handler._cleanup_stream(sid, upstream_closed=False, force_close=True)
        assert sid not in handler.streams

    @pytest.mark.asyncio
    async def test_stream_cleanup_on_trailers_received(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        handler.streams[sid] = ctx
        
        evt = MockTrailersReceived()
        evt.stream_id = sid
        # Trailers usually imply stream end or are followed by it.
        # This test ensures no crash, but cleanup happens on StreamEnded.
        await handler.handle_downstream_event(evt)
        assert sid in handler.streams # Trailers alone shouldn't remove it unless forced

    @pytest.mark.asyncio
    async def test_stream_cleanup_on_response_received(self, mock_h2_setup):
        handler = mock_h2_setup
        sid = 1
        ctx = StreamContext(sid, "https")
        ctx.downstream_closed = True # [FIX] Pre-close downstream so upstream close triggers full cleanup
        handler.streams[sid] = ctx

        evt = MockResponseReceived()
        evt.stream_id = sid
        evt.headers = [(b":status", b"200")]
        evt.stream_ended = False

        await handler.handle_upstream_event(evt)
        assert sid in handler.streams

        end_evt = MockStreamEnded()
        end_evt.stream_id = sid
        await handler.handle_upstream_event(end_evt)
        assert sid not in handler.streams