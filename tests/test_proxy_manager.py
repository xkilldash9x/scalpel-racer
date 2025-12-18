# tests/test_proxy_manager.py

"""
Tests for proxy_manager.py.
Refactored to align with aioquic-based implementation.
Removed legacy manual parser tests (QuicPacketParser, etc.).
Tests now verify ProxyManager callbacks and high-level Interceptor logic.
"""
import pytest
import asyncio
import sys
import importlib
from unittest.mock import MagicMock, patch, AsyncMock

# -- Define Dummy Base Class --
# We need a real class for inheritance so H3ProxyInterceptor retains its methods.
# Inheriting from MagicMock causes all methods on the subclass to become Mocks.
class DummyQuicConnectionProtocol:
    def __init__(self, *args, **kwargs):
        self._quic = MagicMock()
    
    def connection_made(self, transport):
        pass
    
    def transmit(self):
        pass

# -- FORCE MOCK AIOQUIC --
# Mock aioquic unconditionally.
mock_aioquic = MagicMock()

# Mock aioquic.asyncio explicitly to provide the dummy base class
mock_aioquic_asyncio = MagicMock()
mock_aioquic_asyncio.QuicConnectionProtocol = DummyQuicConnectionProtocol

mock_aioquic_quic = MagicMock()
mock_aioquic_h3 = MagicMock()

# Setup sub-module structures
sys.modules["aioquic"] = mock_aioquic
sys.modules["aioquic.asyncio"] = mock_aioquic_asyncio
sys.modules["aioquic.quic"] = mock_aioquic_quic
sys.modules["aioquic.h3"] = mock_aioquic_h3
sys.modules["aioquic.quic.configuration"] = MagicMock()
sys.modules["aioquic.quic.events"] = MagicMock()
sys.modules["aioquic.h3.connection"] = MagicMock()
sys.modules["aioquic.h3.events"] = MagicMock()

# -- RELOAD PROXY MANAGER --
import proxy_manager
importlib.reload(proxy_manager)

from proxy_manager import (
    ProxyManager,
    QuicServer,
    CapturedRequest,
    H3ProxyInterceptor
)

# -- Data Class Tests --
class TestCapturedRequest:
    def test_repr(self):
        """Verify the string representation of a captured request."""
        headers = {"Host": "example.com"}
        req = CapturedRequest("HTTP/3", "GET", "https://example.com/foo", headers, body=b"test")
        rep = repr(req)
        assert "HTTP/3" in rep
        assert "GET" in rep
        assert "https://example.com/foo" in rep
        assert "4 bytes" in rep

# -- Manager Integration Tests --
class TestProxyManager:
    def test_unified_callback_formatting(self):
        """Test the formatting logic of the unified callback."""
        mock_ext_cb = MagicMock()
        manager = ProxyManager(external_callback=mock_ext_cb)

        # Test CAPTURE propagation
        req = CapturedRequest("HTTP/1.1", "GET", "http://test.local", {})
        
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("CAPTURE", "TCP_CLIENT", req)
            mock_log.info.assert_called()
            # Verify external callback received the request
            mock_ext_cb.assert_called_with("CAPTURE", req)
            # Verify ID assignment
            assert req.id == 0

    def test_quic_logging_passthrough(self):
        """Test that QUIC events are logged (even if raw data is passed)."""
        manager = ProxyManager()
        quic_data = "Raw QUIC Data or Event"
        
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("QUIC", ("1.1.1.1", 443), quic_data)
            log_call = mock_log.info.call_args[0][0]
            assert "[QUIC]" in log_call
            assert "1.1.1.1:443" in log_call
            assert "Raw QUIC Data" in log_call

    def test_error_propagation(self):
        """Test that system errors are logged correctly."""
        manager = ProxyManager()
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("ERROR", "127.0.0.1", "Connection Reset")
            mock_log.error.assert_called()
            assert "Connection Reset" in mock_log.error.call_args[0][0]

    def test_callback_resilience(self):
        """Ensure logging doesn't crash regardless of input data type."""
        manager = ProxyManager()
        test_inputs = [
            ("NotADict", str),
            ({"partial": "data"}, dict),
            (None, type(None)),
            ([1, 2, 3], list),
            (12345, int),
            (b'\x00\x01', bytes)
        ]
        
        with patch("proxy_manager.log") as mock_log:
            for input_data, input_type in test_inputs:
                try:
                    manager.unified_capture_callback("QUIC", "1.2.3.4", input_data)
                except Exception as e:
                    pytest.fail(f"Manager crashed on input type {input_type}: {e}")
                assert mock_log.info.called

# -- H3 Interceptor Logic Tests --
class TestH3ProxyInterceptor:
    
    @pytest.fixture
    def interceptor(self):
        if H3ProxyInterceptor is None:
            pytest.fail("H3ProxyInterceptor is None despite mocks! Check sys.modules patching.")
            
        mock_quic = MagicMock()
        # This will now inherit from DummyQuicConnectionProtocol, not MagicMock
        interceptor = H3ProxyInterceptor(mock_quic)
        interceptor._h3_conn = MagicMock()
        interceptor.callback = MagicMock()
        return interceptor

    @pytest.mark.asyncio
    async def test_headers_processing_capture(self, interceptor):
        """Test that headers trigger a capture callback."""
        # Simulate HeadersReceived event (mocking aioquic object)
        mock_event = MagicMock()
        mock_event.stream_id = 0
        mock_event.headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/")
        ]
        mock_event.stream_ended = True

        # Mock the bridge task to prevent actual network call
        interceptor._bridge_to_upstream = AsyncMock()

        # Run handler
        await interceptor._handle_request_headers(mock_event)

        # Verify Capture
        assert interceptor.callback.called
        captured_req = interceptor.callback.call_args[0][1]
        assert isinstance(captured_req, CapturedRequest)
        assert captured_req.url == "https://example.com/"

    @pytest.mark.asyncio
    async def test_upstream_trigger(self, interceptor):
        """Test that a request triggers the upstream bridge."""
        mock_event = MagicMock()
        mock_event.stream_id = 5
        mock_event.headers = [(b":authority", b"target.local")]
        mock_event.stream_ended = False
        
        interceptor._bridge_to_upstream = AsyncMock()
        
        await interceptor._handle_request_headers(mock_event)
        
        interceptor._bridge_to_upstream.assert_called()
        call_args = interceptor._bridge_to_upstream.call_args
        # Check args: stream_id, authority, headers, fin
        assert call_args[0][0] == 5
        assert call_args[0][1] == "target.local"

class TestQuicServerStructure:
    def test_server_init(self):
        """Ensure QuicServer initializes without immediate error."""
        callback = MagicMock()
        server = QuicServer("0.0.0.0", 4433, callback)
        assert server.host == "0.0.0.0"
        assert server.port == 4433
    
    def test_ssl_context_missing_files(self):
        """Test graceful handling of missing certs."""
        callback = MagicMock()
        server = QuicServer("0.0.0.0", 4433, callback)
        
        with patch("os.path.exists", return_value=False):
            with patch("proxy_manager.log") as mock_log:
                server.load_server_ssl_context()
                mock_log.warning.assert_called()