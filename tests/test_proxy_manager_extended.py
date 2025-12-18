
import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock, ANY
import proxy_manager
from proxy_manager import ProxyManager, QuicServer, CapturedRequest

# Mock aioquic presence for testing
proxy_manager.HAS_AIOQUIC = True

@pytest.fixture
def mock_aioquic():
    # Because proxy_manager imports serve/connect from aioquic.asyncio,
    # and we might have defined dummies or they might be missing if imported before patch.
    # The safest way is to patch them where they are used or ensure they exist in proxy_manager.
    # Since we added dummy functions in proxy_manager.py, we can patch them there.
    with patch("proxy_manager.serve", new_callable=AsyncMock) as mock_serve, \
         patch("proxy_manager.connect", new_callable=AsyncMock) as mock_connect, \
         patch("proxy_manager.QuicConfiguration") as mock_config, \
         patch("proxy_manager.H3Connection") as mock_h3_conn, \
         patch("proxy_manager.QuicConnectionProtocol") as mock_quic_proto:
        yield {
            "serve": mock_serve,
            "connect": mock_connect,
            "config": mock_config,
            "h3_conn": mock_h3_conn,
            "quic_proto": mock_quic_proto
        }

@pytest.fixture
def manager():
    return ProxyManager(tcp_port=8080, quic_port=4433)

class TestProxyManagerExtended:

    @pytest.mark.asyncio
    async def test_run_starts_servers(self, manager):
        with patch("proxy_core.start_proxy_server", new_callable=AsyncMock) as mock_start_proxy, \
             patch.object(manager.quic_server, "start", new_callable=AsyncMock) as mock_quic_start:

            task = asyncio.create_task(manager.run())
            await asyncio.sleep(0.01) # Let it start

            mock_start_proxy.assert_called_once()
            mock_quic_start.assert_called_once()

            manager.stop()
            await task

    def test_captured_request_repr(self):
        req = CapturedRequest("HTTP/1.1", "GET", "http://example.com", {}, b"body")
        assert repr(req) == "<HTTP/1.1 GET http://example.com (4 bytes)>"

    def test_unified_capture_callback(self, manager):
        mock_ext_callback = MagicMock()
        manager.external_callback = mock_ext_callback

        # Test CAPTURE
        req = CapturedRequest("HTTP/1.1", "GET", "http://example.com", {}, b"")
        manager.unified_capture_callback("CAPTURE", req)
        assert req.id == 0
        assert manager.count == 1
        mock_ext_callback.assert_called_with("CAPTURE", req)

        # Test QUIC
        manager.unified_capture_callback("QUIC", ("127.0.0.1", 1234), "msg")
        mock_ext_callback.assert_called_with("QUIC", "msg")

        # Test SYSTEM
        manager.unified_capture_callback("SYSTEM", "sys_msg")
        mock_ext_callback.assert_called_with("SYSTEM", "sys_msg")

        # Test ERROR
        manager.unified_capture_callback("ERROR", "err_source", "err_msg")
        mock_ext_callback.assert_called_with("ERROR", "err_msg")

class TestQuicServer:
    @pytest.mark.asyncio
    async def test_start_no_aioquic(self):
        # Temporarily disable
        orig = proxy_manager.HAS_AIOQUIC
        proxy_manager.HAS_AIOQUIC = False
        try:
            qs = QuicServer("localhost", 4433, None)
            await qs.start() # Should return early, logging error
            # No assert needed, just ensuring no crash
        finally:
            proxy_manager.HAS_AIOQUIC = orig

    @pytest.mark.asyncio
    async def test_start_with_aioquic(self, mock_aioquic):
        qs = QuicServer("localhost", 4433, None)
        with patch.object(qs, "load_server_ssl_context") as mock_load_ctx:
             await qs.start()
             mock_aioquic["serve"].assert_called_once()
             mock_load_ctx.assert_called_once()

    def test_load_server_ssl_context_found(self):
        qs = QuicServer("localhost", 4433, None)
        with patch("os.path.exists", return_value=True), \
             patch("proxy_manager.QuicConfiguration") as mock_config:

            qs.load_server_ssl_context()
            mock_config.return_value.load_cert_chain.assert_called()

    def test_load_server_ssl_context_not_found(self):
        qs = QuicServer("localhost", 4433, None)
        with patch("os.path.exists", return_value=False), \
             patch("proxy_manager.QuicConfiguration") as mock_config:

            qs.load_server_ssl_context()
            mock_config.return_value.load_cert_chain.assert_not_called()

def test_h3_logic_reload():
    import sys
    import importlib

    # Store original modules to restore later
    original_modules = sys.modules.copy()

    # Define a base class for QuicConnectionProtocol so inheritance works
    class MockQuicConnectionProtocol:
        def __init__(self, *args, **kwargs):
            self._quic = MagicMock()
        def connection_made(self, transport): pass
        def quic_event_received(self, event): pass

    # Mock aioquic modules
    mock_aioquic = MagicMock()
    sys.modules["aioquic"] = mock_aioquic

    # Mock asyncio module inside aioquic
    mock_asyncio_mod = MagicMock()
    mock_asyncio_mod.QuicConnectionProtocol = MockQuicConnectionProtocol
    sys.modules["aioquic.asyncio"] = mock_asyncio_mod

    sys.modules["aioquic.quic"] = MagicMock()
    sys.modules["aioquic.quic.configuration"] = MagicMock()
    sys.modules["aioquic.quic.events"] = MagicMock()
    sys.modules["aioquic.h3"] = MagicMock()
    sys.modules["aioquic.h3.connection"] = MagicMock()
    sys.modules["aioquic.h3.events"] = MagicMock()

    # Now reload proxy_manager to pick up the mocks
    try:
        importlib.reload(proxy_manager)

        # Now the classes should be defined
        assert proxy_manager.HAS_AIOQUIC
        assert proxy_manager.H3ProxyInterceptor is not None

        # Test H3ProxyInterceptor logic
        interceptor = proxy_manager.H3ProxyInterceptor(MagicMock())
        interceptor._h3_conn = MagicMock()
        interceptor._stream_contexts = {}

        # Test connection_made
        transport = MagicMock()
        interceptor.connection_made(transport)
        # verify socket options set
        transport.get_extra_info.assert_called_with('socket')

    finally:
        # Restore original modules
        # This is a bit brute-force but ensures we don't leave mocks around
        to_delete = [k for k in sys.modules if k not in original_modules and k.startswith("aioquic")]
        for k in to_delete:
            del sys.modules[k]

        # Restore modified modules if any (aioquic wasn't there before, so deletion is enough)

        # RELOAD proxy_manager to restore its original state (likely without aioquic)
        importlib.reload(proxy_manager)
