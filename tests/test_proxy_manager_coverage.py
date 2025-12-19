
import asyncio
import logging
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import importlib

# Fixture to safely handle sys.modules manipulation
@pytest.fixture
def clean_sys_modules():
    """
    Snapshot sys.modules before test and restore after.
    This ensures no mock modules leak into other tests.
    """
    original_modules = sys.modules.copy()
    yield

    # Restore original modules
    sys.modules.clear()
    sys.modules.update(original_modules)

    # Force reload of proxy_manager if it's still loaded, to reset global state like HAS_AIOQUIC
    if 'proxy_manager' in sys.modules:
        del sys.modules['proxy_manager']

@pytest.fixture
def mock_aioquic_available(clean_sys_modules, monkeypatch):
    """Mocks aioquic modules to simulate installation."""

    # Create dummy modules structure
    aioquic = MagicMock()
    aioquic.asyncio = MagicMock()
    aioquic.quic = MagicMock()
    aioquic.h3 = MagicMock()

    # Define a base class for QuicConnectionProtocol
    class MockQuicConnectionProtocol:
        def __init__(self, quic_connection, *args, **kwargs):
            self._quic = quic_connection
        def connection_made(self, transport): pass
        def datagram_received(self, data, addr): pass

    # Assign mocks
    aioquic.asyncio.QuicConnectionProtocol = MockQuicConnectionProtocol
    aioquic.asyncio.serve = AsyncMock()
    aioquic.asyncio.connect = MagicMock()

    aioquic.quic.configuration.QuicConfiguration = MagicMock()

    # Event classes
    aioquic.quic.events.StreamDataReceived = type("StreamDataReceived", (object,), {})
    aioquic.quic.events.HandshakeCompleted = type("HandshakeCompleted", (object,), {})
    aioquic.quic.events.ConnectionTerminated = type("ConnectionTerminated", (object,), {})
    aioquic.quic.events.QuicEvent = type("QuicEvent", (object,), {})

    aioquic.h3.connection.H3Connection = MagicMock()

    # H3 Event classes
    aioquic.h3.events.DataReceived = type("DataReceived", (object,), {})
    aioquic.h3.events.HeadersReceived = type("HeadersReceived", (object,), {})
    aioquic.h3.events.H3Event = type("H3Event", (object,), {})

    # Inject into sys.modules
    sys.modules['aioquic'] = aioquic
    sys.modules['aioquic.asyncio'] = aioquic.asyncio
    sys.modules['aioquic.quic'] = aioquic.quic
    sys.modules['aioquic.quic.configuration'] = aioquic.quic.configuration
    sys.modules['aioquic.quic.events'] = aioquic.quic.events
    sys.modules['aioquic.h3'] = aioquic.h3
    sys.modules['aioquic.h3.connection'] = aioquic.h3.connection
    sys.modules['aioquic.h3.events'] = aioquic.h3.events

    # Import proxy_manager ensuring it sees the mocks
    if 'proxy_manager' in sys.modules:
        del sys.modules['proxy_manager']

    import proxy_manager
    # Ensure the global flag is set
    monkeypatch.setattr(proxy_manager, 'HAS_AIOQUIC', True)

    yield proxy_manager

@pytest.fixture
def mock_aioquic_missing(clean_sys_modules, monkeypatch):
    """Simulates missing aioquic."""

    # Ensure aioquic is not in sys.modules
    for mod in list(sys.modules.keys()):
        if mod.startswith('aioquic'):
            del sys.modules[mod]

    # Mock __import__ to raise ImportError for aioquic
    orig_import = __import__
    def mock_import(name, *args, **kwargs):
        if name.startswith('aioquic'):
            raise ImportError("aioquic not found")
        return orig_import(name, *args, **kwargs)

    with patch('builtins.__import__', side_effect=mock_import):
        if 'proxy_manager' in sys.modules:
            del sys.modules['proxy_manager']
        import proxy_manager
        monkeypatch.setattr(proxy_manager, 'HAS_AIOQUIC', False)
        yield proxy_manager

@pytest.mark.asyncio
async def test_proxy_manager_without_aioquic(mock_aioquic_missing):
    """Test ProxyManager initialization and start when aioquic is missing."""
    pm = mock_aioquic_missing.ProxyManager()
    assert pm.quic_server is not None

    with patch('proxy_manager.log') as mock_log:
        await pm.quic_server.start()
        mock_log.error.assert_called_with("Cannot start QUIC Server: aioquic library is missing.")

@pytest.mark.asyncio
async def test_proxy_manager_with_aioquic_init(mock_aioquic_available):
    """Test ProxyManager init with aioquic present."""
    pm = mock_aioquic_available.ProxyManager()
    assert mock_aioquic_available.HAS_AIOQUIC is True

    with patch('os.path.exists', return_value=True), \
         patch('proxy_manager.QuicConfiguration') as MockConfig:
        config = pm.quic_server.load_server_ssl_context()
        assert config.load_cert_chain.called

@pytest.mark.asyncio
async def test_proxy_manager_run_stop(mock_aioquic_missing):
    """Test run and stop lifecycle."""
    pm = mock_aioquic_missing.ProxyManager(tcp_port=0)

    with patch('proxy_core.start_proxy_server', new_callable=AsyncMock) as mock_start_proxy:
         task = asyncio.create_task(pm.run())
         await asyncio.sleep(0.01)

         assert mock_start_proxy.called

         pm.stop()
         await task

@pytest.mark.asyncio
async def test_h3_proxy_interceptor_logic(mock_aioquic_available):
    """Test the logic within H3ProxyInterceptor."""
    interceptor = mock_aioquic_available.H3ProxyInterceptor(MagicMock())
    interceptor._h3_conn = MagicMock()

    event = mock_aioquic_available.HeadersReceived()
    event.stream_id = 1
    event.headers = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"), (b":path", b"/")]
    event.stream_ended = True

    with patch.object(interceptor, '_handle_request_headers', new_callable=AsyncMock) as mock_handle:
        interceptor._h3_conn.handle_event.return_value = [event]
        quic_event = mock_aioquic_available.StreamDataReceived()
        interceptor.quic_event_received(quic_event)
        mock_handle.assert_called_with(event)

@pytest.mark.asyncio
async def test_h3_handle_request_headers(mock_aioquic_available):
    """Test processing of request headers in interceptor."""
    interceptor = mock_aioquic_available.H3ProxyInterceptor(MagicMock())
    interceptor.callback = MagicMock()

    event = mock_aioquic_available.HeadersReceived()
    event.stream_id = 1
    event.headers = [(b":method", b"GET"), (b":authority", b"example.com"), (b":path", b"/")]
    event.stream_ended = True

    with patch.object(interceptor, '_bridge_to_upstream', new_callable=AsyncMock) as mock_bridge:
        await interceptor._handle_request_headers(event)

        # Check capture callback
        assert interceptor.callback.call_args[0][0] == "CAPTURE"
        req = interceptor.callback.call_args[0][1]
        assert req.url == "https://example.com/"

        assert 1 in interceptor._stream_contexts
        mock_bridge.assert_called()

@pytest.mark.asyncio
async def test_upstream_bridge_logic(mock_aioquic_available):
    """Test UpstreamBridge logic."""
    bridge = mock_aioquic_available.UpstreamBridge(MagicMock())
    bridge._h3_conn = MagicMock()
    bridge.downstream_interceptor = MagicMock()
    bridge.client_stream_id = 10

    event = mock_aioquic_available.DataReceived()
    event.data = b"response data"
    event.stream_ended = True

    bridge._h3_conn.handle_event.return_value = [event]

    quic_event = mock_aioquic_available.StreamDataReceived()
    bridge.quic_event_received(quic_event)

    bridge.downstream_interceptor.relay_response_data.assert_called_with(10, b"response data", True)
    bridge.downstream_interceptor.mark_stream_complete.assert_called_with(10)
