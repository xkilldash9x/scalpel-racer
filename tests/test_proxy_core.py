# FILE: ./tests/test_proxy_core.py
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, ANY
import proxy_core
from proxy_core import NativeProxyHandler, StreamContext

# Mock h2 dependencies if not present
try:
    import h2.connection
    import h2.events
except ImportError:
    pass

@pytest.fixture
def proxy_handler():
    client_reader = AsyncMock()
    client_writer = MagicMock()
    client_writer.drain = AsyncMock()
    client_writer.write = MagicMock()
    client_writer.is_closing.return_value = False
    
    capture_cb = MagicMock()
    
    # [FIX] Mock SettingCodes to prevent AttributeError on update_settings
    MockSettingCodes = MagicMock()
    MockSettingCodes.ENABLE_CONNECT_PROTOCOL = 1

    # [FIX] Patch H2Connection, H2Configuration AND SettingCodes
    with patch("proxy_core.H2Connection") as MockH2Conn, \
         patch("proxy_core.H2Configuration") as MockH2Config, \
         patch("proxy_core.SettingCodes", MockSettingCodes), \
         patch("proxy_core.H2_AVAILABLE", True):
        
        handler = NativeProxyHandler(
            client_reader, client_writer, 
            "example.com:443", capture_cb, None, None
        )
        # Manually setup mocks since the real init won't populate them if patched
        handler.downstream_conn = MagicMock()
        handler.downstream_conn.data_to_send.return_value = b""
        handler.downstream_conn.local_flow_control_window.return_value = 65535
        
        handler.upstream_conn = MagicMock()
        handler.upstream_conn.data_to_send.return_value = b""
        handler.upstream_conn.local_flow_control_window.return_value = 65535
        
        return handler

@pytest.mark.asyncio
async def test_resolve_target(proxy_handler):
    proxy_handler.explicit_host = "example.com:8443"
    assert proxy_handler._resolve_target() is True
    assert proxy_handler.upstream_port == 8443
    
    proxy_handler.explicit_host = "example.com"
    assert proxy_handler._resolve_target() is True
    assert proxy_handler.upstream_port == 443

@pytest.mark.asyncio
async def test_connect_upstream(proxy_handler):
    with patch("asyncio.open_connection") as mock_open:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        # Setup ALPN
        mock_transport = MagicMock()
        mock_transport.selected_alpn_protocol.return_value = "h2"
        mock_writer.get_extra_info.return_value = mock_transport
        
        mock_open.return_value = (mock_reader, mock_writer)
        
        proxy_handler.upstream_host = "example.com"
        proxy_handler.upstream_port = 443
        
        await proxy_handler.connect_upstream()
        
        assert proxy_handler.upstream_reader == mock_reader
        assert proxy_handler.upstream_writer == mock_writer

@pytest.mark.asyncio
async def test_handle_request_received(proxy_handler):
    # Setup H2 event
    event = MagicMock()
    event.stream_id = 1
    event.headers = [(b":method", b"GET"), (b":path", b"/"), (b"host", b"example.com")]
    event.stream_ended = False
    
    await proxy_handler.handle_request_received(event)
    
    assert 1 in proxy_handler.streams
    ctx = proxy_handler.streams[1]
    assert ctx.request_pseudo[":method"] == "GET"
    
    # Verify forwarding
    proxy_handler.upstream_conn.send_headers.assert_called_with(1, event.headers, end_stream=False)

@pytest.mark.asyncio
async def test_handle_data_received_capture_and_forward(proxy_handler):
    # Setup Stream Context
    ctx = StreamContext(1, "https")
    proxy_handler.streams[1] = ctx
    
    event = MagicMock()
    event.stream_id = 1
    event.data = b"payload"
    event.flow_controlled_length = 7
    event.stream_ended = False
    
    # Mock writers
    proxy_handler.upstream_writer = MagicMock()
    proxy_handler.upstream_writer.drain = AsyncMock()
    
    # Mock data_to_send to simulate data generation
    proxy_handler.upstream_conn.data_to_send.return_value = b"H2FRAME"
    
    await proxy_handler.handle_data_received(event)
    
    # Verify capture
    assert ctx.request_body == b"payload"
    
    # Verify forwarding logic (forward_data)
    proxy_handler.upstream_conn.send_data.assert_called_with(1, b"payload", end_stream=False)
    # Verify ack on downstream (source)
    proxy_handler.downstream_conn.acknowledge_received_data.assert_called_with(7, 1)

@pytest.mark.asyncio
async def test_flow_control_wait(proxy_handler):
    # Simulate blocked window
    ctx = StreamContext(1, "https")
    proxy_handler.streams[1] = ctx
    
    # Window 0
    proxy_handler.upstream_conn.local_flow_control_window.return_value = 0
    
    event = MagicMock()
    event.stream_id = 1
    event.data = b"payload"
    event.flow_controlled_length = 7
    
    # Start task to handle data (which will block)
    task = asyncio.create_task(proxy_handler.handle_data_received(event))
    
    await asyncio.sleep(0.01)
    assert not task.done() # Should be blocked waiting for window
    
    # Simulate WindowUpdate
    update_event = MagicMock()
    update_event.stream_id = 1
    await proxy_handler.handle_window_updated(update_event)
    
    # Open window for the check loop
    proxy_handler.upstream_conn.local_flow_control_window.return_value = 100
    
    # Task should complete now
    await asyncio.wait_for(task, timeout=1.0)
    proxy_handler.upstream_conn.send_data.assert_called()

@pytest.mark.asyncio
async def test_cleanup(proxy_handler):
    # [FIX] Create a mock task and explicitly set done() to False
    mock_task = MagicMock()
    mock_task.done.return_value = False
    
    proxy_handler.tasks = [mock_task]
    proxy_handler.client_writer.wait_closed = AsyncMock()
    
    await proxy_handler.cleanup()
    
    # Now this should pass because the loop condition 'not task.done()' is met
    mock_task.cancel.assert_called()
    assert proxy_handler.closed.is_set()