# tests/test_proxy_core_advanced.py
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, call
import proxy_core
from proxy_core import NativeProxyHandler, StreamContext

# Robustly retrieve or mock ErrorCodes and SettingCodes
try:
    from h2.errors import ErrorCodes
    from h2.settings import SettingCodes
except ImportError:
    # Fallback mocks for testing in environments where h2 might be missing/broken
    class ErrorCodes:
        NO_ERROR = 0
        PROTOCOL_ERROR = 1
        FLOW_CONTROL_ERROR = 3
        CANCEL = 8
    
    class SettingCodes:
        ENABLE_CONNECT_PROTOCOL = 8

# Ensure proxy_core uses these if it fell back to objects
if proxy_core.ErrorCodes is object:
    proxy_core.ErrorCodes = ErrorCodes
if proxy_core.SettingCodes is object:
    proxy_core.SettingCodes = SettingCodes

# --- Fixtures ---

@pytest.fixture
def advanced_handler():
    """
    Creates a NativeProxyHandler with fully mocked connections for Sans-IO testing.
    """
    client_reader = AsyncMock()
    client_writer = MagicMock()
    client_writer.drain = AsyncMock()
    client_writer.is_closing.return_value = False
    
    # Patch H2 components globally for the handler init
    # [FIX] We MUST patch H2_AVAILABLE to True to bypass the guard clause in __init__
    with patch("proxy_core.H2Connection") as MockH2Conn, \
         patch("proxy_core.H2Configuration"), \
         patch("proxy_core.SettingCodes", SettingCodes), \
         patch("proxy_core.H2_AVAILABLE", True):
        
        handler = NativeProxyHandler(
            client_reader, client_writer, 
            "example.com:443", MagicMock(), None, None
        )
        
        # Setup Downstream Mock
        handler.downstream_conn = MagicMock()
        handler.downstream_conn.data_to_send.return_value = b""
        # Default large windows to prevent accidental blocking in non-flow tests
        handler.downstream_conn.local_flow_control_window.return_value = 65535
        # [FIX] Set outbound window as INT, not MagicMock, to support min() comparison
        handler.downstream_conn.outbound_flow_control_window = 65535
        
        # Setup Upstream Mock
        handler.upstream_conn = MagicMock()
        handler.upstream_conn.data_to_send.return_value = b""
        handler.upstream_conn.local_flow_control_window.return_value = 65535
        # [FIX] Set outbound window as INT, not MagicMock, to support min() comparison
        handler.upstream_conn.outbound_flow_control_window = 65535
        
        handler.upstream_conn.remote_flow_control_window.return_value = 65535

        handler.upstream_writer = MagicMock()
        handler.upstream_writer.drain = AsyncMock()
        handler.upstream_writer.is_closing.return_value = False

        return handler

# --- Flow Control Tests (The Hard Stuff) ---

@pytest.mark.asyncio
async def test_forward_data_insufficient_window_then_update(advanced_handler):
    """
    Verifies that forward_data pauses when the window is too small, 
    and resumes only after a relevant WINDOW_UPDATE is received.
    """
    # 1. Setup: Stream 1, Upstream Window is 0 (Blocked)
    stream_id = 1
    ctx = StreamContext(stream_id, "https")
    advanced_handler.streams[stream_id] = ctx
    
    # Mock destination (Upstream) to report 0 window
    # Note: remote_flow_control_window is a method
    advanced_handler.upstream_conn.remote_flow_control_window.side_effect = lambda sid: 0
    
    # Event data (payload > window)
    event = MagicMock()
    event.stream_id = stream_id
    event.data = b"payload"
    event.flow_controlled_length = 7
    event.stream_ended = False

    # 2. Action: Call forward_data (should block)
    # We run this in a task so we can simulate the update concurrently
    task = asyncio.create_task(advanced_handler.forward_data(advanced_handler.upstream_conn, stream_id, event.data, event.flow_controlled_length, event.stream_ended))
    
    # Allow task to hit the wait point
    await asyncio.sleep(0.01)
    
    # [Robustness] Check if task failed early
    if task.done():
        exc = task.exception()
        if exc:
            raise exc
        assert False, "Task completed early but should be blocked waiting for flow control"
    
    # Verify no data sent yet
    advanced_handler.upstream_conn.send_data.assert_not_called()

    # 3. Simulate WINDOW_UPDATE on Stream 1
    # Open the window in the mock
    advanced_handler.upstream_conn.remote_flow_control_window.side_effect = lambda sid: 100
    
    update_event = MagicMock()
    update_event.stream_id = stream_id
    
    await advanced_handler.handle_window_updated(update_event)

    # 4. Result: Task should complete and send data
    await asyncio.wait_for(task, timeout=0.1)
    
    advanced_handler.upstream_conn.send_data.assert_called_with(1, b"payload", end_stream=False)
    # Verify Ack sent to source (Downstream)
    advanced_handler.downstream_conn.acknowledge_received_data.assert_called_with(7, 1)


@pytest.mark.asyncio
async def test_forward_data_global_window_update(advanced_handler):
    """
    Verifies that a Global WINDOW_UPDATE (Stream 0) unblocks a specific stream.
    """
    stream_id = 5
    ctx = StreamContext(stream_id, "https")
    advanced_handler.streams[stream_id] = ctx
    
    # Block via Connection Window (Stream window might be fine, but Connection is 0)
    # Note: outbound_flow_control_window is a property. We mock the check inside forward_data
    # by modifying the attribute directly or relying on how forward_data accesses it.
    # In forward_data: conn_window = destination_conn.outbound_flow_control_window
    
    # To simulate blocking via connection window, we set the property to 0
    advanced_handler.upstream_conn.outbound_flow_control_window = 0
    advanced_handler.upstream_conn.remote_flow_control_window.return_value = 100

    event = MagicMock()
    event.stream_id = stream_id
    event.data = b"123"
    event.flow_controlled_length = 3
    event.stream_ended = False
    
    task = asyncio.create_task(advanced_handler.forward_data(advanced_handler.upstream_conn, stream_id, event.data, event.flow_controlled_length, event.stream_ended))
    
    await asyncio.sleep(0.01)
    
    # [Robustness]
    if task.done() and task.exception():
        raise task.exception()
    assert not task.done()

    # Unblock via Stream 0 Update
    # Set the property back to 100
    advanced_handler.upstream_conn.outbound_flow_control_window = 100
    
    update_event = MagicMock()
    update_event.stream_id = 0 # Global
    await advanced_handler.handle_window_updated(update_event)

    await asyncio.wait_for(task, timeout=0.1)
    advanced_handler.upstream_conn.send_data.assert_called_once()


@pytest.mark.asyncio
async def test_forward_data_timeout(advanced_handler):
    """
    Verifies that if the window never opens, we timeout and terminate the connection.
    """
    stream_id = 1
    ctx = StreamContext(stream_id, "https")
    advanced_handler.streams[stream_id] = ctx
    
    # Permanently blocked
    advanced_handler.upstream_conn.remote_flow_control_window.return_value = 0
    
    event = MagicMock()
    event.stream_id = stream_id
    event.data = b"payload"
    event.flow_controlled_length = 7
    event.stream_ended = False
    
    # Reduce timeout for test speed
    with patch("proxy_core.FLOW_CONTROL_TIMEOUT", 0.1):
        # We expect terminate() to be called, which sets self.closed
        await advanced_handler.forward_data(advanced_handler.upstream_conn, stream_id, event.data, event.flow_controlled_length, event.stream_ended)

    assert advanced_handler.closed.is_set()
    # Verify connection close called with FLOW_CONTROL_ERROR
    advanced_handler.downstream_conn.close_connection.assert_called_with(error_code=ErrorCodes.FLOW_CONTROL_ERROR)


# --- Lifecycle & Shutdown Tests ---

@pytest.mark.asyncio
async def test_handle_stream_reset_forwarding(advanced_handler):
    """
    Verifies that RST_STREAM received on one side is forwarded to the other.
    """
    advanced_handler.streams[3] = StreamContext(3, "https")
    
    event = MagicMock()
    event.stream_id = 3
    event.error_code = ErrorCodes.CANCEL
    
    # [FIX] Ensure upstream connection reports stream as NOT closed, allowing reset to be sent
    advanced_handler.upstream_conn.stream_is_closed.return_value = False
    
    # Receive RST on Downstream -> Forward to Upstream
    await advanced_handler.handle_stream_reset(advanced_handler.downstream_conn, event)
    
    advanced_handler.upstream_conn.reset_stream.assert_called_with(3, ErrorCodes.CANCEL)
    assert 3 not in advanced_handler.streams


@pytest.mark.asyncio
async def test_graceful_shutdown_sequence(advanced_handler):
    """
    Verifies the GOAWAY dance: Send GOAWAY, wait for streams, close.
    """
    # Setup: 1 active stream
    advanced_handler.streams[1] = StreamContext(1, "https")
    
    # Mock state to allow GOAWAY sending
    advanced_handler.downstream_conn.state_machine.state = 'OPEN'
    advanced_handler.upstream_conn.state_machine.state = 'OPEN'

    # Create shutdown task
    shutdown_task = asyncio.create_task(advanced_handler.graceful_shutdown())
    
    await asyncio.sleep(0.01)
    
    # 1. Verify GOAWAY sent immediately (Max ID)
    advanced_handler.downstream_conn.close_connection.assert_called_with(error_code=ErrorCodes.NO_ERROR, last_stream_id=2147483647)
    
    assert not shutdown_task.done(), "Should be waiting for streams to drain"
    
    # 2. Simulate stream finishing
    del advanced_handler.streams[1]
    
    # 3. Task should complete
    await asyncio.wait_for(shutdown_task, timeout=0.1)
    assert advanced_handler.closed.is_set()


@pytest.mark.asyncio
async def test_handle_connection_terminated_peer(advanced_handler):
    """
    Verifies that receiving a GOAWAY from peer triggers our own graceful shutdown.
    """
    event = MagicMock()
    event.error_code = ErrorCodes.NO_ERROR
    event.last_stream_id = 10
    
    # Mock graceful_shutdown to verify it's called
    with patch.object(advanced_handler, 'graceful_shutdown', new_callable=AsyncMock) as mock_shutdown:
        await advanced_handler.handle_connection_terminated(event)
        mock_shutdown.assert_called_once_with(last_stream_id=10)

# --- Edge Cases ---

@pytest.mark.asyncio
async def test_handle_trailers(advanced_handler):
    """
    Verifies forwarding of gRPC trailers (Headers frame with END_STREAM).
    """
    advanced_handler.streams[1] = StreamContext(1, "https")
    
    event = MagicMock()
    event.stream_id = 1
    event.headers = [(b"grpc-status", b"0")]
    
    await advanced_handler.handle_trailers_received(event)
    
    advanced_handler.upstream_conn.send_headers.assert_called_with(1, event.headers, end_stream=True)
    assert advanced_handler.streams[1].downstream_closed is True