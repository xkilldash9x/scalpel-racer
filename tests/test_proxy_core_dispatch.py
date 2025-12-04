import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_core import NativeProxyHandler

# Fallback mocks for H2 events if not installed
try:
    from h2.events import (
        RequestReceived, 
        DataReceived, StreamEnded, StreamReset, 
        WindowUpdated, ConnectionTerminated, TrailersReceived, ResponseReceived
    )
except ImportError:
    class RequestReceived: pass
    class DataReceived: pass
    class StreamEnded: pass
    class StreamReset: pass
    class WindowUpdated: pass
    class ConnectionTerminated: pass
    class TrailersReceived: pass
    class ResponseReceived: pass

def create_event(cls, **kwargs):
    """
    Helper to instantiate H2 events compatibly.
    Real h2 events require arguments in __init__.
    Mock/Fallback events might not accept arguments.
    """
    try:
        return cls(**kwargs)
    except TypeError:
        # Fallback for dummy classes that take no init args
        obj = cls()
        for k, v in kwargs.items():
            setattr(obj, k, v)
        return obj

@pytest.fixture
def dispatch_handler():
    # Patch H2 deps to ensure init works.
    # CRITICAL: We must patch the event classes in proxy_core to match the ones
    # used in this test. Otherwise, if proxy_core loaded the fallback 'object' aliases,
    # isinstance(event, proxy_core.RequestReceived) will return True for ANY event.
    
    # [FIX] Use yield to keep patches active during test execution
    with patch("proxy_core.H2_AVAILABLE", True), \
         patch("proxy_core.H2Connection"), \
         patch("proxy_core.H2Configuration"), \
         patch("proxy_core.SettingCodes"), \
         patch("proxy_core.RequestReceived", RequestReceived), \
         patch("proxy_core.DataReceived", DataReceived), \
         patch("proxy_core.StreamEnded", StreamEnded), \
         patch("proxy_core.StreamReset", StreamReset), \
         patch("proxy_core.WindowUpdated", WindowUpdated), \
         patch("proxy_core.ConnectionTerminated", ConnectionTerminated), \
         patch("proxy_core.TrailersReceived", TrailersReceived), \
         patch("proxy_core.ResponseReceived", ResponseReceived):
        
        handler = NativeProxyHandler(AsyncMock(), MagicMock(), "test:443", MagicMock(), None, None)
        handler.downstream_conn = MagicMock()
        handler.upstream_conn = MagicMock()
        yield handler

# -- Downstream Dispatch Tests --

@pytest.mark.asyncio
async def test_handle_downstream_dispatch(dispatch_handler):
    # Mock all specific handlers
    dispatch_handler.handle_request_received = AsyncMock()
    dispatch_handler.handle_data_received = AsyncMock()
    dispatch_handler.handle_stream_ended = AsyncMock()
    dispatch_handler.handle_stream_reset = AsyncMock()
    dispatch_handler.handle_window_updated = AsyncMock()
    dispatch_handler.handle_connection_terminated = AsyncMock()
    dispatch_handler.handle_trailers_received = AsyncMock()

    # 1. RequestReceived
    evt_req = create_event(RequestReceived, stream_id=1, headers=[])
    await dispatch_handler.handle_downstream_event(evt_req)
    dispatch_handler.handle_request_received.assert_awaited_with(evt_req)

    # 2. DataReceived
    evt_data = create_event(DataReceived, stream_id=1, data=b'', flow_controlled_length=0)
    await dispatch_handler.handle_downstream_event(evt_data)
    dispatch_handler.handle_data_received.assert_awaited_with(evt_data)

    # 3. StreamEnded
    evt_end = create_event(StreamEnded, stream_id=1)
    await dispatch_handler.handle_downstream_event(evt_end)
    dispatch_handler.handle_stream_ended.assert_awaited_with(dispatch_handler.downstream_conn, evt_end)

    # 4. StreamReset
    evt_rst = create_event(StreamReset, stream_id=1, error_code=0)
    await dispatch_handler.handle_downstream_event(evt_rst)
    dispatch_handler.handle_stream_reset.assert_awaited_with(dispatch_handler.downstream_conn, evt_rst)

    # 5. WindowUpdated
    evt_win = create_event(WindowUpdated, stream_id=0, delta=10)
    await dispatch_handler.handle_downstream_event(evt_win)
    dispatch_handler.handle_window_updated.assert_awaited_with(evt_win)

    # 6. ConnectionTerminated
    evt_term = create_event(ConnectionTerminated, error_code=0, last_stream_id=0, additional_data=None)
    await dispatch_handler.handle_downstream_event(evt_term)
    dispatch_handler.handle_connection_terminated.assert_awaited_with(evt_term)

    # 7. TrailersReceived
    evt_trail = create_event(TrailersReceived, stream_id=1, headers=[])
    await dispatch_handler.handle_downstream_event(evt_trail)
    dispatch_handler.handle_trailers_received.assert_awaited_with(evt_trail)

# -- Upstream Dispatch Tests --

@pytest.mark.asyncio
async def test_handle_upstream_dispatch(dispatch_handler):
    dispatch_handler.forward_data = AsyncMock()
    dispatch_handler.handle_stream_ended = AsyncMock()
    dispatch_handler.handle_stream_reset = AsyncMock()
    dispatch_handler.handle_window_updated = AsyncMock()
    dispatch_handler.handle_connection_terminated = AsyncMock()

    # 1. ResponseReceived (Direct header send)
    evt_resp = create_event(ResponseReceived, stream_id=1, headers=[], stream_ended=False)
    
    await dispatch_handler.handle_upstream_event(evt_resp)
    dispatch_handler.downstream_conn.send_headers.assert_called_with(1, [], end_stream=False)

    # 2. DataReceived
    evt_data = create_event(DataReceived, stream_id=1, data=b'', flow_controlled_length=0)
    await dispatch_handler.handle_upstream_event(evt_data)
    dispatch_handler.forward_data.assert_awaited_with(dispatch_handler.downstream_conn, evt_data)

    # 3. StreamEnded
    evt_end = create_event(StreamEnded, stream_id=1)
    await dispatch_handler.handle_upstream_event(evt_end)
    dispatch_handler.handle_stream_ended.assert_awaited_with(dispatch_handler.upstream_conn, evt_end)

    # 4. TrailersReceived (Direct header send)
    evt_trail = create_event(TrailersReceived, stream_id=1, headers=[])
    
    await dispatch_handler.handle_upstream_event(evt_trail)
    dispatch_handler.downstream_conn.send_headers.assert_called_with(1, [], end_stream=True)

# -- Read Loop Wrapper Tests --

@pytest.mark.asyncio
async def test_read_loop_wrapper_success(dispatch_handler):
    dispatch_handler.read_loop = AsyncMock()
    
    await dispatch_handler._read_loop_wrapper("reader", "conn", "handler")
    dispatch_handler.read_loop.assert_awaited_with("reader", "conn", "handler")

@pytest.mark.asyncio
async def test_read_loop_wrapper_connection_error(dispatch_handler):
    # Simulate connection reset inside read_loop
    dispatch_handler.read_loop = AsyncMock(side_effect=ConnectionResetError())
    
    # Should catch error and set closed
    await dispatch_handler._read_loop_wrapper("reader", "conn", "handler")
    assert dispatch_handler.closed.is_set()

@pytest.mark.asyncio
async def test_read_loop_wrapper_unexpected_error(dispatch_handler):
    # Simulate unexpected error
    dispatch_handler.read_loop = AsyncMock(side_effect=ValueError("Boom"))
    
    # Should re-raise so TaskGroup sees it
    with pytest.raises(ValueError, match="Boom"):
        await dispatch_handler._read_loop_wrapper("reader", "conn", "handler")