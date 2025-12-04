import pytest
import asyncio
import ssl
from unittest.mock import MagicMock, AsyncMock, patch, ANY
from proxy_core import NativeProxyHandler, ErrorCodes

# -- Fixtures --

@pytest.fixture
def io_handler():
    """
    Instantiates a NativeProxyHandler with mocks suitable for testing IO loops.
    """
    client_reader = AsyncMock()
    
    # Explicitly define writer as MagicMock (sync methods like close/write)
    # but attach AsyncMock for async methods (drain, wait_closed).
    client_writer = MagicMock()
    client_writer.drain = AsyncMock()
    client_writer.wait_closed = AsyncMock()
    client_writer.is_closing.return_value = False
    
    # Mock SettingCodes
    MockSettings = MagicMock()
    MockSettings.ENABLE_CONNECT_PROTOCOL = 8

    with patch("proxy_core.H2_AVAILABLE", True), \
         patch("proxy_core.H2Connection"), \
         patch("proxy_core.H2Configuration"), \
         patch("proxy_core.SettingCodes", MockSettings):
        
        handler = NativeProxyHandler(
            client_reader, client_writer, 
            "upstream.com:443", MagicMock(), None, None
        )
        
        handler.downstream_conn = MagicMock()
        handler.upstream_conn = MagicMock()
        
        yield handler

# -- Connection & Orchestration Tests --

@pytest.mark.asyncio
async def test_run_orchestration_success(io_handler):
    io_handler.connect_upstream = AsyncMock()
    io_handler.upstream_reader = AsyncMock()
    io_handler.upstream_writer = MagicMock()
    io_handler.upstream_writer.wait_closed = AsyncMock()
    io_handler.upstream_writer.is_closing.return_value = False
    
    io_handler.flush = AsyncMock()

    with patch("asyncio.TaskGroup") as MockTaskGroup:
        tg_instance = MockTaskGroup.return_value
        tg_instance.__aenter__ = AsyncMock(return_value=tg_instance)
        tg_instance.__aexit__ = AsyncMock()
        tg_instance.create_task.return_value = MagicMock()

        io_handler._read_loop_wrapper = AsyncMock()
        await io_handler.run()

    io_handler.connect_upstream.assert_called_once()
    assert tg_instance.create_task.call_count == 2

@pytest.mark.asyncio
async def test_connect_upstream_success(io_handler):
    io_handler.upstream_host = "secure.com"
    io_handler.upstream_port = 443

    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_transport = MagicMock()
    mock_transport.selected_alpn_protocol.return_value = "h2"
    mock_writer.get_extra_info.return_value = mock_transport

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)) as mock_open, \
         patch("ssl.create_default_context") as mock_ssl_ctx:
        
        await io_handler.connect_upstream()

        mock_open.assert_awaited_with("secure.com", 443, ssl=mock_ssl_ctx.return_value)
        assert io_handler.upstream_reader == mock_reader
        assert io_handler.upstream_writer == mock_writer

@pytest.mark.asyncio
async def test_connect_upstream_alpn_failure(io_handler):
    io_handler.upstream_host = "bad-alpn.com"
    io_handler.upstream_port = 443
    
    mock_writer = MagicMock()
    mock_transport = MagicMock()
    mock_transport.selected_alpn_protocol.return_value = "http/1.1" 
    mock_writer.get_extra_info.return_value = mock_transport
    
    # Use MagicMock for unused reader to prevent unawaited warnings
    mock_reader_unused = MagicMock() 

    with patch("asyncio.open_connection", return_value=(mock_reader_unused, mock_writer)):
        with pytest.raises(ConnectionError, match="Failed to connect upstream"):
            await io_handler.connect_upstream()

@pytest.mark.asyncio
async def test_run_connection_failure(io_handler):
    io_handler.connect_upstream = AsyncMock(side_effect=ConnectionError("DNS failure"))
    io_handler.terminate = AsyncMock()

    await io_handler.run()
    io_handler.terminate.assert_awaited_with(ErrorCodes.CONNECT_ERROR)

# -- Read Loop & IO Tests --

@pytest.mark.asyncio
async def test_read_loop_data_flow(io_handler):
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [b"DATA", b""]
    
    mock_conn = MagicMock()
    mock_conn.receive_data.return_value = [] 
    
    io_handler.flush = AsyncMock()
    
    # Use simple async function to avoid AsyncMock overhead for simple callback
    async def noop_handler(evt): pass

    await io_handler.read_loop(mock_reader, mock_conn, noop_handler)

    mock_conn.receive_data.assert_called_with(b"DATA")
    io_handler.flush.assert_called()
    assert io_handler.closed.is_set()

@pytest.mark.asyncio
async def test_read_loop_idle_timeout(io_handler):
    mock_reader = AsyncMock()
    
    async def timeout_effect(*args, **kwargs):
        raise asyncio.TimeoutError()
    
    with patch("asyncio.wait_for", side_effect=timeout_effect):
        io_handler.graceful_shutdown = AsyncMock()
        # Mock dummy handler
        async def noop(e): pass
        await io_handler.read_loop(mock_reader, MagicMock(), noop)

    io_handler.graceful_shutdown.assert_awaited()

@pytest.mark.asyncio
async def test_read_loop_protocol_error(io_handler):
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"BAD_DATA"
    
    mock_conn = MagicMock()
    mock_conn.receive_data.side_effect = Exception("Protocol Violation")
    
    terminate_called = False
    async def mock_terminate(error_code):
        nonlocal terminate_called
        terminate_called = True
        assert error_code == ErrorCodes.PROTOCOL_ERROR

    io_handler.terminate = mock_terminate
    
    async def bypass_wait_for(coro, timeout):
        return await coro

    with patch("asyncio.wait_for", side_effect=bypass_wait_for):
        async def noop_handler(evt): pass
        await io_handler.read_loop(mock_reader, mock_conn, noop_handler)

    assert terminate_called is True

# -- Flush & Write Tests --

@pytest.mark.asyncio
async def test_flush_success(io_handler):
    mock_conn = MagicMock()
    mock_conn.data_to_send.return_value = b"PENDING_BYTES"
    
    mock_writer = MagicMock()
    # Explicitly set drain as AsyncMock
    mock_writer.drain = AsyncMock()
    mock_writer.is_closing.return_value = False

    await io_handler.flush(mock_conn, mock_writer)

    mock_writer.write.assert_called_with(b"PENDING_BYTES")
    mock_writer.drain.assert_awaited()

@pytest.mark.asyncio
async def test_flush_write_error(io_handler):
    mock_conn = MagicMock()
    mock_conn.data_to_send.return_value = b"BYTES"
    
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock(side_effect=ConnectionResetError())
    mock_writer.is_closing.return_value = False

    await io_handler.flush(mock_conn, mock_writer)
    assert io_handler.closed.is_set()

@pytest.mark.asyncio
async def test_cleanup_closes_writers(io_handler):
    # Ensure client_writer has the necessary async mocks attached
    io_handler.client_writer.wait_closed = AsyncMock()
    
    io_handler.upstream_writer = MagicMock()
    io_handler.upstream_writer.wait_closed = AsyncMock()
    io_handler.upstream_writer.is_closing.return_value = False

    await io_handler.cleanup()

    io_handler.client_writer.close.assert_called()
    io_handler.upstream_writer.close.assert_called()