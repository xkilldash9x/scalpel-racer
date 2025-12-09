# tests/test_proxy_timeout.py
import pytest
import asyncio
import warnings
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer, INITIAL_LINE_TIMEOUT, HEADERS_TIMEOUT, TLS_HANDSHAKE_TIMEOUT

@pytest.mark.asyncio
async def test_initial_line_timeout():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8000, bind_addr="127.0.0.1")
    
    # [FIX] Use MagicMock + Future for reader to avoid AsyncMock overhead and unawaited warnings
    reader = MagicMock()
    reader_future = asyncio.Future()
    # The Future won't be completed in the timeout scenario, which mimics a hang
    reader.readline.return_value = reader_future
    
    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing.return_value = False

    async def mock_wait_for_timeout(coro, timeout):
        if timeout == INITIAL_LINE_TIMEOUT:
            # Raise timeout immediately; ignore coro (don't await it)
            raise asyncio.TimeoutError()
        # For other timeouts, await the coroutine normally
        if asyncio.iscoroutine(coro) or asyncio.isfuture(coro):
            return await coro
        return coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_client(reader, writer)
    
    writer.close.assert_called()
    
    # Cleanup: Cancel the future to avoid warnings about pending futures
    reader_future.cancel()

@pytest.mark.asyncio
async def test_header_reading_timeout():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8000, bind_addr="127.0.0.1")
    
    # [FIX] Use MagicMock + Future side effects for explicit control
    reader = MagicMock()
    f_line1 = asyncio.Future()
    f_line1.set_result(b"GET /test HTTP/1.1\r\n")
    f_timeout = asyncio.Future() # Hangs forever
    
    reader.readline.side_effect = [f_line1, f_timeout]

    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing.return_value = False

    async def mock_wait_for_timeout(coro, timeout):
        if timeout == HEADERS_TIMEOUT:
            # Raise timeout immediately; don't await coro
            raise asyncio.TimeoutError()
        if asyncio.iscoroutine(coro) or asyncio.isfuture(coro):
            return await coro
        return coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_client(reader, writer)
    
    writer.close.assert_called()
    
    # Cleanup pending future
    f_timeout.cancel()

@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore::RuntimeWarning:unittest.mock")
async def test_tls_handshake_timeout(monkeypatch):
    # [FIX] Added bind_addr
    server = CaptureServer(port=8000, bind_addr="127.0.0.1")
    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()
    mock_loop = MagicMock()
    
    # Explicitly mock start_tls to return a future we can control/ignore
    f_tls = asyncio.Future()
    mock_loop.start_tls.return_value = f_tls
    
    monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)
    
    reader = MagicMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing.return_value = False
    mock_transport = MagicMock()
    mock_protocol = MagicMock()
    writer.get_extra_info.return_value = mock_transport
    writer._protocol = mock_protocol

    async def mock_wait_for_timeout(coro, timeout):
        if timeout == TLS_HANDSHAKE_TIMEOUT:
            # Close the coroutine to prevent "coroutine was never awaited" warnings
            if asyncio.iscoroutine(coro):
                coro.close()
            raise asyncio.TimeoutError()
        if asyncio.iscoroutine(coro) or asyncio.isfuture(coro):
            return await coro
        return coro

    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}), \
         patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_connect(reader, writer, "example.com:443")
    
    writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    
    # Cleanup
    f_tls.cancel()