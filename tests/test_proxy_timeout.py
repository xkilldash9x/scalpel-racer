# FILE: tests/test_proxy_timeout.py
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer, INITIAL_LINE_TIMEOUT, HEADERS_TIMEOUT, TLS_HANDSHAKE_TIMEOUT

@pytest.mark.asyncio
async def test_initial_line_timeout():
    server = CaptureServer(port=8000)
    reader = AsyncMock()
    writer = MagicMock()
    # writer.close is sync
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing.return_value = False

    async def mock_wait_for_timeout(coro, timeout):
        if timeout == INITIAL_LINE_TIMEOUT:
            # Await coro to prevent warning
            try:
                await coro
            except Exception:
                pass
            raise asyncio.TimeoutError()
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_client(reader, writer)
    writer.close.assert_called()

@pytest.mark.asyncio
async def test_header_reading_timeout():
    server = CaptureServer(port=8000)
    reader = AsyncMock()
    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing.return_value = False
    reader.readline.side_effect = [
        b"GET /test HTTP/1.1\r\n",
    ]

    async def mock_wait_for_timeout(coro, timeout):
        if timeout == HEADERS_TIMEOUT:
            # Await coro to prevent warning
            try:
                await coro
            except Exception:
                pass
            raise asyncio.TimeoutError()
        if timeout == INITIAL_LINE_TIMEOUT:
             return await coro
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_client(reader, writer)
    writer.close.assert_called()

@pytest.mark.asyncio
async def test_tls_handshake_timeout(monkeypatch):
    server = CaptureServer(port=8000)
    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()
    mock_loop = MagicMock()
    mock_loop.start_tls = AsyncMock() 
    monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)
    reader = AsyncMock()
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
            try:
                await coro
            except Exception:
                pass
            raise asyncio.TimeoutError()
        if asyncio.iscoroutine(coro) or asyncio.isfuture(coro):
            return await coro
        return coro

    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}), \
         patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.handle_connect(reader, writer, "example.com:443")
    writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")