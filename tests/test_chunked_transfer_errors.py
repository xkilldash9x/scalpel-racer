# tests/test_chunked_transfer_errors.py
import asyncio
import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch, AsyncMock, MagicMock
from scalpel_racer import CaptureServer, CapturedRequest

@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    async def _start_server(enable_tunneling=False):
        port = unused_tcp_port_factory()
        # [FIX] Added bind_addr
        server = CaptureServer(port=port, bind_addr="127.0.0.1", enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())
        try:
            await asyncio.wait_for(server.ready_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port}")
        return server, port
    yield _start_server
    for server in servers:
        server.stop_event.set()
    await asyncio.sleep(0.1)

@pytest.mark.asyncio
async def test_chunked_malformed_size(server_manager):
    server, port = await server_manager()
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    
    request_head = (
        b"POST /chunked HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    writer.write(request_head)
    writer.write(b"G\r\nHello\r\n") 
    await writer.drain()

    response = await reader.read(1024)
    writer.close()
    await writer.wait_closed()

    assert b"HTTP/1.1 400 Bad Request" in response
    assert b"Error processing request body" in response

@pytest.mark.asyncio
async def test_chunked_incomplete_data(server_manager):
    server, port = await server_manager()
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    
    request_head = (
        b"POST /chunked HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    writer.write(request_head)
    writer.write(b"A\r\nHello") 
    await writer.drain()
    
    try:
        if writer.can_write_eof():
            writer.write_eof()
        else:
            writer.close()
    except OSError:
        pass

    try:
        response = await reader.read(1024)
        assert b"HTTP/1.1 400 Bad Request" in response
        assert b"Error processing request body" in response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    assert len(server.request_log) == 0

@pytest.mark.asyncio
async def test_chunked_timeout():
    # [FIX] Added bind_addr
    server_direct = CaptureServer(port=8000, bind_addr="127.0.0.1", enable_tunneling=False)
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.is_closing.return_value = False
    writer.close = MagicMock()

    reader.readline.side_effect = [
        b"Host: example.com\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"\r\n"
    ]

    wait_for_call_count = 0
    async def mock_wait_for_timeout(coro, timeout):
        nonlocal wait_for_call_count
        wait_for_call_count += 1
        if wait_for_call_count == 1:
             return await coro
        elif wait_for_call_count == 2:
             try:
                 await coro
             except Exception:
                 pass
             raise asyncio.TimeoutError()

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server_direct.process_http_request(reader, writer, "POST", "/", "HTTP/1.1", b"", "http")

    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 408 Request Timeout" in response_data
    assert b"Timeout reading chunked request body" in response_data