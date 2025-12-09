# tests/test_scalpel_racer.py
import pytest
import asyncio
import httpx
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from scalpel_racer import CapturedRequest, ScanResult, CaptureServer, Last_Byte_Stream_Body, HOP_BY_HOP_HEADERS

# Helper for async iteration compatibility
async def a_next(gen):
    try:
        return await gen.__anext__()
    except StopAsyncIteration:
        return None

# --- Unit Tests ---
def test_captured_request_str():
    req = CapturedRequest(1, "GET", "http://example.com/test", {}, b"payload")
    assert str(req) == "1     GET     http://example.com/test (7 bytes) "

def test_captured_request_edited():
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"A")
    req.edited_body = b"B{{SYNC}}C"
    assert req.get_attack_payload() == b"B{{SYNC}}C"
    assert str(req) == "1     POST    http://example.com (10 bytes) [E]"

@pytest.mark.asyncio
async def test_last_byte_stream_body_single_byte():
    payload = b"A"
    barrier = asyncio.Barrier(2)

    async def streamer():
        parts = []
        async for part in Last_Byte_Stream_Body(payload, barrier, warmup_ms=0):
            parts.append(part)
        return parts

    task = asyncio.create_task(streamer())
    await asyncio.sleep(0.05)
    assert not task.done()

    await barrier.wait()
    parts = await task
    assert parts == [b"A"]

@pytest.mark.asyncio
async def test_last_byte_stream_body_empty():
    payload = b""
    barrier = asyncio.Barrier(2)

    gen = Last_Byte_Stream_Body(payload, barrier, 0)
    task = asyncio.create_task(a_next(gen))
    await asyncio.sleep(0.05)
    assert not task.done()

    await barrier.wait()
    result = await task
    assert result == b""
    
    await gen.aclose()

# --- Integration Tests for CaptureServer ---

@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    async def _start_server(target_override=None, scope_regex=None, enable_tunneling=False):
        port = unused_tcp_port_factory()
        # [FIX] Added bind_addr="127.0.0.1"
        server = CaptureServer(port=port, bind_addr="127.0.0.1", target_override=target_override, scope_regex=scope_regex, enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())

        try:
            await asyncio.wait_for(server.ready_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            if not task.done():
                 task.cancel()
            if task.done() and task.exception():
                 print(f"Server task exception during startup: {task.exception()}")
            pytest.fail(f"Server failed to start on port {port} (Timeout waiting for ready_event)")
        
        if server.server is None:
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port}")
             
        return server, port

    yield _start_server

    for server in servers:
        server.stop_event.set()
    await asyncio.sleep(0.1) 

@pytest.mark.asyncio
async def test_capture_server_urljoin_fix(server_manager):
    target_base = "http://upstream.com/api/v1"
    server, port = await server_manager(target_override=target_base)
    assert server.target_override == "http://upstream.com/api/v1/"
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        response = await client.get(f"http://doesntmatter.com/resource?q=1")
    assert b"Captured" in response.content
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://upstream.com/api/v1/resource?q=1"

@pytest.mark.asyncio
async def test_capture_server_absolute_uri_parsing_fix(server_manager):
    target_base = "http://target.com/"
    server, port = await server_manager(target_override=target_base)
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    request = (
        b"GET http://external.com/foo?bar=baz HTTP/1.1\r\n"
        b"Host: confusing.com\r\n"
        b"X-Test: value\r\n"
        b"\r\n"
    )
    writer.write(request)
    await writer.drain()
    response = await reader.read(1024)
    writer.close()
    await writer.wait_closed()
    assert b"Captured" in response
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://target.com/foo?bar=baz"

@pytest.mark.asyncio
async def test_capture_server_header_filtering(server_manager):
    server, port = await server_manager(target_override="http://target.com/")
    
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        headers = {
            "X-Keep-Me": "yes",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
            "Proxy-Connection": "keep-alive",
            "Host": "target.com",
            "Accept-Encoding": "gzip"
        }
        await client.get(f"http://target.com/test", headers=headers)
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert "X-Keep-Me" in captured.headers
    captured_headers_lower = {k.lower() for k in captured.headers.keys()}
    for header in HOP_BY_HOP_HEADERS:
        assert header not in captured_headers_lower, f"Header {header} was not filtered from log!"

@pytest.mark.asyncio
async def test_capture_server_robust_parsing():
    # [FIX] Added bind_addr="127.0.0.1"
    server = CaptureServer(port=8000, bind_addr="127.0.0.1", enable_tunneling=False)
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock() 

    reader.readline.side_effect = [
        b"GET  /test  HTTP/1.1\r\n", 
        b"Host: example.com\r\n",
        b"Malformed-Header\r\n",
        b"Content-Length: invalid\r\n",
        b"Valid-Header: value\r\n",
        b"\r\n"
    ]

    async def mock_wait_for(coro, timeout):
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.method == "GET"
    assert captured.url == "http://example.com/test"
    expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
    assert writer.write.call_args_list[-1].args[0] == expected_response

@pytest.mark.asyncio
async def test_capture_server_relaxed_parsing_version(server_manager):
    server, port = await server_manager()
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    request = (
        b"GET /foo\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )
    writer.write(request)
    await writer.drain()
    response = await reader.read(1024)
    writer.close()
    await writer.wait_closed()
    assert b"Captured" in response
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://example.com/foo"