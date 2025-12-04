# FILE: ./tests/test_scalpel_racer.py
import pytest
import asyncio
import httpx
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# Note: The imports below assume the updated scalpel_racer.py structure.
from scalpel_racer import CapturedRequest, ScanResult, CaptureServer, Last_Byte_Stream_Body, HOP_BY_HOP_HEADERS

# Helper for async iteration compatibility
async def a_next(gen):
    try:
        return await gen.__anext__()
    except StopAsyncIteration:
        # Handle cases where the generator might exit without yielding (e.g. empty payload)
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

# (Tests for Last_Byte_Stream_Body remain the same)
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
    
    # [FIX] Explicitly close the generator
    await gen.aclose()

# --- Integration Tests for CaptureServer ---

# Helper fixture to manage server lifecycle in tests
@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    async def _start_server(target_override=None, scope_regex=None, enable_tunneling=False):
        port = unused_tcp_port_factory()
        server = CaptureServer(port=port, target_override=target_override, scope_regex=scope_regex, enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())

        # [Defense in Depth] Use ready_event for robust synchronization
        try:
            await asyncio.wait_for(server.ready_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            if not task.done():
                 task.cancel()
            # Provide detailed error information if the task completed with an exception
            if task.done() and task.exception():
                 print(f"Server task exception during startup: {task.exception()}")
            pytest.fail(f"Server failed to start on port {port} (Timeout waiting for ready_event)")
        
        # Final check if server failed during start (e.g. bind error)
        if server.server is None:
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port}")
             
        return server, port

    yield _start_server

    # Cleanup
    for server in servers:
        server.stop_event.set()
    await asyncio.sleep(0.1) 

# (Tests for urljoin_fix, absolute_uri_parsing_fix, header_filtering remain the same)
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


# Test B05 Fix (Robust Parsing)
# Updated to reflect the new structure where asyncio.wait_for wraps the header reading helper function.
@pytest.mark.asyncio
async def test_capture_server_robust_parsing():
    # Test fix using direct handle_client call with mocks
    server = CaptureServer(port=8000, enable_tunneling=False)

    # Use spec=asyncio.StreamReader to ensure mock behaves correctly with hasattr checks
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock() 

    # Simulate request with unusual spacing and malformed header

    # Set side_effect on the method so awaited calls return these values
    reader.readline.side_effect = [
        b"GET  /test  HTTP/1.1\r\n", # Extra spaces (read by handle_client)
        # The following lines are read inside the read_headers helper in process_http_request
        b"Host: example.com\r\n",
        b"Malformed-Header\r\n",       # No colon
        b"Content-Length: invalid\r\n", # Invalid CL
        b"Valid-Header: value\r\n",
        b"\r\n"
    ]

    # We mock asyncio.wait_for to simply await the coroutine.
    async def mock_wait_for(coro, timeout):
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.method == "GET"
    assert captured.url == "http://example.com/test"
    # Check original casing preservation
    assert captured.headers["Valid-Header"] == "value"
    assert "Malformed-Header" not in captured.headers
    assert captured.body == b"" # CL was invalid (0)

    # Verify dummy response (HTTP/1.1 defaults to keep-alive)
    expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."

    # Check the final write call matches the dummy response
    assert writer.write.call_args_list[-1].args[0] == expected_response

# Test the fix for relaxed parsing in handle_client (allowing HTTP/1.0 default)
@pytest.mark.asyncio
async def test_capture_server_relaxed_parsing_version(server_manager):
    server, port = await server_manager()

    # Use raw asyncio streams
    reader, writer = await asyncio.open_connection('127.0.0.1', port)

    # Request line missing HTTP/Version (Common in simple clients or older specs)
    request = (
        b"GET /foo\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )
    writer.write(request)
    await writer.drain()

    # Read response
    response = await reader.read(1024)
    writer.close()
    await writer.wait_closed()

    # The key is that this request is now accepted (previous version rejected it)
    assert b"Captured" in response
    assert len(server.request_log) == 1
    captured = server.request_log[0]

    assert captured.url == "http://example.com/foo"