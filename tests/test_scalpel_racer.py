import pytest
import asyncio
import httpx
import pytest_asyncio 
from unittest.mock import AsyncMock, MagicMock
from scalpel_racer import CapturedRequest, ScanResult, CaptureServer, Last_Byte_Stream_Body, HOP_BY_HOP_HEADERS

# Removed global pytestmark

# --- Unit Tests ---

def test_captured_request_str():
    req = CapturedRequest(1, "GET", "http://example.com/test", {}, b"payload")
    # Updated expected string format (removed brackets around ID)
    assert str(req) == "1     GET     http://example.com/test (7 bytes) "

def test_captured_request_edited():
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"A")
    req.edited_body = b"B{{SYNC}}C"
    assert req.get_attack_payload() == b"B{{SYNC}}C"
    # Updated expected string format and length (B + 8 chars + C = 10 bytes)
    assert str(req) == "1     POST    http://example.com (10 bytes) [E]"

# Test B04 Fix (Single-byte optimization)
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
    assert not task.done() # Should be waiting at barrier BEFORE yielding anything

    await barrier.wait()
    parts = await task
    assert parts == [b"A"] # Should yield [b"A"], not [b"", b"A"]

# Test B04 Fix (Empty payload optimization)
@pytest.mark.asyncio
async def test_last_byte_stream_body_empty():
    payload = b""
    barrier = asyncio.Barrier(2)

    # Use anext() built-in for async generators
    gen = Last_Byte_Stream_Body(payload, barrier, 0)
    task = asyncio.create_task(anext(gen))
    await asyncio.sleep(0.05)
    assert not task.done() # Should wait at barrier

    await barrier.wait()
    result = await task
    assert result == b""

# --- Integration Tests for CaptureServer ---

# Helper fixture to manage server lifecycle in tests
@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    # Updated fixture to allow configuring enable_tunneling, defaulting to False for legacy tests
    async def _start_server(target_override=None, scope_regex=None, enable_tunneling=False):
        port = unused_tcp_port_factory()
        # Pass enable_tunneling flag
        server = CaptureServer(port=port, target_override=target_override, scope_regex=scope_regex, enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())
        await asyncio.sleep(0.1) # Give it time to start
        
        # Check if server started successfully (server attribute is set AND stop_event is not set)
        # If stop_event is set, it means start() failed (e.g., binding error)
        if server.server is None and server.stop_event.is_set():
             # Clean up the task if the server failed to start
             if not task.done():
                 task.cancel()
             # Check if the task has an exception (e.g. binding error)
             if task.done() and task.exception():
                 print(f"Server task exception: {task.exception()}")
             pytest.fail(f"Server failed to start on port {port}")
             
        return server, port

    yield _start_server

    # Cleanup
    for server in servers:
        server.stop_event.set()
    # Allow cleanup time
    await asyncio.sleep(0.1) 

# Test B01 Fix (urljoin behavior)
@pytest.mark.asyncio
async def test_capture_server_urljoin_fix(server_manager):
    # Target override WITHOUT trailing slash provided by user
    target_base = "http://upstream.com/api/v1"
    # enable_tunneling=False (default in fixture) ensures "Captured." response
    server, port = await server_manager(target_override=target_base)

    # Verify the fix in __init__
    assert server.target_override == "http://upstream.com/api/v1/"

    # UPDATE: Use 'proxy' argument in init, not 'proxies' in get
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        # We must use the proxy argument for httpx to send the request correctly to the proxy server
        # When using a proxy, the client sends the full URL in the request line
        
        # The host in the URL here doesn't matter much as the target override is active, 
        # but it's required for a valid HTTP request via proxy.
        response = await client.get(f"http://doesntmatter.com/resource?q=1")

    # Verify dummy response
    assert b"Captured" in response.content

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    # Should now correctly join the path based on the override
    assert captured.url == "http://upstream.com/api/v1/resource?q=1"

# Test B02 Fix (Absolute URI parsing / ValueError)
@pytest.mark.asyncio
async def test_capture_server_absolute_uri_parsing_fix(server_manager):
    target_base = "http://target.com/"
    # enable_tunneling=False (default in fixture)
    server, port = await server_manager(target_override=target_base)

    # We need to send a request with an absolute URI in the request line AND potentially confusing Host header
    # We use raw asyncio streams for precise control over the request format.
    
    # Use 127.0.0.1 for connection, as the server binds to 0.0.0.0 but we connect locally
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    
    # Request line uses absolute URL (external.com), Host header points elsewhere (ignored due to override)
    request = (
        b"GET http://external.com/foo?bar=baz HTTP/1.1\r\n"
        b"Host: confusing.com\r\n"
        b"X-Test: value\r\n"
        b"\r\n"
    )
    writer.write(request)
    await writer.drain()
    
    # Read response
    response = await reader.read(1024)
    writer.close()
    await writer.wait_closed()

    # The key is that this did not crash the handler (B02 fix)
    assert b"Captured" in response
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    
    # The fix ensures that the path "/foo?bar=baz" (extracted from external.com) is joined with the target override
    assert captured.url == "http://target.com/foo?bar=baz"

# Test B03 Fix (Hop-by-Hop Filtering)
@pytest.mark.asyncio
async def test_capture_server_header_filtering(server_manager):
    # enable_tunneling=False (default in fixture)
    server, port = await server_manager(target_override="http://target.com/")

    # UPDATE: Use 'proxy' argument in init, not 'proxies' in get
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        headers = {
            "X-Keep-Me": "yes",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked", # Should be removed
            "Proxy-Connection": "keep-alive", # Should be removed
            "Host": "target.com",
            "Accept-Encoding": "gzip"
        }
        await client.get(f"http://target.com/test", headers=headers)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    captured_headers_lower = {k.lower() for k in captured.headers.keys()}

    # Verify all defined hop-by-hop headers are absent from the log
    for header in HOP_BY_HOP_HEADERS:
        assert header not in captured_headers_lower, f"Header {header} was not filtered from log!"

    assert 'x-keep-me' in captured_headers_lower

# Test B05 Fix (Robust Parsing)
@pytest.mark.asyncio
async def test_capture_server_robust_parsing():
    # Test fix using direct handle_client call with mocks
    # Initialize with enable_tunneling=False to use dummy response
    server = CaptureServer(port=8000, enable_tunneling=False)

    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False # Mock is_closing
    # Mock wait_closed for await compatibility
    writer.wait_closed = AsyncMock() 

    # Simulate request with unusual spacing and malformed header
    # handle_client reads the first line
    # process_http_request reads the subsequent lines
    reader.readline.side_effect = [
        b"GET  /test  HTTP/1.1\r\n", # Extra spaces (read by handle_client)
        b"Host: example.com\r\n",      # (read by process_http_request)
        b"Malformed-Header\r\n",       # No colon
        b"Content-Length: invalid\r\n", # Invalid CL
        b"Valid-Header: value\r\n",
        b"\r\n"
    ]
    # readexactly is used for body if CL > 0, but here CL will be 0 due to invalid value

    await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.method == "GET"
    assert captured.url == "http://example.com/test"
    assert captured.headers["Valid-Header"] == "value"
    assert "Malformed-Header" not in captured.headers
    assert captured.body == b"" # CL was invalid (0)
    
    # Verify dummy response (Updated to match full response)
    expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
    writer.write.assert_any_call(expected_response)