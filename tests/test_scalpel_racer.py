import pytest
import asyncio
import httpx
from scalpel_racer import CapturedRequest, ScanResult, CaptureServer, XY_stream_body, send_probe

# --- Unit Tests ---

def test_captured_request_str():
    req = CapturedRequest(
        id=1,
        method="GET",
        url="http://example.com/test",
        headers={"Host": "example.com"},
        body=b"payload"
    )
    assert str(req) == "[1] GET http://example.com/test (7 bytes)"

def test_scan_result_init():
    res = ScanResult(index=0, status_code=200, duration=150.5)
    assert res.index == 0
    assert res.status_code == 200
    assert res.duration == 150.5
    assert res.error is None

@pytest.mark.asyncio
async def test_xy_stream_body():
    payload = b"hello"
    barrier = asyncio.Barrier(1)

    parts = []
    async for part in XY_stream_body(payload, barrier, warmup_ms=0):
        parts.append(part)

    assert parts == [b"hell", b"o"]
    assert b"".join(parts) == payload

@pytest.mark.asyncio
async def test_xy_stream_body_empty():
    payload = b""
    barrier = asyncio.Barrier(1)

    parts = []
    async for part in XY_stream_body(payload, barrier, warmup_ms=0):
        parts.append(part)

    assert parts == [b""]

# --- Integration Tests for CaptureServer ---

@pytest.mark.asyncio
async def test_capture_server_basic_flow():
    # Setup
    port = 8888
    target_base = "http://upstream.com"
    server = CaptureServer(port=port, target_override=target_base)

    # Start server in background
    asyncio.create_task(server.start())
    await asyncio.sleep(0.5) # Give it time to start

    # Send a request to the capture server
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"http://127.0.0.1:{port}/path/to/resource",
            headers={"X-Test": "value"},
            content=b"test-body"
        )

    # Verify response
    assert response.status_code == 200
    assert b"Captured" in response.content

    # Verify captured request
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.method == "POST"
    # The CaptureServer constructs target URL using target_override
    assert captured.url == "http://upstream.com/path/to/resource"
    assert captured.headers["X-Test"] == "value"
    assert captured.body == b"test-body"

    # Clean up
    server.stop_event.set()
    # Allow some time for cleanup if needed, though stop_event handles it in the loop
    await asyncio.sleep(0.1)

@pytest.mark.asyncio
async def test_capture_server_scope_filter():
    port = 8889
    target_base = "http://upstream.com"
    # Only allow paths starting with /api
    server = CaptureServer(port=port, target_override=target_base, scope_regex=r"/api/.*")

    asyncio.create_task(server.start())
    await asyncio.sleep(0.5)

    async with httpx.AsyncClient() as client:
        # Out of scope
        resp1 = await client.get(f"http://127.0.0.1:{port}/other")
        assert resp1.status_code == 200 # Returns 200 OK but empty content length for ignored
        assert len(server.request_log) == 0

        # In scope
        resp2 = await client.get(f"http://127.0.0.1:{port}/api/v1/test")
        assert resp2.status_code == 200
        assert b"Captured" in resp2.content
        assert len(server.request_log) == 1

    server.stop_event.set()
    await asyncio.sleep(0.1)

@pytest.mark.asyncio
async def test_capture_server_no_override_host_header():
    port = 8890
    server = CaptureServer(port=port) # No target override

    asyncio.create_task(server.start())
    await asyncio.sleep(0.5)

    async with httpx.AsyncClient() as client:
        # When sending request to localhost, Host header is usually 127.0.0.1:port
        # But we can spoof it or rely on behavior.
        # Let's send a request and check what URL is constructed.
        resp = await client.get(f"http://127.0.0.1:{port}/foo", headers={"Host": "real-target.com"})

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    # Should use Host header if no override
    assert captured.url == "http://real-target.com/foo"

    server.stop_event.set()
    await asyncio.sleep(0.1)
