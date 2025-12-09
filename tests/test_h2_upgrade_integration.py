# tests/test_h2_upgrade_integration.py
import pytest
import pytest_asyncio
import asyncio
import httpx
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scalpel_racer import CaptureServer, CAManager

CA_MANAGER = CAManager()
CA_MANAGER.initialize()

@pytest_asyncio.fixture
async def capture_server(unused_tcp_port_factory):
    port = unused_tcp_port_factory()
    # [FIX] Added bind_addr
    server = CaptureServer(port=port, bind_addr="127.0.0.1", enable_tunneling=False)
    
    import scalpel_racer
    scalpel_racer.CA_MANAGER = CA_MANAGER

    task = asyncio.create_task(server.start())
    try:
        await asyncio.wait_for(server.ready_event.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pytest.fail("Server failed to start")
        
    yield server, port
    
    server.stop_event.set()
    await task

@pytest.mark.asyncio
async def test_h2_negotiation_and_capture(capture_server):
    server, port = capture_server
    import proxy_core
    assert proxy_core.H2_AVAILABLE, "H2 library not available, test will fail"

    proxy_url = f"http://127.0.0.1:{port}"
    async with httpx.AsyncClient(proxy=proxy_url, verify=False, http2=True) as client:
        try:
            response = await client.post("https://example.com/api/h2test", json={"test": "data"})
            assert response.status_code == 200
            assert response.text == "Captured."
            assert response.http_version == "HTTP/2"
        except httpx.ProxyError as e:
            pytest.fail(f"Proxy connection failed: {e}")

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    
    assert captured.method == "POST"
    assert captured.url == "https://example.com/api/h2test"
    assert captured.body == b'{"test":"data"}'

@pytest.mark.asyncio
async def test_h1_fallback(capture_server):
    server, port = capture_server
    proxy_url = f"http://127.0.0.1:{port}"
    async with httpx.AsyncClient(proxy=proxy_url, verify=False, http2=False) as client:
        response = await client.get("https://example.com/api/h1test")
        assert response.status_code == 200
        assert response.text == "Captured."
        assert response.http_version == "HTTP/1.1"

    assert len(server.request_log) == 1
    assert server.request_log[0].url == "https://example.com:443/api/h1test"