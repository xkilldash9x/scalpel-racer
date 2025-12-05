# tests/test_h2_upgrade_integration.py
import pytest
import pytest_asyncio
import asyncio
import httpx
import os
import sys

# Ensure imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scalpel_racer import CaptureServer, CAManager

# Initialize CAManager for the tests
CA_MANAGER = CAManager()
CA_MANAGER.initialize()

@pytest_asyncio.fixture
async def capture_server(unused_tcp_port_factory):
    """
    Spins up a CaptureServer instance with tunneling enabled.
    """
    port = unused_tcp_port_factory()
    
    # Enable tunneling to allow the proxy to attempt upstream connections
    server = CaptureServer(port=port, enable_tunneling=False)
    
    # Inject the initialized CA_MANAGER into the global scope of scalpel_racer 
    # so handle_connect can find it.
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
    """
    Verifies that an HTTP/2 client can connect, negotiate 'h2' via ALPN,
    and have its request parsed by the H2 handler.
    """
    server, port = capture_server
    
    # Verify proxy_core was imported
    import proxy_core
    assert proxy_core.H2_AVAILABLE, "H2 library not available, test will fail"

    # Configure httpx client to use the proxy and force HTTP/2
    proxy_url = f"http://127.0.0.1:{port}"
    
    # [FIX] Use 'proxy' instead of 'proxies' for newer httpx versions
    async with httpx.AsyncClient(proxy=proxy_url, verify=False, http2=True) as client:
        try:
            # Send a request to a dummy HTTPS target
            # CaptureServer (enable_tunneling=False) should intercept and return "Captured."
            response = await client.post("https://example.com/api/h2test", json={"test": "data"})
            
            # Verify the response comes from CaptureServer (HTTP/1.1 response body "Captured.")
            # Note: Even if client talks H2 to Proxy, Proxy talks H2 to Client, 
            # the *body* returned by CaptureServer in non-tunnel mode is "Captured."
            assert response.status_code == 200
            assert response.text == "Captured."
            
            # Verify the protocol used was indeed HTTP/2
            assert response.http_version == "HTTP/2"

        except httpx.ProxyError as e:
            pytest.fail(f"Proxy connection failed: {e}")

    # Check the logs
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    
    assert captured.method == "POST"
    assert captured.url == "https://example.com/api/h2test"
    # [FIX] Expect compact JSON (no spaces) as sent by httpx
    assert captured.body == b'{"test":"data"}'

@pytest.mark.asyncio
async def test_h1_fallback(capture_server):
    """
    Verifies that HTTP/1.1 clients still work via the fallback path.
    """
    server, port = capture_server
    proxy_url = f"http://127.0.0.1:{port}"
    
    # Force http2=False
    # [FIX] Use 'proxy' instead of 'proxies' for newer httpx versions
    async with httpx.AsyncClient(proxy=proxy_url, verify=False, http2=False) as client:
        response = await client.get("https://example.com/api/h1test")
        
        assert response.status_code == 200
        assert response.text == "Captured."
        assert response.http_version == "HTTP/1.1"

    assert len(server.request_log) == 1
    # [FIX] Update expectation to include port 443 which urlunparse adds
    assert server.request_log[0].url == "https://example.com:443/api/h1test"