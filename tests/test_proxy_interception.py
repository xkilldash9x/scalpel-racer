import pytest
import asyncio
import httpx
import pytest_asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

# Import the module itself to manipulate global state (like CA_MANAGER)
import scalpel_racer
from scalpel_racer import CaptureServer, HOP_BY_HOP_HEADERS

# Helper fixture to manage server lifecycle
@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    # This fixture enables tunneling for interception tests by default
    async def _start_server(target_override=None, scope_regex=None, enable_tunneling=True):
        port = unused_tcp_port_factory()
        server = CaptureServer(port=port, target_override=target_override, scope_regex=scope_regex, enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())
        await asyncio.sleep(0.1) # Give it time to start
        
        # Check if server started successfully
        if server.server is None and server.stop_event.is_set():
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port}")
             
        return server, port

    yield _start_server

    for server in servers:
        server.stop_event.set()
    await asyncio.sleep(0.1)

# --- Helper for Async Iterators (Mocking response streaming) ---
async def async_iter(items):
    for item in items:
        yield item

# --- Helpers for Context Managers (Robust Mocking) ---
class MockStreamContext:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, exc_type, exc_value, traceback):
        pass

class MockStreamErrorContext:
    async def __aenter__(self):
        raise httpx.ConnectError("Connection refused")
    async def __aexit__(self, *args):
        pass

# --- Tests for HTTP Tunneling (New Functionality) ---

@pytest.mark.asyncio
async def test_http_tunneling_success(server_manager):
    """Test that the proxy correctly tunnels HTTP requests upstream."""
    server, port = await server_manager()

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.reason_phrase = "Created"
    mock_response.headers = {"X-Upstream": "True", "Content-Length": "13", "Connection": "close"}
    
    mock_response.aiter_raw.side_effect = lambda: async_iter([b"Upstream data"])

    mock_client = AsyncMock()
    mock_client.stream = MagicMock()
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamContext(mock_response)
    server.proxy_client = mock_client

    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        request_headers = {"Host": "example.com", "User-Agent": "TestClient", "Connection": "keep-alive"}
        response = await client.post(f"http://example.com/api/submit", headers=request_headers, content=b"request body")

    assert response.status_code == 201
    assert response.text == "Upstream data"
    assert response.headers["X-Upstream"] == "True"
    
    assert "Connection" not in response.headers
    assert "Content-Length" in response.headers

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://example.com/api/submit"
    assert captured.method == "POST"

    mock_client.stream.assert_called_once()
    args, kwargs = mock_client.stream.call_args
    
    assert args[0] == "POST"
    assert args[1] == "http://example.com/api/submit"
    assert kwargs['content'] == b"request body"
    
    sent_headers = kwargs['headers']
    assert "Connection" not in sent_headers
    assert sent_headers["User-Agent"] == "TestClient"


@pytest.mark.asyncio
async def test_http_tunneling_upstream_error(server_manager):
    """Test proxy behavior when the upstream request fails."""
    server, port = await server_manager()

    mock_client = AsyncMock()
    mock_client.stream = MagicMock()
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamErrorContext()
    server.proxy_client = mock_client

    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        response = await client.get(f"http://unreachable.com/test")

    assert response.status_code == 502
    assert "Upstream request failed" in response.text

# --- Tests for HTTPS Interception (New Functionality) ---

@pytest.mark.asyncio
async def test_handle_connect_logic(monkeypatch):
    """Test the logic inside handle_connect, mocking the TLS upgrade."""
    
    server = CaptureServer(port=8000, enable_tunneling=False)

    # 1. Mock Dependencies (CA_MANAGER and loop.start_tls)

    mock_ca = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ca.get_ssl_context.return_value = mock_ssl_context
    
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        mock_loop = MagicMock()
        mock_start_tls = AsyncMock()
        mock_loop.start_tls = mock_start_tls
        monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)

        # 2. Mock Reader/Writer
        reader = AsyncMock()
        reader.at_eof = MagicMock(return_value=False)
        
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.is_closing.return_value = False
        
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        
        writer.transport = mock_transport
        mock_transport.get_protocol.return_value = mock_protocol

        # 3. Simulate the request that comes *after* the conceptual upgrade
        reader.readline.side_effect = [
            b"GET /api/data HTTP/1.1\r\n",
            b"Host: secure.example.com\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
            b"" # EOF
        ]

        # Call the handler
        await server.handle_connect(reader, writer, "secure.example.com:443")

        # 4. Verify Interactions
        mock_ca.get_ssl_context.assert_called_with("secure.example.com")
        writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        mock_start_tls.assert_called_once()
        args, kwargs = mock_start_tls.call_args
        
        assert args[2] == mock_ssl_context
        assert kwargs['server_side'] == True
        assert args[0] == mock_transport
        assert args[1] == mock_protocol

        assert len(server.request_log) == 1
        captured = server.request_log[0]
        assert captured.method == "GET"
        
        # FIXED: URL should include port 443 because the CONNECT request included it
        assert captured.url == "https://secure.example.com:443/api/data"

        expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
        writer.write.assert_any_call(expected_response)


@pytest.mark.asyncio
async def test_handle_connect_invalid_target(monkeypatch):
    """Test handle_connect with an invalid target format."""
    server = CaptureServer(port=8000)
    
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': MagicMock()}):
        
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()

        await server.handle_connect(reader, writer, "example.com")

        writer.write.assert_called_with(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid CONNECT target")

@pytest.mark.asyncio
async def test_handle_connect_no_start_tls_support(monkeypatch, capsys):
    """Test behavior when loop.start_tls is not available."""
    server = CaptureServer(port=8000)
    
    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()

    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        mock_loop = MagicMock()
        if hasattr(mock_loop, 'start_tls'):
            delattr(mock_loop, 'start_tls')
        
        monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)

        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()

        await server.handle_connect(reader, writer, "example.com:443")

        writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        captured = capsys.readouterr()
        assert "does not support loop.start_tls" in captured.out

@pytest.mark.asyncio
async def test_handle_client_connect_disabled(server_manager):
    """Test that CONNECT requests are dropped if CA_MANAGER is disabled."""
    server, port = await server_manager()
    
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': None}):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()

        response = await reader.read(1024)
        assert response == b""
        assert reader.at_eof()

        writer.close()
        await writer.wait_closed()