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
        
        # Check if server started successfully (if stop_event is set, start() failed)
        if server.server is None and server.stop_event.is_set():
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port}")
             
        return server, port

    yield _start_server

    # Cleanup
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
    # Start server with tunneling enabled
    server, port = await server_manager()

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.reason_phrase = "Created"
    # Content-Length matches the body size
    mock_response.headers = {"X-Upstream": "True", "Content-Length": "13", "Connection": "close"}
    
    # aiter_raw must return an async iterator
    mock_response.aiter_raw.side_effect = lambda: async_iter([b"Upstream data"])

    mock_client = AsyncMock()
    # Explicitly make stream a MagicMock so it's not awaitable (not a coroutine)
    # The real client.stream is a sync method returning an async context manager.
    mock_client.stream = MagicMock()
    # Configure mock client stream to return our explicit context manager
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamContext(mock_response)
    server.proxy_client = mock_client

    # Send request using a client configured to use the proxy
    # Use 'proxy' argument (httpx >= 0.28.0)
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        request_headers = {"Host": "example.com", "User-Agent": "TestClient", "Connection": "keep-alive"}
        response = await client.post(f"http://example.com/api/submit", headers=request_headers, content=b"request body")

    # Check if the response came from the mock upstream
    assert response.status_code == 201
    assert response.text == "Upstream data"
    assert response.headers["X-Upstream"] == "True"
    
    # Verify hop-by-hop headers are removed from the response sent to the client
    assert "Connection" not in response.headers
    # Content-Length should BE present because we removed it from HOP_BY_HOP_HEADERS list
    assert "Content-Length" in response.headers

    # Check if the request was captured
    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://example.com/api/submit"
    assert captured.method == "POST"

    # Check if the upstream request was made correctly
    mock_client.stream.assert_called_once()
    args, kwargs = mock_client.stream.call_args
    
    # method and url are passed as positional arguments in scalpel_racer.py
    assert args[0] == "POST"
    assert args[1] == "http://example.com/api/submit"
    assert kwargs['content'] == b"request body"
    
    # Verify hop-by-hop headers were removed from the request sent upstream
    sent_headers = kwargs['headers']
    assert "Connection" not in sent_headers
    assert sent_headers["User-Agent"] == "TestClient"


@pytest.mark.asyncio
async def test_http_tunneling_upstream_error(server_manager):
    """Test proxy behavior when the upstream request fails."""
    server, port = await server_manager()

    # Mock the client to raise an exception
    mock_client = AsyncMock()
    # Explicitly make stream a MagicMock
    mock_client.stream = MagicMock()
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamErrorContext()
    server.proxy_client = mock_client

    # Use 'proxy' argument
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        response = await client.get(f"http://unreachable.com/test")

    # Check for the 502 Bad Gateway response generated by the proxy
    assert response.status_code == 502
    assert "Upstream request failed" in response.text

# --- Tests for HTTPS Interception (New Functionality) ---

@pytest.mark.asyncio
async def test_handle_connect_logic(monkeypatch):
    """Test the logic inside handle_connect, mocking the TLS upgrade."""
    
    # Test without tunneling first to verify capture and dummy response
    server = CaptureServer(port=8000, enable_tunneling=False)

    # 1. Mock Dependencies (CA_MANAGER and loop.start_tls)

    # Mock CA_MANAGER
    mock_ca = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ca.get_ssl_context.return_value = mock_ssl_context
    
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        # Mock loop.start_tls (critical for testing interception)
        mock_loop = MagicMock()
        mock_start_tls = AsyncMock()
        mock_loop.start_tls = mock_start_tls
        # Patch asyncio.get_running_loop to return our mock loop
        monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)

        # 2. Mock Reader/Writer
        reader = AsyncMock()
        # at_eof is NOT a coroutine, it's a synchronous method. AsyncMock makes everything coroutines by default.
        reader.at_eof = MagicMock(return_value=False)
        
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.is_closing.return_value = False
        
        # Mock the transport and protocol required by start_tls
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        writer.get_transport.return_value = mock_transport
        mock_transport.get_protocol.return_value = mock_protocol

        # 3. Simulate the request that comes *after* the conceptual upgrade
        # The server will read these lines from the (conceptually decrypted) stream
        reader.readline.side_effect = [
            b"GET /api/data HTTP/1.1\r\n",
            b"Host: secure.example.com\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
            b"" # EOF for the loop
        ]

        # Call the handler
        await server.handle_connect(reader, writer, "secure.example.com:443")

        # 4. Verify Interactions

        # Verify CA was consulted
        mock_ca.get_ssl_context.assert_called_with("secure.example.com")

        # Verify 200 OK sent before upgrade
        writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Verify start_tls was called correctly
        mock_start_tls.assert_called_once()
        args, kwargs = mock_start_tls.call_args
        
        # ssl_context is passed as a positional argument (3rd arg, index 2)
        assert args[2] == mock_ssl_context
        assert kwargs['server_side'] == True
        assert args[0] == mock_transport
        assert args[1] == mock_protocol

        # Verify the request inside the tunnel was processed and captured
        assert len(server.request_log) == 1
        captured = server.request_log[0]
        assert captured.method == "GET"
        # URL should be HTTPS
        assert captured.url == "https://secure.example.com/api/data"

        # Verify response inside the tunnel (Dummy response because enable_tunneling=False)
        expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
        writer.write.assert_any_call(expected_response)


@pytest.mark.asyncio
async def test_handle_connect_invalid_target(monkeypatch):
    """Test handle_connect with an invalid target format."""
    server = CaptureServer(port=8000)
    
    # Ensure CA_MANAGER is mocked/available so the global lookup inside handle_connect works.
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': MagicMock()}):
        
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()

        # Invalid target (no port)
        await server.handle_connect(reader, writer, "example.com")

        # Verify 400 Bad Request response
        writer.write.assert_called_with(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid CONNECT target")

@pytest.mark.asyncio
async def test_handle_connect_no_start_tls_support(monkeypatch, capsys):
    """Test behavior when loop.start_tls is not available."""
    server = CaptureServer(port=8000)
    
    # Mock CA_MANAGER
    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()

    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        # Mock the loop to NOT have start_tls attribute
        mock_loop = MagicMock()
        # Remove the attribute explicitly from the mock object representation
        if hasattr(mock_loop, 'start_tls'):
            delattr(mock_loop, 'start_tls')
        
        monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)

        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()

        await server.handle_connect(reader, writer, "example.com:443")

        # Verify 200 OK was sent
        writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        # Verify error message was printed
        captured = capsys.readouterr()
        assert "does not support loop.start_tls" in captured.out

@pytest.mark.asyncio
async def test_handle_client_connect_disabled(server_manager):
    """Test that CONNECT requests are dropped if CA_MANAGER is disabled."""
    # Start server
    server, port = await server_manager()
    
    # Disable CA_MANAGER globally using patch.dict context manager
    # This simulates the state where cryptography is not installed or initialization failed.
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': None}):

        # Connect locally
        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        # Send CONNECT
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()

        # The connection should be closed immediately by the server (in handle_client)
        response = await reader.read(1024)
        assert response == b""
        assert reader.at_eof()

        writer.close()
        await writer.wait_closed()