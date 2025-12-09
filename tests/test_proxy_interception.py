# tests/test_proxy_interception.py
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
# [FIX] Use @pytest_asyncio.fixture for async generators
@pytest_asyncio.fixture
async def server_manager(unused_tcp_port_factory):
    servers = []
    # This fixture enables tunneling for interception tests by default
    async def _start_server(target_override=None, scope_regex=None, enable_tunneling=True):
        port = unused_tcp_port_factory()
        # [FIX] Added bind_addr="127.0.0.1" to fix TypeError
        server = CaptureServer(port=port, bind_addr="127.0.0.1", target_override=target_override, scope_regex=scope_regex, enable_tunneling=enable_tunneling)
        servers.append(server)
        task = asyncio.create_task(server.start())

        # [Defense in Depth] Wait for the server to be ready instead of arbitrary sleep
        try:
            await asyncio.wait_for(server.ready_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
             if not task.done():
                 task.cancel()
             pytest.fail(f"Server failed to start on port {port} (Timeout waiting for ready_event)")

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


# -- Helper for Async Iterators (Mocking response streaming) --
async def async_iter(items):
    for item in items:
        yield item

# -- Helpers for Context Managers (Robust Mocking) --
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

# -- Tests for HTTP Tunneling --
@pytest.mark.asyncio
async def test_http_tunneling_success(server_manager):
    server, port = await server_manager(enable_tunneling=True)
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.reason_phrase = "Created"
    mock_response.headers = {"X-Upstream": "True", "Content-Length": "13", "Connection": "close", "Upgrade": "h2c"}
    mock_response.aiter_raw.side_effect = lambda: async_iter([b"Upstream data"])

    mock_client = AsyncMock()
    mock_client.stream = MagicMock()
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamContext(mock_response)
    server.proxy_client = mock_client

    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        request_headers = {"Host": "example.com", "User-Agent": "TestClient", "Connection": "keep-alive"}
        response = await client.post(f"http://example.com/api/submit", headers=request_headers, content=b"request body")

    assert response.status_code == 201
    assert "Connection" not in response.headers
    assert "Upgrade" not in response.headers
    
    assert len(server.request_log) == 1

    mock_client.stream.assert_called_once()
    args, kwargs = mock_client.stream.call_args
    sent_headers = kwargs['headers']
    assert "Host" not in sent_headers
    assert "Connection" not in sent_headers

@pytest.mark.asyncio
async def test_http_tunneling_upstream_error(server_manager):
    server, port = await server_manager(enable_tunneling=True)
    mock_client = AsyncMock()
    mock_client.stream = MagicMock()
    mock_client.stream.side_effect = lambda *args, **kwargs: MockStreamErrorContext()
    server.proxy_client = mock_client

    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        # We expect a 502 from the proxy, which httpx might raise as an error or return as a response.
        try:
            response = await client.get(f"http://unreachable.com/test")
            assert response.status_code == 502
        except (httpx.ProxyError, httpx.ConnectError):
            pass

# -- Tests for HTTPS Interception (New Functionality) --
@pytest.mark.asyncio
async def test_handle_connect_logic(monkeypatch):
    """Test the logic inside handle_connect, mocking the TLS upgrade."""

    # Test without tunneling first to verify capture and dummy response
    # [FIX] Added bind_addr="127.0.0.1"
    server = CaptureServer(port=8000, bind_addr="127.0.0.1", enable_tunneling=False)

    # 1. Mock Dependencies (CA_MANAGER and loop.start_tls)

    # Mock CA_MANAGER
    mock_ca = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ca.get_ssl_context.return_value = mock_ssl_context

    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        # Mock loop.start_tls (critical for testing interception)
        mock_loop = MagicMock()
        
        # Use MagicMock returning a Future for start_tls for better compatibility with wait_for mocking
        future_tls = asyncio.Future()
        mock_new_transport = MagicMock(name="NewTLSTransport")
        future_tls.set_result(mock_new_transport)
        mock_start_tls = MagicMock(return_value=future_tls)

        mock_loop.start_tls = mock_start_tls
        # Patch asyncio.get_running_loop to return our mock loop
        monkeypatch.setattr("asyncio.get_running_loop", lambda: mock_loop)

        # 2. Mock Reader/Writer
        # Use spec=asyncio.StreamReader to ensure mock behaves correctly with hasattr checks
        reader = AsyncMock(spec=asyncio.StreamReader)
        reader.at_eof = MagicMock(return_value=False)
        
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.is_closing.return_value = False
        
        # Mock the transport and protocol required by start_tls
        mock_transport = MagicMock(name="InitialTransport")
        mock_protocol = MagicMock(name="Protocol")
        
        # [FIX] Configure writer mock so handle_connect can retrieve transport/protocol
        # Configure get_extra_info on the writer mock
        writer.get_extra_info.side_effect = lambda name, default=None: mock_transport if name == 'transport' else default
        
        # Configure start_tls for Python 3.11+ path simulation
        writer.start_tls = AsyncMock()

        # Crucial: Set _protocol attribute as the implementation relies on it for robust retrieval
        writer._protocol = mock_protocol

        # Configure the fallback path as well (Defense in Depth for the test)
        mock_transport.get_protocol.return_value = mock_protocol


        # [FIX] Vital: Ensure the protocol's _stream_reader IS our configured reader
        # This ensures that when the code swaps readers, it swaps to the one we configured.
        mock_protocol._stream_reader = reader

        # 3. Simulate the request that comes *after* the conceptual upgrade
        
        # We define side_effects on the reader.readline METHOD directly.
        # This ensures that when the SUT calls await reader.readline(), it gets these values.
        reader.readline.side_effect = [
            # Read by handle_connect loop (1st iteration)
            b"GET /api/data HTTP/1.1\r\n",
            # Read by process_http_request -> read_headers
            b"Host: secure.example.com\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
            # Read by handle_connect loop (2nd iteration) - Relaxed parsing test
            b"GET /api/relaxed\r\n", # Missing version
            # Read by process_http_request -> read_headers
            b"Host: secure.example.com\r\n",
            b"\r\n",
            # Next read by handle_connect loop will hit EOF (b"")
            b""
        ]

        # We mock asyncio.wait_for to simply await the coroutine.
        # Since reader.readline is an AsyncMock with side_effect, awaiting it returns the next item.
        async def mock_wait_for(coro, timeout):
            # We must check if the coro is the future returned by start_tls or the readline coroutine
            if asyncio.isfuture(coro):
                 return await coro
            return await coro

        # Call the handler
        connect_target = "secure.example.com:443"
        
        # Patch StreamWriter creation to capture the newly created writer inside handle_connect
        with patch('asyncio.wait_for', side_effect=mock_wait_for), \
             patch('asyncio.StreamWriter') as MockStreamWriter:
             
            # Setup the mock for the *new* writer created after TLS upgrade
            mock_new_writer = MockStreamWriter.return_value
            mock_new_writer.write = MagicMock()
            mock_new_writer.drain = AsyncMock()
            mock_new_writer.is_closing.return_value = False

            await server.handle_connect(reader, writer, connect_target)

        # 4. Verify Interactions

        # Verify CA was consulted with the host part
        mock_ca.get_ssl_context.assert_called_with("secure.example.com")

        # Verify 200 OK sent before upgrade (on the initial writer)
        writer.write.assert_any_call(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Verify start_tls was called correctly (Writer method preferred)
        writer.start_tls.assert_called_once()

        # Ensure legacy loop.start_tls was NOT called
        mock_start_tls.assert_not_called()
        
        # Verify StreamWriter was NOT re-initialized (as we used in-place upgrade)
        MockStreamWriter.assert_not_called()

        # Verify both requests inside the tunnel were processed and captured
        assert len(server.request_log) == 2
        captured1 = server.request_log[0]
        assert captured1.method == "GET"
        assert captured1.url == f"https://{connect_target}/api/data"

        captured2 = server.request_log[1]
        assert captured2.method == "GET"
        assert captured2.url == f"https://{connect_target}/api/relaxed"

        # Verify responses inside the tunnel (Dummy response) - written to the ORIGINAL writer (updated in-place)
        # Request 1 (HTTP/1.1) is keep-alive
        expected_response1 = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
        # Request 2 (Defaulted to HTTP/1.0 by the fix) is close
        expected_response2 = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nCaptured."
        writer.write.assert_any_call(expected_response1)
        writer.write.assert_any_call(expected_response2)

@pytest.mark.asyncio
async def test_handle_connect_invalid_target(monkeypatch):
    """Test handle_connect with an invalid target format."""
    # [FIX] Added bind_addr="127.0.0.1"
    server = CaptureServer(port=8000, bind_addr="127.0.0.1")

    # Ensure CA_MANAGER is mocked/available so the global lookup inside handle_connect works.
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': MagicMock()}):
        
        reader = AsyncMock()
        writer = MagicMock()
        writer.drain = AsyncMock()

        # FIX: Use a target format that is actually invalid (non-numeric port)
        # The implementation allows targets without ports, so we test the invalid port case.
        await server.handle_connect(reader, writer, "example.com:notaport")

        # Verify 400 Bad Request response
        writer.write.assert_called_with(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid CONNECT target")

# -- Coverage Increase Tests --

@pytest.mark.asyncio
async def test_handle_connect_ca_disabled(capsys):
    """Test CONNECT request when CA_MANAGER is globally disabled."""
    # [FIX] Added bind_addr="127.0.0.1"
    server = CaptureServer(port=8001, bind_addr="127.0.0.1")

    # Explicitly set global CA_MANAGER to None
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': None}):
        
        reader = AsyncMock()
        writer = MagicMock()
        
        # [FIX] Define the full sequence of reads upfront, avoiding side_effect modification issues.
        # This resolves the TypeError: can only concatenate list (not "list_iterator") to list.
        # This includes the initial CONNECT line read by handle_client, 
        # and the subsequent header drain reads also handled by handle_client.
        reader.readline.side_effect = [
            b"CONNECT example.com:443 HTTP/1.1\r\n", # Initial line
            b"Host: example.com\r\n",                # Header drain 1
            b"\r\n"                                  # Header drain end
        ]

        # We need to mock wait_for as handle_client calls it for the drain
        async def mock_wait_for(coro, timeout):
             return await coro

        # We must call handle_client as it handles the initial CONNECT line and the drain
        with patch('asyncio.wait_for', side_effect=mock_wait_for):
             # The side effect is already fully configured.
             # Previous implementation attempted concatenation here:
             # reader.readline.side_effect = [b"CONNECT..."] + reader.readline.side_effect
             await server.handle_client(reader, writer)


        # Verify it exits gracefully and prints a warning
        captured = capsys.readouterr()
        assert "[!] Received CONNECT request but TLS interception is disabled." in captured.out