# tests/test_url_construction.py
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer

# --- Unit Tests for construct_target_url (The Core Logic) ---
class TestURLConstruction:

    @pytest.fixture
    def server(self):
        # [FIX] Added bind_addr
        return CaptureServer(port=8080, bind_addr="127.0.0.1")

    @pytest.fixture
    def server_override(self):
        # [FIX] Added bind_addr
        return CaptureServer(port=8080, bind_addr="127.0.0.1", target_override="http://override.com/api")

    # --- Scenario 1: Standard HTTP Proxy (No Tunnel, No Override) ---

    def test_http_proxy_absolute(self, server):
        scheme = "http"
        target = "http://example.com/foo?q=1"
        headers = {"host": "example.com"} 
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://example.com/foo?q=1"

    def test_http_proxy_absolute_https(self, server):
        scheme = "http" 
        target = "https://secure.com/bar"
        headers = {"host": "secure.com"}
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://secure.com/bar"

    def test_http_proxy_relative_fallback(self, server):
        scheme = "http"
        target = "/foo?q=1"
        headers = {"host": "fallback.com"}
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://fallback.com/foo?q=1"

    def test_http_proxy_relative_missing_host(self, server):
        scheme = "http"
        target = "/foo"
        headers = {}
        explicit_host = None

        with pytest.raises(ValueError, match="Cannot determine target host"):
            server.construct_target_url(scheme, target, headers, explicit_host)

    # --- Scenario 2: HTTPS Interception (CONNECT Tunnel, No Override) ---

    def test_https_tunnel_relative(self, server):
        scheme = "https" 
        target = "/data"
        headers = {"host": "tunnel.com:443"} 
        explicit_host = "tunnel.com:443" 

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://tunnel.com:443/data"

    def test_https_tunnel_relative_host_mismatch(self, server):
        scheme = "https"
        target = "/data"
        headers = {"host": "spoofed.com"}
        explicit_host = "tunnel.com"

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://tunnel.com/data"

    def test_https_tunnel_absolute_rare(self, server):
        scheme = "https"
        target = "https://other.com/api"
        headers = {"host": "tunnel.com"}
        explicit_host = "tunnel.com"

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://other.com/api"

    # --- Scenario 3: Target Override Active ---

    def test_override_http_absolute(self, server_override):
        scheme = "http"
        target = "http://original.com/path/to/resource?a=b"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/path/to/resource?a=b"

    def test_override_http_relative(self, server_override):
        scheme = "http"
        target = "/resource?a=b"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/resource?a=b"

    def test_override_https_tunnel(self, server_override):
        scheme = "https"
        target = "/secure/data"
        headers = {"host": "tunnel.com"}
        explicit_host = "tunnel.com"

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/secure/data" 

    def test_override_root_path(self, server_override):
        scheme = "http"
        target = "/"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/"

    # --- Scenario 4: Edge Cases and Parsing Robustness ---

    def test_parsing_double_slashes(self, server):
        scheme = "http"
        target = "/foo//bar"
        headers = {"host": "example.com"}
        
        url = server.construct_target_url(scheme, target, headers, None)
        assert url == "http://example.com/foo//bar"

    def test_parsing_absolute_no_path(self, server):
        scheme = "http"
        target = "http://example.com"
        headers = {}
        
        url = server.construct_target_url(scheme, target, headers, None)
        assert url == "http://example.com"

    def test_invalid_relative_format(self, server):
        scheme = "http"
        target = "foo/bar"
        headers = {"host": "example.com"}
        
        with pytest.raises(ValueError, match="Invalid request target format"):
            server.construct_target_url(scheme, target, headers, None)

# --- Integration Tests for process_http_request ---

@pytest.mark.asyncio
@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore::RuntimeWarning:unittest.mock")
async def test_header_canonicalization_and_url_construction():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8080, bind_addr="127.0.0.1", enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    reader.readline.side_effect = [
        b"GET /test HTTP/1.1\r\n",
        b"HoSt: Example.COM\r\n",         
        b"X-Custom: Value\r\n",
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]

    async def mock_wait_for(coro, timeout):
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://Example.COM/test"
    assert captured.headers["X-Custom"] == "Value"

@pytest.mark.asyncio
async def test_missing_host_header_error_response():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8080, bind_addr="127.0.0.1", enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    reader.readline.side_effect = [
        b"GET /test HTTP/1.1\r\n",
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]

    async def mock_wait_for(coro, timeout):
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    assert len(server.request_log) == 0
    write_calls = writer.write.call_args_list
    # [FIX] call is used as local variable here, no import needed
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 400 Bad Request" in response_data
    assert b"Cannot determine target host" in response_data
    writer.close.assert_called()

@pytest.mark.asyncio
async def test_process_http_request_incomplete_body_read_handling():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8000, bind_addr="127.0.0.1", enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    reader.readline.side_effect = [
        b"Host: example.com\r\n",
        b"Content-Length: 10\r\n",
        b"\r\n"
    ]
    incomplete_read_error = asyncio.IncompleteReadError(partial=b"abc", expected=10)
    reader.readexactly.side_effect = incomplete_read_error

    async def mock_wait_for_process(coro, timeout):
        try:
            return await coro
        except asyncio.IncompleteReadError as e:
            raise e

    with patch('asyncio.wait_for', side_effect=mock_wait_for_process):
        await server.process_http_request(reader, writer, "POST", "/", "HTTP/1.0", b"", "http")

    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 400 Bad Request" in response_data
    assert b"Incomplete body read. Expected 10, got 3." in response_data

@pytest.mark.asyncio
async def test_process_http_request_body_read_timeout():
    # [FIX] Added bind_addr
    server = CaptureServer(port=8000, bind_addr="127.0.0.1", enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    reader.readline.side_effect = [
        b"Host: example.com\r\n",
        b"Content-Length: 10\r\n",
        b"\r\n"
    ]

    wait_for_call_count = 0
    async def mock_wait_for_timeout(coro, timeout):
        nonlocal wait_for_call_count
        wait_for_call_count += 1
        if wait_for_call_count == 1:
             return await coro
        elif wait_for_call_count == 2:
             raise asyncio.TimeoutError()

    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.process_http_request(reader, writer, "POST", "/", "HTTP/1.1", b"", "http")

    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 408 Request Timeout" in response_data
    assert b"Timeout" in response_data