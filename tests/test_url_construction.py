# test_url_construction.py

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import pytest_asyncio
from scalpel_racer import CaptureServer

# --- Unit Tests for construct_target_url (The Core Logic) ---
# (These tests remain the same as they validate the logic of the method itself)
class TestURLConstruction:

    @pytest.fixture
    def server(self):
        # Default server, no override
        return CaptureServer(port=8080)

    @pytest.fixture
    def server_override(self):
        # Server with override, ensuring trailing slash is added by __init__
        return CaptureServer(port=8080, target_override="http://override.com/api")

    # --- Scenario 1: Standard HTTP Proxy (No Tunnel, No Override) ---

    def test_http_proxy_absolute(self, server):
        scheme = "http"
        target = "http://example.com/foo?q=1"
        # Headers are expected normalized (lowercase keys)
        headers = {"host": "example.com"} 
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://example.com/foo?q=1"

    def test_http_proxy_absolute_https(self, server):
        # Less common, but possible for a client to send GET https://... to an http proxy
        scheme = "http" # Transport scheme to proxy is http
        target = "https://secure.com/bar"
        headers = {"host": "secure.com"}
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://secure.com/bar"

    def test_http_proxy_relative_fallback(self, server):
        # Client sends relative URL (GET /foo). Relies on Host header.
        scheme = "http"
        target = "/foo?q=1"
        headers = {"host": "fallback.com"}
        explicit_host = None

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://fallback.com/foo?q=1"

    def test_http_proxy_relative_missing_host(self, server):
        # Client sends relative URL (GET /foo) but no Host header.
        scheme = "http"
        target = "/foo"
        headers = {}
        explicit_host = None

        # Should raise ValueError as host cannot be determined
        with pytest.raises(ValueError, match="Cannot determine target host"):
            server.construct_target_url(scheme, target, headers, explicit_host)

    # --- Scenario 2: HTTPS Interception (CONNECT Tunnel, No Override) ---

    def test_https_tunnel_relative(self, server):
        scheme = "https" # Inside the tunnel
        target = "/data"
        headers = {"host": "tunnel.com:443"} # Host header usually matches CONNECT host
        explicit_host = "tunnel.com:443" # From CONNECT (Authority form)

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        # urlunparse preserves the explicit port
        assert url == "https://tunnel.com:443/data"

    def test_https_tunnel_relative_host_mismatch(self, server):
        # Host header doesn't match CONNECT host. CONNECT host (explicit_host) takes precedence.
        scheme = "https"
        target = "/data"
        headers = {"host": "spoofed.com"}
        explicit_host = "tunnel.com"

        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://tunnel.com/data"

    def test_https_tunnel_absolute_rare(self, server):
        # Client sends absolute URL inside the tunnel (Rare, usually indicates misconfiguration)
        scheme = "https"
        target = "https://other.com/api"
        headers = {"host": "tunnel.com"}
        explicit_host = "tunnel.com"

        # The logic correctly identifies this as an absolute URL (Case B) and returns it directly.
        url = server.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "https://other.com/api"

    # --- Scenario 3: Target Override Active ---

    def test_override_http_absolute(self, server_override):
        # Client sends absolute URL, but override replaces the base.
        scheme = "http"
        target = "http://original.com/path/to/resource?a=b"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        # Should be override base + path/query from target
        assert url == "http://override.com/api/path/to/resource?a=b"

    def test_override_http_relative(self, server_override):
        # Client sends relative URL.
        scheme = "http"
        target = "/resource?a=b"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/resource?a=b"

    def test_override_https_tunnel(self, server_override):
        # Inside CONNECT tunnel, override is active.
        scheme = "https"
        target = "/secure/data"
        headers = {"host": "tunnel.com"}
        explicit_host = "tunnel.com"

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/secure/data" # Note: Override scheme is http

    def test_override_root_path(self, server_override):
        # Client requests the root path
        scheme = "http"
        target = "/"
        headers = {"host": "original.com"}
        explicit_host = None

        url = server_override.construct_target_url(scheme, target, headers, explicit_host)
        assert url == "http://override.com/api/"

    # --- Scenario 4: Edge Cases and Parsing Robustness (Phase 2) ---

    def test_parsing_double_slashes(self, server):
        # Test a common proxy scenario: GET /foo//bar
        scheme = "http"
        target = "/foo//bar"
        headers = {"host": "example.com"}
        
        url = server.construct_target_url(scheme, target, headers, None)
        # urlunparse preserves the path structure
        assert url == "http://example.com/foo//bar"

    def test_parsing_absolute_no_path(self, server):
        # GET http://example.com
        scheme = "http"
        target = "http://example.com"
        headers = {}
        
        url = server.construct_target_url(scheme, target, headers, None)
        # The implementation returns absolute targets as-is (fidelity) if no override is set.
        assert url == "http://example.com"

    def test_invalid_relative_format(self, server):
        # GET foo/bar (missing leading slash - this is not valid origin-form)
        scheme = "http"
        target = "foo/bar"
        headers = {"host": "example.com"}
        
        # This should be rejected in relative context (Case C)
        with pytest.raises(ValueError, match="Invalid request target format"):
            server.construct_target_url(scheme, target, headers, None)

# --- Integration Tests for process_http_request (Header Canonicalization, Timeouts, and Hardening) ---

@pytest.mark.asyncio
async def test_header_canonicalization_and_url_construction():
    # Initialize server
    server = CaptureServer(port=8080, enable_tunneling=False)

    # Use spec=asyncio.StreamReader to ensure mock behaves correctly with hasattr checks
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    # Simulate request with mixed-case Host header

    # Mock handle_client's initial read and subsequent reads in process_http_request
    # We assign side_effect to the METHOD so awaiting calls yields these.
    reader.readline.side_effect = [
        b"GET /test HTTP/1.1\r\n",        # (read by handle_client)
        # (read by process_http_request -> read_headers)
        b"HoSt: Example.COM\r\n",         
        b"X-Custom: Value\r\n",
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]

    # Simple mock for wait_for that simply returns the result of the coroutine
    async def mock_wait_for(coro, timeout):
        return await coro

    # We must call handle_client as it orchestrates the flow
    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    # Verify the request was captured
    assert len(server.request_log) == 1
    captured = server.request_log[0]

    # 1. Verify URL Construction used the normalized Host header value correctly
    assert captured.url == "http://Example.COM/test"

    # 2. Verify the CapturedRequest stores the original casing (Fidelity)
    assert "X-Custom" in captured.headers
    assert captured.headers["X-Custom"] == "Value"

@pytest.mark.asyncio
async def test_missing_host_header_error_response():
    # Test that a 400 response is sent if URL cannot be determined
    server = CaptureServer(port=8080, enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    # Simulate relative request with NO Host header
    reader.readline.side_effect = [
        b"GET /test HTTP/1.1\r\n",
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]

    # Simple mock for wait_for
    async def mock_wait_for(coro, timeout):
        return await coro

    with patch('asyncio.wait_for', side_effect=mock_wait_for):
        await server.handle_client(reader, writer)

    # Verify no request was captured
    assert len(server.request_log) == 0

    # Verify 400 Bad Request response was sent
    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 400 Bad Request" in response_data
    assert b"Cannot determine target host" in response_data
    # Verify connection is closed (by the finally block in handle_client)
    writer.close.assert_called()

@pytest.mark.asyncio
async def test_process_http_request_incomplete_body_read_handling():
    # Test the improved handling of incomplete body reads (Hardening)
    server = CaptureServer(port=8000, enable_tunneling=False)

    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    # Simulate headers indicating Content-Length 10
    reader.readline.side_effect = [
        # (Lines read inside read_headers helper)
        b"Host: example.com\r\n",
        b"Content-Length: 10\r\n",
        b"\r\n"
    ]

    # Simulate IncompleteReadError during body reading (readexactly)
    # This exception will be propagated by the wait_for wrapping it.
    incomplete_read_error = asyncio.IncompleteReadError(partial=b"abc", expected=10)
    reader.readexactly.side_effect = incomplete_read_error

    # Helper specific to this test, handling the wait_for calls inside process_http_request
    async def mock_wait_for_process(coro, timeout):
        try:
            # Await the coroutine (read_headers or readexactly)
            return await coro
        except asyncio.IncompleteReadError as e:
            # If readexactly fails, propagate the exception as wait_for would
            raise e

    # Call process_http_request directly (requires patching wait_for used inside it)
    # We use a version that defaults to 1.0 due to the relaxed parsing fix.
    with patch('asyncio.wait_for', side_effect=mock_wait_for_process):
        await server.process_http_request(reader, writer, "POST", "/", "HTTP/1.0", b"", "http")

    # Should return 400 Bad Request due to incomplete read
    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 400 Bad Request" in response_data
    assert b"Incomplete body read. Expected 10, got 3." in response_data
    # Connection closure is handled by handle_client's finally block in a real scenario.

@pytest.mark.asyncio
async def test_process_http_request_body_read_timeout():
    # Test handling of timeout during body read
    server = CaptureServer(port=8000, enable_tunneling=False)

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

    # Helper specific to this test: simulate TimeoutError on the second wait_for call (body read)
    wait_for_call_count = 0
    async def mock_wait_for_timeout(coro, timeout):
        nonlocal wait_for_call_count
        wait_for_call_count += 1
        if wait_for_call_count == 1: # First call (read_headers)
             return await coro
        elif wait_for_call_count == 2: # Second call (readexactly)
             raise asyncio.TimeoutError()

    # Call process_http_request directly
    with patch('asyncio.wait_for', side_effect=mock_wait_for_timeout):
        await server.process_http_request(reader, writer, "POST", "/", "HTTP/1.1", b"", "http")

    # Should return 408 Request Timeout
    write_calls = writer.write.call_args_list
    response_data = b"".join(call[0][0] for call in write_calls)

    assert b"HTTP/1.1 408 Request Timeout" in response_data
    assert b"Timeout" in response_data