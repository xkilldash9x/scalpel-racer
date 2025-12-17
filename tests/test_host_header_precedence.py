from unittest.mock import AsyncMock, MagicMock, call
import pytest
from proxy_core import Http11ProxyHandler

@pytest.mark.asyncio
async def test_fallback_to_host_header():
    """
    If the target URI is relative, use the Host header.
    """
    mock_reader = AsyncMock()
    mock_writer = AsyncMock()

    handler = Http11ProxyHandler(
        reader=mock_reader,
        writer=mock_writer,
        explicit_host=None,
        manager_callback=MagicMock(),
        target_override=None,
        scope_pattern=None
    )

    # Mock _connect_upstream
    handler._connect_upstream = AsyncMock(return_value=(AsyncMock(), AsyncMock()))
    handler._pipe = AsyncMock()

    # Simulate a request with relative URI and Host header
    target = "/path"
    headers = [("Host", "fallback-host.com")]
    headers_dict = {"host": "fallback-host.com"}
    version = b"HTTP/1.1"

    await handler._handle_request("GET", target, version, headers, headers_dict)

    # Verify it connected to the host from the Host header
    # Corrected expectation: Defaults to port 80 if SSL is not enabled
    handler._connect_upstream.assert_called_with("fallback-host.com", 80)
