import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from proxy_core import Http11ProxyHandler

@pytest.mark.asyncio
async def test_fallback_to_host_header():
    """
    If the target URI is relative, use the Host header.
    """
    mock_reader = AsyncMock()
    # [FIX] Use MagicMock for writer because .write() is synchronous, only .drain() is async
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()

    handler = Http11ProxyHandler(
        reader=mock_reader,
        writer=mock_writer,
        explicit_host=None,
        manager_callback=Mock(),
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

    # [FIX] Expect port 80 because upstream_verify_ssl defaults to False (HTTP)
    # The code logic is: if scheme=="https" -> 443, else -> 80.
    handler._connect_upstream.assert_called_with("fallback-host.com", 80)

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
        manager_callback=Mock(),
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
    handler._connect_upstream.assert_called_with("fallback-host.com", 443) # Default HTTPS since verify_ssl defaults false but code uses port 443 default if not specified
