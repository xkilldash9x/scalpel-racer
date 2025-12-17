################################################################################
## START OF FILE: tests/test_host_header_precedence.py
################################################################################
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
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()

    # [FIX] Patch _pipe on the CLASS to respect __slots__ restrictions
    with patch.object(Http11ProxyHandler, '_pipe', new_callable=AsyncMock):
        handler = Http11ProxyHandler(
            reader=mock_reader,
            writer=mock_writer,
            explicit_host=None,
            manager_callback=Mock(),
            target_override=None,
            scope_pattern=None
        )

        u_writer_mock = MagicMock()
        u_writer_mock.drain = AsyncMock()
        
        with patch.object(Http11ProxyHandler, '_connect_upstream', return_value=(AsyncMock(), u_writer_mock)) as mock_conn:
            # Simulate a request with relative URI and Host header
            target = "/path"
            headers = [("Host", "fallback-host.com")]
            headers_dict = {"host": "fallback-host.com"}
            version = b"HTTP/1.1"

            await handler._handle_request("GET", target, version, headers, headers_dict)

            # [FIX] Default is port 80 for HTTP when verify_ssl is False
            mock_conn.assert_called_with("fallback-host.com", 80)