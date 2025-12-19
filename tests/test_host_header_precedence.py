import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
import time
from proxy_core import Http11ProxyHandler

@pytest.mark.asyncio
async def test_fallback_to_host_header():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()

    with patch.object(Http11ProxyHandler, '_pipe', new_callable=AsyncMock):
        handler = Http11ProxyHandler(mock_reader, mock_writer, None, Mock(), None, None)
        u_writer_mock = MagicMock()
        u_writer_mock.drain = AsyncMock()
        
        with patch.object(Http11ProxyHandler, '_connect_upstream', return_value=(AsyncMock(), u_writer_mock)) as mock_conn:
            target = "/path"
            headers = [("Host", "fallback-host.com")]
            headers_dict = {"host": "fallback-host.com"}
            version = b"HTTP/1.1"
            await handler._handle_request("GET", target, version, headers, headers_dict, time.time())
            mock_conn.assert_called_with("fallback-host.com", 80)
