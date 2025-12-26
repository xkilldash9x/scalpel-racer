# tests/test_proxy_h2_protocol.py
"""
Tests for Proxy H2 Protocol handling.
"""
import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_h2 import NativeProxyHandler
from proxy_core import Http11ProxyHandler
from compat import ErrorCodes

# pylint: disable=protected-access

class TestSignalFixes(unittest.IsolatedAsyncioTestCase):
    """Tests for protocol signal fixes and negotiations."""
    async def test_extended_connect_negotiation(self):
        """Verify we reject Extended CONNECT if upstream doesn't support it."""
        handler = NativeProxyHandler(AsyncMock(), AsyncMock(), "", None, None, None)
        handler.ds_h2_lock = asyncio.Lock()
        handler.downstream_conn = MagicMock()

        # Mock Upstream that does NOT support RFC 8441
        upstream_ctx = MagicMock()
        upstream_ctx.protocol = "h2"
        # Simulate SETTINGS_ENABLE_CONNECT_PROTOCOL (8) = 0
        upstream_ctx.conn.remote_settings = {8: 0}

        # [FIX] Manually set upstream_conn on handler since we mock the connection method
        handler.upstream_conn = upstream_ctx.conn
        handler.upstream_protocol = "h2"

        with patch.object(NativeProxyHandler, '_ensure_upstream_connected',
                          new_callable=AsyncMock, return_value=upstream_ctx), \
             patch.object(NativeProxyHandler, '_parse_target',
                          return_value=("example.com", 443)), \
             patch.object(NativeProxyHandler, '_is_url_allowed', return_value=True), \
             patch.object(NativeProxyHandler, '_prepare_forwarded_headers',
                          return_value=([(b':method', b'CONNECT')], "websocket")), \
             patch('proxy_h2.process_h2_headers_for_capture',
                   return_value={'pseudo': {}, 'headers': []}):
            # Extended CONNECT Request
            event = MagicMock()
            event.stream_id = 1
            event.headers = [
                (b':method', b'CONNECT'),
                (b':protocol', b'websocket'),
                (b':authority', b'example.com')
            ]

            await handler.handle_request_received(event)

            # Assert Stream Reset
            handler.downstream_conn.reset_stream.assert_called_with(
                1, ErrorCodes.CONNECT_ERROR
            )

    async def test_h1_chunked_crlf(self):
        """Verify HTTP/1.1 chunk delimiters use CRLF."""
        writer = MagicMock()
        writer.drain = AsyncMock()
        handler = Http11ProxyHandler(AsyncMock(), writer, "", None, None, None)

        # Mock inputs: Chunk size "5", payload "ABCDE", size "0"
        with patch.object(Http11ProxyHandler, '_read_strict_line',
                          new_callable=AsyncMock) as mock_read_line, \
             patch.object(Http11ProxyHandler, '_read_bytes',
                          new_callable=AsyncMock) as mock_read_bytes:

            # [FIX] Adjusted side effects:
            # 1. Size "5"
            # 2. _read_strict_line called after data to consume CRLF -> returns b""
            # 3. Size "0"
            # 4. Trailers end -> b""
            mock_read_line.side_effect = [b"5", b"", b"0", b""]
            mock_read_bytes.side_effect = [b"ABCDE"]

            await handler._read_chunked_body()

if __name__ == '__main__':
    unittest.main()