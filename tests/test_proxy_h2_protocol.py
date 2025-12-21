import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_core import NativeProxyHandler, Http11ProxyHandler, ErrorCodes

class TestSignalFixes(unittest.IsolatedAsyncioTestCase):
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
        with patch.object(NativeProxyHandler, '_ensure_upstream_connected', new_callable=AsyncMock, return_value=upstream_ctx), \
             patch.object(NativeProxyHandler, '_parse_target', return_value=("example.com", 443)), \
             patch.object(NativeProxyHandler, '_is_url_allowed', return_value=True), \
             patch.object(NativeProxyHandler, '_prepare_forwarded_headers', return_value=([(b':method', b'CONNECT')], "websocket")), \
             patch.object(NativeProxyHandler, '_process_headers_for_capture', return_value={'pseudo': {}, 'headers': []}):
            # Extended CONNECT Request
            event = MagicMock()
            event.stream_id = 1
            event.headers = [
                (b':method', b'CONNECT'), 
                (b':protocol', b'websocket'), 
                (b':authority', b'example.com')
            ]
            
            await handler._process_stream_request(event)
            
            # Assert Stream Reset
            handler.downstream_conn.reset_stream.assert_called_with(1, ErrorCodes.CONNECT_ERROR)

    async def test_h1_chunked_crlf(self):
        """Verify HTTP/1.1 chunk delimiters use CRLF."""
        writer = MagicMock()
        writer.drain = AsyncMock()
        handler = Http11ProxyHandler(AsyncMock(), writer, "", None, None, None)
        
        # Mock inputs: Chunk size "5", payload "ABCDE", size "0"
        with patch.object(Http11ProxyHandler, '_read_strict_line', new_callable=AsyncMock) as mock_read_line, \
             patch.object(Http11ProxyHandler, '_read_bytes_raw', new_callable=AsyncMock) as mock_read_bytes:
            mock_read_line.side_effect=[b"5", b"0", b""]
            mock_read_bytes.side_effect = [b"ABCDE", b"\r\n"]
            
            await handler._stream_chunked_body(writer)
            
            # Check writes. Should find b'\r\n' appended to size '5'
            # The logic: u_writer.write(line + b'\r\n')
            calls = [args[0] for args, _ in writer.write.call_args_list]
            self.assertIn(b"5\r\n", calls)
            # Ensure we didn't just use \n
            self.assertNotIn(b"5\n", calls)

if __name__ == '__main__':
    unittest.main()