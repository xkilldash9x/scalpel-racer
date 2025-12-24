
import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from proxy_core import Http11ProxyHandler, PayloadTooLargeError, ProxyError, NativeProxyHandler, StreamContext
import pytest

class TestHttp11ProxyHandler(unittest.TestCase):
    def setUp(self):
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_callback = MagicMock()
        self.handler = Http11ProxyHandler(
            self.mock_reader, self.mock_writer, "example.com", self.mock_callback,
            None, None, strict_mode=True
        )

    def test_read_strict_line_normal(self):
        self.handler.buffer = bytearray(b"Line1\r\nLine2\n")

        async def run():
            line1 = await self.handler._read_strict_line()
            line2 = await self.handler._read_strict_line()
            return line1, line2

        l1, l2 = asyncio.run(run())
        self.assertEqual(l1, b"Line1")
        self.assertEqual(l2, b"Line2")

    def test_read_strict_line_compaction(self):
        self.handler.buffer = bytearray(b"A" * 70000)
        self.handler._buffer_offset = 66000
        self.mock_reader.read.return_value = b"\n"

        async def run_compaction():
            return await self.handler._read_strict_line()

        line = asyncio.run(run_compaction())
        self.assertEqual(line, b"A" * 4000)
        self.assertEqual(self.handler._buffer_offset, 4001)
        self.assertTrue(len(self.handler.buffer) < 10000)

    def test_read_bytes_too_large(self):
        async def run():
            with self.assertRaises(PayloadTooLargeError):
                await self.handler._read_bytes(11 * 1024 * 1024)
        asyncio.run(run())

    def test_validate_request_pseudo_headers(self):
        async def run():
            headers = {b':method': b'GET'}
            valid = await self.handler._validate_request('GET', headers)
            self.assertFalse(valid)
        asyncio.run(run())

    def test_validate_request_connect_no_host(self):
        async def run():
            headers = {b'user-agent': b'test'}
            valid = await self.handler._validate_request('CONNECT', headers)
            self.assertFalse(valid)
        asyncio.run(run())

    def test_chunked_body_read(self):
        self.handler.buffer = bytearray(b"4\r\nTest\r\n0\r\n\r\n")
        async def run():
            return await self.handler._read_chunked_body()

        body = asyncio.run(run())
        self.assertEqual(body, b"Test")

class TestNativeProxyHandler(unittest.TestCase):
    def setUp(self):
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_callback = MagicMock()
        with patch('proxy_core.H2Connection') as MockH2:
            self.handler = NativeProxyHandler(
                self.mock_reader, self.mock_writer, "example.com", self.mock_callback,
                None, None
            )
            self.handler.downstream_conn = MagicMock()
            self.handler.downstream_conn.local_settings = MagicMock()

    def test_stream_context_slots(self):
        ctx = StreamContext(1, "https", None)
        with self.assertRaises(AttributeError):
            ctx.new_attr = 1

    def test_prepare_forwarded_headers(self):
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"connection", b"close"),
            (b"te", b"trailers"),
            (b"te", b"deflate"),
            (b"accept", b"*/*")
        ]
        out, protocol = self.handler._prepare_forwarded_headers(headers)

        keys = [k for k, v in out]
        self.assertIn(b":method", keys)
        self.assertNotIn(b"connection", keys)
        self.assertIn(b"te", keys)

    def test_cleanup_stream(self):
        ctx = StreamContext(1, "https", None)
        t = MagicMock()
        ctx.sender_tasks.append(t)
        self.handler.streams[1] = ctx

        self.handler._cleanup_stream(1, force_close=True)
        self.assertNotIn(1, self.handler.streams)
        t.cancel.assert_called()

if __name__ == "__main__":
    unittest.main()
