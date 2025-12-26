# tests/test_proxy_core_coverage.py
"""
Coverage tests for proxy core modules.
"""
import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import pytest
from proxy_core import Http11ProxyHandler, PayloadTooLargeError
from proxy_h2 import NativeProxyHandler
from proxy_common import H2StreamContext as StreamContext

# pylint: disable=protected-access

class TestHttp11ProxyHandler(unittest.TestCase):
    """Tests for Http11ProxyHandler."""
    def setUp(self):
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_callback = MagicMock()
        self.handler = Http11ProxyHandler(
            self.mock_reader, self.mock_writer, "example.com", self.mock_callback,
            None, None, strict_mode=True
        )

    def test_read_strict_line_normal(self):
        """Test normal line reading."""
        self.handler.buffer = bytearray(b"Line1\r\nLine2\n")

        async def run():
            line1 = await self.handler._read_strict_line()
            line2 = await self.handler._read_strict_line()
            return line1, line2

        l1, l2 = asyncio.run(run())
        self.assertEqual(l1, b"Line1")
        self.assertEqual(l2, b"Line2")

    def test_read_strict_line_compaction(self):
        """Test buffer compaction during read."""
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
        """Test reading bytes exceeding limit."""
        async def run():
            with self.assertRaises(PayloadTooLargeError):
                await self.handler._read_bytes(11 * 1024 * 1024)
        asyncio.run(run())

    def test_validate_request_pseudo_headers(self):
        """Test rejection of pseudo-headers in H1."""
        async def run():
            headers = {':method': 'GET'}
            valid = await self.handler._validate_request('GET', headers)
            self.assertFalse(valid)
        asyncio.run(run())

    def test_validate_request_connect_no_host(self):
        """Test CONNECT request validation."""
        async def run():
            headers = {'user-agent': 'test'}
            valid = await self.handler._validate_request('CONNECT', headers)
            self.assertFalse(valid)
        asyncio.run(run())

    def test_chunked_body_read(self):
        """Test reading chunked body."""
        self.handler.buffer = bytearray(b"4\r\nTest\r\n0\r\n\r\n")
        async def run():
            return await self.handler._read_chunked_body()

        body = asyncio.run(run())
        self.assertEqual(body, b"Test")

class TestNativeProxyHandler(unittest.TestCase):
    """Tests for NativeProxyHandler."""
    def setUp(self):
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_callback = MagicMock()
        # pylint: disable=unused-variable
        with patch('proxy_h2.H2Connection') as mock_h2:
            self.handler = NativeProxyHandler(
                self.mock_reader, self.mock_writer, "example.com", self.mock_callback,
                None, None
            )
            self.handler.downstream_conn = MagicMock()
            self.handler.downstream_conn.local_settings = MagicMock()
        # pylint: enable=unused-variable

    def test_stream_context_slots(self):
        """Test StreamContext slots enforcement."""
        ctx = StreamContext(1, "https", None)
        with self.assertRaises(AttributeError):
            # pylint: disable=assigning-non-slot
            ctx.new_attr = 1
            # pylint: enable=assigning-non-slot

    def test_prepare_forwarded_headers(self):
        """Test header preparation and filtering."""
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
        # pylint: disable=unused-variable
        out, protocol = self.handler._prepare_forwarded_headers(headers)
        # pylint: enable=unused-variable

        keys = [k for k, v in out]
        self.assertIn(b":method", keys)
        self.assertNotIn(b"connection", keys)
        self.assertIn(b"te", keys)

    def test_cleanup_stream(self):
        """Test stream cleanup logic."""
        ctx = StreamContext(1, "https", None)
        t = MagicMock()
        ctx.sender_tasks.append(t)
        self.handler.streams[1] = ctx

        self.handler._cleanup_stream(1, force_close=True)
        self.assertNotIn(1, self.handler.streams)
        t.cancel.assert_called()

if __name__ == "__main__":
    unittest.main()