# tests/test_zombie_stream.py
"""
Tests for Zombie Stream detection and cleanup in Proxy H2.
"""
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_h2 import NativeProxyHandler
from proxy_common import H2StreamContext as StreamContext

# Mock H2 Events to avoid strict dependency on h2 library for this test file
# pylint: disable=too-few-public-methods
class MockStreamEnded:
    """Mock for h2.events.StreamEnded."""
    def __init__(self, stream_id):
        self.stream_id = stream_id

class MockResponseReceived:
    """Mock for h2.events.ResponseReceived."""
    def __init__(self, stream_id, headers, stream_ended=False):
        self.stream_id = stream_id
        self.headers = headers
        self.stream_ended = stream_ended
# pylint: enable=too-few-public-methods

class TestProxyZombieStreams(unittest.IsolatedAsyncioTestCase):
    """Tests for stream lifecycle and cleanup."""
    async def test_stream_cleanup_on_response_received(self):
        """
        Verifies that a stream is correctly removed from memory (self.streams)
        only when BOTH downstream and upstream have closed.
        Specific focus: Ensure Upstream StreamEnded sets upstream_closed=True.
        """
        # 1. Setup Handler
        handler = NativeProxyHandler(None, None, "", None, None, None)
        handler.closed = asyncio.Event()

        # Mock locks/connections to prevent attribute errors during flow
        handler.downstream_conn = MagicMock()
        handler.ds_h2_lock = asyncio.Lock()

        # [FIX] writer.write is synchronous, drain is async.
        # AsyncMock for the whole object fails on write().
        handler.client_writer = MagicMock()
        handler.client_writer.drain = AsyncMock()

        handler.ds_socket_lock = asyncio.Lock()

        # 2. Simulate an active stream where Client (Downstream) has ALREADY finished
        stream_id = 1
        ctx = StreamContext(stream_id, "https", None)
        ctx.downstream_closed = True
        ctx.upstream_closed = False
        handler.streams[stream_id] = ctx

        # 3. Simulate Server (Upstream) ending the stream
        event = MockStreamEnded(stream_id)

        # Run the upstream handler
        # If buggy: it sets downstream_closed=True (no change) and stream remains.
        # If fixed: it sets upstream_closed=True, satisfying cleanup condition.
        # [FIX] Must patch proxy_h2.StreamEnded so isinstance(event, StreamEnded) is True
        with patch("proxy_h2.StreamEnded", MockStreamEnded):
            await handler.handle_upstream_event(event)

        # 4. Assertion: Stream should be gone
        self.assertNotIn(stream_id, handler.streams,
            "Zombie Stream detected! Stream persisted after Upstream closed.")

        # Verify internal state just in case cleanup logic changes
        self.assertTrue(ctx.upstream_closed, "Context upstream_closed flag was not set.")

    async def test_upstream_response_forwarding(self):
        """
        Verifies that Response headers from the server are actually forwarded
        to the downstream queue (Fixes the dropped headers bug).
        """
        handler = NativeProxyHandler(None, None, "", None, None, None)
        handler.enable_tunneling = True
        handler.upstream_conn = MagicMock()

        stream_id = 1
        ctx = StreamContext(stream_id, "https", None)
        handler.streams[stream_id] = ctx

        # Simulate 200 OK from upstream (Bytes on the wire)
        raw_headers = [(b':status', b'200'), (b'server', b'nginx')]
        event = MockResponseReceived(stream_id, raw_headers)

        # [FIX] Must patch proxy_h2.ResponseReceived so isinstance(event, ResponseReceived) is True
        with patch("proxy_h2.ResponseReceived", MockResponseReceived):
            await handler.handle_upstream_event(event)

        # Check Queue
        # Should contain: (headers, end_stream, ack_len)
        item = await ctx.downstream_queue.get()

        # [UPDATED] Expect Bytes, because proxy_core._prepare_forwarded_headers now preserves bytes.
        expected_headers = [(b':status', b'200'), (b'server', b'nginx')]

        self.assertEqual(item[0], expected_headers)
        self.assertFalse(item[1]) # Stream not ended yet

if __name__ == "__main__":
    unittest.main()