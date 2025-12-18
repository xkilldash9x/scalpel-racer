import asyncio
import unittest
from unittest.mock import MagicMock, patch
from proxy_core import NativeProxyHandler, StreamContext

class MockStreamEnded:
    def __init__(self, stream_id): self.stream_id = stream_id

class TestProxyZombieStreams(unittest.IsolatedAsyncioTestCase):
    async def test_stream_cleanup(self):
        handler = NativeProxyHandler(None, None, "", None, None, None)
        sid = 1
        ctx = StreamContext(sid, "https"); ctx.downstream_closed = True
        handler.streams[sid] = ctx
        
        with patch("proxy_core.StreamEnded", MockStreamEnded):
            await handler.handle_upstream_event(MockStreamEnded(sid))
        
        self.assertNotIn(sid, handler.streams)
