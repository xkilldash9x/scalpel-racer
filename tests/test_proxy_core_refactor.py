import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock
from proxy_core import NativeProxyHandler, StreamContext

class TestProxyCoreFlowControl(unittest.IsolatedAsyncioTestCase):
    async def test_stream_sender_infinite_spin_fix(self):
        conn = MagicMock(); writer = AsyncMock(); queue = asyncio.Queue()
        flow_event = asyncio.Event(); flow_event.set()
        conn.outbound_flow_control_window = 0
        conn.remote_flow_control_window.return_value = 0
        
        await queue.put((b"A" * 10, True, 0)); await queue.put(None)
        handler = NativeProxyHandler(None, None, "", None, None, None); handler.closed = asyncio.Event()
        
        task = asyncio.create_task(handler._stream_sender(1, conn, writer, queue, flow_event, asyncio.Lock(), asyncio.Lock(), None, None, None, None))
        await asyncio.sleep(0.1)
        self.assertFalse(flow_event.is_set())
        task.cancel()
