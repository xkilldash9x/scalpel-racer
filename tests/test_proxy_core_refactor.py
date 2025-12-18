# test_proxy_core_refactor.py

import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock
from proxy_core import NativeProxyHandler, StreamContext

class TestProxyCoreFlowControl(unittest.IsolatedAsyncioTestCase):
    async def test_stream_sender_infinite_spin_fix(self):
        """
        Verifies that _stream_sender does not busy-loop when available window is 0.
        It should clear the flow_event and wait.
        """
        # Setup Mocks
        conn = MagicMock()
        writer = AsyncMock()
        queue = asyncio.Queue()
        h2_lock = asyncio.Lock()
        socket_lock = asyncio.Lock()
        flow_event = asyncio.Event()
        
        # Start event as Set (Open), typical state
        flow_event.set()
        
        # Scenario: Window is 0
        conn.outbound_flow_control_window = 0
        conn.remote_flow_control_window.return_value = 0
        conn.data_to_send.return_value = None
        
        # Enqueue one item with data
        payload = b"A" * 10
        await queue.put((payload, True, 0))
        # Enqueue None to terminate the loop eventually
        await queue.put(None)
        
        # Instantiate Handler (mocking init to avoid overhead)
        handler = NativeProxyHandler(None, None, "", None, None, None)
        handler.closed = asyncio.Event()
        
        # Run _stream_sender in a task
        task = asyncio.create_task(
            handler._stream_sender(
                1, conn, writer, queue, flow_event, h2_lock, socket_lock,
                None, None, None, None
            )
        )
        
        # Wait a short duration. 
        # If buggy, it spins 100% CPU and flow_event remains SET.
        # If fixed, it clears flow_event and enters await.
        await asyncio.sleep(0.1)
        
        # ASSERTION 1: Verify event was cleared (entered stall state)
        self.assertFalse(flow_event.is_set(), "Flow event should be cleared when window is 0")
        
        # Now simulate Window Update
        conn.outbound_flow_control_window = 100
        conn.remote_flow_control_window.return_value = 100
        flow_event.set()
        
        # Wait for task to finish (it should send data and exit on None)
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            self.fail("Task hung (infinite loop or didn't wake up)")
            
        # ASSERTION 2: Verify Send called
        conn.send_data.assert_called()

if __name__ == "__main__":
    unittest.main()