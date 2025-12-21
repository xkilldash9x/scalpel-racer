# tests/test_fixes_verification.py
import unittest
import threading
import time
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import sys

# Mock netfilterqueue before importing packet_controller
sys.modules['netfilterqueue'] = MagicMock()
from packet_controller import PacketController

class TestPacketControllerFix(unittest.TestCase):
    def test_lifecycle_loop_fix_verified(self):
        """
        Verifies that _delayed_release correctly loops to handle multiple sequences.
        """
        with patch('subprocess.call'):
            pc = PacketController("127.0.0.1", 80, 55555)
            # Mock NFQ
            pc.nfqueue = MagicMock()
        
        pc.active = True
        
        # Start the thread
        t = threading.Thread(target=pc._delayed_release, daemon=True)
        t.start()
        
        # --- Sequence 1 ---
        pkt1 = MagicMock()
        with pc.lock:
            pc.first_packet_info = (10, pkt1)
            pc.first_packet_held.set()
        
        # Trigger release
        pc.subsequent_packets_released.set()
        time.sleep(0.2)
        pkt1.accept.assert_called_once()
        
        # Verify state reset
        self.assertFalse(pc.first_packet_held.is_set())
        
        # --- Sequence 2 (The fix verification) ---
        pkt2 = MagicMock()
        with pc.lock:
            pc.first_packet_info = (20, pkt2)
            pc.first_packet_held.set()
            
        pc.subsequent_packets_released.set()
        time.sleep(0.2)
        pkt2.accept.assert_called_once()
        
        pc.active = False
        pc.first_packet_held.set() # Wake thread
        t.join(1.0)

# --- Proxy Core Verification ---
from proxy_core import Http11ProxyHandler, NativeProxyHandler

class TestProxyFixes(unittest.IsolatedAsyncioTestCase):
    async def test_h1_extensions(self):
        """Verifies H1 chunk streaming implementation."""
        handler = Http11ProxyHandler(AsyncMock(), MagicMock(), "", None, None, None)
        # Verify _read_bytes_raw exists and works
        await handler._read_bytes_raw(10)
        
        # Verify _stream_chunked_body exists
        handler._read_strict_line = AsyncMock(side_effect=[b"0", b""])
        await handler._stream_chunked_body(MagicMock())

    async def test_h2_extensions(self):
        """Verifies H2 stream processing refactor."""
        handler = NativeProxyHandler(AsyncMock(), MagicMock(), "", None, None, None)
        event = MagicMock()
        event.stream_id = 1
        event.headers = []
        
        with patch.object(handler, '_process_headers_for_capture'), \
             patch.object(handler, '_prepare_forwarded_headers', return_value=([], None)):
             # Verify _process_stream_request exists
             await handler._process_stream_request(event)

if __name__ == '__main__':
    unittest.main()