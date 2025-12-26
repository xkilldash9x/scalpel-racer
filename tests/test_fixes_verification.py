# tests/test_fixes_verification.py
"""
Verification tests for bug fixes and regressions.
"""
import unittest
import threading
import time
import sys
from unittest.mock import MagicMock, patch, AsyncMock

# Mock netfilterqueue before importing packet_controller
sys.modules['netfilterqueue'] = MagicMock()

# pylint: disable=wrong-import-position
from packet_controller import PacketController
from proxy_core import Http11ProxyHandler
from proxy_h2 import NativeProxyHandler
# pylint: enable=wrong-import-position

class TestPacketControllerFix(unittest.TestCase):
    """Tests for PacketController fixes."""
    def test_lifecycle_loop_fix_verified(self):
        """
        Verifies that _delayed_release correctly loops to handle multiple sequences.
        """
        with patch('packet_controller.subprocess.run'):
            pc = PacketController("127.0.0.1", 80, 55555)
            # Mock NFQ
            pc.nfqueue = MagicMock()

        pc.active = True

        # Start the thread
        # pylint: disable=protected-access
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
        # pylint: enable=protected-access

class TestProxyFixes(unittest.IsolatedAsyncioTestCase):
    """Tests for Proxy Core and H2 fixes."""
    async def test_h1_extensions(self):
        """Verifies H1 chunk streaming implementation."""
        handler = Http11ProxyHandler(AsyncMock(), MagicMock(), "", None, None, None)

        # [FIX] Use _read_bytes instead of _read_bytes_raw
        # Also need to mock buffer behavior to avoid "Incomplete read" error
        # We need _read_bytes to succeed reading 10 bytes.
        # pylint: disable=protected-access
        handler.reader.read.return_value = b"1234567890"
        await handler._read_bytes(10)

        # Verify _read_strict_line exists (used by chunked body)
        # Mocking it to simulate "0\r\n" (chunk size 0) followed by "\r\n" (trailers end)
        # Patching on class because of __slots__
        with patch.object(Http11ProxyHandler, '_read_strict_line', side_effect=[b"0", b""]):
            await handler._read_chunked_body()
        # pylint: enable=protected-access

    async def test_h2_extensions(self):
        """Verifies H2 stream processing refactor."""
        handler = NativeProxyHandler(AsyncMock(), MagicMock(), "", None, None, None)

        # [FIX] Check for the existence of the NEW method handles
        # Instead of _process_headers_for_capture (which is now in proxy_common),
        # we check if handle_request_received exists and can be called.

        event = MagicMock()
        event.stream_id = 1
        event.headers = []
        event.stream_ended = True

        # Mock the dependencies that handle_request_received calls
        # We patch where it is used: proxy_h2 imports it from proxy_common
        # Patching on class because of __slots__
        # Also patch _ensure_upstream_connected to prevent network calls
        with patch('proxy_h2.process_h2_headers_for_capture') as mock_process, \
             patch.object(NativeProxyHandler, '_prepare_forwarded_headers',
                          return_value=([], None)), \
             patch.object(NativeProxyHandler, '_ensure_upstream_connected',
                          new_callable=AsyncMock), \
             patch.object(NativeProxyHandler, 'flush', new_callable=AsyncMock):

            mock_process.return_value = {"pseudo": {}, "headers": []}

            # This confirms the method exists and runs without AttributeError
            await handler.handle_request_received(event)

if __name__ == '__main__':
    unittest.main()
