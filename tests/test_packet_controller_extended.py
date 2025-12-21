# tests/test_packet_controller_extended.py
import unittest
import threading
import time
import struct
import os
import subprocess
from unittest.mock import MagicMock, patch

# Mock dependencies for test environment
import sys
sys.modules['netfilterqueue'] = MagicMock()
from packet_controller import PacketController

class TestPacketController(unittest.TestCase):
    def setUp(self):
        # Patch dependencies
        self.patch_which = patch('shutil.which', return_value='/usr/bin/nft')
        self.patch_call = patch('subprocess.call')
        self.patch_nfq = patch('packet_controller.NetfilterQueue')
        
        self.mock_which = self.patch_which.start()
        self.mock_call = self.patch_call.start()
        self.mock_nfq = self.patch_nfq.start()
        
        # Setup controller with mocked queue
        self.mock_nfq_instance = MagicMock()
        self.mock_nfq.return_value = self.mock_nfq_instance
        self.mock_nfq_instance.get_fd.return_value = 999
        
        self.controller = PacketController("127.0.0.1", 80, 55555)

    def tearDown(self):
        self.controller.stop()
        self.patch_which.stop()
        self.patch_call.stop()
        self.patch_nfq.stop()

    def create_packet(self, seq, payload_len=0, flags=0x10): 
        # Helper to create valid TCP/IP packets
        # IPv4(20) + TCP(20) + Payload
        total_len = 40 + payload_len
        # IP Header (IHL=5)
        # Fix: Protocol (Index 9) must be 6 (TCP).
        # Structure: !BBH (4 bytes) + ID(2) + Flags(2) + TTL(1) + Proto(1) + Checksum(2) + Src(4) + Dst(4)
        # Simplified construction:
        ip = struct.pack("!BBHHHBBHII", 0x45, 0, total_len, 0, 0, 64, 6, 0, 0, 0)
        
        # TCP Header (Offset 12: Data Offset=5 words, Offset 13: Flags)
        tcp = struct.pack("!HHIIBBHHH", 0, 0, seq, 0, 0x50, flags, 0, 0, 0)
        return ip + tcp + b'X'*payload_len

    def test_lifecycle_loop_fix(self):
        """Verify _delayed_release handles multiple sequential flows (Zombie Thread Fix)."""
        self.controller.active = True
        
        # Start the release thread in isolation
        t = threading.Thread(target=self.controller._delayed_release, daemon=True)
        t.start()
        
        # --- Flow 1 ---
        pkt1 = MagicMock()
        pkt1.get_payload.return_value = self.create_packet(seq=10, payload_len=10)
        
        with self.controller.lock:
            self.controller.first_packet_info = (10, pkt1)
            self.controller.first_packet_held.set()
        
        # Simulate trigger
        self.controller.subsequent_packets_released.set()
        # [FIX] Increase sleep to account for thread context switch latency
        time.sleep(0.2) 
        
        pkt1.accept.assert_called_once()
        self.assertIsNone(self.controller.first_packet_info)
        
        # --- Flow 2 (Regression Check) ---
        # If thread died after Flow 1, this will fail
        pkt2 = MagicMock()
        pkt2.get_payload.return_value = self.create_packet(seq=100, payload_len=10)
        
        with self.controller.lock:
            self.controller.first_packet_info = (100, pkt2) 
            self.controller.first_packet_held.set() 

        self.controller.subsequent_packets_released.set()
        # [FIX] Increase sleep
        time.sleep(0.2)
        
        pkt2.accept.assert_called_once()
        
        self.controller.active = False
        self.controller.first_packet_held.set() # Wake thread
        t.join(1.0)

    def test_tcp_syn_sequence_logic(self):
        """Verify tracking of initial sequence from first payload packet."""
        # [FIX] The Controller explicitly ignores packets without payload (SYNs).
        # We must test with a payload packet to trigger the logic.
        pkt_data = MagicMock()
        # Packet with 10 bytes of payload
        pkt_data.get_payload.return_value = self.create_packet(seq=1000, payload_len=10, flags=0x18)
        
        self.controller.active = True
        self.controller._queue_callback(pkt_data)
        
        # Expected next = Seq(1000) + Len(10) = 1010
        self.assertEqual(self.controller.expected_next_seq, 1010)

    def test_clean_stop(self):
        """Verify stop() handles cleanup without deadlocking."""
        self.controller.start()
        
        # Verify the controller is active and threads are running
        self.assertTrue(self.controller.active)
        self.assertTrue(self.controller.listener_thread.is_alive())
        
        # Act: Call stop
        # We don't mock os.close here because NetfilterQueue manages its 
        # own internal socket. Patching it can interfere with the environment.
        self.controller.stop()
        
        # Assert
        self.assertFalse(self.controller.active)
        # Verify nftables cleanup was called
        self.mock_call.assert_any_call(['nft', 'delete', 'table', 'ip', 'scalpel_racer_ctx'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

if __name__ == '__main__':
    unittest.main()