# tests/test_packet_controller.py
import pytest
import time
import struct
import threading
import subprocess
from unittest.mock import MagicMock, patch, call, ANY
from packet_controller import PacketController, QUEUE_NUM, REORDER_DELAY

class TestPacketController:
    
    @pytest.fixture
    def pc(self):
        """Fixture for a standard PacketController instance."""
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            return PacketController("1.2.3.4", 80, 1000)

    @patch("packet_controller.subprocess.check_call")
    def test_iptables_interaction_insert(self, mock_run, pc):
        """
        Test Idempotency & Security:
        1. Insert Rule (-I) -> Rule doesn't exist -> Execute Insert.
        2. Insert Rule (-I) -> Rule exists -> Do nothing.
        3. Verify PSH flag is REMOVED from the rule.
        """
        # Case 1: Rule missing (Check fails), should Insert
        mock_run.side_effect = [subprocess.CalledProcessError(1, "cmd"), None]
        pc._manage_iptables("I")
        
        assert mock_run.call_count == 2
        # Verify -C check
        assert "-C" in mock_run.call_args_list[0][0][0]
        
        # Verify -I action (Security: Insert at top)
        args = mock_run.call_args_list[1][0][0]
        assert "-I" in args
        assert str(QUEUE_NUM) in args
        
        # CRITICAL VERIFICATION: Ensure PSH flag is NOT in the arguments
        assert "PSH" not in args
        assert "--tcp-flags" not in args

        # Case 2: Rule exists, should NOT insert again
        mock_run.reset_mock()
        mock_run.side_effect = [None] # Check succeeds
        pc._manage_iptables("I")
        
        assert mock_run.call_count == 1
        assert "-C" in mock_run.call_args_list[0][0][0]
        # No -I call

    @patch("packet_controller.subprocess.check_call")
    def test_iptables_interaction_delete(self, mock_run, pc):
        """
        Test Idempotency:
        1. Delete Rule -> Rule exists -> Execute Delete.
        2. Delete Rule -> Rule missing -> Do nothing.
        """
        # Case 1: Rule exists, should delete
        mock_run.side_effect = [None, None]
        pc._manage_iptables("D")
        
        assert mock_run.call_count == 2
        assert "-D" in mock_run.call_args_list[1][0][0]

        # Case 2: Rule missing, should NOT delete
        mock_run.reset_mock()
        mock_run.side_effect = [subprocess.CalledProcessError(1, "cmd")]
        pc._manage_iptables("D")
        
        assert mock_run.call_count == 1
        # No -D call

    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.check_call")
    def test_start_success(self, mock_run, mock_nfq, pc):
        """Test successful start up sequence."""
        mock_run.return_value = None 
        
        mock_nfq_instance = mock_nfq.return_value
        mock_nfq_instance.run.side_effect = lambda: time.sleep(0.1)

        pc.start()

        assert pc.active is True
        assert pc.nfqueue is not None
        mock_nfq_instance.bind.assert_called_with(QUEUE_NUM, pc._queue_callback)
        
        assert pc.listener_thread.is_alive()
        assert pc.release_thread.is_alive()
        
        pc.stop()
        assert pc.active is False

    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.check_call")
    def test_start_bind_failure(self, mock_run, mock_nfq, pc):
        """
        CRITICAL: If NFQueue bind fails, we MUST remove the iptables rule
        and raise an exception.
        """
        mock_run.return_value = None
        mock_nfq.return_value.bind.side_effect = OSError("Bind failed")

        with pytest.raises(RuntimeError, match="Failed to bind NFQueue"):
            pc.start()
        
        # Verify cleanup occurred (iptables delete)
        assert mock_run.call_count >= 2
        # Ensure Delete was attempted
        assert any("-D" in call[0][0] for call in mock_run.call_args_list)

    def _build_raw_packet(self, seq, payload_len, proto=6):
        """
        Helper to build raw IPv4+TCP byte strings for testing logic without Scapy.
        """
        # IPv4 Header (20 bytes)
        # Ver(4) + IHL(5) = 0x45
        total_len = 20 + 20 + payload_len
        # Pack: ! B B H H H B B H I I
        # I (Unsigned Int) used for Source/Dest IP for simplicity (0, 0)
        ip_header = struct.pack("!BBHHHBBHII", 
                                0x45, 0, total_len, 0, 0, 
                                64, proto, 0, 0, 0)
        
        # TCP Header (20 bytes)
        # Data Offset (5 words) = 0x50
        data_offset = (5 << 4)
        # Pack: ! H H I I B B H H H
        tcp_header = struct.pack("!HHIIBBHHH", 
                                 1234, 80, seq, 0, 
                                 data_offset, 0, 0, 0, 0)
        
        payload = b'X' * payload_len
        return ip_header + tcp_header + payload

    def test_queue_callback_logic(self, pc):
        """Test the logic using raw packet construction."""
        pc.active = True
        
        def create_mock_pkt(seq, payload_len):
            pkt = MagicMock()
            pkt.get_payload.return_value = self._build_raw_packet(seq, payload_len)
            pc._queue_callback(pkt)
            return pkt

        # 1. First Packet (Seq 100, Len 10) -> SHOULD HOLD
        pkt1 = create_mock_pkt(100, 10)
        pkt1.accept.assert_not_called()
        assert pc.first_packet_info[0] == 100
        assert pc.expected_next_seq == 110
        assert pc.first_packet_held.is_set()

        # 2. Duplicate First Packet (Retransmission) -> SHOULD PASS
        pkt1_dup = create_mock_pkt(100, 10)
        pkt1_dup.accept.assert_called_once()

        # 3. Next Packet (Seq 110, Len 5) -> SHOULD PASS & TRIGGER SYNC
        pkt2 = create_mock_pkt(110, 5)
        pkt2.accept.assert_called_once()
        assert pc.expected_next_seq == 115
        assert pc.subsequent_packets_released.is_set()

        # 4. Out of Order (Seq 200) -> SHOULD PASS
        pkt3 = create_mock_pkt(200, 5)
        pkt3.accept.assert_called_once()

    def test_queue_callback_edge_cases(self, pc):
        """Test parsing robustness against malformed/irrelevant packets."""
        pc.active = True
        
        # 1. Non-IPv4 Packet (Version 6)
        pkt = MagicMock()
        # Ver=6, IHL=0, then random bytes
        pkt.get_payload.return_value = b'\x60' + b'\x00'*39 
        pc._queue_callback(pkt)
        pkt.accept.assert_called_once()

        # 2. Non-TCP Protocol (UDP = 17)
        pkt = MagicMock()
        pkt.get_payload.return_value = self._build_raw_packet(100, 10, proto=17)
        pc._queue_callback(pkt)
        pkt.accept.assert_called_once()

        # 3. Empty TCP Payload (e.g. ACK)
        pkt = MagicMock()
        pkt.get_payload.return_value = self._build_raw_packet(100, 0)
        pc._queue_callback(pkt)
        pkt.accept.assert_called_once()
        # Verify it didn't trigger logic
        assert pc.first_packet_info is None

        # 4. Truncated Packet (Too short for IP header)
        pkt = MagicMock()
        pkt.get_payload.return_value = b'\x00' * 10
        pc._queue_callback(pkt)
        pkt.accept.assert_called_once()

    def test_delayed_release_logic(self, pc):
        """Test the timing and release logic of the background thread."""
        pc.active = True
        
        # Setup fake packet
        mock_pkt = MagicMock()
        pc.first_packet_info = (100, mock_pkt)
        
        # Case 1: Timeout waiting for subsequent packets
        pc.first_packet_held.wait = MagicMock(return_value=True)
        pc.subsequent_packets_released.wait = MagicMock(return_value=False) # Timeout
        
        with patch("time.sleep") as mock_sleep:
            pc._delayed_release_first_packet()
            
            # It should NOT sleep for REORDER_DELAY if it timed out (just releases)
            mock_sleep.assert_not_called()
            mock_pkt.accept.assert_called_once()
            assert pc.first_packet_info is None

        # Case 2: Success sync
        pc.first_packet_info = (100, mock_pkt)
        mock_pkt.reset_mock()
        pc.subsequent_packets_released.wait = MagicMock(return_value=True) # Sync happen
        
        with patch("time.sleep") as mock_sleep:
            pc._delayed_release_first_packet()
            
            mock_sleep.assert_called_with(REORDER_DELAY)
            mock_pkt.accept.assert_called_once()

    @patch("packet_controller.subprocess.check_call")
    def test_stop_fail_open(self, mock_run, pc):
        """Ensure stop() releases held packets so traffic isn't lost."""
        pc.active = True
        pc.nfqueue = MagicMock()
        pc.listener_thread = MagicMock()
        pc.release_thread = MagicMock()

# Explicitly set is_alive to False to satisfy the assertion later
        pc.listener_thread.is_alive.return_value = False
        pc.release_thread.is_alive.return_value = False
        
        # Simulate a held packet
        mock_pkt = MagicMock()
        pc.first_packet_info = (100, mock_pkt)

        pc.stop()
        
        # Verify packet was accepted (Fail Open)
        mock_pkt.accept.assert_called_once()
        assert pc.first_packet_info is None
        
        # Verify iptables cleanup
        assert any("-D" in call[0][0] for call in mock_run.call_args_list)
        assert not pc.active
        assert not pc.listener_thread.is_alive()
        assert not pc.release_thread.is_alive()
