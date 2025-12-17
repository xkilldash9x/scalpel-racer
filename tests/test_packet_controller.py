################################################################################
## START OF FILE: tests/test_packet_controller.py
################################################################################
# tests/test_packet_controller.py
"""
Tests for packet_controller.py using nftables (nft).
[VECTOR] Updated to verify 'nft' command sequences and queue binding.
"""
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
        # Force availability for testing logic
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            return PacketController("1.2.3.4", 80, 1000)

    @patch("packet_controller.subprocess.call")
    def test_nftables_add_sequence(self, mock_run, pc):
        """
        Verifies that start() executes the correct sequence of 'nft' commands
        to establish the interception table, chain, and rule.
        """
        mock_run.return_value = 0
        
        with patch("packet_controller.NetfilterQueue"):
            pc.start()
        
        assert mock_run.call_count >= 3
        
        # 1. Create Table
        cmd_table = mock_run.call_args_list[0][0][0]
        assert "add" in cmd_table and "table" in cmd_table and "scalpel_racer" in cmd_table

        # 2. Create Chain
        cmd_chain = mock_run.call_args_list[1][0][0]
        assert "chain" in cmd_chain and "output_hook" in cmd_chain

        # 3. Add Rule
        cmd_rule = mock_run.call_args_list[2][0][0]
        assert "rule" in cmd_rule and "queue" in cmd_rule and str(QUEUE_NUM) in cmd_rule

    @patch("packet_controller.subprocess.call")
    def test_nftables_cleanup_sequence(self, mock_run, pc):
        """
        Verifies that stop() cleans up the nftables configuration atomically.
        """
        pc.active = True
        pc.listener_thread = MagicMock()
        pc.release_thread = MagicMock()
        pc.nfqueue = MagicMock()

        pc.stop()
        
        # Look for table deletion
        delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
        assert len(delete_calls) > 0
        args = delete_calls[0][0][0]
        assert "delete" in args and "table" in args and "scalpel_racer" in args

    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.call")
    def test_start_bind_failure_cleanup(self, mock_run, mock_nfq, pc):
        """
        If NFQueue binding fails, we must rollback nftables rules.
        """
        mock_run.return_value = 0
        mock_nfq.return_value.bind.side_effect = OSError("Permission denied")

        with pytest.raises(OSError):
            pc.start()
        
        # Verify rollback attempt
        delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
        assert len(delete_calls) > 0

    def _build_raw_packet(self, seq, payload_len, proto=6):
        """Helper to build raw IPv4+TCP byte strings."""
        total_len = 20 + 20 + payload_len
        ip_header = struct.pack("!BBHHHBBHII", 0x45, 0, total_len, 0, 0, 64, proto, 0, 0, 0)
        data_offset = (5 << 4)
        tcp_header = struct.pack("!HHIIBBHHH", 1234, 80, seq, 0, data_offset, 0, 0, 0, 0)
        payload = b'X' * payload_len
        return ip_header + tcp_header + payload

    def test_queue_callback_logic(self, pc):
        """Test the First-Seq packet holding logic."""
        pc.active = True
        
        def create_mock_pkt(seq, payload_len):
            pkt = MagicMock()
            pkt.get_payload.return_value = self._build_raw_packet(seq, payload_len)
            pc._queue_callback(pkt)
            return pkt

        # 1. First Packet -> HOLD
        pkt1 = create_mock_pkt(100, 10)
        pkt1.accept.assert_not_called()
        assert pc.first_packet_info[0] == 100
        assert pc.first_packet_held.is_set()

        # 2. Next Packet -> PASS & RELEASE
        pkt2 = create_mock_pkt(110, 5)
        pkt2.accept.assert_called_once()
        assert pc.subsequent_packets_released.is_set()

    def test_delayed_release_logic(self, pc):
        """Test the timing and release logic of the background thread."""
        pc.active = True
        mock_pkt = MagicMock()
        pc.first_packet_info = (100, mock_pkt)
        
        # Case 1: Success sync
        # Reset event mocks
        pc.first_packet_held.wait = MagicMock(return_value=True)
        pc.subsequent_packets_released.wait = MagicMock(return_value=True) # Sync happened
        
        with patch("time.sleep") as mock_sleep:
            pc._delayed_release()
            mock_sleep.assert_called_with(REORDER_DELAY)
            mock_pkt.accept.assert_called_once()
            assert pc.first_packet_info is None

        # Case 2: Sync Timeout (Fail Open behavior check)
        # Reset state
        mock_pkt.reset_mock()
        pc.first_packet_info = (100, mock_pkt)
        pc.first_packet_held.wait = MagicMock(return_value=True)
        pc.subsequent_packets_released.wait = MagicMock(return_value=False) # Timeout
        
        with patch("time.sleep") as mock_sleep:
            pc._delayed_release()
            
            # Should NOT sleep for reorder delay if we timed out waiting
            mock_sleep.assert_not_called()
            # But SHOULD accept the packet eventually to avoid dropping it
            mock_pkt.accept.assert_called_once()
            assert pc.first_packet_info is None

    def test_thread_lifecycle_integration(self, pc):
        """Ensure threads start and stop correctly via start()/stop()."""
        # We rely on integration via start() because _start_listener_thread is internal/implementation detail
        with patch("packet_controller.subprocess.call", return_value=0), \
             patch("packet_controller.NetfilterQueue"):
            
            pc.start()
            assert pc.listener_thread.is_alive()
            assert pc.release_thread.is_alive()
            
            pc.stop()
            assert not pc.listener_thread.is_alive()
            # release_thread is daemon, might stay alive briefly in test but join() is not explicitly called in stop usually
            # unless implemented. Checking active flag is safer.
            assert pc.active is False

    def test_packet_controller_integration(self, pc):
        """Test the integration of the packet controller with nftables logic."""
        with patch("packet_controller.subprocess.call", return_value=0) as mock_run:
            with patch("packet_controller.NetfilterQueue") as MockNFQ:
                pc.start()
                
                # Verify nftables add calls
                add_calls = [c for c in mock_run.call_args_list if "add" in c[0][0]]
                assert len(add_calls) >= 3
                
                # Verify NFQueue bind
                assert pc.nfqueue.bind.called
                
                # Simulate packet flow
                mock_pkt = MagicMock()
                mock_pkt.get_payload.return_value = self._build_raw_packet(100, 10)
                pc._queue_callback(mock_pkt)
                
                assert pc.first_packet_held.is_set()
                
                # Trigger release logic manually to simulate thread action
                pc.subsequent_packets_released.wait = MagicMock(return_value=True)
                with patch("time.sleep") as mock_sleep:
                    pc._delayed_release()
                    mock_sleep.assert_called_with(REORDER_DELAY)
                    mock_pkt.accept.assert_called_once()
                    
                pc.stop()
                
                # Verify nftables delete calls
                delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
                assert len(delete_calls) > 0
                
                # Verify NFQueue unbind
                assert pc.nfqueue.unbind.called