# tests/test_packet_controller.py
import pytest
import time
from unittest.mock import MagicMock, patch, call
import subprocess
import threading
from packet_controller import PacketController

class TestPacketController:
    
    @patch("packet_controller.subprocess.check_call")
    def test_iptables_interaction(self, mock_run):
        """Test that iptables rules are checked before appending/deleting."""
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            # Sequence: 
            # 1. Check if rule exists (Failure -> Rule doesn't exist)
            # 2. Append rule (Success)
            mock_run.side_effect = [subprocess.CalledProcessError(1, "cmd"), None, None, None]
            
            pc = PacketController("1.2.3.4", 80, 1000)
            pc._manage_iptables("A")
            
            # Verify Append called
            args = mock_run.call_args_list[1][0][0]
            assert "iptables" in args
            assert "-A" in args
            assert "NFQUEUE" in args

    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.check_call")
    def test_start_sequence(self, mock_run, mock_nfq):
        """Test binding to the queue and starting threads."""
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            pc = PacketController("1.2.3.4", 80, 1000)
            
            # Mock subprocess to pass rule checks
            mock_run.return_value = None

            # CRITICAL FIX: Make nfqueue.run block briefly so the thread stays alive
            # Otherwise the thread exits immediately and is_alive() returns False
            mock_nfq_instance = mock_nfq.return_value
            mock_nfq_instance.run.side_effect = lambda: time.sleep(0.5)
            
            pc.start()
            
            assert pc.active is True
            mock_nfq.return_value.bind.assert_called_with(99, pc._queue_callback)
            
            # Threads should now be alive because run() is blocking
            assert pc.listener_thread.is_alive()
            assert pc.release_thread.is_alive()
            
            pc.stop()

    def test_queue_callback_logic(self):
        """
        Tests the core First-Sequence Sync logic:
        1. Hold first packet.
        2. Let subsequent packets pass (Sync).
        3. Release first packet.
        """
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            pc = PacketController("1.2.3.4", 80, 1000)
            pc.active = True
            
            # Setup Mock Packets
            mock_pkt1 = MagicMock()
            mock_pkt1.get_payload.return_value = b"dummy"
            
            with patch("packet_controller.IP") as MockIP, \
                 patch("packet_controller.TCP") as MockTCP:
                
                # Mock IP/TCP Structure
                ip_layer = MagicMock()
                tcp_layer = MagicMock()
                MockIP.return_value = ip_layer
                ip_layer.__contains__.return_value = True
                ip_layer.__getitem__.return_value = tcp_layer
                
                # -- PACKET 1 (First Packet) --
                tcp_layer.seq = 100
                tcp_layer.payload = b"A" * 10 # len 10
                
                pc._queue_callback(mock_pkt1)
                
                # Assert Held
                assert pc.first_packet_info is not None
                mock_pkt1.accept.assert_not_called()
                assert pc.expected_next_seq == 110 # 100 + 10
                assert pc.first_packet_held.is_set()
                
                # -- PACKET 2 (Subsequent Packet) --
                tcp_layer.seq = 110 # Matches expected
                mock_pkt2 = MagicMock()
                
                pc._queue_callback(mock_pkt2)
                
                # Assert Accepted Immediately
                mock_pkt2.accept.assert_called_once()
                assert pc.subsequent_packets_released.is_set()

    def test_delayed_release_logic(self):
        """Test the thread that waits for sync before releasing packet 1."""
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            pc = PacketController("1.2.3.4", 80, 1000)
            pc.active = True
            
            # Mock Events
            pc.first_packet_held.wait = MagicMock(return_value=True)
            pc.subsequent_packets_released.wait = MagicMock(return_value=True)
            
            # Mock Packet
            mock_pkt = MagicMock()
            pc.first_packet_info = (100, mock_pkt)
            
            with patch("time.sleep") as mock_sleep:
                pc._delayed_release_first_packet()
                
                # Should sleep for reorder delay
                mock_sleep.assert_called_with(0.010)
                # Should accept packet
                mock_pkt.accept.assert_called_once()
                # Should clear state
                assert pc.first_packet_info is None

    @patch("packet_controller.subprocess.check_call")
    def test_stop_cleanup(self, mock_run):
        """Ensure stop() unbinds queue and removes firewall rules."""
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            pc = PacketController("1.2.3.4", 80, 1000)
            pc.active = True
            pc.nfqueue = MagicMock()
            pc.listener_thread = MagicMock()
            pc.release_thread = MagicMock()
            
            pc.stop()
            
            assert pc.active is False
            pc.nfqueue.unbind.assert_called()
            # Check iptables delete rule called
            args = mock_run.call_args_list[-1][0][0]
            assert "-D" in args