# tests/test_packet_controller.py
"""
Tests for the PacketController module.
"""
import struct
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from packet_controller import PacketController, QUEUE_NUM, REORDER_DELAY

class TestPacketController:
    """Tests for packet interception and reordering logic."""

    @pytest.fixture
    def pc(self):
        # Force NFQUEUE_AVAILABLE to True to test logic on non-Linux systems if needed
        with patch("packet_controller.NFQUEUE_AVAILABLE", True):
            return PacketController("1.2.3.4", 80, 1000)

    @patch("packet_controller.subprocess.run")
    def test_nftables_add_sequence(self, mock_run, pc):
        """Validates that start() executes the correct sequence of 'nft' commands."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        with patch("packet_controller.NetfilterQueue"):
            pc.start()

        assert mock_run.call_count >= 3

        # 1. Create Table
        cmd_table = mock_run.call_args_list[0][0][0]
        assert "add" in cmd_table and "table" in cmd_table and "scalpel_racer_ctx" in cmd_table

        # 2. Create Chain
        cmd_chain = mock_run.call_args_list[1][0][0]
        assert "chain" in cmd_chain and "output_hook" in cmd_chain

        # 3. Add Rule
        cmd_rule = mock_run.call_args_list[2][0][0]
        assert "rule" in cmd_rule and "queue" in cmd_rule and str(QUEUE_NUM) in cmd_rule

    @patch("packet_controller.subprocess.run")
    def test_nftables_cleanup_sequence(self, mock_run, pc):
        """Verifies that stop() cleans up the nftables configuration atomically."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        pc.active = True
        pc.listener_thread = MagicMock()
        pc.release_thread = MagicMock()
        pc.nfqueue = MagicMock()

        pc.stop()

        # Verify table deletion
        delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
        assert len(delete_calls) > 0

        args = delete_calls[0][0][0]
        assert "delete" in args and "table" in args and "scalpel_racer_ctx" in args

    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.run")
    def test_start_bind_failure_cleanup(self, mock_run, mock_nfq, pc):
        """If NFQueue binding fails, we must rollback nftables rules immediately."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        mock_nfq.return_value.bind.side_effect = OSError("Permission denied")

        # The controller now catches OSError and logs it instead of raising.
        pc.start()

        # Verify rollback attempt
        delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
        assert len(delete_calls) > 0

    def _build_raw_packet(self, seq, payload_len, proto=6):
        """Helper to build raw IPv4+TCP byte strings for payload analysis."""
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
            # pylint: disable=protected-access
            pc._queue_callback(pkt)
            # pylint: enable=protected-access
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
        pc.first_packet_held.wait = MagicMock(return_value=True)
        pc.subsequent_packets_released.wait = MagicMock(return_value=True) # Sync happened

        # Let's use a side effect on subsequent_packets_released.wait to stop the loop
        def side_effect_stop(*args, **kwargs):
            pc.active = False
            return True

        pc.subsequent_packets_released.wait = MagicMock(side_effect=side_effect_stop)

        with patch("time.sleep") as mock_sleep:
            # pylint: disable=protected-access
            pc._delayed_release()
            # pylint: enable=protected-access

            mock_sleep.assert_called_with(REORDER_DELAY)
            mock_pkt.accept.assert_called_once()
            assert pc.first_packet_info is None

    def test_delayed_release_timeout(self, pc):
        """Test the timeout case for delayed release."""
        pc.active = True
        mock_pkt = MagicMock()
        pc.first_packet_info = (100, mock_pkt)

        pc.first_packet_held.wait = MagicMock(return_value=True)

        # Timeout on subsequent packet
        def side_effect_timeout(*args, **kwargs):
            pc.active = False
            return False # Timeout

        pc.subsequent_packets_released.wait = MagicMock(side_effect=side_effect_timeout)

        with patch("time.sleep") as mock_sleep:
            # pylint: disable=protected-access
            pc._delayed_release()
            # pylint: enable=protected-access

            # Should NOT sleep if timed out
            mock_sleep.assert_not_called()
            # But MUST accept the packet (fail open)
            mock_pkt.accept.assert_called_once()
            assert pc.first_packet_info is None

    def test_thread_lifecycle_integration(self, pc):
        """Ensure threads start and stop correctly via start()/stop()."""
        with patch("packet_controller.subprocess.run",
                   return_value=subprocess.CompletedProcess(args=[], returncode=0)), \
             patch("packet_controller.NetfilterQueue"):

            pc.start()
            assert pc.listener_thread.is_alive()
            assert pc.release_thread.is_alive()

            pc.stop()
            assert not pc.listener_thread.is_alive()
            assert pc.active is False

    def test_packet_controller_integration(self, pc):
        """Full integration simulation of the packet controller flow."""
        with patch("packet_controller.subprocess.run",
                   return_value=subprocess.CompletedProcess(args=[], returncode=0)) as mock_run:
            with patch("packet_controller.NetfilterQueue"):
                pc.start()

                # Verify nftables add calls
                add_calls = [c for c in mock_run.call_args_list if "add" in c[0][0]]
                assert len(add_calls) >= 3

                # Verify NFQueue bind
                assert pc.nfqueue.bind.called

                # Simulate packet flow
                mock_pkt = MagicMock()
                mock_pkt.get_payload.return_value = self._build_raw_packet(100, 10)
                # pylint: disable=protected-access
                pc._queue_callback(mock_pkt)
                # pylint: enable=protected-access

                assert pc.first_packet_held.is_set()

                # Trigger release logic manually to simulate thread action
                pc.subsequent_packets_released.wait = MagicMock(return_value=True)
                with patch("time.sleep") as mock_sleep:
                    # pylint: disable=protected-access
                    pc._delayed_release()
                    # pylint: enable=protected-access
                    mock_sleep.assert_called_with(REORDER_DELAY)
                    mock_pkt.accept.assert_called_once()

                pc.stop()

                # Verify nftables delete calls
                delete_calls = [c for c in mock_run.call_args_list if "delete" in c[0][0]]
                assert len(delete_calls) > 0

                # Verify NFQueue unbind
                assert pc.nfqueue.unbind.called