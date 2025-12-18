import pytest
import time
import struct
import threading
import subprocess
from unittest.mock import MagicMock, patch
from packet_controller import PacketController, QUEUE_NUM

class TestPacketController:
    @pytest.fixture
    def pc(self):
        with patch("packet_controller.NFQUEUE_AVAILABLE", True): return PacketController("1.2.3.4", 80, 1000)

    @patch("packet_controller.subprocess.call")
    def test_nftables_add_sequence(self, mock_run, pc):
        mock_run.return_value = 0
        with patch("packet_controller.NetfilterQueue"): pc.start()
        assert mock_run.call_count >= 3
        cmd_table = mock_run.call_args_list[0][0][0]
        assert "add" in cmd_table and "scalpel_racer_ctx" in cmd_table

    def _build_raw_packet(self, seq, payload_len):
        total_len = 20 + 20 + payload_len
        ip = struct.pack("!BBHHHBBHII", 0x45, 0, total_len, 0, 0, 64, 6, 0, 0, 0)
        tcp = struct.pack("!HHIIBBHHH", 1234, 80, seq, 0, (5 << 4), 0, 0, 0, 0)
        return ip + tcp + (b'X' * payload_len)

    def test_queue_callback_logic(self, pc):
        pc.active = True
        pkt1 = MagicMock(); pkt1.get_payload.return_value = self._build_raw_packet(100, 10)
        pc._queue_callback(pkt1)
        pkt1.accept.assert_not_called()
        assert pc.first_packet_held.is_set()

        pkt2 = MagicMock(); pkt2.get_payload.return_value = self._build_raw_packet(110, 5)
        pc._queue_callback(pkt2)
        pkt2.accept.assert_called_once()
        assert pc.subsequent_packets_released.is_set()
