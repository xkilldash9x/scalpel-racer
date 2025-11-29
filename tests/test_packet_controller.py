import pytest
from unittest.mock import MagicMock, patch, ANY
import threading
import time
import sys

# We need to ensure scalpel_racer is imported so we can patch it
import scalpel_racer

# --- Tests ---

@patch("scalpel_racer.NetfilterQueue", create=True)
@patch("os.system")
@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
def test_packet_controller_lifecycle(mock_system, MockNetfilterQueue):
    # Re-import or ensure the class is available
    from scalpel_racer import PacketController

    controller = PacketController(target_ip="1.2.3.4", target_port=443)

    # Test setup
    controller.setup_iptables()
    mock_system.assert_called_with(ANY)
    args, _ = mock_system.call_args
    assert "iptables -A OUTPUT" in args[0]
    assert "1.2.3.4" in args[0]

    # Test start
    controller.start()
    MockNetfilterQueue.return_value.bind.assert_called_with(1, controller.process_packet)

    # Test teardown
    controller.teardown_iptables()
    args, _ = mock_system.call_args
    assert "iptables -D OUTPUT" in args[0]

    # Test stop
    controller.stop()
    MockNetfilterQueue.return_value.unbind.assert_called_once()

@patch("scalpel_racer.NetfilterQueue", create=True)
@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
def test_packet_controller_process_packet_not_armed(MockNetfilterQueue):
    from scalpel_racer import PacketController
    controller = PacketController("1.2.3.4", 443)
    mock_packet = MagicMock()

    controller.process_packet(mock_packet)

    mock_packet.accept.assert_called_once()
    assert controller.first_packet is None

@patch("scalpel_racer.NetfilterQueue", create=True)
@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
def test_packet_controller_process_packet_armed_logic(MockNetfilterQueue):
    from scalpel_racer import PacketController
    controller = PacketController("1.2.3.4", 443)
    controller.arm()

    assert controller.armed is True

    # 1. First packet (should be held)
    mock_pkt1 = MagicMock()
    controller.process_packet(mock_pkt1)

    mock_pkt1.accept.assert_not_called()
    assert controller.first_packet == mock_pkt1

    # 2. Second packet (should be accepted immediately)
    mock_pkt2 = MagicMock()
    controller.process_packet(mock_pkt2)

    mock_pkt2.accept.assert_called_once()
    assert controller.first_packet == mock_pkt1 # Still holding first

    # 3. Release
    controller.release_first_packet()
    mock_pkt1.accept.assert_called_once()
    assert controller.first_packet is None
    assert controller.armed is False
