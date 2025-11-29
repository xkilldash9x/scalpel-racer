import pytest
from unittest.mock import MagicMock, patch, ANY
import threading
import time
import sys
import platform

# We need to ensure scalpel_racer is imported so we can patch it
import scalpel_racer

# Mock NetfilterQueue if not available, primarily for CI environments or non-Linux systems
# This ensures tests can run even if the library isn't installed or the OS isn't supported.
try:
    import netfilterqueue
except ImportError:
    # Create a mock module and class
    MockNFQ = MagicMock()
    sys.modules['netfilterqueue'] = MockNFQ

# --- Tests ---

# We patch the imported class/module in the target module's namespace
@patch("scalpel_racer.NetfilterQueue", create=True)
@patch("os.system")
# Ensure the SUT thinks NFQUEUE is available
@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
def test_packet_controller_lifecycle(mock_system, MockNetfilterQueue):
    # Re-import or ensure the class is available
    from scalpel_racer import PacketController

    # Handle the case where the mock might be assigned if the import failed in scalpel_racer.py
    if MockNetfilterQueue is None:
        pytest.skip("NetfilterQueue mock is None, likely due to import failure handling in source.")

    controller = PacketController(target_ip="1.2.3.4", target_port=443)

    # Test setup
    controller.setup_iptables()
    mock_system.assert_called_with(ANY)
    args, _ = mock_system.call_args
    assert "iptables -A OUTPUT" in args[0]
    assert "1.2.3.4" in args[0]

    # Test start
    controller.start()
    # Check if bind was called on the instance of the mock
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
    if MockNetfilterQueue is None:
        pytest.skip("NetfilterQueue mock is None.")
        
    controller = PacketController("1.2.3.4", 443)
    mock_packet = MagicMock()

    controller.process_packet(mock_packet)

    mock_packet.accept.assert_called_once()
    assert controller.first_packet is None

@patch("scalpel_racer.NetfilterQueue", create=True)
@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
def test_packet_controller_process_packet_armed_logic(MockNetfilterQueue):
    from scalpel_racer import PacketController
    if MockNetfilterQueue is None:
        pytest.skip("NetfilterQueue mock is None.")

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

@patch("scalpel_racer.NFQUEUE_AVAILABLE", False)
def test_packet_controller_init_unavailable():
     from scalpel_racer import PacketController
     with pytest.raises(RuntimeError, match="NetfilterQueue is not available"):
         PacketController("1.2.3.4", 443)