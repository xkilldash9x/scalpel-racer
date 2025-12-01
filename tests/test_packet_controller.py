import pytest
from unittest.mock import MagicMock, patch, ANY
import threading
import time
import sys
import subprocess
import platform

# --- Mocking Dependencies ---

# Mock NetfilterQueue and Scapy as they require specific OS/libs/privileges.
# Define mock classes/modules
MockNFQ = MagicMock()
MockScapy = MagicMock()
MockIP = MagicMock()
MockTCP = MagicMock()

# Mock the modules in sys.modules before importing the SUT
sys.modules['netfilterqueue'] = MockNFQ
# We mock the specific class constructor used in the SUT
MockNFQ.NetfilterQueue = MockNFQ
sys.modules['scapy.all'] = MockScapy
MockScapy.IP = MockIP
MockScapy.TCP = MockTCP

# We use a fixture to handle the platform patching and module reloading required for testing
# the conditional imports in packet_controller.py.
@pytest.fixture
def setup_linux_environment():
    """Fixture to simulate a Linux environment and reload the module with mocks."""
    # Patch sys.platform to 'linux' so the conditional imports in the SUT execute
    with patch("sys.platform", "linux"):
        # We need to reload the module because the imports (and NFQUEUE_AVAILABLE definition) 
        # happen at module load time.
        import importlib
        
        # CLEANUP: Ensure we are not reloading a Mock object left over from other tests
        if 'packet_controller' in sys.modules:
            if not isinstance(sys.modules['packet_controller'], type(sys)):
                 del sys.modules['packet_controller']
        
        import packet_controller
        
        # Manually ensure the module uses our mocks in case the try/except block failed silently
        packet_controller.NetfilterQueue = MockNFQ
        packet_controller.IP = MockIP
        packet_controller.TCP = MockTCP
        # Force NFQUEUE_AVAILABLE to True for testing purposes
        packet_controller.NFQUEUE_AVAILABLE = True
       
        # Reload again to ensure all definitions are updated
        importlib.reload(packet_controller)
        
        yield packet_controller

        # Clean up: Reload after test
        importlib.reload(packet_controller)


# --- Fixtures and Helpers ---

@pytest.fixture
def mock_dependencies(setup_linux_environment):
    """Fixture to reset mocks and provide access to them."""
    MockNFQ.reset_mock()
    MockScapy.reset_mock()
    MockIP.reset_mock()
    MockTCP.reset_mock()

    # Mock the NetfilterQueue instance (the return value of the constructor)
    nfq_instance = MockNFQ.return_value

    # Mock subprocess.check_call for iptables management
    with patch("subprocess.check_call") as mock_check_call:
        yield {
            "nfq_instance": nfq_instance,
            "check_call": mock_check_call,
            "IP": MockIP,
            "TCP": MockTCP,
            "module": setup_linux_environment
        }

@pytest.fixture
def controller(mock_dependencies):
    # Import the class under test from the reloaded module
    PacketController = mock_dependencies["module"].PacketController
    ctrl = PacketController(target_ip="1.2.3.4", target_port=443, source_port=12345)
    yield ctrl

# Helper to mock a packet structure (NFQ packet + Scapy layers)
def create_mock_packet(deps, seq, payload_len):
    mock_pkt = MagicMock()
    mock_tcp_segment = MagicMock()
    mock_tcp_segment.seq = seq
    mock_tcp_segment.payload = b"A" * payload_len

    mock_ip_packet = MagicMock()
    # Mocking IP(pkt.get_payload())
    deps["IP"].return_value = mock_ip_packet
    
    # Mocking ip_packet[TCP]
    mock_ip_packet.__getitem__.return_value = mock_tcp_segment
    
    # Mocking 'if TCP not in ip_packet'
    mock_ip_packet.__contains__.side_effect = lambda key: key == deps["TCP"]

    return mock_pkt

# --- Tests ---

def test_init_unavailable():
    # Test initialization when dependencies are missing (NFQUEUE_AVAILABLE is False)
    # Simulate this by patching the platform to non-linux and reloading.
    with patch("sys.platform", "darwin"):
        import importlib
        
        # Clean up potential mocks before import
        if 'packet_controller' in sys.modules:
             if not isinstance(sys.modules['packet_controller'], type(sys)):
                 del sys.modules['packet_controller']

        import packet_controller as pc_darwin
        importlib.reload(pc_darwin)
        
        assert pc_darwin.NFQUEUE_AVAILABLE is False
        with pytest.raises(ImportError, match="NetfilterQueue is not available"):
            pc_darwin.PacketController("1.2.3.4", 443, 12345)

# --- Lifecycle and System Interaction Tests ---

def test_start_stop_lifecycle(controller, mock_dependencies):
    # We patch threading.Thread methods to control execution.
    with patch("threading.Thread.start") as mock_thread_start, \
         patch("threading.Thread.join") as mock_thread_join, \
         patch("threading.Thread.is_alive", return_value=True):
        
        # Simulate -C failing (rule missing) so -A is called
        mock_dependencies["check_call"].side_effect = [
            subprocess.CalledProcessError(1, "iptables -C"), # -C fails
            None, # -A succeeds
            subprocess.CalledProcessError(1, "iptables -C"), # Stop: -C fails
            None  # Stop: -D succeeds (if logic attempts D)
        ]

        controller.start()

        assert controller.active is True
        
        # Verify -A was called (it should be the second call)
        assert mock_dependencies["check_call"].call_count >= 2
        args_add = mock_dependencies["check_call"].call_args_list[1]
        assert args_add[0][0][1] == '-A'
        
        # Reset side effect for stop() phase if needed, or rely on the list above
        
        # 2. Stop
        controller.stop()

        assert controller.active is False
        
        # Verify -D was called
        # Calls so far: -C(fail), -A(ok), -C(fail), -D(ok)
        assert mock_dependencies["check_call"].call_count >= 4
        args_del = mock_dependencies["check_call"].call_args_list[3]
        assert args_del[0][0][1] == '-D'

def test_manage_iptables_permission_error(controller, mock_dependencies):
    # Test error handling when iptables command fails
    
    # Simulate CalledProcessError with return code indicating permission issue (e.g., 4)
    mock_dependencies["check_call"].side_effect = [
        subprocess.CalledProcessError(returncode=4, cmd="iptables"),
        None # Second call for cleanup attempt (-D)
    ]

    with pytest.raises(PermissionError, match="Ensure running as root"):
        controller._manage_iptables(action='A')
    
    # Verify cleanup (-D) was attempted
    assert mock_dependencies["check_call"].call_count == 2
    assert mock_dependencies["check_call"].call_args[0][0][1] == '-D'

def test_start_bind_permission_error(controller, mock_dependencies):
    # Test error handling when binding to NFQueue fails

    # Simulate OSError during bind
    mock_dependencies["nfq_instance"].bind.side_effect = OSError("Permission denied")

    # Patch thread start/join
    with patch("threading.Thread.start"), patch("threading.Thread.join"):
        with pytest.raises(PermissionError, match="Root privileges required"):
            controller.start()

    # Verify iptables rule was cleaned up (-D) even though start failed
    mock_dependencies["check_call"].assert_called()
    assert mock_dependencies["check_call"].call_args[0][0][1] == '-D'

# --- Core Logic Tests (_queue_callback) ---

def test_queue_callback_reordering_sequence(controller, mock_dependencies):
    # Test the interception and reordering logic
    controller.active = True

    # 1. First packet (Seq 1000, Len 100)
    pkt1 = create_mock_packet(mock_dependencies, seq=1000, payload_len=100)
    controller._queue_callback(pkt1)

    # Verify: Held, not accepted, state updated
    pkt1.accept.assert_not_called()
    assert controller.first_packet_info == (1000, pkt1)
    assert controller.expected_next_seq == 1100
    assert controller.first_packet_held.is_set()

    # 2. Second packet (Seq 1100, Len 50)
    pkt2 = create_mock_packet(mock_dependencies, seq=1100, payload_len=50)
    controller._queue_callback(pkt2)

    # Verify: Accepted immediately, state updated
    pkt2.accept.assert_called_once()
    assert controller.expected_next_seq == 1150
    assert controller.subsequent_packets_released.is_set()

def test_queue_callback_non_data_packet(controller, mock_dependencies):
    # Test that packets without payload (e.g., ACKs) are ignored
    controller.active = True
    pkt = create_mock_packet(mock_dependencies, seq=1000, payload_len=0)
    controller._queue_callback(pkt)
    
    pkt.accept.assert_called_once()
    assert controller.first_packet_info is None

def test_queue_callback_unexpected_sequence(controller, mock_dependencies):
    # Test handling of out-of-order packets
    controller.active = True
    
    # Hold first packet
    pkt1 = create_mock_packet(mock_dependencies, seq=1000, payload_len=100)
    controller._queue_callback(pkt1)

    # Receive packet with unexpected sequence
    pkt_unexpected = create_mock_packet(mock_dependencies, seq=1500, payload_len=50)
    controller._queue_callback(pkt_unexpected)

    # Verify: Accepted immediately, state remains unchanged
    pkt_unexpected.accept.assert_called_once()
    assert controller.expected_next_seq == 1100

# --- Release Logic Tests (_delayed_release_first_packet) ---
# We test these by calling the method directly and mocking synchronization primitives (Event.wait)

@patch("time.sleep")
def test_delayed_release_reorder_scenario(mock_sleep, controller, mock_dependencies):
    # Test the standard reordering scenario
    controller.active = True
    pkt1 = MagicMock()
    controller.first_packet_info = (1000, pkt1)
    REORDER_DELAY = mock_dependencies["module"].REORDER_DELAY

    # We patch threading.Event.wait to simulate the synchronization instantly.
    # 1. first_packet_held.wait() -> returns True
    # 2. subsequent_packets_released.wait() -> returns True
    with patch.object(threading.Event, 'wait', return_value=True):
        # Run the method directly.
        controller._delayed_release_first_packet()

    # Verify the reorder delay was applied (because wait returned True for subsequent packets)
    mock_sleep.assert_called_with(REORDER_DELAY)
    
    # The packet should be released
    pkt1.accept.assert_called_once()
    assert controller.first_packet_info is None

@patch("time.sleep")
def test_delayed_release_small_payload_timeout(mock_sleep, controller):
    # Test the case where the entire payload fits in one packet (timeout scenario)
    
    controller.active = True
    pkt1 = MagicMock()
    controller.first_packet_info = (1000, pkt1)
    
    # We patch threading.Event.wait to simulate the synchronization instantly.
    # 1. first_packet_held.wait() -> returns True (packet arrived)
    # 2. subsequent_packets_released.wait() -> returns False (timeout occurred)
    with patch.object(threading.Event, 'wait', side_effect=[True, False]) as mock_wait:
        # Run the method directly.
        controller._delayed_release_first_packet()

        # Verify the waits occurred with correct timeouts
        mock_wait.assert_any_call(timeout=5)
        mock_wait.assert_any_call(timeout=0.5)

    # Verify: Sleep (REORDER_DELAY) was NOT called (because wait returned False)
    mock_sleep.assert_not_called()
    
    # Verify packet was accepted
    pkt1.accept.assert_called_once()