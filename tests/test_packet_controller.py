import pytest
from unittest.mock import MagicMock, patch, ANY
import threading
import time
import sys
import subprocess
import platform

MockNFQ = MagicMock()
MockScapy = MagicMock()
MockIP = MagicMock()
MockTCP = MagicMock()

sys.modules['netfilterqueue'] = MockNFQ
MockNFQ.NetfilterQueue = MockNFQ
sys.modules['scapy.all'] = MockScapy
MockScapy.IP = MockIP
MockScapy.TCP = MockTCP

@pytest.fixture
def setup_linux_environment():
    with patch("sys.platform", "linux"):
        import importlib
        
        if 'packet_controller' in sys.modules:
             if not isinstance(sys.modules['packet_controller'], type(sys)):
                 del sys.modules['packet_controller']
        
        import packet_controller
        
        packet_controller.NetfilterQueue = MockNFQ
        packet_controller.IP = MockIP
        packet_controller.TCP = MockTCP
        packet_controller.NFQUEUE_AVAILABLE = True
       
        importlib.reload(packet_controller)
        
        yield packet_controller

        importlib.reload(packet_controller)


@pytest.fixture
def mock_dependencies(setup_linux_environment):
    MockNFQ.reset_mock()
    MockScapy.reset_mock()
    MockIP.reset_mock()
    MockTCP.reset_mock()

    nfq_instance = MockNFQ.return_value

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
    PacketController = mock_dependencies["module"].PacketController
    ctrl = PacketController(target_ip="1.2.3.4", target_port=443, source_port=12345)
    yield ctrl

def create_mock_packet(deps, seq, payload_len):
    mock_pkt = MagicMock()
    mock_tcp_segment = MagicMock()
    mock_tcp_segment.seq = seq
    mock_tcp_segment.payload = b"A" * payload_len

    mock_ip_packet = MagicMock()
    deps["IP"].return_value = mock_ip_packet
    mock_ip_packet.__getitem__.return_value = mock_tcp_segment
    mock_ip_packet.__contains__.side_effect = lambda key: key == deps["TCP"]

    return mock_pkt

def test_init_unavailable():
    # [FIX] Force unload of packet_controller to ensure clean import
    if 'packet_controller' in sys.modules:
        del sys.modules['packet_controller']
    
    # [FIX] Simulate an environment where 'unittest' is NOT present to bypass the test-guard
    # and force the real ImportError logic to trigger.
    with patch.dict(sys.modules):
        if 'unittest' in sys.modules:
            del sys.modules['unittest']

        with patch("sys.platform", "darwin"):
            import packet_controller as pc_darwin
            import importlib
            importlib.reload(pc_darwin)
    
            assert pc_darwin.NFQUEUE_AVAILABLE is False
            
            with pytest.raises(ImportError, match="NetfilterQueue is not available"):
                pc_darwin.PacketController("1.2.3.4", 443, 12345)
            
    # Clean up so subsequent tests reload correctly
    if 'packet_controller' in sys.modules:
        del sys.modules['packet_controller']

def test_start_stop_lifecycle(controller, mock_dependencies):
    with patch("threading.Thread.start") as mock_thread_start, \
         patch("threading.Thread.join") as mock_thread_join, \
         patch("threading.Thread.is_alive", return_value=True):
        
        # Start: -C (fails), -A (succeeds)
        # Stop: -C (SUCCEEDS), -D (succeeds)
        mock_dependencies["check_call"].side_effect = [
            subprocess.CalledProcessError(1, "iptables -C"), 
            None, 
            None, 
            None 
        ]

        controller.start()

        assert controller.active is True
        
        assert mock_dependencies["check_call"].call_count >= 2
        args_add = mock_dependencies["check_call"].call_args_list[1]
        assert args_add[0][0][1] == '-A'
        
        controller.stop()

        assert controller.active is False
        
        assert mock_dependencies["check_call"].call_count >= 4
        args_del = mock_dependencies["check_call"].call_args_list[3]
        assert args_del[0][0][1] == '-D'

def test_manage_iptables_permission_error(controller, mock_dependencies):
    # -C check fails (expected), -A fails with permission error
    mock_dependencies["check_call"].side_effect = [
        subprocess.CalledProcessError(1, "iptables -C"), 
        subprocess.CalledProcessError(returncode=4, cmd="iptables"), 
        None 
    ]

    with pytest.raises(PermissionError, match="Ensure running as root"):
        controller._manage_iptables(action='A')
    
    assert mock_dependencies["check_call"].call_count == 2 

def test_queue_callback_reordering_sequence(controller, mock_dependencies):
    controller.active = True

    pkt1 = create_mock_packet(mock_dependencies, seq=1000, payload_len=100)
    controller._queue_callback(pkt1)

    pkt1.accept.assert_not_called()
    assert controller.first_packet_info == (1000, pkt1)
    assert controller.expected_next_seq == 1100
    assert controller.first_packet_held.is_set()

    pkt2 = create_mock_packet(mock_dependencies, seq=1100, payload_len=50)
    controller._queue_callback(pkt2)

    pkt2.accept.assert_called_once()
    assert controller.expected_next_seq == 1150
    assert controller.subsequent_packets_released.is_set()

def test_queue_callback_non_data_packet(controller, mock_dependencies):
    controller.active = True
    pkt = create_mock_packet(mock_dependencies, seq=1000, payload_len=0)
    controller._queue_callback(pkt)
    
    pkt.accept.assert_called_once()
    assert controller.first_packet_info is None

def test_queue_callback_unexpected_sequence(controller, mock_dependencies):
    controller.active = True
    
    pkt1 = create_mock_packet(mock_dependencies, seq=1000, payload_len=100)
    controller._queue_callback(pkt1)

    pkt_unexpected = create_mock_packet(mock_dependencies, seq=1500, payload_len=50)
    controller._queue_callback(pkt_unexpected)

    pkt_unexpected.accept.assert_called_once()
    assert controller.expected_next_seq == 1100

@patch("time.sleep")
def test_delayed_release_reorder_scenario(mock_sleep, controller, mock_dependencies):
    controller.active = True
    pkt1 = MagicMock()
    controller.first_packet_info = (1000, pkt1)
    REORDER_DELAY = mock_dependencies["module"].REORDER_DELAY

    with patch.object(threading.Event, 'wait', return_value=True):
        controller._delayed_release_first_packet()

    mock_sleep.assert_called_with(REORDER_DELAY)
    
    pkt1.accept.assert_called_once()
    assert controller.first_packet_info is None

@patch("time.sleep")
def test_delayed_release_small_payload_timeout(mock_sleep, controller):
    controller.active = True
    pkt1 = MagicMock()
    controller.first_packet_info = (1000, pkt1)
    
    with patch.object(threading.Event, 'wait', side_effect=[True, False]) as mock_wait:
        controller._delayed_release_first_packet()

        mock_wait.assert_any_call(timeout=5)
        mock_wait.assert_any_call(timeout=0.5)

    mock_sleep.assert_not_called()
    pkt1.accept.assert_called_once()