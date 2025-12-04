# FILE: ./tests/test_combined_fixes.py
import pytest
import sys
import os
import threading
import socket
import subprocess
from unittest.mock import patch, MagicMock, AsyncMock, ANY
import time
import select
import asyncio
import types

# --- Setup Environment for Imports ---

# Mock dependencies for packet_controller and low_level
MockNFQ = MagicMock()
MockScapy = MagicMock()
MockIP = MagicMock()
MockTCP = MagicMock()
MockScapy.IP = MockIP
MockScapy.TCP = MockTCP

# Configure sys.modules before importing the SUTs
sys.modules['netfilterqueue'] = MockNFQ
MockNFQ.NetfilterQueue = MockNFQ # Ensure the class itself is the mock
sys.modules['scapy.all'] = MockScapy

# Mock H2 for low_level tests
try:
    import h2.events
    from h2.events import StreamEnded
except ImportError:
    # Define placeholder mocks if h2 is not installed
    class ResponseReceived: pass
    class DataReceived: pass
    class StreamEnded: pass
    class StreamReset: pass
    sys.modules['h2.events'] = MagicMock(
        ResponseReceived=ResponseReceived, DataReceived=DataReceived,
        StreamEnded=StreamEnded, StreamReset=StreamReset
    )
    sys.modules['h2.connection'] = MagicMock()
    sys.modules['h2.config'] = MagicMock()

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import necessary modules after path setup
import scalpel_racer
from sync_http11 import HTTP11SyncEngine
# Import CapturedRequest robustly
try:
    from structures import CapturedRequest
except ImportError:
    from sync_http11 import CapturedRequest # Use placeholder if structures not available


# --- Test Fixtures ---

@pytest.fixture
def sync_engine():
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"A{{SYNC}}B")
    return HTTP11SyncEngine(req, concurrency=2)

@pytest.fixture
def packet_controller():
    # Setup environment for packet_controller import
    with patch("sys.platform", "linux"):
        # We must reload the module to ensure the mocks and platform patch are picked up
        import importlib
        
        # Handle potential conflicts if packet_controller was already imported
        if 'packet_controller' in sys.modules:
             # Ensure we reload the actual module object, not a mock placeholder
             if not isinstance(sys.modules['packet_controller'], type(sys)):
                 del sys.modules['packet_controller']

        import packet_controller
        
        # Ensure the module uses the mocks defined at the top of this file
        packet_controller.NFQUEUE_AVAILABLE = True
        # Ensure the specific classes are the mocked ones
        packet_controller.NetfilterQueue = MockNFQ.NetfilterQueue
        packet_controller.IP = MockIP
        packet_controller.TCP = MockTCP
        
        importlib.reload(packet_controller)

        from packet_controller import PacketController
        ctrl = PacketController("1.2.3.4", 443, 12345)
        yield ctrl
        
        # Cleanup
        importlib.reload(packet_controller)

@pytest.fixture
def h2_engine():
    # Mock dependencies required for initialization
    with patch('low_level.NFQUEUE_AVAILABLE', False), \
         patch('low_level.PacketController', None):
        from low_level import HTTP2RaceEngine
        try:
            from structures import CapturedRequest
        except ImportError:
            from low_level import CapturedRequest # Use placeholder

        req = CapturedRequest(1, "GET", "https://example.com", {}, b"")
        # Initialize the engine
        engine = HTTP2RaceEngine(req, concurrency=5) # Set concurrency=5 for B05 test
        # Mock the socket and connection objects
        engine.sock = MagicMock()
        engine.conn = MagicMock()
        return engine

# --- Helper Functions ---

def run_receive_loop_iteration(engine, select_result, io_side_effect=None):
    """Helper to run the receive loop with mocked I/O until it stops."""
    
    if io_side_effect:
        effect_iterator = iter(io_side_effect)
        def combined_effect(*args, **kwargs):
            try:
                effect = next(effect_iterator)
            except StopIteration:
                engine.all_streams_finished.set()
                return b"" # Return empty bytes on recv or None on sendall
            if isinstance(effect, Exception):
                raise effect
            return effect

        engine.sock.recv.side_effect = combined_effect
        engine.sock.sendall.side_effect = combined_effect

    with patch('select.select', return_value=select_result):
        t = threading.Thread(target=engine._receive_loop)
        t.start()
        t.join(timeout=0.5)
        if t.is_alive():
            engine.all_streams_finished.set()
            t.join(timeout=0.1)
            pytest.fail("Receive loop did not terminate.")

# --- Test Cases ---

# Test E1: Synchronization Failure Handling (sync_http11.py)
@patch('socket.create_connection')
def test_E1_broken_barrier_handling(mock_create_conn, sync_engine):
    mock_sock = MagicMock()
    mock_create_conn.return_value = mock_sock
    
    # Simulate BrokenBarrierError during wait
    sync_engine.barrier = MagicMock()
    sync_engine.barrier.wait.side_effect = threading.BrokenBarrierError()
    sync_engine.barrier.broken = False

    sync_engine._attack_thread(0)
    
    # After fix: Result recorded with specific error, raised as ConnectionError
    assert sync_engine.results[0] is not None
    assert "ConnectionError: Synchronization barrier broken." in sync_engine.results[0].error
    # Ensure abort is still called in the finally block (fail-fast)
    sync_engine.barrier.abort.assert_called()


# Test E2: Receiver Loop OSError Handling (low_level.py)
def test_E2_oserror_handling(h2_engine):
    h2_engine.streams[1] = {"finished": False, "error": None}
    
    # Simulate select indicating socket is ready, then recv raising OSError
    run_receive_loop_iteration(h2_engine, ([h2_engine.sock], [], []), io_side_effect=[OSError("IO Error")])
    
    # After fix: Catches OSError and handles closure
    assert h2_engine.streams[1]["finished"] is True
    assert "Connection error: IO Error" in h2_engine.streams[1]["error"]

# Test E3/N2: Receiver Loop sendall placement and Flow Control (low_level.py)
def test_E3_N2_sendall_placement_and_error_handling(h2_engine):
    h2_engine.conn.data_to_send.return_value = b"ACK_OR_WINDOW_UPDATE"
    h2_engine.streams[1] = {"finished": False, "error": None}

    # N2: Simulate select indicating NO read data (empty list), but data needs sending.
    # E3: Simulate sendall raising an error during this send attempt.
    
    # After fix: sendall is called even if not ready (N2), and error is caught (E3)
    run_receive_loop_iteration(h2_engine, ([], [], []), io_side_effect=[socket.error("Send failed")])
    
    # Verify sendall was attempted (N2)
    h2_engine.sock.sendall.assert_called()

    # Verify connection closed handling due to send error (E3)
    assert h2_engine.streams[1]["finished"] is True
    assert "Connection error: Send failed" in h2_engine.streams[1]["error"]

# Test B05: Premature Completion Race (low_level.py)
def test_B05_completion_check_uses_concurrency(h2_engine):
    # Dynamically import the event class used by the module under test
    from low_level import StreamEnded
    
    # Setup: Concurrency is 5, but only 1 stream initialized yet
    # h2_engine.concurrency is 5 (set in fixture)
    h2_engine.streams = {
        1: {"finished": False}
    }
    
    # FIX: Initialize with stream_id directly in the constructor.
    # The original code failed because StreamEnded() cannot be called without arguments.
    event = StreamEnded(stream_id=1)
    
    h2_engine._process_events([event])
    
    # After fix: all_streams_finished should NOT be set (1/5 finished)
    assert not h2_engine.all_streams_finished.is_set()
    
    # Simulate completion
    for i in range(2, 6):
        h2_engine.streams[i*2+1] = {"finished": True}
    h2_engine._process_events([])
    assert h2_engine.all_streams_finished.is_set()
    
    # Simulate completion
    for i in range(2, 6):
        h2_engine.streams[i*2+1] = {"finished": True}
    h2_engine._process_events([])
    assert h2_engine.all_streams_finished.is_set()
    
    # Simulate completion
    for i in range(2, 6):
        h2_engine.streams[i*2+1] = {"finished": True}
    h2_engine._process_events([])
    assert h2_engine.all_streams_finished.is_set()

# Test PC1: IPTables Idempotency and Syntax (packet_controller.py)
def test_PC1_iptables_idempotency_and_syntax(packet_controller):
    with patch('subprocess.check_call') as mock_check_call:
        # Scenario 1: Rule does not exist
        # -C fails, then -A succeeds
        mock_check_call.side_effect = [subprocess.CalledProcessError(1, 'iptables'), None]
        
        packet_controller._manage_iptables('A')
        
        # After fix: 2 calls (-C, -A)
        assert mock_check_call.call_count == 2
        
        # Verify the ACTION command syntax (PC1 Syntax Fix)
        action_call_args = mock_check_call.call_args_list[1][0][0]
        assert action_call_args[1] == '-A'
        # Crucial check: Ensure -C is NOT present in the action command (ensures copy() was used)
        assert '-C' not in action_call_args

        # Scenario 2: Rule already exists
        mock_check_call.reset_mock()
        mock_check_call.side_effect = [None] # -C succeeds
        
        packet_controller._manage_iptables('A')
        
        # After fix: 1 call (-C)
        assert mock_check_call.call_count == 1

# Test PC2: Missing iptables binary (packet_controller.py)
def test_PC2_iptables_not_found(packet_controller):
    # Simulate FileNotFoundError when calling iptables
    with patch('subprocess.check_call', side_effect=FileNotFoundError("iptables not found")):
        # After fix: Raises descriptive RuntimeError
        with pytest.raises(RuntimeError, match="iptables command not found"):
            packet_controller._manage_iptables('A')

# Test B03: Unsafe Packet Release (packet_controller.py)
@patch("time.sleep")
def test_B03_delayed_release_stops_if_inactive(mock_sleep, packet_controller):
    # Setup: Packet held, controller active
    packet_controller.active = True
    mock_pkt = MagicMock()
    packet_controller.first_packet_info = (1000, mock_pkt)
    
    # Mock waits to return immediately
    with patch.object(threading.Event, 'wait', return_value=True):
        # Simulate controller stopping just before release
        packet_controller.active = False
        packet_controller._delayed_release_first_packet()

    # After fix: pkt.accept() should NOT be called
    mock_pkt.accept.assert_not_called()

# Note: B01/P1 verification relies on the modified tests/test_b01_tls_interception.py.
# Note: P2/P3 verification relies on the structural changes (inner functions, removal of prints) and the existing tests/test_proxy_timeout.py.