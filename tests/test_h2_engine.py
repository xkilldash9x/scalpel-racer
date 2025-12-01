# tests/test_h2_engine.py

import pytest
from unittest.mock import MagicMock, patch, ANY
import socket
import ssl
import threading
import time
import hashlib
import sys
import select

# Mock the h2 library imports before importing the SUT (low_level.py).
# Attempt to use the real h2 library if installed, otherwise mock it.
try:
    import h2.connection
    import h2.config
    import h2.events
    H2_INSTALLED = True
except ImportError:
    H2_INSTALLED = False
    # Define placeholder mocks if h2 is not installed
    MockH2Connection = MagicMock()
    MockH2Config = MagicMock()
    
    # Define distinct types for events for isinstance checks in low_level.py
    class ResponseReceived: pass
    class DataReceived: pass
    class StreamEnded: pass
    class StreamReset: pass

    # Patch sys.modules so low_level.py can import them
    sys.modules['h2.connection'] = MagicMock(H2Connection=MockH2Connection)
    sys.modules['h2.config'] = MagicMock(H2Configuration=MockH2Config)
    sys.modules['h2.events'] = MagicMock(
        ResponseReceived=ResponseReceived, DataReceived=DataReceived,
        StreamEnded=StreamEnded, StreamReset=StreamReset
    )

# Mock PacketController dependency
MockPacketController = MagicMock()
# Mock the module structure expected by low_level.py
packet_controller_mock_module = MagicMock(PacketController=MockPacketController, NFQUEUE_AVAILABLE=True)
sys.modules['packet_controller'] = packet_controller_mock_module

# Define placeholder classes required by low_level.py type hints.
class CapturedRequest:
    def __init__(self, id=1, method="POST", url="https://example.com:443/api/test?q=1", headers=None, body=b'{"data":"payload"}'):
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.edited_body = None
    def get_attack_payload(self):
        return self.edited_body if self.edited_body is not None else self.body

class ScanResult:
     def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None, body_snippet: str = None, error: str = None):
        self.index = index;
        self.status_code = status_code; self.duration = duration
        self.body_hash = body_hash; self.body_snippet = body_snippet;
        self.error = error

# Ensure the SUT uses these placeholders when it tries to import from scalpel_racer
@pytest.fixture(autouse=True)
def patch_imports(monkeypatch):
    # Mock the scalpel_racer module that low_level.py attempts to import from
    mock_scalpel_racer = MagicMock()
    mock_scalpel_racer.CapturedRequest = CapturedRequest
    mock_scalpel_racer.ScanResult = ScanResult
    mock_scalpel_racer.MAX_RESPONSE_BODY_READ = 1024*1024
    
    # Temporarily modify sys.modules so low_level.py imports our mock
    with patch.dict('sys.modules', {'scalpel_racer': mock_scalpel_racer}):
        # We need to reload low_level to ensure it picks up the patched imports
        import importlib
        import low_level
        # Import the SUT here so it uses the patched environment
        from low_level import HTTP2RaceEngine
        importlib.reload(low_level)
        
        # Expose the imported class to the tests
        yield HTTP2RaceEngine
        
        importlib.reload(low_level) # Reload after test to clean up

# --- Fixtures ---

@pytest.fixture
def mock_request():
    return CapturedRequest(
        headers={"X-Custom": "Value", "Host": "ignored.com", "Content-Length": "ignored"}
    )

@pytest.fixture
def mock_dependencies():
    # Reset mocks
    if not H2_INSTALLED:
        MockH2Connection.reset_mock()
    MockPacketController.reset_mock()

    # Mock socket, SSL, and H2Connection class using patch contexts
    # NOTE: We patch 'low_level.H2Connection' instead of 'h2.connection.H2Connection'
    # because low_level.py has likely already imported it via 'from h2.connection import H2Connection'
    # so patching the source module won't affect the reference inside low_level.
    with patch('socket.create_connection') as mock_create_conn, \
         patch('socket.gethostbyname') as mock_gethostbyname, \
         patch('ssl.create_default_context') as mock_ssl_ctx_cls, \
         patch('low_level.H2Connection') as MockH2ConnCls: 

        # Setup Socket/DNS
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        mock_gethostbyname.return_value = "1.2.3.4"

        # Setup SSL
        mock_ssl_ctx = mock_ssl_ctx_cls.return_value
        mock_wrapped_sock = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_wrapped_sock
        mock_wrapped_sock.selected_alpn_protocol.return_value = "h2"

        # Setup H2 Connection Instance
        mock_h2_conn_instance = MockH2ConnCls.return_value
        mock_h2_conn_instance.data_to_send.return_value = b"MOCK_H2_FRAMES"
        # Mock state machine for close_connection check
        mock_h2_conn_instance.state_machine = MagicMock()
        mock_h2_conn_instance.state_machine.state = 'OPEN'

        yield {
            "gethostbyname": mock_gethostbyname,
            "create_connection": mock_create_conn,
            "raw_sock": mock_sock,
            "ssl_ctx": mock_ssl_ctx,
            "wrapped_sock": mock_wrapped_sock,
            "h2_conn": mock_h2_conn_instance,
            "packet_controller": MockPacketController
        }

@pytest.fixture
def engine(patch_imports, mock_request):
    # patch_imports fixture ensures HTTP2RaceEngine is the correctly imported class
    HTTP2RaceEngine = patch_imports
    # Standard engine configuration
    # Ensure PacketController mock is used by the module under test (low_level.py)
    # We patch the reference inside the low_level module context.
    with patch('low_level.PacketController', MockPacketController):
        # We also ensure NFQUEUE_AVAILABLE is True in the module context for testing
        with patch('low_level.NFQUEUE_AVAILABLE', True):
             return HTTP2RaceEngine(mock_request, concurrency=3, strategy="spa", warmup_ms=10)

# --- Tests ---

# --- Initialization and Parsing ---

def test_parse_target(engine):
    assert engine.target_host == "example.com"
    assert engine.target_port == 443

def test_parse_target_http_warning(capsys, engine):
    req = CapturedRequest(url="http://example.com/foo")
    # Retrieve class dynamically to avoid reload issues
    HTTP2RaceEngine = engine.__class__
    
    # Instantiate directly
    engine_http = HTTP2RaceEngine(req, 1)
    
    assert engine_http.target_port == 443 # Defaults to 443 for H2
    captured = capsys.readouterr()
    assert "Warning: Target scheme is HTTP" in captured.out

# --- Connection Handling ---

def test_connect_success(engine, mock_dependencies):
    engine.connect()

    # Verify DNS, TCP Connection, TCP_NODELAY
    mock_dependencies["gethostbyname"].assert_called_with("example.com")
    mock_dependencies["create_connection"].assert_called_with(("1.2.3.4", 443), timeout=10)
    mock_dependencies["raw_sock"].setsockopt.assert_called_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Verify SSL Wrapping and ALPN
    mock_dependencies["ssl_ctx"].set_alpn_protocols.assert_called_with(["h2"])

    # Verify H2 Initialization and sending preface
    mock_dependencies["h2_conn"].initiate_connection.assert_called()
    mock_dependencies["wrapped_sock"].sendall.assert_called_with(b"MOCK_H2_FRAMES")

def test_connect_alpn_failure(engine, mock_dependencies):
    # Simulate ALPN failure
    mock_dependencies["wrapped_sock"].selected_alpn_protocol.return_value = "http/1.1"

    with pytest.raises(ConnectionError, match="Server did not negotiate HTTP/2"):
        engine.connect()

    # Ensure the socket is closed
    mock_dependencies["wrapped_sock"].close.assert_called_once()

def test_connect_ssl_error(engine, mock_dependencies):
    # Simulate SSL Handshake failure
    mock_dependencies["ssl_ctx"].wrap_socket.side_effect = ssl.SSLError(1, "Handshake failed")

    with pytest.raises(ConnectionError, match="SSL Handshake failed"):
        engine.connect()

    # Ensure the raw socket is closed
    mock_dependencies["raw_sock"].close.assert_called_once()

# --- Header Construction ---

def test_construct_h2_headers(engine):
    payload_len = 100
    headers = engine._construct_h2_headers(payload_len)
    headers_dict = dict(headers)

    assert headers_dict[':method'] == "POST"
    assert headers_dict[':authority'] == "example.com"
    assert headers_dict['x-custom'] == "Value"
    assert 'host' not in headers_dict
    # Default Content-Type added as existing ones were filtered/missing
    assert headers_dict['content-type'] == 'application/x-www-form-urlencoded'

# --- Attack Phase Tests ---

def setup_connected_engine(engine, mock_dependencies):
    """Helper to put the engine into a connected state."""
    engine.connect()
    # engine.conn is already set by connect() to be mock_dependencies["h2_conn"] 
    # because of the patching in mock_dependencies fixture
    
    engine.sock = mock_dependencies["wrapped_sock"]
    # Reset mocks to focus on the next phase
    mock_dependencies["h2_conn"].reset_mock()
    mock_dependencies["wrapped_sock"].reset_mock()
    return engine

def test_prepare_requests(engine, mock_dependencies):
    engine = setup_connected_engine(engine, mock_dependencies)
    payload = engine.request.get_attack_payload()
    partial_body = payload[:-1]

    engine._prepare_requests()

    # Verify 3 streams initialized (IDs 1, 3, 5)
    assert len(engine.streams) == 3

    # Verify H2 interactions: send_headers and send_data (partial)
    assert engine.conn.send_headers.call_count == 3
    assert engine.conn.send_data.call_count == 3
    args, kwargs = engine.conn.send_data.call_args_list[0]
    assert args[1] == partial_body
    assert kwargs['end_stream'] is False

    engine.sock.sendall.assert_called_once()

def test_trigger_requests(engine, mock_dependencies):
    engine = setup_connected_engine(engine, mock_dependencies)
    engine._prepare_requests()
    engine.conn.reset_mock()
    engine.sock.reset_mock()

    payload = engine.request.get_attack_payload()
    final_byte = payload[-1:]

    engine._trigger_requests()

    # Verify start times are set
    assert engine.streams[1]["start_time"] is not None

    # Verify H2 interactions (final data frame)
    assert engine.conn.send_data.call_count == 3
    args, kwargs = engine.conn.send_data.call_args_list[0]
    assert args[1] == final_byte
    assert kwargs['end_stream'] is True

    engine.sock.sendall.assert_called_once()

# --- Response Handling Tests ---

# Helper to simulate events for testing _process_events
def create_event(EventType, **kwargs):
    # Dynamically get the event class (handles both real H2 events and mocks)
    if H2_INSTALLED:
        import h2.events
        EventClass = getattr(h2.events, EventType)
        # Real H2 events (>= 4.0.0) typically require keyword args (like stream_id)
        return EventClass(**kwargs)
    else:
        # Use the mocked classes defined at the top of the file
        EventClass = getattr(sys.modules['h2.events'], EventType)
        event = EventClass()
        for key, value in kwargs.items():
            setattr(event, key, value)
        return event


def test_process_events(engine, mock_dependencies):
    engine.conn = mock_dependencies["h2_conn"]
    # [Fix] Match concurrency to the number of streams defined in this test (2)
    engine.concurrency = 2
    # Setup initial stream state
    engine.streams = {
        1: {"index": 0, "headers": {}, "body": bytearray(), "finished": False, "error": None},
        3: {"index": 1, "headers": {}, "body": bytearray(), "finished": False, "error": None}
    }

    # Simulate events
    events = [
        create_event("ResponseReceived", stream_id=1, headers=[(b':status', b'200')]),
        create_event("DataReceived", stream_id=1, data=b"Hello", flow_controlled_length=5),
        create_event("StreamReset", stream_id=3, error_code=8),
        create_event("StreamEnded", stream_id=1)
    ]

    engine._process_events(events)

    # Verify Stream 1 (Success)
    s1 = engine.streams[1]
    assert s1["headers"][':status'] == '200'
    assert bytes(s1["body"]) == b"Hello"
    assert s1["finished"] is True
    engine.conn.acknowledge_received_data.assert_called_with(5, 1)

    # Verify Stream 3 (Reset)
    s3 = engine.streams[3]
    assert s3["finished"] is True
    assert "Stream reset" in s3["error"]

    assert engine.all_streams_finished.is_set()

# --- Receive Loop Tests (Concurrency and Socket Interaction) ---

# Helper function to test the receive loop logic by simulating socket data
def run_receive_loop_with_data(engine, data_sequence, mock_dependencies):
    mock_sock = mock_dependencies["wrapped_sock"]
    engine.sock = mock_sock
    
    # Configure mock socket to return data when recv is called
    mock_sock.recv.side_effect = data_sequence
    
    # Configure select.select to always indicate the socket is ready for reading
    with patch("select.select", return_value=([mock_sock], [], [])):
        # Run the loop in a background thread to simulate the actual execution
        thread = threading.Thread(target=engine._receive_loop)
        thread.start()
        
        # Wait for the loop to finish (signaled by all_streams_finished or EOF/Error)
        finished = engine.all_streams_finished.wait(timeout=1)
        thread.join(timeout=0.1)
        
        if not finished:
             pytest.fail("Receiver loop did not finish in time.")

def test_receive_loop_success_scenario(engine, mock_dependencies):
    # Initialize stream state
    engine.streams[1] = {"index": 0, "headers": {}, "body": bytearray(), "finished": False, "error": None}
    
    # Important: Set the engine's connection object which is used inside the loop
    engine.conn = mock_dependencies["h2_conn"]

    # Define H2 events corresponding to a successful response
    events = [
        create_event("ResponseReceived", stream_id=1, headers=[(b':status', b'200')]),
        create_event("StreamEnded", stream_id=1)
    ]
    mock_dependencies["h2_conn"].receive_data.return_value = events
    
    # Simulate receiving data, then EOF (b"")
    run_receive_loop_with_data(engine, [b"RAW_H2_FRAMES", b""], mock_dependencies)
    
    # Verify stream state update
    assert engine.streams[1]["finished"] is True
    assert engine.streams[1]["headers"][':status'] == '200'

def test_receive_loop_connection_closed_by_server(engine, mock_dependencies):
    engine.streams[1] = {"index": 0, "finished": False, "error": None, "headers": {}, "body": bytearray()}
    engine.conn = mock_dependencies["h2_conn"]

    # Simulate EOF (b"") immediately
    run_receive_loop_with_data(engine, [b""], mock_dependencies)

    # Verify stream state (handled by _handle_connection_closed)
    assert engine.streams[1]["finished"] is True
    assert "Connection closed by server." in engine.streams[1]["error"]

def test_receive_loop_socket_error(engine, mock_dependencies):
    engine.streams[1] = {"index": 0, "finished": False, "error": None, "headers": {}, "body": bytearray()}
    engine.conn = mock_dependencies["h2_conn"]

    # Simulate socket error during recv
    run_receive_loop_with_data(engine, [socket.error("Read error")], mock_dependencies)

    # Verify stream state
    assert engine.streams[1]["finished"] is True
    assert "Connection error: Read error" in engine.streams[1]["error"]

def test_receive_loop_protocol_error(engine, mock_dependencies):
    engine.streams[1] = {"index": 0, "finished": False, "error": None, "headers": {}, "body": bytearray()}
    engine.conn = mock_dependencies["h2_conn"]

    # Simulate H2 protocol error when connection.receive_data is called
    mock_dependencies["h2_conn"].receive_data.side_effect = Exception("H2 Protocol Violation")
    
    run_receive_loop_with_data(engine, [b"BAD_DATA"], mock_dependencies)

    # Verify stream state
    assert engine.streams[1]["finished"] is True
    assert "HTTP/2 Protocol Error: H2 Protocol Violation" in engine.streams[1]["error"]

# --- Finalization and Integration ---

def test_finalize_results(engine):
    start_time = time.perf_counter() - 1.0

    engine.streams = {
        1: {"index": 0, "start_time": start_time, "headers": {':status': '200'}, "body": bytearray(b"Success"), "finished": True, "error": None},
        3: {"index": 1, "start_time": start_time, "headers": {}, "body": bytearray(), "finished": False, "error": None}, # Timeout
    }

    results = engine._finalize_results()

    assert len(results) == 2
    r0 = results[0]
    assert r0.status_code == 200
    assert r0.body_snippet == "Success"
    assert r0.duration > 950

    r1 = results[1]
    assert r1.status_code == 0
    assert r1.error == "Response timeout"

@patch('threading.Thread')
def test_run_attack_first_seq_integration(MockThread, engine, mock_dependencies):
    # Initialize engine with 'first-seq' strategy
    engine.strategy = "first-seq"

    # Mock the socket source port lookup
    mock_dependencies["wrapped_sock"].getsockname.return_value = ("127.0.0.1", 54321)

    # Simulate the attack finishing quickly
    engine.all_streams_finished.set()

    engine.run_attack()

    # Verify PacketController initialization (IP comes from DNS mock)
    MockPacketController.assert_called_with("1.2.3.4", 443, 54321)
    mock_pc_instance = MockPacketController.return_value

    # Verify PacketController lifecycle
    mock_pc_instance.start.assert_called_once()
    
    # Verify attack phases executed: 
    # run_attack -> _prepare_requests -> send_headers
    assert mock_dependencies["h2_conn"].send_headers.call_count > 0
    
    # Verify cleanup
    mock_pc_instance.stop.assert_called_once()