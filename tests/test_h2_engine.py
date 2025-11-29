import pytest
from unittest.mock import MagicMock, patch, ANY
import socket
import ssl
from scalpel_racer import HTTP2RaceEngine, CapturedRequest, ScanResult

# Mock the h2 library if not available
try:
    import h2.events
    import h2.connection
    import h2.config
except ImportError:
    import sys
    sys.modules['h2'] = MagicMock()
    sys.modules['h2.connection'] = MagicMock()
    sys.modules['h2.events'] = MagicMock()
    sys.modules['h2.config'] = MagicMock()
    sys.modules['h2.errors'] = MagicMock()


# --- Mocks ---

@pytest.fixture
def mock_request():
    return CapturedRequest(
        id=1,
        method="POST",
        url="https://example.com/api/test",
        headers={"Content-Type": "application/json", "User-Agent": "Test"},
        body=b'{"key": "value"}'
    )

@pytest.fixture
def mock_h2_connection():
    # Patch the H2Connection class used in scalpel_racer
    with patch("scalpel_racer.h2.connection.H2Connection") as MockH2Conn:
        conn_instance = MockH2Conn.return_value
        # HTTP/2 stream IDs start at 1 and increment by 2
        conn_instance.get_next_available_stream_id.side_effect = range(1, 100, 2)
        conn_instance.data_to_send.return_value = b"MOCK_H2_DATA"
        yield conn_instance

@pytest.fixture
def mock_socket():
    # Patch socket creation
    with patch("socket.create_connection") as mock_create_conn:
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        yield mock_sock

@pytest.fixture
def mock_ssl_context():
    # Patch SSL context creation and wrapping
    with patch("ssl.create_default_context") as mock_ctx_cls:
        mock_ctx = mock_ctx_cls.return_value
        mock_wrap_socket = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_wrap_socket
        # Simulate successful HTTP/2 negotiation
        mock_wrap_socket.selected_alpn_protocol.return_value = "h2"
        yield mock_ctx, mock_wrap_socket

# --- Tests ---

def test_h2_engine_initialization(mock_request):
    engine = HTTP2RaceEngine(mock_request, concurrency=5, strategy="spa", warmup_ms=100)
    assert engine.concurrency == 5
    assert engine.strategy == "spa"
    assert engine.warmup_ms == 100
    assert engine.target_host == "example.com"
    assert engine.target_port == 443

@patch("scalpel_racer.H2_AVAILABLE", True)
def test_h2_engine_create_connection(mock_request, mock_socket, mock_ssl_context, mock_h2_connection):
    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="spa", warmup_ms=10)

    engine._create_connection()

    # Verify SSL setup
    mock_ctx, mock_sock = mock_ssl_context
    mock_ctx.set_alpn_protocols.assert_called_with(['h2'])
    
    # Verify H2 initialization and data sent
    mock_h2_connection.initiate_connection.assert_called_once()
    mock_sock.sendall.assert_called_with(b"MOCK_H2_DATA")

@patch("scalpel_racer.H2_AVAILABLE", True)
def test_h2_engine_create_connection_alpn_failure(mock_request, mock_socket, mock_ssl_context):
    mock_ctx, mock_sock = mock_ssl_context
    mock_sock.selected_alpn_protocol.return_value = "http/1.1" # Fail ALPN

    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="spa", warmup_ms=10)

    with pytest.raises(RuntimeError, match="Server did not negotiate HTTP/2"):
        engine._create_connection()

@patch("time.sleep")
@patch("scalpel_racer.H2_AVAILABLE", True)
def test_h2_engine_run_attack_spa(mock_sleep, mock_request, mock_socket, mock_ssl_context, mock_h2_connection):
    engine = HTTP2RaceEngine(mock_request, concurrency=2, strategy="spa", warmup_ms=50)

    # Mock socket recv to simulate responses
    mock_ctx, mock_sock = mock_ssl_context

    # 1. First call returns some data (triggering events)
    # 2. Second call returns b"" (EOF) to break the loop
    mock_sock.recv.side_effect = [b"RESPONSE_DATA", b""]

    # Mock H2 events processing
    # We import the actual event classes if available for isinstance checks, otherwise use Mocks
    try:
        from h2.events import ResponseReceived, DataReceived, StreamEnded
        EventBase = object
    except ImportError:
        # Define placeholder mocks if h2 is not installed
        ResponseReceived = type('ResponseReceived', (MagicMock,), {})
        DataReceived = type('DataReceived', (MagicMock,), {})
        StreamEnded = type('StreamEnded', (MagicMock,), {})
        EventBase = MagicMock

    # Define mock event structure that mimics the real events
    class MockResponseReceived(EventBase):
        def __init__(self, stream_id, headers):
            self.stream_id = stream_id
            self.headers = headers
    
    class MockDataReceived(EventBase):
        def __init__(self, stream_id, data):
            self.stream_id = stream_id
            self.data = data

    class MockStreamEnded(EventBase):
        def __init__(self, stream_id):
            self.stream_id = stream_id

    # If h2 is installed, we must use the actual event types for isinstance checks in the SUT
    if EventBase is object:
         MockResponseReceived = ResponseReceived
         MockDataReceived = DataReceived
         MockStreamEnded = StreamEnded

    event_headers_1 = MockResponseReceived(stream_id=1, headers=[(b':status', b'200')])
    event_body_1 = MockDataReceived(stream_id=1, data=b"Response Body 1")
    event_end_1 = MockStreamEnded(stream_id=1)
    event_headers_2 = MockResponseReceived(stream_id=3, headers=[(b':status', b'200')])

    # Configure mock connection to return these events when receive_data is called
    mock_h2_connection.receive_data.return_value = [event_headers_1, event_body_1, event_end_1, event_headers_2]

    results = engine.run_attack()

    # Verification
    assert len(results) == 2
    assert results[0].status_code == 200
    assert "Response Body 1" in results[0].body_snippet

    # Verify H2 interactions (Headers -> Partial Body -> Trigger)
    assert mock_h2_connection.send_headers.call_count == 2
    # 2 streams * (1 partial + 1 trigger) = 4 data sends
    assert mock_h2_connection.send_data.call_count == 4
    
    # Verify warmup sleep
    mock_sleep.assert_called_with(0.05)

@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
@patch("scalpel_racer.H2_AVAILABLE", True)
@patch("scalpel_racer.sys.platform", "linux")
@patch("scalpel_racer.PacketController")
@patch("socket.gethostbyname")
def test_h2_engine_run_attack_first_seq(mock_gethostbyname, MockPacketController, mock_request, mock_socket, mock_ssl_context, mock_h2_connection):
    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="first-seq", warmup_ms=0)
    mock_gethostbyname.return_value = "1.2.3.4"

    mock_controller = MockPacketController.return_value

    # Mock socket recv
    mock_ctx, mock_sock = mock_ssl_context
    mock_sock.recv.return_value = b"" # Immediate EOF for simplicity

    engine.run_attack()

    # Verify PacketController usage lifecycle
    mock_controller.setup_iptables.assert_called_once()
    mock_controller.start.assert_called_once()
    mock_controller.arm.assert_called_once()
    mock_controller.release_first_packet.assert_called_once()
    mock_controller.stop.assert_called_once()
    mock_controller.teardown_iptables.assert_called_once()

@patch("scalpel_racer.NFQUEUE_AVAILABLE", False)
@patch("scalpel_racer.H2_AVAILABLE", True)
def test_h2_engine_run_attack_first_seq_unavailable(mock_request):
    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="first-seq", warmup_ms=0)
    with pytest.raises(RuntimeError, match="First-Seq strategy requires Linux and NetfilterQueue"):
        engine.run_attack()