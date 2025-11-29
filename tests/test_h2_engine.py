import pytest
from unittest.mock import MagicMock, patch, ANY
import socket
import ssl
from scalpel_racer import HTTP2RaceEngine, CapturedRequest, ScanResult

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
    with patch("scalpel_racer.h2.connection.H2Connection") as MockH2Conn:
        conn_instance = MockH2Conn.return_value
        conn_instance.get_next_available_stream_id.side_effect = range(1, 100, 2)
        conn_instance.data_to_send.return_value = b"MOCK_H2_DATA"
        yield conn_instance

@pytest.fixture
def mock_socket():
    with patch("socket.create_connection") as mock_create_conn:
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        yield mock_sock

@pytest.fixture
def mock_ssl_context():
    with patch("ssl.create_default_context") as mock_ctx_cls:
        mock_ctx = mock_ctx_cls.return_value
        mock_wrap_socket = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_wrap_socket
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

def test_h2_engine_create_connection(mock_request, mock_socket, mock_ssl_context, mock_h2_connection):
    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="spa", warmup_ms=10)

    engine._create_connection()

    mock_ctx, mock_sock = mock_ssl_context
    mock_ctx.set_alpn_protocols.assert_called_with(['h2'])
    mock_sock.sendall.assert_called_with(b"MOCK_H2_DATA")
    mock_h2_connection.initiate_connection.assert_called_once()

def test_h2_engine_create_connection_alpn_failure(mock_request, mock_socket, mock_ssl_context):
    mock_ctx, mock_sock = mock_ssl_context
    mock_sock.selected_alpn_protocol.return_value = "http/1.1" # Fail ALPN

    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="spa", warmup_ms=10)

    with pytest.raises(RuntimeError, match="Server did not negotiate HTTP/2"):
        engine._create_connection()

@patch("time.sleep")
def test_h2_engine_run_attack_spa(mock_sleep, mock_request, mock_socket, mock_ssl_context, mock_h2_connection):
    engine = HTTP2RaceEngine(mock_request, concurrency=2, strategy="spa", warmup_ms=50)

    # Mock socket recv to simulate responses
    mock_ctx, mock_sock = mock_ssl_context

    # We need to simulate the read loop.
    # 1. First call returns some data (triggering events)
    # 2. Second call returns None (EOF) to break the loop or we can rely on timeout logic if we mock settimeout
    mock_sock.recv.side_effect = [b"RESPONSE_DATA", b""]

    # Mock H2 events processing
    from h2.events import ResponseReceived, DataReceived, StreamEnded

    # Create Mock events instead of real ones to avoid read-only attribute issues if any
    # Or just subclass/use MagicMock
    event_headers_1 = MagicMock(spec=ResponseReceived)
    event_headers_1.stream_id = 1
    event_headers_1.headers = [(b':status', b'200')]

    event_body_1 = MagicMock(spec=DataReceived)
    event_body_1.stream_id = 1
    event_body_1.data = b"Response Body 1"

    event_end_1 = MagicMock(spec=StreamEnded)
    event_end_1.stream_id = 1

    event_headers_2 = MagicMock(spec=ResponseReceived)
    event_headers_2.stream_id = 3
    event_headers_2.headers = [(b':status', b'200')]

    # We need to make sure isinstance checks pass if the code uses them.
    # MagicMock(spec=Class) usually works for isinstance.

    # Configure mock connection to return these events when receive_data is called
    mock_h2_connection.receive_data.return_value = [event_headers_1, event_body_1, event_end_1, event_headers_2]

    results = engine.run_attack()

    # Verification
    assert len(results) == 2
    assert results[0].status_code == 200
    assert "Response Body 1" in results[0].body_snippet

    # Verify send calls (Headers -> Partial Body -> Trigger)
    assert mock_h2_connection.send_headers.call_count == 2
    assert mock_h2_connection.send_data.call_count == 4
    mock_sleep.assert_called_with(0.05)

@patch("scalpel_racer.NFQUEUE_AVAILABLE", True)
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

    # Verify PacketController usage
    mock_controller.setup_iptables.assert_called_once()
    mock_controller.start.assert_called_once()
    mock_controller.arm.assert_called_once()
    mock_controller.release_first_packet.assert_called_once()
    mock_controller.stop.assert_called_once()
    mock_controller.teardown_iptables.assert_called_once()

@patch("scalpel_racer.NFQUEUE_AVAILABLE", False)
def test_h2_engine_run_attack_first_seq_unavailable(mock_request):
    engine = HTTP2RaceEngine(mock_request, concurrency=1, strategy="first-seq", warmup_ms=0)
    with pytest.raises(RuntimeError, match="First-Seq strategy requires Linux and NetfilterQueue"):
        engine.run_attack()
