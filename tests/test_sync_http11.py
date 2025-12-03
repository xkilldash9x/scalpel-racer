# tests/test_sync_http11.py
import pytest
from unittest.mock import MagicMock, patch, ANY
import socket
import ssl
import threading
import time
from http.client import HTTPResponse
import io

# Import the SUT and necessary placeholders
# We use the placeholders defined within the SUT file itself for consistency
from sync_http11 import HTTP11SyncEngine, CapturedRequest, ScanResult, SYNC_MARKER

# --- Fixtures ---

@pytest.fixture
def mock_request():
    # Create a request with 2 sync markers (3 stages)
    return CapturedRequest(
        id=1, method="POST", url="https://example.com/api/test",
        headers={"X-Custom": "Value"},
        body=b"Stage1{{SYNC}}Stage2{{SYNC}}Stage3"
    )

@pytest.fixture
def engine(mock_request):
    # Initialize engine with concurrency 2
    return HTTP11SyncEngine(mock_request, concurrency=2)

@pytest.fixture
def mock_dependencies():
    # Mock network interactions
    with patch('socket.create_connection') as mock_create_conn, \
         patch('socket.gethostbyname') as mock_gethostbyname, \
         patch('ssl.create_default_context') as mock_ssl_ctx_cls:

        # Setup Socket/DNS
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        mock_gethostbyname.return_value = "1.2.3.4"

        # Setup SSL
        mock_ssl_ctx = mock_ssl_ctx_cls.return_value
        mock_wrapped_sock = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_wrapped_sock

        yield {
            "gethostbyname": mock_gethostbyname,
            "create_connection": mock_create_conn,
            "raw_sock": mock_sock,
            "ssl_ctx": mock_ssl_ctx,
            "wrapped_sock": mock_wrapped_sock,
        }

# --- Tests ---

def test_initialization_and_parsing(engine):
    assert engine.target_host == "example.com"
    assert engine.target_port == 443
    assert engine.scheme == "https"
    # Verify stages are split correctly
    assert engine.stages == [b"Stage1", b"Stage2", b"Stage3"]
    # Verify total length excludes markers
    assert engine.total_payload_len == len(b"Stage1Stage2Stage3")
    # Verify barrier is set for the correct number of threads
    assert engine.barrier.parties == 2

def test_initialization_no_sync_marker():
    req = CapturedRequest(id=1, method="GET", url="http://test.com", headers={}, body=b"data")
    with pytest.raises(ValueError, match="requires at least one {{SYNC}} marker"):
        HTTP11SyncEngine(req, 2)

def test_connect_success(engine, mock_dependencies):
    engine.target_ip = "1.2.3.4" # Set IP directly to skip DNS in this test
    sock = engine._connect()

    # Verify TCP Connection and TCP_NODELAY
    mock_dependencies["create_connection"].assert_called_with(("1.2.3.4", 443), timeout=10)
    mock_dependencies["raw_sock"].setsockopt.assert_called_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Verify SSL Wrapping and ALPN (forced to http/1.1)
    mock_dependencies["ssl_ctx"].set_alpn_protocols.assert_called_with(["http/1.1"])
    assert sock == mock_dependencies["wrapped_sock"]

def test_serialize_headers(engine):
    headers_bytes = engine._serialize_headers()
    headers_str = headers_bytes.decode('utf-8')

    assert "POST /api/test HTTP/1.1\r\n" in headers_str
    assert "Host: example.com\r\n" in headers_str
    assert "X-Custom: Value\r\n" in headers_str
    # Content-Length should be the total length (excluding {{SYNC}} markers)
    assert f"Content-Length: {len(b'Stage1Stage2Stage3')}\r\n" in headers_str
    # Connection must be keep-alive for this engine
    assert "Connection: keep-alive\r\n" in headers_str

# --- Integration Test: Attack Thread Synchronization (C03 Verification) ---

# Helper to mock the HTTPResponse parsing
@patch('sync_http11.HTTPResponse')
def test_c03_attack_thread_synchronization(MockHTTPResponse, engine, mock_dependencies):
    """Verify C03: Threads synchronize at barriers before sending subsequent stages."""
    
    # Setup mocks
    engine.target_ip = "1.2.3.4"
    mock_sock = mock_dependencies["wrapped_sock"]
    
    # Mock the response parsing
    mock_response_instance = MockHTTPResponse.return_value
    mock_response_instance.status = 200
    mock_response_instance.read.side_effect = [b"Response Body", b""] # Read body, then EOF

    # We will run the attack thread logic directly and control the barrier manually.
    
    # Reset the barrier for the test. We use 2 parties: the attack thread and this test thread.
    engine.barrier = threading.Barrier(2)

    # Run the attack thread (index 0)
    thread = threading.Thread(target=engine._attack_thread, args=(0,))
    thread.start()

    # Wait briefly for the thread to reach the first barrier
    time.sleep(0.1)

    # Verify: Initial send (Headers + Stage1) occurred
    calls = mock_sock.sendall.call_args_list
    assert len(calls) == 1

    # Release barrier for Stage 2
    engine.barrier.wait()
    time.sleep(0.1)
    assert len(calls) == 2

    # Release barrier for Stage 3
    engine.barrier.wait()
    time.sleep(0.1)
    assert len(calls) == 3

    # Verify payloads
    calls = mock_sock.sendall.call_args_list
    initial_payload = calls[0][0][0]
    assert b"HTTP/1.1\r\n" in initial_payload
    assert b"Stage1" in initial_payload
    assert b"Stage2" not in initial_payload

    stage2_payload = calls[1][0][0]
    assert stage2_payload == b"Stage2"

    stage3_payload = calls[2][0][0]
    assert stage3_payload == b"Stage3"
    
    # Wait for the thread to finish
    thread.join(timeout=1)

    # Verify response processing
    MockHTTPResponse.assert_called_once_with(mock_sock, method="POST")
    mock_response_instance.begin.assert_called_once()
    
    # Verify result
    result = engine.results[0]
    assert result is not None
    assert result.status_code == 200
    assert result.body_snippet == "Response Body"