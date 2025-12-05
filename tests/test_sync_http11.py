import pytest
from unittest.mock import MagicMock, patch, ANY, call
import socket
import ssl
import threading
import time
from http.client import HTTPResponse

from sync_http11 import HTTP11SyncEngine, CapturedRequest, ScanResult, SYNC_MARKER

# --- Fixtures ---

@pytest.fixture
def mock_request():
    return CapturedRequest(
        1, "POST", "https://example.com/api/test",
        {"X-Custom": "Value"},
        b"Stage1{{SYNC}}Stage2{{SYNC}}Stage3"
    )

@pytest.fixture
def engine(mock_request):
    return HTTP11SyncEngine(mock_request, concurrency=2)

@pytest.fixture
def mock_dependencies():
    with patch('socket.create_connection') as mock_create_conn, \
         patch('socket.gethostbyname') as mock_gethostbyname, \
         patch('ssl.create_default_context') as mock_ssl_ctx_cls:

        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        mock_gethostbyname.return_value = "1.2.3.4"

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

# --- Parsing Tests ---

def test_initialization_parsing_success(engine):
    assert engine.target_host == "example.com"
    assert engine.target_port == 443
    assert engine.scheme == "https"
    assert engine.total_payload_len == len(b"Stage1Stage2Stage3")

def test_initialization_parsing_http_default_port():
    # [FIX] Provide all positional args: id, method, url, headers, body
    req = CapturedRequest(1, "GET", "http://plain.com/foo", {}, b"A{{SYNC}}B")
    eng = HTTP11SyncEngine(req, 1)
    assert eng.target_port == 80
    assert eng.scheme == "http"

def test_initialization_parsing_explicit_ports():
    # [FIX] Provide all positional args
    req = CapturedRequest(1, "POST", "https://secure.com:8443/foo", {}, b"A{{SYNC}}B")
    eng = HTTP11SyncEngine(req, 1)
    assert eng.target_port == 8443
    
    req_http = CapturedRequest(2, "GET", "http://plain.com:8080/foo", {}, b"A{{SYNC}}B")
    eng_http = HTTP11SyncEngine(req_http, 1)
    assert eng_http.target_port == 8080

def test_initialization_parsing_invalid_scheme():
    # [FIX] Provide all positional args
    req = CapturedRequest(1, "GET", "ftp://files.com", {}, b"A{{SYNC}}B")
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        HTTP11SyncEngine(req, 1)

def test_initialization_no_sync_marker():
    # [FIX] Provide all positional args
    req = CapturedRequest(1, "GET", "http://test.com", {}, b"NoMarkers")
    with pytest.raises(ValueError, match="requires at least one {{SYNC}} marker"):
        HTTP11SyncEngine(req, 1)

# --- Connection Tests ---

def test_connect_https_success(engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    sock = engine._connect()
    
    mock_dependencies["create_connection"].assert_called_with(("1.2.3.4", 443), timeout=10)
    mock_dependencies["ssl_ctx"].set_alpn_protocols.assert_called_with(["http/1.1"])
    mock_dependencies["ssl_ctx"].wrap_socket.assert_called()
    assert sock == mock_dependencies["wrapped_sock"]

def test_connect_http_success(mock_dependencies):
    # [FIX] Provide all positional args
    req = CapturedRequest(1, "GET", "http://plain.com", {}, b"A{{SYNC}}B")
    engine = HTTP11SyncEngine(req, 1)
    engine.target_ip = "5.6.7.8"
    
    sock = engine._connect()
    
    mock_dependencies["create_connection"].assert_called_with(("5.6.7.8", 80), timeout=10)
    # SSL context should not be created for HTTP
    mock_dependencies["ssl_ctx"].wrap_socket.assert_not_called()
    assert sock == mock_dependencies["raw_sock"]

def test_connect_socket_error(engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    mock_dependencies["create_connection"].side_effect = socket.error("Network Unreachable")
    
    with pytest.raises(ConnectionError, match="Connection failed"):
        engine._connect()

def test_connect_ssl_error(engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    mock_dependencies["ssl_ctx"].wrap_socket.side_effect = ssl.SSLError("Handshake failed")
    
    with pytest.raises(ConnectionError, match="SSL Handshake failed"):
        engine._connect()
    
    # Verify raw socket was closed
    mock_dependencies["raw_sock"].close.assert_called()

# --- Attack Thread & Execution Tests ---

def test_serialize_headers_content_type_logic(engine):
    # Case 1: Auto-add Content-Type for POST
    engine.request.method = "POST"
    engine.request.headers = {}
    headers = engine._serialize_headers().decode()
    assert "Content-Type: application/x-www-form-urlencoded" in headers
    
    # Case 2: Preserve existing Content-Type
    engine.request.headers = {"Content-Type": "application/json"}
    headers = engine._serialize_headers().decode()
    assert "Content-Type: application/json" in headers
    assert "application/x-www-form-urlencoded" not in headers

def test_run_attack_dns_failure(engine, mock_dependencies):
    mock_dependencies["gethostbyname"].side_effect = socket.gaierror("Name unknown")
    
    results = engine.run_attack()
    
    assert len(results) == 2
    for res in results:
        assert res.status_code == 0
        assert "DNS error" in res.error

@patch('sync_http11.HTTPResponse')
def test_attack_thread_success_flow(MockHTTPResponse, engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    mock_sock = mock_dependencies["wrapped_sock"]
    
    # Mock Response
    mock_resp = MockHTTPResponse.return_value
    mock_resp.status = 201
    # read(MAX) returns body, read(1) returns empty (not truncated)
    mock_resp.read.side_effect = [b"Created", b""] 

    # We need a thread to simulate the concurrent nature, 
    # but we can use the main thread as one of the parties for the barrier.
    engine.barrier = threading.Barrier(2)

    # Start the attack thread
    t = threading.Thread(target=engine._attack_thread, args=(0,))
    t.start()
    
    # Simulate other threads hitting barrier for Stage 1 -> Stage 2
    engine.barrier.wait(timeout=1)
    # Simulate other threads hitting barrier for Stage 2 -> Stage 3
    engine.barrier.wait(timeout=1)
    
    t.join(timeout=1)
    
    # Verification
    assert engine.results[0].status_code == 201
    assert engine.results[0].body_snippet == "Created"
    
    # Verify sends
    assert mock_sock.sendall.call_count == 3 # Headers+S1, S2, S3

@patch('sync_http11.HTTPResponse')
def test_attack_thread_truncated_response(MockHTTPResponse, engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    
    mock_resp = MockHTTPResponse.return_value
    mock_resp.status = 200
    # First read returns MAX bytes, Second read returns MORE bytes (Trigger truncation warning)
    mock_resp.read.side_effect = [b"A"*1024, b"X"] 

    engine.barrier = MagicMock() # Bypass barrier for this unit test
    
    # Run synchronously
    with patch("builtins.print") as mock_print:
        engine._attack_thread(0)
        
        # Verify warning printed
        args, _ = mock_print.call_args
        assert "Response truncated" in args[0]

@patch('sync_http11.HTTPResponse')
def test_attack_thread_broken_barrier(MockHTTPResponse, engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    
    # Simulate BrokenBarrierError during wait
    engine.barrier = MagicMock()
    # [FIX] Ensure 'broken' property is False so logic proceeds to abort()
    engine.barrier.broken = False 
    engine.barrier.wait.side_effect = threading.BrokenBarrierError()
    
    engine._attack_thread(0)
    
    # [FIX] Updated string match to include (fail-fast) which is now part of the error message
    assert "ConnectionError: Synchronization barrier broken" in engine.results[0].error
    # Verify barrier abort was called in finally
    engine.barrier.abort.assert_called()

def test_attack_thread_connection_error(engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    # Simulate connect failure
    mock_dependencies["create_connection"].side_effect = socket.error("Timeout")
    
    engine.barrier = MagicMock()
    # [FIX] Ensure 'broken' property is False so logic proceeds to abort()
    engine.barrier.broken = False
    
    engine._attack_thread(0)
    
    assert engine.results[0].status_code == 0
    # [FIX] Update expectation to match actual error string structure
    assert "Connection failed: OSError: Timeout" in engine.results[0].error
    
    # Ensure barrier was aborted to release other threads
    engine.barrier.abort.assert_called()

@patch('sync_http11.HTTPResponse')
def test_attack_thread_snippet_encoding_error(MockHTTPResponse, engine, mock_dependencies):
    engine.target_ip = "1.2.3.4"
    mock_resp = MockHTTPResponse.return_value
    mock_resp.status = 200
    # Invalid UTF-8 sequence
    bad_bytes = b"\x80\x81"
    mock_resp.read.side_effect = [bad_bytes, b""]
    
    engine.barrier = MagicMock()
    engine._attack_thread(0)
    
    # Snippet should fall back to repr() or use ignore/replace
    # The implementation uses errors='ignore', so \x80\x81 becomes empty string
    assert engine.results[0].body_snippet == ""

def test_run_attack_integration(engine, mock_dependencies):
    # Test the high-level run_attack method orchestration
    engine.target_host = "test.com"
    engine.barrier = MagicMock()
    
    # Mock _attack_thread to just set a result
    def mock_thread_target(idx):
        engine.results[idx] = ScanResult(idx, 200, 10.0)
    
    engine._attack_thread = mock_thread_target
    
    results = engine.run_attack()
    
    assert len(results) == 2
    assert results[0].status_code == 200
    mock_dependencies["gethostbyname"].assert_called_with("test.com")