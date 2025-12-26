# tests/test_sync_http11.py
import pytest
import threading
import socket
import ssl
import time
from unittest.mock import MagicMock, patch, ANY
from sync_http11 import HTTP11SyncEngine, ScanResult
from structures import CapturedRequest

class TestHTTP11SyncEngine:

    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(
            request_id=1, method="POST", url="https://target.com/api",
            headers=[("User-Agent", "Test"), ("Content-Type", "application/json"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
            body=b"part1{{SYNC}}part2"
        )

    def test_initialization(self, sample_req):
        """Verify initialization and payload splitting."""
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=5)
            assert engine.target_host == "target.com"
            assert engine.target_port == 443
            assert len(engine.stages) == 2
            assert engine.stages[0] == b"part1"
            assert engine.stages[1] == b"part2"
            assert engine.barrier.parties == 5

    def test_init_invalid_scheme(self):
        """Ensure non-HTTP/HTTPS schemes raise ValueError."""
        req = CapturedRequest(request_id=0, method="GET", headers=[], url="ftp://target.com", body=b"")
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            HTTP11SyncEngine(req, 1)

    # [FIX] Patch DNS to prevent real lookup failure during test
    @patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4")
    def test_init_no_sync_marker_implicit(self, mock_dns):
        """
        [UPDATED] Ensure missing {{SYNC}} marker triggers Implicit Last-Byte-Sync.
        Previously expected to raise ValueError, now expects auto-split.
        """
        req = CapturedRequest(request_id=0, method="GET", headers=[], url="http://a.com", body=b"nosync")
        engine = HTTP11SyncEngine(req, 1)
        
        # Should split "nosync" into "nosyn" and "c"
        assert len(engine.stages) == 2
        assert engine.stages[0] == b"nosyn"
        assert engine.stages[1] == b"c"

    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.ssl.create_default_context")
    def test_connect_https(self, mock_ssl_ctx, mock_create_conn, sample_req):
        """Test HTTPS connection setup, ALPN, and TCP optimizations."""
        # Need to mock DNS for init
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=1)
            engine.target_ip = "1.2.3.4"
        
        mock_raw_sock = MagicMock()
        mock_create_conn.return_value = mock_raw_sock
        mock_ssl_sock = MagicMock()
        mock_ssl_ctx.return_value.wrap_socket.return_value = mock_ssl_sock
        
        sock = engine._connect()
        
        assert sock == mock_ssl_sock
        mock_create_conn.assert_called_with(("1.2.3.4", 443), timeout=ANY)
        
        # Verify Nagle disabled (Precision Requirement)
        # Using assert_any_call because SO_SNDBUF is called afterwards
        mock_raw_sock.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Verify ALPN (Protocol Requirement)
        mock_ssl_ctx.return_value.set_alpn_protocols.assert_called_with(["http/1.1"])

    @patch("sync_http11.socket.create_connection")
    def test_connect_socket_error(self, mock_create_conn, sample_req):
        """Test proper exception wrapping for socket errors."""
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=1)
        
        engine.target_ip = "1.2.3.4"
        mock_create_conn.side_effect = socket.error("Connection refused")
        
        # [FIX] Updated regex to match "Connection failed"
        with pytest.raises(ConnectionError, match="Connection failed"):
            engine._connect()

    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.ssl.create_default_context")
    def test_connect_ssl_error(self, mock_ssl_ctx, mock_create_conn, sample_req):
        """Test proper exception wrapping for SSL errors."""
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=1)
            
        engine.target_ip = "1.2.3.4"
        mock_ssl_ctx.return_value.wrap_socket.side_effect = ssl.SSLError("Handshake fail")
        
        # [FIX] Updated regex to match "Connection failed"
        with pytest.raises(ConnectionError, match="Connection failed"):
            engine._connect()

    def test_serialize_headers(self, sample_req):
        """Test HTTP/1.1 header construction, duplicate preservation, and logic."""
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=1)
            
        # Add a hop-by-hop header to test filtering
        engine.request.headers.append(("Connection", "close"))
        engine.request.headers.append(("Host", "fake.com")) # Should be overridden
        # Add duplicate header
        engine.request.headers.append(("X-Custom", "Val1"))
        engine.request.headers.append(("X-Custom", "Val2"))
        
        headers_bytes = engine._serialize_headers()
        headers_str = headers_bytes.decode('utf-8')
        
        assert "POST /api HTTP/1.1" in headers_str
        assert "Host: target.com" in headers_str # Verified override
        assert "Content-Length: 10" in headers_str # len("part1part2")
        assert "Connection: keep-alive" in headers_str # Forced keep-alive
        # "close" should be filtered out or overridden
        assert "Connection: close" not in headers_str
        # Duplicates preserved
        assert "Set-Cookie: a=1" in headers_str
        assert "Set-Cookie: b=2" in headers_str
        assert "X-Custom: Val1" in headers_str
        assert "X-Custom: Val2" in headers_str

    @patch("sync_http11.HTTPResponse")
    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.ssl.create_default_context")
    def test_run_attack_flow(self, mock_ssl, mock_conn, mock_http_resp, sample_req):
        """
        Critical Test: Verify the threaded attack flow, barrier usage, and sending sequence.
        """
        concurrency = 2
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(sample_req, concurrency=concurrency)
        
        # Mock Socket
        mock_sock_inst = MagicMock()
        mock_ssl.return_value.wrap_socket.return_value = mock_sock_inst
        
        # Generator for unique mock responses per call
        def create_mock_response(*args, **kwargs):
            m = MagicMock()
            m.status = 200
            m.read.side_effect = [b"Response Body", b""] # Body then EOF
            return m
            
        mock_http_resp.side_effect = create_mock_response
        
        # Wrap the real barrier to spy on 'wait' calls
        real_barrier = threading.Barrier(concurrency)
        mock_barrier = MagicMock(wraps=real_barrier)
        engine.barrier = mock_barrier
        
        # Mock DNS
        engine.target_ip = "1.2.3.4" 
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            results = engine.run_attack()
            
            assert len(results) == 2
            assert results[0].status_code == 200
            assert results[0].body_hash is not None
            
            # Verify data sent: Headers+Part1, then Part2
            # 2 threads * 2 sends = 4 calls total
            mock_sock_inst.sendall.assert_any_call(b"part2")
            
            # Verify synchronization occurred (each thread waits once)
            assert mock_barrier.wait.call_count >= 2

    @patch("sync_http11.socket.gethostbyname", side_effect=socket.gaierror("No address"))
    def test_run_attack_dns_failure(self, mock_dns, sample_req):
        """Verify fail-fast behavior on DNS failure."""
        engine = HTTP11SyncEngine(sample_req, concurrency=2)
        results = engine.run_attack()
        
        assert len(results) == 2
        assert results[0].error is not None
        assert "DNS Fail" in results[0].error

    @patch("sync_http11.HTTPResponse")
    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.ssl.create_default_context")
    def test_response_truncation_warning(self, mock_ssl, mock_conn, mock_http_resp, sample_req):
        """Test that oversized responses trigger a warning log."""
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
             engine = HTTP11SyncEngine(sample_req, concurrency=1)
        engine.target_ip = "1.2.3.4"
        mock_sock = MagicMock()
        mock_ssl.return_value.wrap_socket.return_value = mock_sock
        
        mock_resp = MagicMock()
        mock_resp.status = 200
        # [FIX] Mock isclosed to return False so the check passes
        mock_resp.isclosed.return_value = False
        
        # read(limit) returns full, then read(1) returns more data
        mock_resp.read.side_effect = [b"A" * 1024*1024, b"X"] 
        mock_http_resp.return_value = mock_resp
        
        with patch("sync_http11.logger") as mock_logger:
            engine._attack_thread(0)
            # Verify warning call
            warning_calls = [c for c in mock_logger.warning.call_args_list if "truncated" in c[0][0]]
            assert len(warning_calls) > 0