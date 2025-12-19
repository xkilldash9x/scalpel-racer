import pytest
import socket
import ssl
import time
from unittest.mock import MagicMock, patch, ANY
from low_level import HTTP2RaceEngine, ScanResult, CapturedRequest, StreamContext

class TestHTTP2RaceEngine:
    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(1, method="POST", url="https://target.com/api", headers=[("User-Agent", "Test"), ("Content-Type", "application/json")], body=b"payload")

    def test_initialization(self, sample_req):
        # Default HTTPS/443
        engine = HTTP2RaceEngine(sample_req, concurrency=5)
        assert engine.target_port == 443
        assert engine.target_host == "target.com"
        
        # HTTP Default
        req_http = CapturedRequest(1, "GET", "http://target.com", [], b"")
        engine_http = HTTP2RaceEngine(req_http, concurrency=1)
        assert engine_http.target_port == 80
        
        # Explicit Port
        req_port = CapturedRequest(1, "GET", "https://target.com:8443", [], b"")
        engine_port = HTTP2RaceEngine(req_port, concurrency=1)
        assert engine_port.target_port == 8443

    def test_initialization_relative_url_fallback(self):
        # Case 1: Relative URL, Host header present
        req = CapturedRequest(1, method="GET", url="v1/metrics", headers=[("Host", "example.com")], body=b"")
        engine = HTTP2RaceEngine(req, concurrency=1)
        
        assert engine.target_host == "example.com"
        assert engine.target_port == 443 
        
        # Case 2: Relative URL, Host header with port
        req_port = CapturedRequest(2, method="GET", url="v1/metrics", headers=[("Host", "example.com:8080")], body=b"")
        engine_port = HTTP2RaceEngine(req_port, concurrency=1)
        
        assert engine_port.target_host == "example.com"
        assert engine_port.target_port == 8080

        # Check :path construction
        headers = engine_port._build_headers(0)
        h_dict = dict(headers)
        assert h_dict[':path'] == "/v1/metrics"
        assert h_dict[':authority'] == "example.com:8080"

    def test_build_headers_compliance(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        
        # Headers that must be stripped or handled
        engine.request.headers.append(("Connection", "Upgrade"))
        engine.request.headers.append(("TE", "trailers"))
        engine.request.headers.append(("Content-Length", "999")) # Should be overwritten
        
        # Inject URL with query
        engine.request.url = "https://target.com/api?id=1"
        
        headers = engine._build_headers(cl=50)
        h_dict = dict(headers)
        
        # Pseudo-headers
        assert h_dict[":path"] == "/api?id=1"
        assert h_dict[":authority"] == "target.com"
        
        # Stripping checks
        assert "connection" not in h_dict
        assert "te" not in h_dict
        
        # Content-Length (Must be the calculated one)
        assert h_dict["content-length"] == "50"
        
        # Default Content-Type logic
        assert "content-type" in h_dict 

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    def test_connect_security_config(self, mock_ssl_ctx, mock_create_conn, sample_req):
        mock_raw = MagicMock(); mock_create_conn.return_value = mock_raw
        mock_ssl = MagicMock(); mock_ssl.selected_alpn_protocol.return_value = "h2"
        
        context_instance = mock_ssl_ctx.return_value
        context_instance.wrap_socket.return_value = mock_ssl
        
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        with patch("low_level.socket.gethostbyname", return_value="1.2.3.4"):
            engine.connect()
            
        # Nagle's Algorithm disabled
        mock_raw.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Socket Buffer Optimization
        mock_raw.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        mock_raw.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        
        # ALPN and Verify Mode
        context_instance.set_alpn_protocols.assert_called_with(["h2"])
        assert context_instance.check_hostname is False
        assert context_instance.verify_mode == ssl.CERT_NONE

    def test_run_attack_missing_host_error(self):
        # Request with relative URL and NO Host header
        req = CapturedRequest(99, "GET", "v1/metrics", [], b"")
        engine = HTTP2RaceEngine(req, concurrency=1)
        
        # Should return a result with error, NOT raise exception
        results = engine.run_attack()
        
        assert len(results) == 1
        assert results[0].error is not None
        assert "Target host could not be determined" in results[0].error

    @patch("low_level.PacketController")
    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    @patch("low_level.H2Connection")
    def test_run_attack_first_seq_integration(self, mock_h2, mock_ssl, mock_sock, mock_pc_cls, sample_req):
        mock_pc = mock_pc_cls.return_value
        engine = HTTP2RaceEngine(sample_req, concurrency=1, strategy="first-seq")
        
        mock_ssl.return_value.wrap_socket.return_value.selected_alpn_protocol.return_value = "h2"
        
        with patch("low_level.socket.gethostbyname"), \
             patch("low_level.NFQUEUE_AVAILABLE", True), \
             patch.object(engine, "_recv"), \
             patch.object(engine.finished, "wait"):
             
             engine.run_attack()
             
             # PacketController Lifecycle
             mock_pc_cls.assert_called()
             mock_pc.start.assert_called_once()
             mock_pc.stop.assert_called_once()

    def test_process_stream_accounting(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=2)
        
        # [FIX] Removed extraneous 3rd argument 'None'
        s1 = StreamContext(1, 0)
        s3 = StreamContext(3, 1)
        
        engine.streams = {1: s1, 3: s3}
        engine.conn = MagicMock()
        
        # -- Mock H2 Event classes --
        class MockStreamEnded: pass
        class MockResponseReceived: pass
        class MockDataReceived: pass
        class MockStreamReset: pass

        with patch("low_level.StreamEnded", MockStreamEnded), \
             patch("low_level.ResponseReceived", MockResponseReceived), \
             patch("low_level.DataReceived", MockDataReceived), \
             patch("low_level.StreamReset", MockStreamReset):
            
            # End first stream
            e_end = MockStreamEnded()
            e_end.stream_id = 1
            
            engine._process_events([e_end])
            
            assert engine.streams[1].finished is True
            assert not engine.finished.is_set()
            
            # End second stream
            e_end2 = MockStreamEnded()
            e_end2.stream_id = 3
            engine._process_events([e_end2])
            
            assert engine.streams[3].finished is True
            assert engine.finished.is_set()

    def test_finalize_results_lazy_decoding(self, sample_req):
        # Verify that _finalize correctly handles raw byte headers
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        
        # [FIX] Removed extraneous 3rd argument 'None'
        s1 = StreamContext(1, 0)
        s1.finished = True
        s1.start_time = 1000.0
        s1.end_time = 1000.1
        s1.headers = [
            (b':status', b'201'),
            (b'server', b'nginx'),
            (b'content-type', b'application/json')
        ]
        s1.body = bytearray(b'{"success":true}')
        
        engine.streams = {1: s1}
        
        results = engine._finalize()
        
        assert len(results) == 1
        res = results[0]
        
        assert res.status_code == 201
        assert res.duration > 0
        assert res.body_hash is not None 

    def test_receive_loop_disconnect(self, sample_req):
        # Test graceful exit when server closes connection
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        
        with patch("low_level.selectors.DefaultSelector") as MockSelector:
            mock_sel_instance = MockSelector.return_value
            mock_key = MagicMock()
            mock_key.fileobj = engine.sock
            mock_sel_instance.select.return_value = [(mock_key, "EVENT_READ")]
            
            # Mock recv: Returns empty bytes immediately
            engine.sock.recv.return_value = b""
            
            engine._recv()
            
        assert engine.finished.is_set()

    def test_cleanup_on_exception(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        
        # Force an error in connect
        with patch("low_level.socket.create_connection", side_effect=Exception("Network fail")):
             with patch("low_level.socket.gethostbyname"):
                 engine.run_attack()
        
        # Mock sock created then error occurs during preparation
        mock_sock = MagicMock()
        engine.sock = mock_sock
        
        # Patch connect so it returns None instead of running real connect
        with patch.object(engine, 'connect', return_value=None):
            # Fail during prepare
            with patch.object(engine, "_build_headers", side_effect=ValueError("Header Error")):
                engine.run_attack()
        
        mock_sock.close.assert_called()
        assert engine.finished.is_set()
        
    def test_cleanup_on_timeout(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        engine.conn = MagicMock()
        
        with patch.object(engine, 'connect', return_value=None):
            # Mock time.sleep to simulate a timeout
            with patch("low_level.time.sleep", side_effect=TimeoutError):
                engine.run_attack()
        
        engine.sock.close.assert_called()
        assert engine.finished.is_set()
        
    def test_cleanup_on_interrupt(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        engine.conn = MagicMock()
        
        with patch.object(engine, 'connect', return_value=None):
            # Mock a KeyboardInterrupt
            with patch("low_level.time.sleep", side_effect=KeyboardInterrupt):
                with pytest.raises(KeyboardInterrupt):
                    engine.run_attack()
        
        engine.sock.close.assert_called()
        assert engine.finished.is_set()