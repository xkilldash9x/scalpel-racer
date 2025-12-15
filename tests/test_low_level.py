# tests/test_low_level.py
import pytest
import socket
import ssl
import time
from unittest.mock import MagicMock, patch, ANY
from low_level import HTTP2RaceEngine, ScanResult
from structures import CapturedRequest

class TestHTTP2RaceEngine:
    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(
            id=1,
            method="POST",
            url="https://target.com/api",
            headers=[("User-Agent", "Test"), ("Content-Type", "application/json")],
            body=b"payload"
        )

    def test_initialization(self, sample_req):
        """Test URL parsing and defaults."""
        # HTTPS default
        engine = HTTP2RaceEngine(sample_req, concurrency=5)
        assert engine.target_port == 443
        assert engine.target_host == "target.com"
        
        # HTTP default
        req_http = CapturedRequest(1, "GET", "http://target.com", [], b"")
        engine_http = HTTP2RaceEngine(req_http, concurrency=1)
        assert engine_http.target_port == 80
        
        # Explicit Port
        req_port = CapturedRequest(1, "GET", "https://target.com:8443", [], b"")
        engine_port = HTTP2RaceEngine(req_port, concurrency=1)
        assert engine_port.target_port == 8443

    def test_construct_h2_headers_compliance(self, sample_req):
        """
        Security & Compliance Test:
        1. Strips hop-by-hop headers (case insensitive).
        2. Adds Pseudo-headers correctly.
        3. Handles Query parameters.
        4. Corrects Content-Length.
        """
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        
        # Inject headers that must be stripped or handled
        engine.request.headers.append(("Connection", "Upgrade"))
        engine.request.headers.append(("TE", "trailers"))
        engine.request.headers.append(("Content-Length", "999")) # Should be overwritten
        
        # Inject URL with query
        engine.request.url = "https://target.com/api?id=1"
        
        headers = engine._construct_h2_headers(content_length=50)
        h_dict = dict(headers)
        
        # Check Pseudo-headers
        assert h_dict[":path"] == "/api?id=1"
        assert h_dict[":authority"] == "target.com"
        
        # Check Stripping
        assert "connection" not in h_dict
        assert "te" not in h_dict
        
        # Check Content-Length (Must be the calculated one, not the injected one)
        assert h_dict["content-length"] == "50"
        
        # Check Default Content-Type logic
        assert h_dict["content-type"] == "application/json" # Preserved from sample

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    def test_connect_security_config(self, mock_ssl_ctx, mock_create_conn, sample_req):
        """
        Verify Security Configuration:
        1. Nagle's Algorithm disabled (TCP_NODELAY) for timing precision.
        2. ALPN set to h2.
        3. SSL Context configured (CERT_NONE is expected for this tool).
        """
        mock_raw_sock = MagicMock()
        mock_create_conn.return_value = mock_raw_sock
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.selected_alpn_protocol.return_value = "h2"
        
        context_instance = mock_ssl_ctx.return_value
        context_instance.wrap_socket.return_value = mock_ssl_sock
        
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        with patch("low_level.socket.gethostbyname", return_value="1.2.3.4"):
            engine.connect()
            
        # 1. TCP_NODELAY
        mock_raw_sock.setsockopt.assert_called_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # 2. ALPN
        context_instance.set_alpn_protocols.assert_called_with(["h2"])
        
        # 3. Verify Mode (Explicit check to ensure we know we are disabling it)
        assert context_instance.check_hostname is False
        assert context_instance.verify_mode == ssl.CERT_NONE

    @patch("low_level.PacketController")
    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    @patch("low_level.H2Connection")
    def test_run_attack_first_seq_integration(self, mock_h2, mock_ssl, mock_sock, mock_pc_cls, sample_req):
        """Test that PacketController is engaged when strategy='first-seq'."""
        mock_pc_instance = mock_pc_cls.return_value
        
        engine = HTTP2RaceEngine(sample_req, concurrency=1, strategy="first-seq")
        
        # Setup minimum mocks to run
        mock_ssl.return_value.wrap_socket.return_value.selected_alpn_protocol.return_value = "h2"
        with patch("low_level.socket.gethostbyname"), \
             patch("low_level.NFQUEUE_AVAILABLE", True), \
             patch.object(engine, "_receive_loop"), \
             patch.object(engine.all_streams_finished, "wait"):
            
            engine.run_attack()
            
            # Verify PacketController Lifecycle
            mock_pc_cls.assert_called()
            mock_pc_instance.start.assert_called_once()
            mock_pc_instance.stop.assert_called_once()

    def test_process_stream_accounting(self, sample_req):
        """
        Test that active_streams count is managed correctly.
        Optimization Check: Ensures O(1) tracking instead of O(N).
        """
        engine = HTTP2RaceEngine(sample_req, concurrency=2)
        engine.streams = {
            1: {"index": 0, "headers": {}, "body": bytearray(), "finished": False},
            3: {"index": 1, "headers": {}, "body": bytearray(), "finished": False}
        }
        engine.active_streams_count = 2 # Manually set for test
        engine.conn = MagicMock()
        
        # -- FIX: Mock H2 Event classes as Real Classes --
        # The 'isinstance' check in low_level.py requires these to be types, not Mock objects.
        class MockStreamEnded:
            pass
        class MockResponseReceived:
            pass
        class MockDataReceived:
            pass
        class MockStreamReset:
            pass

        # Patch the module-level imports in low_level
        with patch("low_level.StreamEnded", MockStreamEnded), \
             patch("low_level.ResponseReceived", MockResponseReceived), \
             patch("low_level.DataReceived", MockDataReceived), \
             patch("low_level.StreamReset", MockStreamReset):
            
            # End first stream
            e_end = MockStreamEnded()
            e_end.stream_id = 1
            
            engine._process([e_end])
            
            assert engine.streams[1]["finished"] is True
            assert engine.active_streams_count == 1
            assert not engine.all_streams_finished.is_set()
            
            # End second stream
            e_end2 = MockStreamEnded()
            e_end2.stream_id = 3
            engine._process([e_end2])
            
            assert engine.active_streams_count == 0
            assert engine.all_streams_finished.is_set()

    def test_receive_loop_disconnect(self, sample_req):
        """Test graceful exit when server closes connection (recv returns empty)."""
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        
        # Mock select: Ready to read
        with patch("low_level.select.select", return_value=([engine.sock], [], [])):
            # Mock recv: Returns empty bytes immediately
            engine.sock.recv.return_value = b""
            
            engine._receive_loop()
            
        assert engine.all_streams_finished.is_set()

    def test_cleanup_on_exception(self, sample_req):
        """Test that sockets are closed even if attack fails."""
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        
        # Force an error in connect
        with patch("low_level.socket.create_connection", side_effect=Exception("Network fail")):
             with patch("low_level.socket.gethostbyname"):
                 engine.run_attack()
        
        # Mock sock created then error occurs
        mock_sock = MagicMock()
        engine.sock = mock_sock
        with patch("low_level.HTTP2RaceEngine.connect", return_value=None):
            # Fail during prepare
            with patch.object(engine, "_construct_h2_headers", side_effect=ValueError("Header Error")):
                engine.run_attack()
        
        mock_sock.close.assert_called()