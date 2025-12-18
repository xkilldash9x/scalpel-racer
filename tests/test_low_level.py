import pytest
import socket
import ssl
import time
from unittest.mock import MagicMock, patch, ANY
from low_level import HTTP2RaceEngine, ScanResult, CapturedRequest, StreamContext

class TestHTTP2RaceEngine:
    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(1, method="POST", url="https://target.com/api", headers=[("User-Agent", "Test")], body=b"payload")

    def test_initialization(self, sample_req):
        engine = HTTP2RaceEngine(sample_req, concurrency=5)
        assert engine.target_port == 443
        assert engine.target_host == "target.com"

    def test_initialization_relative_url_fallback(self):
        req = CapturedRequest(1, method="GET", url="v1/metrics", headers=[("Host", "example.com")], body=b"")
        engine = HTTP2RaceEngine(req, concurrency=1)
        assert engine.target_host == "example.com"

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    def test_connect_security_config(self, mock_ssl_ctx, mock_create_conn, sample_req):
        mock_raw = MagicMock(); mock_create_conn.return_value = mock_raw
        mock_ssl = MagicMock(); mock_ssl.selected_alpn_protocol.return_value = "h2"
        mock_ssl_ctx.return_value.wrap_socket.return_value = mock_ssl
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        with patch("low_level.socket.gethostbyname", return_value="1.2.3.4"):
            engine.connect()
        mock_raw.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @patch("low_level.PacketController")
    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    @patch("low_level.H2Connection")
    def test_run_attack_first_seq_integration(self, mock_h2, mock_ssl, mock_sock, mock_pc_cls, sample_req):
        mock_pc = mock_pc_cls.return_value
        engine = HTTP2RaceEngine(sample_req, concurrency=1, strategy="first-seq")
        mock_ssl.return_value.wrap_socket.return_value.selected_alpn_protocol.return_value = "h2"

        # [FIX] Patch the class method instead of the instance method because of __slots__
        with patch("low_level.socket.gethostbyname", return_value="1.2.3.4"), \
             patch("low_level.NFQUEUE_AVAILABLE", True), \
             patch("low_level.HTTP2RaceEngine._recv"), \
             patch.object(engine.finished, "wait"):

             engine.run_attack()

             mock_pc_cls.assert_called()
             mock_pc.start.assert_called_once()
             mock_pc.stop.assert_called_once()
