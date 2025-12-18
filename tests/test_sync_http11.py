import pytest
from unittest.mock import MagicMock, patch
from sync_http11 import HTTP11SyncEngine, CapturedRequest
import socket

class TestHTTP11SyncEngine:
    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.ssl.create_default_context")
    def test_connect_https(self, mock_ssl, mock_conn, sample_req=None):
        req = CapturedRequest(1, "GET", "https://t.com", [], b"")
        
        # [FIX] Mock gethostbyname to prevent DNS lookup failure
        with patch("sync_http11.socket.gethostbyname", return_value="1.2.3.4"):
            engine = HTTP11SyncEngine(req, 1)
            
            mock_raw = MagicMock()
            mock_conn.return_value = mock_raw
            mock_ssl.return_value.wrap_socket.return_value = MagicMock()
            
            engine._connect()
            mock_raw.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
