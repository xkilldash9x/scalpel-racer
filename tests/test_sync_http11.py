# tests/test_sync_http11.py

import pytest
from unittest.mock import MagicMock, patch
from sync_http11 import HTTP11SyncEngine, SYNC_MARKER
from structures import CapturedRequest

class TestSyncEngine:
    @pytest.fixture
    def staged_req(self):
        return CapturedRequest(
            id=1, url="http://t.com", method="POST",
            headers=[], body=b"part1" + SYNC_MARKER + b"part2"
        )

    def test_stage_parsing(self, staged_req):
        """Verify payload splitting and barrier initialization."""
        engine = HTTP11SyncEngine(staged_req, concurrency=3)
        assert len(engine.stages) == 2
        assert engine.stages[0] == b"part1"
        assert engine.stages[1] == b"part2"
        assert engine.barrier.parties == 3

    @patch("sync_http11.ssl.create_default_context")
    @patch("sync_http11.socket.create_connection")
    def test_connect_https(self, mock_create, mock_ssl, staged_req):
        """Verify SSL wrapping for HTTPS."""
        staged_req.url = "https://t.com"
        engine = HTTP11SyncEngine(staged_req, concurrency=1)
        
        mock_raw = MagicMock()
        mock_create.return_value = mock_raw
        
        engine._connect()
        
        mock_ssl.return_value.wrap_socket.assert_called_with(mock_raw, server_hostname="t.com")

    def test_header_serialization(self, staged_req):
        """Verify HTTP/1.1 raw header construction."""
        staged_req.headers = [("User-Agent", "TestAgent")]
        engine = HTTP11SyncEngine(staged_req, concurrency=1)
        
        raw = engine._serialize_headers()
        
        assert b"POST / HTTP/1.1\r\n" in raw
        assert b"Host: t.com\r\n" in raw
        assert b"User-Agent: TestAgent\r\n" in raw
        assert b"Content-Length: 10\r\n" in raw # len("part1part2")

    @patch("sync_http11.socket.create_connection")
    @patch("sync_http11.HTTPResponse")
    def test_execution_flow(self, mock_resp, mock_conn, staged_req):
        """Verify thread sends data and waits on barrier."""
        engine = HTTP11SyncEngine(staged_req, concurrency=1)
        engine.target_ip = "127.0.0.1"
        engine.target_port = 80
        engine.scheme = 'http'
        
        # Mock socket
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        
        # Mock response
        mock_resp_inst = mock_resp.return_value
        mock_resp_inst.status = 200
        mock_resp_inst.read.return_value = b"OK"
        
        engine._attack_thread(0)
        
        # Verify socket sent headers+part1, then part2
        assert mock_sock.sendall.call_count >= 2
        assert engine.results[0].status_code == 200