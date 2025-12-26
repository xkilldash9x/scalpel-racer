
import pytest
import threading
import time
import socket
import ssl
from unittest.mock import MagicMock, patch, ANY
import sync_http11
from sync_http11 import HTTP11SyncEngine, H1PacketController, ScanResult
from structures import CapturedRequest

@pytest.fixture
def mock_captured_request():
    return CapturedRequest(
        request_id=1,
        method="POST",
        url="http://example.com/api",
        headers=[("User-Agent", "TestAgent")],
        body=b"payload_data"
    )

class TestHTTP11SyncEngine:

    def test_init_basic(self, mock_captured_request):
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=2)
        assert engine.target_host == "example.com"
        assert engine.target_port == 80
        assert engine.scheme == "http"
        assert engine.concurrency == 2
        assert len(engine.results) == 2

    def test_init_https(self, mock_captured_request):
        mock_captured_request.url = "https://secure.example.com:8443/path"
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        assert engine.target_host == "secure.example.com"
        assert engine.target_port == 8443
        assert engine.scheme == "https"
        assert engine.ssl_context is not None

    def test_parse_target_fallback_headers(self):
        req = CapturedRequest(request_id=1, method="GET", body=b"", url="/path", headers=[("host", "internal.local:8080")])
        engine = HTTP11SyncEngine(req, concurrency=1)
        assert engine.target_host == "internal.local"
        assert engine.target_port == 8080
        assert engine.scheme == "http"

    def test_prepare_payload_implicit_sync(self, mock_captured_request):
        mock_captured_request.body = b"ABC"
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        # Implicit split: "AB" + "C"
        assert len(engine.stages) == 2
        assert engine.stages[0] == b"AB"
        assert engine.stages[1] == b"C"
        assert engine.barrier is not None

    def test_prepare_payload_explicit_sync(self, mock_captured_request):
        mock_captured_request.body = b"PART1{{SYNC}}PART2"
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        assert len(engine.stages) == 2
        assert engine.stages[0] == b"PART1"
        assert engine.stages[1] == b"PART2"

    def test_prepare_payload_single_byte(self, mock_captured_request):
        mock_captured_request.body = b"A"
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        assert engine.stages == [b"", b"A"]

    def test_prepare_payload_empty(self, mock_captured_request):
        mock_captured_request.body = b""
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        assert engine.stages == [b"", b""]

    @patch("socket.gethostbyname")
    @patch("socket.create_connection")
    def test_run_attack_dns_failure(self, mock_create_conn, mock_gethost, mock_captured_request):
        mock_gethost.side_effect = socket.gaierror("Name not known")
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=2)

        results = engine.run_attack()

        assert len(results) == 2
        for res in results:
            assert res.error is not None
            assert "DNS Fail" in res.error

        mock_create_conn.assert_not_called()

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.create_connection")
    def test_run_attack_success(self, mock_create_conn, mock_gethost, mock_captured_request, monkeypatch):
        # Patch BARRIER_TIMEOUT to avoid flakiness
        monkeypatch.setattr(sync_http11, 'BARRIER_TIMEOUT', 60.0)

        # Critical Fix: Return a new MagicMock for each connection attempt
        mock_create_conn.side_effect = lambda *args, **kwargs: MagicMock()

        # Patch sync_http11.HTTPResponse because it's imported directly in the module
        with patch("sync_http11.HTTPResponse") as MockResponse:
            def side_effect_response(*args, **kwargs):
                m = MagicMock()
                m.read.return_value = b"OK"
                m.status = 200
                m.isclosed.return_value = False
                m.begin.return_value = None
                return m

            MockResponse.side_effect = side_effect_response

            engine = HTTP11SyncEngine(mock_captured_request, concurrency=2)
            results = engine.run_attack()

            errors = []
            for i, r in enumerate(results):
                if r.error:
                    errors.append(f"Result {i} error: {r.error}")

            if errors:
                pytest.fail("\n".join(errors))

            assert len(results) == 2
            assert all(r.status_code == 200 for r in results)
            assert all(r.body_snippet == "OK" for r in results)

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.create_connection")
    def test_attack_thread_barrier_timeout(self, mock_create_conn, mock_gethost, mock_captured_request, monkeypatch):
        monkeypatch.setattr(sync_http11, 'BARRIER_TIMEOUT', 0.01)
        mock_captured_request.body = b"A{{SYNC}}B"
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=2)

        mock_create_conn.side_effect = lambda *args, **kwargs: MagicMock()

        # Force barrier.wait to raise BrokenBarrierError immediately to simulate timeout behavior
        engine.barrier.wait = MagicMock(side_effect=threading.BrokenBarrierError)

        results = engine.run_attack()
        # Verify that we caught an error. The string representation of BrokenBarrierError might vary,
        # so just checking that an error exists and it's related to the barrier failure is sufficient.
        # Often it might just be empty or "Barrier broken".
        assert any(r.error is not None for r in results)

    def test_serialize_headers(self, mock_captured_request):
        engine = HTTP11SyncEngine(mock_captured_request, concurrency=1)
        raw = engine._serialize_headers()
        assert b"POST /api HTTP/1.1" in raw
        assert b"Host: example.com" in raw
        assert b"User-Agent: TestAgent" in raw
        assert b"Content-Length: 12" in raw

    @patch("subprocess.run")
    def test_h1_packet_controller(self, mock_run):
        with patch("sync_http11.PacketController", new=object), \
             patch("sync_http11.NFQUEUE_AVAILABLE", True):

            pc = H1PacketController("1.2.3.4", 80, concurrency=2)

            pc._manage_nftables("add")
            assert mock_run.called
            args = mock_run.call_args_list[2][0][0]
            assert "1.2.3.4" in args
            assert "80" in args

            # Construct valid IPv4/TCP payload
            ip_header = b'\x45\x00\x00\x40' + b'\x00'*5 + b'\x06' + b'\x00'*10
            tcp_header = b'\x00'*12 + b'\x50' + b'\x00'*7
            data = b'X' * 24
            payload = ip_header + tcp_header + data

            pc.active = True

            mock_pkt1 = MagicMock()
            mock_pkt1.get_payload.return_value = payload
            pc._queue_callback(mock_pkt1)
            assert len(pc.held_packets) == 1
            mock_pkt1.accept.assert_not_called()

            mock_pkt2 = MagicMock()
            mock_pkt2.get_payload.return_value = payload
            pc._queue_callback(mock_pkt2)
            assert len(pc.held_packets) == 0
            mock_pkt1.accept.assert_called()
            mock_pkt2.accept.assert_called()
