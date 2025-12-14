# tests/test_low_level.py
import pytest
import threading
import time
from unittest.mock import MagicMock, patch, ANY
from low_level import HTTP2RaceEngine
from structures import ScanResult, CapturedRequest

class TestHTTP2RaceEngine:
    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(
            id=1, method="POST", url="https://target.com/api",
            headers=[("User-Agent", "Test")], body=b"payload"
        )

    def test_initialization_parsing(self, sample_req):
        """Verify URL parsing and default port logic."""
        engine = HTTP2RaceEngine(sample_req, concurrency=5)
        assert engine.target_host == "target.com"
        assert engine.target_port == 443
        
        # Test HTTP default
        req_http = CapturedRequest(id=2, method="GET", url="http://target.com", headers=[], body=b"")
        engine_http = HTTP2RaceEngine(req_http, concurrency=1)
        assert engine_http.target_port == 80

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    def test_connect(self, mock_ssl, mock_conn, sample_req):
        """Verify socket configuration (Nagle's algo) and ALPN."""
        mock_raw_sock = MagicMock()
        mock_conn.return_value = mock_raw_sock
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.selected_alpn_protocol.return_value = "h2"
        mock_ssl.return_value.wrap_socket.return_value = mock_ssl_sock
        
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.connect()
        
        # Verify Nagle's algorithm disabled (TCP_NODELAY = 1)
        mock_raw_sock.setsockopt.assert_called()
        # Verify ALPN
        mock_ssl.return_value.set_alpn_protocols.assert_called_with(["h2"])

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    @patch("low_level.H2Connection")
    def test_spa_sequence(self, mock_h2, mock_ssl, mock_sock_create, sample_req):
        """
        Critical Test: Verifies payload splitting for SPA.
        Payload: b'payload' (7 bytes).
        Expected: 
          1. Send Headers (Stream 1)
          2. Send 'payloa' (6 bytes) -> end_stream=False
          3. Wait/Trigger
          4. Send 'd' (1 byte) -> end_stream=True
        """
        engine = HTTP2RaceEngine(sample_req, concurrency=1, strategy="spa", warmup_ms=0)
        
        # Mock connection setup
        mock_socket = MagicMock()
        mock_sock_create.return_value = mock_socket
        
        mock_ssl_ctx = mock_ssl.return_value
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.selected_alpn_protocol.return_value = "h2"
        mock_ssl_ctx.wrap_socket.return_value = mock_ssl_sock
        
        # Mock internal H2 state
        mock_conn_inst = mock_h2.return_value
        mock_conn_inst.get_next_available_stream_id.return_value = 1
        
        # Prevent blocking on receive loop
        with patch.object(engine, "_receive_loop"), \
             patch.object(engine.all_streams_finished, "wait"):
            engine.run_attack()
            
        # Verify Headers
        mock_conn_inst.send_headers.assert_called_once()
        
        # Verify Data Frames
        assert mock_conn_inst.send_data.call_count == 2
        
        args_list = mock_conn_inst.send_data.call_args_list
        # Call 1: Partial
        assert args_list[0][0][1] == b"payloa"
        assert args_list[0][1]['end_stream'] is False
        
        # Call 2: Final (Trigger)
        assert args_list[1][0][1] == b"d"
        assert args_list[1][1]['end_stream'] is True

    def test_process_events_logic(self, sample_req):
        """Test how the engine updates stream state based on H2 events."""
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        
        # Setup stream state manually
        sid = 1
        engine.streams[sid] = {
            "index": 0, "body": bytearray(), "finished": False, 
            "headers": {}, "error": None, "start_time": time.perf_counter()
        }
        
        # Mock Events
        mock_resp = MagicMock()
        mock_resp.stream_id = sid
        mock_resp.headers = [(b":status", b"200"), (b"server", b"test")]
        # isinstance check hack for MagicMock
        mock_resp.__class__.__name__ = "ResponseReceived" 
        
        mock_data = MagicMock()
        mock_data.stream_id = sid
        mock_data.data = b"XYZ"
        mock_data.flow_controlled_length = 3
        mock_data.__class__.__name__ = "DataReceived"

        mock_end = MagicMock()
        mock_end.stream_id = sid
        mock_end.__class__.__name__ = "StreamEnded"

        # Apply patching for isinstance to work with our mocks if needed, 
        # or better, use the real h2 events if available. 
        # Since we mocked h2 in conftest, we must simulate the type checks carefully.
        # However, low_level.py imports classes. We can patch those classes in the module.
        
        with patch("low_level.ResponseReceived", type("ResponseReceived", (), {})) as RR, \
             patch("low_level.DataReceived", type("DataReceived", (), {})) as DR, \
             patch("low_level.StreamEnded", type("StreamEnded", (), {})) as SE:
             
            # Re-create mocks as instances of these patched types
            e1 = RR(); e1.stream_id=sid; e1.headers=[(b":status", b"200")]
            e2 = DR(); e2.stream_id=sid; e2.data=b"XYZ"; e2.flow_controlled_length=3
            e3 = SE(); e3.stream_id=sid
            
            engine.conn = MagicMock() # Needs conn for acknowledgement
            
            # Process Response Headers
            engine._process([e1])
            assert engine.streams[sid]["headers"][":status"] == "200"
            
            # Process Data
            engine._process([e2])
            assert engine.streams[sid]["body"] == b"XYZ"
            engine.conn.acknowledge_received_data.assert_called_with(3, sid)
            
            # Process End
            engine._process([e3])
            assert engine.streams[sid]["finished"] is True
            assert engine.all_streams_finished.is_set()

    def test_finalize_results(self, sample_req):
        """Verify results are calculated and sorted correctly."""
        engine = HTTP2RaceEngine(sample_req, concurrency=2)
        engine.streams = {
            1: {"index": 1, "headers": {":status": "200"}, "body": b"A", "start_time": 100},
            3: {"index": 0, "headers": {":status": "404"}, "body": b"B", "start_time": 100}
        }
        # Mock time to calculate duration
        with patch("low_level.time.perf_counter", return_value=100.050): # +50ms
            results = engine._finalize_results()
            
        assert len(results) == 2
        # Sorted by index
        assert results[0].index == 0
        assert results[0].status_code == 404
        assert results[1].index == 1
        assert results[1].status_code == 200
        # Duration check (~50ms)
        assert 49.0 < results[0].duration < 51.0