# tests/test_low_level_fixed.py
import pytest
import socket
import threading
from unittest.mock import MagicMock, patch, ANY
from low_level import HTTP2RaceEngine, CapturedRequest

class TestHTTP2RaceEngineFixed:
    
    @pytest.fixture
    def sample_req(self):
        return CapturedRequest(1, "GET", "https://[::1]:8443/", [], b"")

    @patch("low_level.socket.create_connection")
    @patch("low_level.ssl.create_default_context")
    def test_connect_ipv6_support(self, mock_ssl, mock_create_conn, sample_req):
        """
        VERIFICATION CASE 1: IPv6 Support
        Ensures connect() uses socket.create_connection with the IPv6 literal
        and DOES NOT call socket.gethostbyname (which fails on IPv6).
        """
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        assert engine.target_host == "::1"
        assert engine.target_port == 8443
        
        # Mock gethostbyname to ensure it is NOT called (or fails if it is)
        with patch("low_level.socket.gethostbyname", side_effect=socket.gaierror("IPv4 only!")) as mock_ghbn:
            engine.connect()
            
            # If gethostbyname was called, it would raise gaierror and connect() would fail
            # Since connect() succeeds (via mock_create_conn), we know the fix is working.
            mock_ghbn.assert_not_called()
            
            # Verify create_connection was called with the correct host/port tuple
            mock_create_conn.assert_called_with(("::1", 8443), timeout=ANY)

    def test_recv_thread_safety(self, sample_req):
        """
        VERIFICATION CASE 2: Socket Write Race Condition
        Ensures sock.sendall is called inside the lock context in _recv.
        """
        engine = HTTP2RaceEngine(sample_req, concurrency=1)
        engine.sock = MagicMock()
        engine.conn = MagicMock()
        engine.lock = MagicMock()
        
        # Mock selector to return one event then nothing
        with patch("low_level.selectors.DefaultSelector") as MockSelector:
            sel_inst = MockSelector.return_value
            # return event, then empty to break loop (via side effect logic or just once)
            mock_key = MagicMock()
            mock_key.fileobj = engine.sock
            sel_inst.select.side_effect = [[(mock_key, "READ")], []]
            
            engine.sock.recv.return_value = b"some_data"
            engine.conn.data_to_send.return_value = b"ACK_FRAME"
            
            # Run _recv (will run once then stop due to mock select returning empty)
            engine.sock.recv.side_effect = [b"data", b""]
            sel_inst.select.return_value = [(mock_key, "READ")]
            
            engine._recv()
            
            # Check Lock usage
            # We want to verify that `sock.sendall` was called while `lock` was acquired.
            # Using __enter__ check as proxy for lock acquisition
            assert engine.lock.__enter__.called
            assert engine.sock.sendall.called
            engine.sock.sendall.assert_called_with(b"ACK_FRAME")

    def test_cl_zero_insertion(self):
        """
        VERIFICATION CASE 3: Content-Length: 0 for Empty POST
        """
        req = CapturedRequest(1, "POST", "https://target.com", [], b"")
        engine = HTTP2RaceEngine(req, concurrency=1)
        
        headers = engine._build_headers(0)
        h_dict = dict(headers)
        
        # Must have content-length: 0
        assert h_dict[b'content-length'] == b'0'

    def test_ipv6_authority_bracketing(self):
        """
        VERIFICATION CASE 4: IPv6 Authority Headers
        """
        req = CapturedRequest(1, "GET", "https://[2001:db8::1]:8443/api", [], b"")
        engine = HTTP2RaceEngine(req, concurrency=1)
        
        headers = engine._build_headers(0)
        h_dict = dict(headers)
        
        # Check that authority header includes brackets
        assert h_dict[b':authority'] == b"[2001:db8::1]:8443"

    @patch("packet_controller.NFQUEUE_AVAILABLE", True)
    @patch("packet_controller.NetfilterQueue")
    @patch("packet_controller.subprocess.call")
    def test_packet_controller_long_timeout(self, mock_sub, mock_nfq):
        """
        VERIFICATION CASE 5: Packet Controller Timeout
        Verifies that PacketController waits longer than the previous 0.5s hardcoded limit.
        """
        from packet_controller import PacketController
        pc = PacketController("1.2.3.4", 80, 12345)
        pc.active = True
        pc.first_packet_held.set() # Wait 1 passes immediately
        
        # Mock the subsequent_packets_released event
        pc.subsequent_packets_released = MagicMock()
        
        # Break the loop after one pass by unsetting active via side effect
        def side_effect(*args, **kwargs):
            pc.active = False
            return True
        pc.subsequent_packets_released.wait.side_effect = side_effect
        
        with patch("time.sleep"): 
             pc._delayed_release()
        
        # Verify call args
        args, kwargs = pc.subsequent_packets_released.wait.call_args
        # Should be 5.0 now
        assert kwargs['timeout'] >= 5.0