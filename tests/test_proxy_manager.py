import pytest
from unittest.mock import MagicMock, patch
from proxy_manager import QuicFrameParser, ProxyManager

class TestFrameParsing:
    def test_quic_stream_frame(self):
        payload = b'\x0a\x04\x03ABC'
        frames = QuicFrameParser.parse_frames(payload)
        assert frames[0]['type'] == "STREAM"
        assert frames[0]['data'] == b'ABC'

class TestManagerCallbackResilience:
    def test_callback_with_garbage(self):
        manager = ProxyManager()
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("QUIC", "1.2.3.4", "NotADict")
            assert mock_log.info.called
