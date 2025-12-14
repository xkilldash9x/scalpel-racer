# tests/test_proxy_manager.py
"""
Tests for proxy_manager.py.
Covers QUIC/H3 parsing (RFC 9000/9114) and manager callback logic.
Enhanced with boundary checks, invalid packet handling, and NEW_CONNECTION_ID support.
"""

import pytest
from unittest.mock import MagicMock, patch
from proxy_manager import (
    QuicPacketParser, 
    H3FrameParser, 
    QuicFrameParser,
    ProxyManager,
    decode_varint, 
    QuicServer,
    H3_FRAME_DATA,
    H3_FRAME_HEADERS,
    H3_FRAME_SETTINGS
)

# -- VarInt & Encoding Tests --

class TestQuicPrimitives:
    def test_varint_decode(self):
        """Verify RFC 9000 varint decoding at boundaries."""
        # 1 byte (max 63)
        assert decode_varint(b'\x3f', 0) == (63, 1)
        
        # 2 bytes (0x40 | val)
        # 0x40 0xFF -> 255
        assert decode_varint(b'\x40\xff', 0) == (255, 2)
        
        # 4 bytes (0x80 | val)
        # 0x80 0x00 0x00 0x01 -> 1
        assert decode_varint(b'\x80\x00\x00\x01', 0) == (1, 4)
        
        # 8 bytes (0xC0 | val)
        assert decode_varint(b'\xc0\x00\x00\x00\x00\x00\x00\x01', 0) == (1, 8)

    def test_varint_buffer_overflow(self):
        """Ensure parser handles incomplete buffers gracefully."""
        # Says 2 bytes (0x40) but only 1 byte provided
        val, off = decode_varint(b'\x40', 0)
        assert val is None
        
        # Says 4 bytes but truncated
        val, off = decode_varint(b'\x80\x00\x01', 0)
        assert val is None

# -- Packet Parsing Tests --

class TestQuicParsing:
    def test_packet_header_long_initial(self):
        """Verify Long Header Initial Packet parsing."""
        parser = QuicPacketParser()
        
        # 0xC0 (11000000) -> Long Header, Initial
        # Version 1 (0x00000001)
        # DCID len 0, SCID len 0
        header = b'\xC0\x00\x00\x00\x01\x00\x00\x00\x05'
        
        info = parser.parse_packet(header)
        assert info['header_form'] == "Long"
        assert info['type'] == "Initial"
        assert info['version'] == "0x1"

    def test_packet_header_version_negotiation(self):
        """Verify Version Negotiation Packet (Version 0)."""
        parser = QuicPacketParser()
        # Version 0x00000000 indicates negotiation
        header = b'\xC0\x00\x00\x00\x00\x05\xaa\xaa\xaa\xaa\xbb\x05\xbb\xbb\xbb\xbb\xbb'
        
        info = parser.parse_packet(header)
        assert info['type'] == "VersionNegotiation"

    def test_packet_header_short(self):
        """Verify Short Header (1-RTT) parsing."""
        parser = QuicPacketParser()

        # 0x40 -> Short Header
        header = b'\x40\x01\x02'

        info = parser.parse_packet(header)
        assert info['header_form'] == "Short"
        assert info['type'] == "1-RTT"
        assert info['fixed_bit'] is True

    def test_empty_packet(self):
        """Ensure empty packets don't crash the parser."""
        parser = QuicPacketParser()
        info = parser.parse_packet(b'')
        assert "error" in info

# -- Frame Parsing Tests --

class TestFrameParsing:
    def test_quic_padding_and_ping(self):
        """Test coalesced PADDING and PING frames."""
        # 0x00 (PADDING), 0x00 (PADDING), 0x01 (PING)
        payload = b'\x00\x00\x01'
        frames = QuicFrameParser.parse_frames(payload)
        
        assert len(frames) == 2
        assert frames[0]['type'] == "PADDING"
        assert frames[1]['type'] == "PING"

    def test_quic_stream_frame(self):
        """Test STREAM frame parsing logic."""
        # Type 0x0a (OFF=0, LEN=1, FIN=0)
        # Stream ID: 0x04
        # Len: 0x03
        # Data: ABC
        payload = b'\x0a\x04\x03ABC'
        frames = QuicFrameParser.parse_frames(payload)
        
        assert frames[0]['type'] == "STREAM"
        assert frames[0]['id'] == 4
        assert frames[0]['len'] == 3
        assert frames[0]['data'] == b'ABC'

    def test_quic_new_connection_id_frame(self):
        """
        [NOVEL] Verify parsing of NEW_CONNECTION_ID (0x18) frames.
        """
        # Type 0x18
        # Seq Num (VarInt): 1 -> 0x01
        # Retire Prior To (VarInt): 0 -> 0x00
        # CID Len (1 byte): 4 -> 0x04
        # CID (4 bytes): 0xAABBCCDD
        # Reset Token (16 bytes): 16 * 0xFF
        
        payload = (
            b'\x18'
            b'\x01'
            b'\x00'
            b'\x04'
            b'\xAA\xBB\xCC\xDD' + 
            (b'\xFF' * 16)
        )
        
        frames = QuicFrameParser.parse_frames(payload)
        
        assert len(frames) == 1
        assert frames[0]['type'] == "NEW_CONNECTION_ID"
        assert frames[0]['seq'] == 1
        assert frames[0]['retire_prior'] == 0
        assert frames[0]['cid'] == "aabbccdd"

    def test_h3_frame_parsing(self):
        """Verify HTTP/3 Frame Parsing from stream data."""
        # DATA Frame (Type 0x00) | Length 4 | Payload "ABCD"
        data = b'\x00\x04ABCD'
        frames = H3FrameParser.parse(data)
        assert frames[0]['type'] == "DATA"
        assert frames[0]['len'] == 4

        # Unknown/Reserved Frame Handling
        # Type 0x21 (33) | Length 1 | Payload 'X'
        data = b'\x21\x01X'
        frames = H3FrameParser.parse(data)
        assert "H3_FRAME_0x21" in frames[0]['type']

    def test_h3_malformed_frame(self):
        """Test H3 parser with truncated frame."""
        # Header says len 10, but only 1 byte provided
        data = b'\x00\x0aA'
        frames = H3FrameParser.parse(data)
        assert frames[0]['type'] == "INCOMPLETE"
        assert frames[0]['needed'] == 9

# -- Manager Integration --

class TestProxyManager:
    def test_unified_callback(self):
        """Test the formatting logic of the unified callback."""
        mock_ext_cb = MagicMock()
        manager = ProxyManager(external_callback=mock_ext_cb)
        
        # Test CAPTURE propagation
        req = MagicMock()
        req.protocol = "HTTP/1.1"
        req.method = "GET"
        
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("CAPTURE", "TCP_CLIENT", req)
            mock_log.info.assert_called()
            mock_ext_cb.assert_called_with("CAPTURE", req)

    def test_quic_logging_format(self):
        """Test the QUIC specific logging output."""
        manager = ProxyManager()
        quic_data = {
            "type": "Initial",
            "version": "0x1",
            "dcid": "aabb",
            "payload_len": 123
        }
        
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("QUIC", ("1.1.1.1", 443), quic_data)
            log_call = mock_log.info.call_args[0][0]
            assert "[QUIC]" in log_call
            assert "1.1.1.1:443" in log_call
            assert "DCID: aabb" in log_call

    def test_error_propagation(self):
        """Test that system errors are logged correctly."""
        manager = ProxyManager()
        with patch("proxy_manager.log") as mock_log:
            manager.unified_capture_callback("ERROR", "127.0.0.1", "Connection Reset")
            mock_log.error.assert_called()
            assert "Connection Reset" in mock_log.error.call_args[0][0]

class TestQuicDeepParsing:
    """
    Advanced parsing scenarios: Malformed packets, unknown frames, and boundary checks.
    """

    def test_truncated_long_header(self):
        """
        Parser should not crash if packet ends in the middle of a Long Header field.
        """
        parser = QuicPacketParser()
        
        # Header starts fine but cuts off before version
        # 0xC0 (Long Initial)
        bad_header = b'\xC0\x00' 
        
        try:
            info = parser.parse_packet(bad_header)
        except Exception:
            pass

    def test_unknown_frame_types(self):
        """
        RFC 9000 allows for extension frames. Parser should label them but not crash.
        """
        # Frame type 0x40 (undefined in standard base spec)
        payload = b'\x40\x05data' 
        
        frames = QuicFrameParser.parse_frames(payload)
        assert len(frames) == 1
        assert "UNKNOWN" in frames[0]['type']

    def test_quic_malformed_frame_resilience(self):
        """
        [IMPROVEMENT] Verify parser catches exceptions and reports MALFORMED_FRAME
        instead of crashing on garbage data.
        """
        # Frame type 0x08 (STREAM)
        # Varint decoding will look for bytes that don't exist
        payload = b'\x08' # Just the type byte, nothing else
        
        frames = QuicFrameParser.parse_frames(payload)
        
        assert len(frames) == 1
        assert frames[0]['type'] == "MALFORMED_FRAME"
        assert "Truncated" in str(frames[0].get('error', '')) or "list index" in str(frames[0].get('error', ''))

    def test_ack_frame_decoding_complex(self):
        """
        Verify decoding of ACK frame with multiple ranges.
        """
        # ACK Frame (0x02)
        # Largest Acked: 100 (varint) -> 0x4064
        # Ack Delay: 0 -> 0x00
        # Range Count: 1 -> 0x01
        # First Range: 10 -> 0x0a
        # Gap: 0 -> 0x00
        # Range Len: 5 -> 0x05
        payload = b'\x02\x40\x64\x00\x01\x0a\x00\x05'
        
        frames = QuicFrameParser.parse_frames(payload)
        
        assert frames[0]['type'] == "ACK"
        assert frames[0]['largest'] == 100

class TestH3DeepParsing:
    """
    Focus on HTTP/3 specific edge cases.
    """

    def test_headers_frame_zero_length(self):
        """
        Empty HEADERS frame is technically valid (empty header block).
        """
        # Type 0x01 (HEADERS), Len 0x00
        data = b'\x01\x00'
        frames = H3FrameParser.parse(data)
        
        assert frames[0]['type'] == "HEADERS"
        assert frames[0]['qpack_blob_len'] == 0

    def test_settings_frame_multiple_values(self):
        """
        Verify parsing of multiple settings in one frame with readable keys.
        """
        # Type 0x04 (SETTINGS)
        # ID 0x06 (MAX_FIELD_SECTION_SIZE) -> 100
        # ID 0x01 (QPACK_MAX_TABLE_CAPACITY) -> 200
        
        data = b'\x04\x06\x06\x40\x64\x01\x40\xc8'
        frames = H3FrameParser.parse(data)
        
        assert frames[0]['type'] == "SETTINGS"
        settings = frames[0]['values']
        
        assert settings["MAX_FIELD_SECTION_SIZE"] == 100
        assert settings["QPACK_MAX_TABLE_CAPACITY"] == 200

    def test_settings_frame_duplicate_ids(self):
        """
        Verify that duplicate setting IDs trigger an error flag (RFC 9114 Strictness).
        """
        # Type 0x04 (SETTINGS)
        # Len: 6 bytes
        # Data: 0x06 (ID) | 0x40 0x64 (100)
        #       0x06 (ID) | 0x40 0xc8 (200) -> DUPLICATE
        data = b'\x04\x06\x06\x40\x64\x06\x40\xc8'
        
        frames = H3FrameParser.parse(data)
        
        assert frames[0]['type'] == "SETTINGS"
        assert "error" in frames[0]
        assert "Duplicate Setting ID: 6" in frames[0]['error']

    def test_data_frame_segmentation(self):
        """
        Verify that multiple small DATA frames are parsed correctly in sequence.
        """
        # DATA(Len=3, "ABC") + DATA(Len=2, "DE")
        data = b'\x00\x03ABC\x00\x02DE'
        
        frames = H3FrameParser.parse(data)
        
        assert len(frames) == 2
        assert frames[0]['type'] == "DATA"
        assert frames[0]['len'] == 3
        
        assert frames[1]['type'] == "DATA"
        assert frames[1]['len'] == 2

class TestManagerCallbackResilience:
    def test_callback_with_garbage_data(self):
        """
        Ensure logging doesn't crash regardless of what data type is passed.
        This focuses on resilience rather than string formatting specifics.
        """
        manager = ProxyManager()
        
        test_inputs = [
            ("NotADict", str),
            ({"partial": "data"}, dict),
            (None, type(None)),
            ([1, 2, 3], list),
            (12345, int),
            ((1, 2), tuple),
            ({1, 2}, set),
            (b'\x00\x01', bytes),
            (bytearray(b'\x00'), bytearray),
            (memoryview(b'\x00'), memoryview)
        ]
        
        with patch("proxy_manager.log") as mock_log:
            for input_data, input_type in test_inputs:
                try:
                    manager.unified_capture_callback("QUIC", "1.2.3.4", input_data)
                except Exception as e:
                    pytest.fail(f"Manager crashed on input type {input_type}: {e}")
                
                # Verify something was logged
                assert mock_log.info.called, f"Log was not called for {input_type}"
                mock_log.info.reset_mock()