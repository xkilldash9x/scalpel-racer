# tests/test_structures.py

import pytest
from structures import CapturedRequest, ScanResult, RaceResult, HOP_BY_HOP_HEADERS, SENSITIVE_HEADERS

class TestStructures:
    def test_captured_request_payload(self):
        """Ensure edited_body takes precedence over body."""
        req = CapturedRequest(
            id=1, method="POST", url="http://example.com", 
            headers=[], body=b"original"
        )
        assert req.get_attack_payload() == b"original"
        assert req.truncated is False

        req.edited_body = b"modified"
        assert req.get_attack_payload() == b"modified"
        assert "[E]" in str(req)

    def test_captured_request_display(self):
        """Test CLI string formatting."""
        req = CapturedRequest(1, "GET", "http://long.com/" + "a"*100, [], b"")
        req.truncated = True
        s = str(req)
        assert "..." in s
        assert "[T]" in s

    def test_captured_request_redaction(self):
        """Test sensitive header redaction."""
        headers = [("Authorization", "Bearer Secret"), ("Cookie", "session=123"), ("Host", "example.com")]
        req = CapturedRequest(1, "GET", "", headers, b"")
        redacted = req._get_redacted_headers()
        assert "[REDACTED]" in redacted
        assert "Bearer Secret" not in redacted
        assert "session=123" not in redacted
        assert "example.com" in redacted

    def test_captured_request_to_dict(self):
        """Test dictionary serialization."""
        req = CapturedRequest(1, "GET", "url", [("H", "V")], b"body")
        d = req.to_dict()
        assert d['id'] == 1
        assert d['body'] == "body"

    def test_scan_result_init(self):
        """Ensure ScanResult stores data correctly."""
        res = ScanResult(index=0, status_code=200, duration=10.5, body_hash="abc")
        assert res.error is None
        assert res.status_code == 200
        assert res.body_hash == "abc"

    def test_hop_by_hop_constants(self):
        """Ensure critical headers are blacklisted."""
        assert "connection" in HOP_BY_HOP_HEADERS
        assert "content-length" in HOP_BY_HOP_HEADERS
        
    def test_race_result_methods(self):
        """Test RaceResult helper methods."""
        res = RaceResult(id=1, scan_results=[], final_status_code=200, final_body=b"final")
        
        # Fixed: Assert against bytes, not string
        assert res.get_final_body() == b"final"
        
        assert res.get_final_headers() == {}
        
        # Fixed: Assert against bytes, not string
        assert res.get_final_attack_payload() == b"final"
        
        # Removed: get_final_attack_headers() does not exist in RaceResult definition