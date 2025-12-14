# tests/test_structures.py

import pytest
from structures import CapturedRequest, ScanResult, HOP_BY_HOP_HEADERS

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

    def test_captured_request_headers_dict(self):
        """Ensure headers are correctly converted to dict."""
        headers = [("Host", "example.com"), ("Accept", "*/*")]
        req = CapturedRequest(1, "GET", "", headers, b"")
        assert req.headers_dict["Host"] == "example.com"

    def test_scan_result_init(self):
        """Ensure ScanResult stores data correctly."""
        res = ScanResult(index=0, status_code=200, duration=10.5, body_hash="abc")
        assert res.error is None
        assert res.status_code == 200
        assert res.body_hash == "abc"

    def test_hop_by_hop_constants(self):
        """Ensure critical headers are blacklisted."""
        assert "connection" in HOP_BY_HOP_HEADERS
        assert "upgrade" in HOP_BY_HOP_HEADERS