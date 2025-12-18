import pytest
from structures import CapturedRequest

class TestStructures:
    def test_captured_request_payload(self):
        req = CapturedRequest(1, "POST", "http://example.com", [], b"original")
        assert req.get_attack_payload() == b"original"
        req.edited_body = b"modified"
        assert req.get_attack_payload() == b"modified"
