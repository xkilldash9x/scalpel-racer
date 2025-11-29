import pytest
from unittest.mock import MagicMock, patch, ANY
import io
import sys
import scalpel_racer

# --- Mocks ---

@pytest.fixture
def mock_stdin(monkeypatch):
    class MockStdin(io.StringIO):
        pass
    return MockStdin()

# --- Tests ---

def test_edit_request_body_interactive():
    # Mock CapturedRequest
    request = scalpel_racer.CapturedRequest(1, "POST", "http://example.com", {}, b"original")

    # Simulate user input: "new content" then Ctrl+D (empty string)
    with patch("sys.stdin", io.StringIO("new content\n")):
        scalpel_racer.edit_request_body(request)

    assert request.edited_body == b"new content\n"

def test_edit_request_body_empty_confirm_no():
    request = scalpel_racer.CapturedRequest(1, "POST", "http://example.com", {}, b"original")

    # Simulate empty input then 'n' for confirmation
    with patch("sys.stdin", io.StringIO("")), \
         patch("builtins.input", side_effect=["n"]):

        scalpel_racer.edit_request_body(request)

    assert request.edited_body is None # Should remain None (unchanged)

def test_edit_request_body_empty_confirm_yes():
    request = scalpel_racer.CapturedRequest(1, "POST", "http://example.com", {}, b"original")

    # Simulate empty input then 'y' for confirmation
    with patch("sys.stdin", io.StringIO("")), \
         patch("builtins.input", side_effect=["y"]):

        scalpel_racer.edit_request_body(request)

    assert request.edited_body == b""

@patch("scalpel_racer.run_scan")
@patch("scalpel_racer.CaptureServer")
def test_main_cli_flow(MockCaptureServer, mock_run_scan):
    # Mock capture server behavior
    server_instance = MockCaptureServer.return_value
    server_instance.request_log = [
        scalpel_racer.CapturedRequest(0, "GET", "http://test.com", {}, b"")
    ]

    # Mock CLI args
    with patch("sys.argv", ["scalpel_racer.py", "-l", "9090"]):
        # Mock inputs: select ID 0, then quit
        with patch("builtins.input", side_effect=["0", "\n", "q"]):
            with pytest.raises(SystemExit) as excinfo:
                scalpel_racer.main()
            assert excinfo.value.code == 0

    MockCaptureServer.assert_called_with(9090, None, None, enable_tunneling=True)
    mock_run_scan.assert_called_once()
    args, _ = mock_run_scan.call_args
    assert args[0].id == 0

@patch("scalpel_racer.CaptureServer")
def test_main_no_capture(MockCaptureServer):
    server_instance = MockCaptureServer.return_value
    server_instance.request_log = [] # Empty log

    with patch("sys.argv", ["scalpel_racer.py"]):
        with pytest.raises(SystemExit):
            scalpel_racer.main()
