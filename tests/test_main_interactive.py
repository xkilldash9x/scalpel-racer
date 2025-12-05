# FILE: ./tests/test_main_interactive.py
import pytest
from unittest.mock import MagicMock, patch, ANY
import io
import sys
import scalpel_racer
import asyncio

# --- Mocks ---

# Helper side_effect for mocked asyncio.run.
def clean_run(coro):
    """
    Simulates asyncio.run() without actually running the loop, for testing CLI orchestration.
    """
    if asyncio.iscoroutine(coro):
        try:
            coro.close()
        except RuntimeError:
            pass
    return None

# --- Tests ---

def test_edit_request_body_interactive():
    # Mock CapturedRequest
    request = scalpel_racer.CapturedRequest(1, "POST", "http://example.com", {}, b"original")

    # Simulate user input: "new content" then Ctrl+D (empty string via StringIO behavior)
    with patch("sys.stdin", io.StringIO("new content\n")):
        scalpel_racer.edit_request_body(request)

    assert request.edited_body == b"new content\n"

def test_edit_request_body_empty_confirm_no():
    request = scalpel_racer.CapturedRequest(1, "POST", "http://example.com", {}, b"original")

    # Simulate empty input then 'n' for confirmation
    # StringIO("") simulates immediate EOF for readline()
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

# Mock run_scan and CaptureServer for the main CLI flow test
@patch("scalpel_racer.run_scan")
@patch("scalpel_racer.CaptureServer")
# Mock CAManager initialization in main
@patch("scalpel_racer.CAManager")
# Mock asyncio.run to prevent actual execution
@patch("asyncio.run", side_effect=clean_run)
def test_main_cli_flow(mock_asyncio_run, MockCAManager, MockCaptureServer, mock_run_scan):
    # Mock capture server behavior
    server_instance = MockCaptureServer.return_value
    server_instance.request_log = [
        scalpel_racer.CapturedRequest(0, "GET", "http://test.com", {}, b"")
    ]
    # FIX: Initialize attributes accessed in main()
    server_instance.capture_count = 1
    # Simulate proxy_client being initialized so asyncio.run(client.aclose()) is called
    server_instance.proxy_client = MagicMock()

    # Mock CLI args
    # Note: When patching sys.argv, main() will parse them. The default strategy='auto' is handled by argparse.
    with patch("sys.argv", ["scalpel_racer.py", "-l", "9090"]):
        # Mock inputs: select ID 0, press Enter after scan, then quit
        with patch("builtins.input", side_effect=["0", "\n", "q"]):
            # main() calls sys.exit(0) on 'q'
            with pytest.raises(SystemExit) as excinfo:
                scalpel_racer.main()
            assert excinfo.value.code == 0

    # Verify initialization calls
    MockCaptureServer.assert_called_with(9090, None, None, enable_tunneling=True, bind_address='127.0.0.1')
    
    # Verify asyncio.run calls: server start, run_scan, client close
    assert mock_asyncio_run.call_count >= 3

@patch("scalpel_racer.CaptureServer")
@patch("scalpel_racer.CAManager")
@patch("asyncio.run", side_effect=clean_run)
def test_main_no_capture(mock_asyncio_run, MockCAManager, MockCaptureServer):
    server_instance = MockCaptureServer.return_value
    server_instance.request_log = [] # Empty log
    server_instance.proxy_client = None
    # FIX: Initialize attributes accessed in main()
    server_instance.capture_count = 0

    with patch("sys.argv", ["scalpel_racer.py"]):
        with pytest.raises(SystemExit) as excinfo:
            scalpel_racer.main()
        assert excinfo.value.code == 0