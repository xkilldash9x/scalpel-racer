import pytest
import sys
import asyncio
import os
from unittest.mock import patch, MagicMock, AsyncMock
import scalpel_racer

# Helper side_effect for mocked asyncio.run.
def clean_run(coro):
    """ Simulates asyncio.run() without actually running the loop, for testing CLI orchestration. """
    # Safety: If a real coroutine sneaks in, close it to silence RuntimeWarnings
    if asyncio.iscoroutine(coro):
        try:
            coro.close()
        except RuntimeError:
            # Handle cases where the coroutine might already be closed or in a weird state
            pass
    return None

def test_main_cli_flow_success_standard():
    # Test standard flow: start server, capture request (simulated), select request, run scan, quit
    test_args = ["scalpel_racer.py", "-c", "5"] # No target override

    # Mock CAManager initialization which happens in main
    # Sequence of inputs: Select request 0, Press Enter after scan, Quit
    with patch("scalpel_racer.CAManager") as MockCAManager, \
         patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
         patch.object(sys, 'argv', test_args), \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["0", "", "q"]), \
         patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run, \
         patch("scalpel_racer.run_scan") as mock_run_scan, \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit

        server_instance = MockServer.return_value
        req0 = scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        server_instance.request_log = [req0]
        server_instance.proxy_client = None # Simulate client not initialized
        
        with pytest.raises(SystemExit):
            scalpel_racer.main()

        # Check that CAManager was initialized
        MockCAManager.assert_called_once()

        # Check that CaptureServer was initialized with tunneling enabled
        MockServer.assert_called_with(8080, None, None, enable_tunneling=True)

        # Check that asyncio.run was called (Server start, (optional client close), run_scan)
        assert mock_asyncio_run.call_count >= 2 # Server start + run_scan

def test_main_cli_edit_and_race(capsys):
    test_args = ["scalpel_racer.py", "-t", "http://example.com"]
    new_body_input = "A{{SYNC}}B\nC\n" # Multiline body with newline at the end

    # Mock CAManager initialization
    # Sequence of inputs: Edit request 0, Select request 0, Press Enter after scan, Quit
    # Simulate reading lines until EOF (empty string) for the body editor
    with patch("scalpel_racer.CAManager"), \
         patch.object(sys, 'argv', test_args), \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["e 0", "0", "", "q"]), \
         patch("sys.stdin.readline", side_effect=[new_body_input, ""]), \
         patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run, \
         patch("scalpel_racer.run_scan") as mock_run_scan, \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit

        server_instance = MockServer.return_value
        req0 = scalpel_racer.CapturedRequest(0, "POST", "http://example.com/foo", {}, b"original")
        server_instance.request_log = [req0]
        server_instance.proxy_client = None
        
        with pytest.raises(SystemExit):
            scalpel_racer.main()

        # Verify the body was edited correctly, preserving line endings
        assert req0.edited_body == b"A{{SYNC}}B\nC\n"
        
        # Verify the scan was run
        assert mock_asyncio_run.call_count >= 2
        
        captured = capsys.readouterr()
        assert "Body updated." in captured.out
        assert "Sync points: 1" in captured.out

def test_main_cli_invalid_input(capsys):
    test_args = ["scalpel_racer.py"]

    # Mock CAManager initialization
    with patch("scalpel_racer.CAManager"), \
         patch.object(sys, 'argv', test_args), \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["invalid", "99", "q"]), \
         patch("asyncio.run", side_effect=clean_run), \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit

        server_instance = MockServer.return_value
        server_instance.request_log = [
            scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        ]
        server_instance.proxy_client = None

        with pytest.raises(SystemExit):
            scalpel_racer.main()

        captured = capsys.readouterr()
        assert "Invalid command." in captured.out
        assert "Invalid ID." in captured.out
        mock_exit.assert_called_with(0)

@patch("sys.platform", "linux")
# Mock os.geteuid only if it exists (non-Windows)
@patch("os.geteuid", return_value=1000 if hasattr(os, 'geteuid') else None)
def test_main_cli_first_seq_warning(mock_geteuid, capsys):
    test_args = ["scalpel_racer.py", "--strategy", "first-seq"]

    with patch("scalpel_racer.CAManager"), \
         patch.object(sys, 'argv', test_args), \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["q"]), \
         patch("asyncio.run", side_effect=clean_run), \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit
        server_instance = MockServer.return_value
        server_instance.request_log = []

        with pytest.raises(SystemExit):
            scalpel_racer.main()

        captured = capsys.readouterr()
        assert "[!] Warning: 'first-seq' strategy requires Linux and Root privileges." in captured.out