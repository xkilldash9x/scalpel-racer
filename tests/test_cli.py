import pytest
import sys
import asyncio
import os
from unittest.mock import patch, MagicMock, AsyncMock
import scalpel_racer

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

def test_main_cli_flow_success_standard():
    test_args = ["scalpel_racer.py", "-c", "5"]
    
    with (
        patch("scalpel_racer.CAManager") as MockCAManager,
        patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True),
        patch.object(sys, 'argv', test_args),
        patch("scalpel_racer.CaptureServer") as MockServer,
        patch("builtins.input", side_effect=["0", "", "q"]),
        patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run,
        patch("scalpel_racer.run_scan") as mock_run_scan,
        patch("sys.exit") as mock_exit
    ):
        mock_exit.side_effect = SystemExit

        server_instance = MockServer.return_value
        req0 = scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        server_instance.request_log = [req0]
        server_instance.proxy_client = None 
        
        with pytest.raises(SystemExit):
            scalpel_racer.main()

        MockCAManager.assert_called_once()
        MockServer.assert_called_with(8080, None, None, enable_tunneling=True)
        assert mock_asyncio_run.call_count >= 2

def test_main_cli_edit_and_race(capsys):
    test_args = ["scalpel_racer.py", "-t", "http://example.com"]
    new_body_input = "A{{SYNC}}B\nC\n" 
    
    with (
        patch("scalpel_racer.CAManager"),
        patch.object(sys, 'argv', test_args),
        patch("scalpel_racer.CaptureServer") as MockServer,
        patch("builtins.input", side_effect=["e 0", "0", "", "q"]),
        patch("sys.stdin.readline", side_effect=[new_body_input, ""]), 
        patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run,
        patch("scalpel_racer.run_scan") as mock_run_scan,
        patch("sys.exit") as mock_exit
    ):
        mock_exit.side_effect = SystemExit

        server_instance = MockServer.return_value
        req0 = scalpel_racer.CapturedRequest(0, "POST", "http://example.com/foo", {}, b"original")
        server_instance.request_log = [req0]
        server_instance.proxy_client = None
        
        with pytest.raises(SystemExit):
            scalpel_racer.main()

        assert req0.edited_body == b"A{{SYNC}}B\nC\n"
        assert mock_asyncio_run.call_count >= 2
        
        captured = capsys.readouterr()
        assert "Body updated." in captured.out
        assert "Sync points: 1" in captured.out

def test_main_cli_invalid_input(capsys):
    test_args = ["scalpel_racer.py"]
    with (
        patch("scalpel_racer.CAManager"),
        patch.object(sys, 'argv', test_args),
        patch("scalpel_racer.CaptureServer") as MockServer,
        patch("builtins.input", side_effect=["invalid", "99", "q"]),
        patch("asyncio.run", side_effect=clean_run),
        patch("sys.exit") as mock_exit
    ):
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
    
    with (
        patch("scalpel_racer.CAManager"),
        patch.object(sys, 'argv', test_args), # Added missing argv patch
        patch("scalpel_racer.CaptureServer") as MockServer,
        patch("builtins.input", side_effect=["q"]),
        patch("asyncio.run", side_effect=clean_run),
        patch("sys.exit") as mock_exit
    ):
        mock_exit.side_effect = SystemExit
        server_instance = MockServer.return_value
        server_instance.request_log = []

        with pytest.raises(SystemExit):
            scalpel_racer.main()

        captured = capsys.readouterr()
        assert "[!] Warning: 'first-seq' strategy requires Linux and Root privileges." in captured.out