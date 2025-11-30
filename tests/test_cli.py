import pytest
import sys
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import scalpel_racer

def clean_run(coro):
    """
    Helper side_effect for mocked asyncio.run.
    It closes the coroutine to prevent 'coroutine never awaited' warnings,
    then returns None.
    """
    if coro:
        coro.close()
    return None

def test_main_cli_quit_immediately(capsys):
    # Test quitting when no requests captured
    with patch("sys.exit") as mock_exit:
        # We need sys.exit to raise SystemExit so execution stops,
        # mirroring real behavior to prevent falling through to input()
        mock_exit.side_effect = SystemExit

        with patch("argparse.ArgumentParser.parse_args") as mock_args:
            mock_args.return_value = MagicMock(
                listen=8080,
                target="http://example.com",
                scope=None,
                concurrency=10,
                warmup=100,
                http2=False
            )

            # Mock CaptureServer start and request_log
            with patch("scalpel_racer.CaptureServer") as MockServer:
                instance = MockServer.return_value
                instance.start = AsyncMock()
                instance.request_log = [] # Empty log

                # Mock asyncio.run to do nothing for start but clean up
                with patch("asyncio.run", side_effect=clean_run):
                    # Expect SystemExit
                    with pytest.raises(SystemExit):
                        scalpel_racer.main()

                mock_exit.assert_called_with(0)
                captured = capsys.readouterr()
                assert "No requests captured" in captured.out

def test_main_cli_flow_success():
    with patch("argparse.ArgumentParser.parse_args") as mock_args, \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["0", "\n", "q"]), \
         patch("scalpel_racer.run_scan") as mock_run_scan, \
         patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run, \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit

        mock_args.return_value = MagicMock(
            listen=8080,
            target="http://example.com",
            scope=None,
            concurrency=10,
            warmup=100,
            http2=False
        )

        server_instance = MockServer.return_value
        server_instance.request_log = [
            scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        ]
        
        # Ensure the mocked run_scan returns a mock coroutine object so clean_run has something to close
        mock_run_scan.return_value = AsyncMock()

        # Wrap in raises because we now expect 'q' to trigger SystemExit
        with pytest.raises(SystemExit):
            scalpel_racer.main()

        # Check that run_scan was called
        mock_run_scan.assert_called_once()
        args = mock_run_scan.call_args
        assert args[0][0].id == 0 # First arg is request
        assert args[0][1] == 10 # concurrency

def test_main_cli_invalid_input(capsys):
    with patch("argparse.ArgumentParser.parse_args") as mock_args, \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["invalid", "99", "q"]), \
         patch("asyncio.run", side_effect=clean_run) as mock_asyncio_run, \
         patch("sys.exit") as mock_exit:

        mock_exit.side_effect = SystemExit

        mock_args.return_value = MagicMock(
            listen=8080,
            target="http://example.com",
            scope=None,
            concurrency=10,
            warmup=100,
            http2=False
        )

        server_instance = MockServer.return_value
        server_instance.request_log = [
            scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        ]

        with pytest.raises(SystemExit):
            scalpel_racer.main()

        captured = capsys.readouterr()
        # Corrected assertions based on actual code output
        assert "Invalid command." in captured.out
        assert "Invalid ID." in captured.out
        mock_exit.assert_called_with(0)

def test_main_keyboard_interrupt(capsys):
    # We need to simulate KeyboardInterrupt during capture_server.start()
    
    def interrupt_effect(coro):
        """Clean up the coro then die."""
        if coro:
            coro.close()
        raise KeyboardInterrupt

    with patch("argparse.ArgumentParser.parse_args") as mock_args, \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("asyncio.run") as mock_asyncio_run, \
         patch("builtins.input", side_effect=["q"]), \
         patch("sys.exit") as mock_exit:

        mock_args.return_value = MagicMock(
            listen=8080,
            target="http://example.com",
            scope=None,
            concurrency=10,
            warmup=100,
            http2=False
        )

        server_instance = MockServer.return_value
        req = MagicMock()
        req.id = 0
        req.method = "GET"
        req.url = "http://example.com"
        server_instance.request_log = [req] # Ensure log not empty so we don't exit early

        # First call to asyncio.run (server.start) raises KeyboardInterrupt
        # Second call (if any) should just pass.
        # We use side_effect with the custom cleanup function.
        mock_asyncio_run.side_effect = [interrupt_effect, clean_run]

        # Let's make mock_exit raise SystemExit to properly exit main
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
             scalpel_racer.main()

        # Should continue to selection menu
        captured = capsys.readouterr()
        assert "Captured Requests" in captured.out
    
        mock_exit.assert_called_with(0)