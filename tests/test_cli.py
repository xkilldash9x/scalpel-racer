import pytest
import sys
from unittest.mock import patch, MagicMock, AsyncMock
import scalpel_racer

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

                # Mock asyncio.run to do nothing for start
                with patch("asyncio.run"):
                    # Expect SystemExit
                    with pytest.raises(SystemExit):
                        scalpel_racer.main()

                mock_exit.assert_called_with(0)
                captured = capsys.readouterr()
                assert "No requests captured" in captured.out

def test_main_cli_flow_success():
    with patch("argparse.ArgumentParser.parse_args") as mock_args, \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["0"]), \
         patch("scalpel_racer.run_scan") as mock_run_scan, \
         patch("asyncio.run") as mock_asyncio_run, \
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
        server_instance.request_log = [
            scalpel_racer.CapturedRequest(0, "GET", "http://example.com/foo", {}, b"")
        ]

        # main calls asyncio.run(capture_server.start()) -> mock_asyncio_run
        # main calls input() -> "0"
        # main calls asyncio.run(run_scan(...)) -> mock_asyncio_run
        # Then loop breaks because we didn't loop in main?
        # Wait, the main loop is:
        # while True:
        #    choice = input(...)
        #    ...
        #    if selected_req:
        #         asyncio.run(run_scan(...))
        #         break

        scalpel_racer.main()

        # Check that run_scan was called
        # mock_run_scan is the function passed to asyncio.run
        # But wait, asyncio.run(coro).
        # We patched run_scan. So run_scan(...) returns a mock object (the coroutine).
        # asyncio.run is called with that mock object.

        mock_run_scan.assert_called_once()
        args = mock_run_scan.call_args
        assert args[0][0].id == 0 # First arg is request
        assert args[0][1] == 10 # concurrency

def test_main_cli_invalid_input(capsys):
    with patch("argparse.ArgumentParser.parse_args") as mock_args, \
         patch("scalpel_racer.CaptureServer") as MockServer, \
         patch("builtins.input", side_effect=["invalid", "99", "q"]), \
         patch("asyncio.run") as mock_asyncio_run, \
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
        assert "Invalid input." in captured.out
        assert "Invalid ID." in captured.out
        mock_exit.assert_called_with(0)
