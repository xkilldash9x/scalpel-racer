import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer, XY_stream_body, main

# Line 85: elif path.startswith("http"): final_url = path
@pytest.mark.asyncio
async def test_capture_server_absolute_uri_request():
    port = 8891
    server = CaptureServer(port=port) # No target override

    # We can invoke handle_client directly to simulate a client sending absolute URI
    reader = AsyncMock()
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()

    # Simulate "GET http://external.com/foo HTTP/1.1"
    reader.readline.side_effect = [
        b"GET http://external.com/foo HTTP/1.1",
        b"Host: external.com\r\n",
        b"Content-Length: 0\r\n",
        b"\r\n",
        b"" # End of body
    ]
    reader.read.return_value = b""

    await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://external.com/foo"


# Line 114-115: Exception handling in handle_client
@pytest.mark.asyncio
async def test_capture_server_handle_client_exception(capsys):
    server = CaptureServer(port=8892)

    reader = AsyncMock()
    reader.readline.side_effect = Exception("Read Error")
    writer = MagicMock()
    writer.close = MagicMock()

    await server.handle_client(reader, writer)

    captured = capsys.readouterr()
    assert "[!] Error handling request: Read Error" in captured.out
    writer.close.assert_called_once()

# Line 133-134: BrokenBarrierError in XY_stream_body
@pytest.mark.asyncio
async def test_xy_stream_body_broken_barrier():
    payload = b"AB"
    barrier = asyncio.Barrier(2) # Needs 2 parties

    # We run the generator, which waits on barrier.
    # We will abort the barrier from outside.

    gen = XY_stream_body(payload, barrier, warmup_ms=0)

    # Get first part
    part1 = await anext(gen)
    assert part1 == b"A"

    # Now it's waiting on barrier.
    # Break the barrier
    await barrier.abort()

    # Next part should still come because exception is caught
    part2 = await anext(gen)
    assert part2 == b"B"


# Line 212-213: KeyboardInterrupt in main (capture loop)
def test_main_keyboard_interrupt(capsys):
    # We need to simulate KeyboardInterrupt during capture_server.start()

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

        # First call to asyncio.run is for capture_server.start()
        # Second call (if any) is for run_scan

        # We want the first call to raise KeyboardInterrupt
        mock_asyncio_run.side_effect = [KeyboardInterrupt, None]

        # We expect SystemExit(0) because input returns 'q', which calls sys.exit(0)
        # But we mocked sys.exit, so it might return None or something.
        # Wait, if input returns 'q', main calls sys.exit(0).
        # Since sys.exit is mocked, it will just register the call.
        # But main expects sys.exit to stop execution.

        # Let's make mock_exit raise SystemExit to properly exit main
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
             main()

        # Should continue to selection menu
        captured = capsys.readouterr()
        assert "Captured Requests" in captured.out
        mock_exit.assert_called_with(0)
