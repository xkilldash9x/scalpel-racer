import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer, Last_Byte_Stream_Body, main

# Helper for async iteration compatibility
async def a_next(gen):
    try:
        return await gen.__anext__()
    except StopAsyncIteration:
        raise

# URL construction logic coverage (Integration test style using mocks)
@pytest.mark.asyncio
async def test_capture_server_absolute_uri_request():
    port = 8891
    # Initialize with enable_tunneling=False
    server = CaptureServer(port=port, enable_tunneling=False) # No target override

    reader = AsyncMock()
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    # Explicitly mock wait_closed as AsyncMock so it can be awaited
    writer.wait_closed = AsyncMock()

    # Simulate "GET http://external.com/foo HTTP/1.1" (Absolute-Form)
    # Configure the reader to return lines sequentially
    reader.readline.side_effect = [
        b"GET http://external.com/foo HTTP/1.1\r\n", 
        b"Host: external.com\r\n",                   
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]
    
    # We do NOT patch asyncio.wait_for here. 
    # The AsyncMock will return immediately, so wait_for will succeed immediately.
    await server.handle_client(reader, writer)

    assert len(server.request_log) == 1
    captured = server.request_log[0]
    assert captured.url == "http://external.com/foo"
    # Verify dummy response (HTTP/1.1 defaults to keep-alive)
    expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nCaptured."
    
    # Check the final write call matches the dummy response
    assert writer.write.call_args_list[-1].args[0] == expected_response


# Exception handling in handle_client
@pytest.mark.asyncio
async def test_capture_server_handle_client_exception(capsys):
    # Initialize with enable_tunneling=False
    server = CaptureServer(port=8892, enable_tunneling=False)

    reader = AsyncMock()
    writer = MagicMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    # Explicitly mock wait_closed as AsyncMock
    writer.wait_closed = AsyncMock()

    # 1. Test ConnectionResetError
    reader.readline.side_effect = ConnectionResetError("Connection lost")
    
    # Just call handle_client; AsyncMock propagates the exception
    await server.handle_client(reader, writer)

    # Verify writer is closed in finally block
    writer.close.assert_called()

    # 2. Test generic exception (should be logged)
    reader.readline.side_effect = Exception("Generic Error")
    
    await server.handle_client(reader, writer)
        
    captured = capsys.readouterr()
    assert "[!] Error handling request: Generic Error" in captured.out


# BrokenBarrierError in Last_Byte_Stream_Body
@pytest.mark.asyncio
async def test_xy_stream_body_broken_barrier():
    payload = b"AB"
    barrier = asyncio.Barrier(2) # Needs 2 parties

    gen = Last_Byte_Stream_Body(payload, barrier, warmup_ms=0)

    # Get first part
    part1 = await a_next(gen)
    assert part1 == b"A"

    # Now it's waiting on barrier.
    # Break the barrier
    await barrier.abort()

    # Next part should still come because exception is caught
    part2 = await a_next(gen)
    assert part2 == b"B"


# KeyboardInterrupt in main (capture loop)
def test_main_keyboard_interrupt(capsys):
    with (
         patch("scalpel_racer.CAManager"),
         patch("argparse.ArgumentParser.parse_args") as mock_args,
         patch("scalpel_racer.CaptureServer") as MockServer,
         patch("asyncio.run") as mock_asyncio_run,
         patch("scalpel_racer.run_scan") as mock_run_scan,
         patch("builtins.input", side_effect=["q"]),
         patch("sys.exit") as mock_exit
    ):

        mock_args.return_value = MagicMock(
            listen=8080,
            target=None, 
            scope=None,
            concurrency=10,
            warmup=100,
            strategy="auto",
            http2=False
        )

        server_instance = MockServer.return_value
        req = MagicMock()
        req.id = 0
        req.method = "GET"
        req.url = "http://example.com"
        req.__str__.return_value = "0     GET     http://example.com (0 bytes)"
        server_instance.request_log = [req] 
        server_instance.proxy_client = None
        
        mock_event = MagicMock()
        server_instance.stop_event = mock_event

        # We want the first call to raise KeyboardInterrupt (the server start)
        mock_asyncio_run.side_effect = [KeyboardInterrupt, None]
        
        mock_run_scan.return_value = MagicMock()
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
             main()

        captured = capsys.readouterr()
        assert "Capture stopped." in captured.out
        assert "Captured Requests" in captured.out
        mock_event.set.assert_called()
        mock_exit.assert_called_with(0)