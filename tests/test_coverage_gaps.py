# tests/test_coverage_gaps.py
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import CaptureServer, Last_Byte_Stream_Body, main
import sys
import logging

async def a_next(gen):
    try:
        return await gen.__anext__()
    except StopAsyncIteration:
        raise

@pytest.mark.asyncio
async def test_capture_server_absolute_uri_request():
    port = 8891
    # [FIX] Added bind_addr
    server = CaptureServer(port=port, bind_addr="127.0.0.1", enable_tunneling=False)
    reader = AsyncMock()
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()

    reader.readline.side_effect = [
        b"GET http://external.com/foo HTTP/1.1\r\n", 
        b"Host: external.com\r\n",                   
        b"Content-Length: 0\r\n",
        b"\r\n"
    ]
    await server.handle_client(reader, writer)
    
    assert len(server.request_log) == 1
    assert server.request_log[0].url == "http://external.com/foo"

@pytest.mark.asyncio
async def test_capture_server_handle_client_exception(caplog):
    # [FIX] Added bind_addr
    server = CaptureServer(port=8892, bind_addr="127.0.0.1", enable_tunneling=False)
    reader = AsyncMock()
    writer = MagicMock()
    writer.close = MagicMock()
    writer.is_closing.return_value = False
    writer.wait_closed = AsyncMock()
    reader.readline.side_effect = ConnectionResetError("Connection lost")
    await server.handle_client(reader, writer)
    writer.close.assert_called()
    reader.readline.side_effect = Exception("Generic Error")
    
    # [FIX] Use caplog to capture logger error
    with caplog.at_level(logging.ERROR):
        await server.handle_client(reader, writer)
    
    assert "Error handling request: Generic Error" in caplog.text

@pytest.mark.asyncio
async def test_xy_stream_body_broken_barrier():
    payload = b"AB"
    barrier = asyncio.Barrier(2)
    gen = Last_Byte_Stream_Body(payload, barrier, warmup_ms=0)
    try:
        part1 = await a_next(gen)
        assert part1 == b"A"
        await barrier.abort()
        part2 = await a_next(gen)
        assert part2 == b"B"
    finally:
        # FIX: Close generator to prevent 'coroutine never awaited' warning
        await gen.aclose()

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
            listen=8080, target=None, scope=None, concurrency=10, 
            warmup=100, strategy="auto", http2=False, bind="127.0.0.1"
        )
        server_instance = MockServer.return_value
        req = MagicMock()
        req.id = 0
        req.method = "GET"
        req.url = "http://example.com"
        req.__str__.return_value = "0      GET     http://example.com (0 bytes)"
        server_instance.request_log = [req] 
        server_instance.proxy_client = None
        server_instance.capture_count = 1
        mock_event = MagicMock()
        server_instance.stop_event = mock_event

        def interrupt_effect(coro):
            if coro and hasattr(coro, 'close'): coro.close()
            raise KeyboardInterrupt

        mock_asyncio_run.side_effect = [interrupt_effect, None]
        mock_run_scan.return_value = MagicMock()
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
             main()

        # [FIX] Use capsys to capture stderr
        captured = capsys.readouterr()
        # Verify execution flow: Either specific stderr msg OR menu appearing in stdout
        assert "Capture stopped" in captured.err or "Total requests captured" in captured.out