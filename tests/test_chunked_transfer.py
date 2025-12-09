# tests/test_chunked_transfer.py
import asyncio
import pytest
import httpx
from scalpel_racer import CaptureServer, CapturedRequest

@pytest.mark.asyncio
async def test_chunked_request_capture(unused_tcp_port):
    port = unused_tcp_port
    # [FIX] Added bind_addr
    server = CaptureServer(port=port, bind_addr="127.0.0.1", enable_tunneling=False)
    server_task = asyncio.create_task(server.start())
    await asyncio.sleep(0.1)

    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        request_head = (
            b"POST /chunked HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )
        writer.write(request_head)

        writer.write(b"5\r\nHello\r\n")
        writer.write(b"6\r\n World\r\n")
        writer.write(b"0\r\n\r\n")
        await writer.drain()

        response = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        assert b"Captured" in response
        assert len(server.request_log) == 1
        captured = server.request_log[0]
        assert captured.body == b"Hello World"

    finally:
        server.stop_event.set()
        await server_task