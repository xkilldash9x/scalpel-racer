import asyncio
import pytest
import httpx
from scalpel_racer import CaptureServer, CapturedRequest

@pytest.mark.asyncio
async def test_chunked_request_capture(unused_tcp_port):
    port = unused_tcp_port
    server = CaptureServer(port=port, enable_tunneling=False)
    server_task = asyncio.create_task(server.start())
    await asyncio.sleep(0.1)

    try:
        # Manually send a chunked request using asyncio streams
        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        request_head = (
            b"POST /chunked HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )
        writer.write(request_head)

        # Send chunks
        writer.write(b"5\r\nHello\r\n")
        writer.write(b"6\r\n World\r\n")
        writer.write(b"0\r\n\r\n")
        await writer.drain()

        # Read response
        response = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        assert b"Captured" in response

        assert len(server.request_log) == 1
        captured = server.request_log[0]

        # Verify the captured body is the decoded content
        assert captured.body == b"Hello World"

    finally:
        server.stop_event.set()
        await server_task
