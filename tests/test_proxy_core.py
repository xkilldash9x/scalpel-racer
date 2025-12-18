import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, call, ANY
from proxy_core import Http11ProxyHandler, NativeProxyHandler, DualProtocolHandler, StreamContext

class MockRequestReceived: pass
class MockDataReceived: pass
class MockStreamEnded: pass

class TestHttp11Proxy:
    @pytest.mark.asyncio
    async def test_cl_te_smuggling_prevention(self):
        reader = AsyncMock(); writer = MagicMock()
        reader.read.side_effect = [b""]
        handler = Http11ProxyHandler(reader, writer, "ex.com", None, None, None, enable_tunneling=False)
        
        async def mock_read(): return b"POST / HTTP/1.1\r\nHost: ex.com\r\nContent-Length: 500\r\nTransfer-Encoding: chunked\r\n\r\n"
        
        with patch.object(Http11ProxyHandler, '_read_strict_line', side_effect=[b"POST / HTTP/1.1", b"Transfer-Encoding: chunked", b"Content-Length: 500", b""]):
            with patch.object(Http11ProxyHandler, '_read_chunked_body', return_value=b""):
                with patch.object(Http11ProxyHandler, '_handle_request', new_callable=AsyncMock) as mock_handle:
                    await handler.run()
                    headers = mock_handle.call_args[0][4]
                    assert 'content-length' not in headers

class TestNativeProxyHandler:
    @pytest.mark.asyncio
    async def test_flow_control_blocking(self):
        handler = NativeProxyHandler(None, None, "", None, None, None)
        ctx = StreamContext(1, "https"); ctx.upstream_flow_event.clear()
        conn = MagicMock(); conn.outbound_flow_control_window = 0
        conn.remote_flow_control_window.return_value = 0
        queue = asyncio.Queue()
        await queue.put((b"DATA", False, 0))
        task = asyncio.create_task(handler._stream_sender(1, conn, AsyncMock(), queue, ctx.upstream_flow_event, asyncio.Lock(), asyncio.Lock(), None, None, None, None))
        await asyncio.sleep(0.1)
        conn.send_data.assert_not_called()
        task.cancel()
