import pytest
import asyncio
import ssl
from unittest.mock import MagicMock, patch
import scalpel_racer

try:
    from asyncio import StreamReaderProtocol
except ImportError:
    try:
        from asyncio.streams import StreamReaderProtocol
    except ImportError:
        StreamReaderProtocol = None

class MockStreamReaderProtocol(StreamReaderProtocol):
    def __init__(self, reader, client_connected_cb=None, loop=None):
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
        super().__init__(reader, client_connected_cb, loop)
        self.transport = None
        
    def connection_made(self, transport):
        super().connection_made(transport)
        self.transport = transport

@pytest.mark.asyncio
async def test_b01_handle_connect_stream_rebinding(monkeypatch):
    if StreamReaderProtocol is None:
        pytest.skip("StreamReaderProtocol not available for testing B01 fix.")

    server = scalpel_racer.CaptureServer(port=8000, enable_tunneling=False)
    loop = asyncio.get_running_loop()

    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()
    
    # [FIX] Ensure mock transport has extra info to satisfy StreamWriter checks
    mock_tls_transport = MagicMock(name="TLSTransport")
    mock_tls_transport.get_extra_info.return_value = None 
    # [CRITICAL FIX] Ensure is_closing returns False so the loop in handle_connect runs
    mock_tls_transport.is_closing.return_value = False
    
    future_tls = asyncio.Future()
    future_tls.set_result(mock_tls_transport)
    mock_start_tls = MagicMock(return_value=future_tls)
    
    if not hasattr(loop, 'start_tls'):
        monkeypatch.setattr(loop, 'start_tls', mock_start_tls, raising=False)
    else:
        monkeypatch.setattr(loop, 'start_tls', mock_start_tls)

    managed_reader = asyncio.StreamReader()
    mock_protocol = MockStreamReaderProtocol(managed_reader, loop=loop)
    
    initial_transport = MagicMock(name="RawTransport")
    # [CRITICAL FIX] Ensure is_closing returns False for initial transport too
    initial_transport.is_closing.return_value = False
    # Ensure get_extra_info returns self for 'transport' to satisfy checks
    initial_transport.get_extra_info.side_effect = lambda name, default=None: initial_transport if name == 'transport' else default
    initial_transport.get_protocol.return_value = mock_protocol
    
    # [FIX] Manually call connection_made to ensure reader is connected to transport
    mock_protocol.connection_made(initial_transport)

    initial_writer = asyncio.StreamWriter(initial_transport, mock_protocol, managed_reader, loop)
    initial_reader_arg = managed_reader

    # [FIX] Pre-fill the reader with all data to avoid timing issues in mock_wait_for
    managed_reader.feed_data(b"GET /api/data HTTP/1.1\r\n")
    managed_reader.feed_data(b"Host: secure.example.com\r\n\r\n")
    managed_reader.feed_data(b"GET /api/relaxed\r\n")
    managed_reader.feed_data(b"Host: secure.example.com\r\n\r\n")
    managed_reader.feed_eof()

    async def mock_wait_for(coro, timeout):
        # Simply await the coroutine since data is already in the buffer
        return await coro
    
    connect_target = "secure.example.com:443"
    
    with patch.object(scalpel_racer, 'CA_MANAGER', mock_ca), \
         patch('asyncio.wait_for', side_effect=mock_wait_for):
        
        await server.handle_connect(initial_reader_arg, initial_writer, connect_target)

    # Assertions
    assert len(server.request_log) == 2, f"Request Log empty. Capture Count: {server.capture_count}"
    assert server.request_log[0].url == f"https://{connect_target}/api/data"
    assert server.request_log[1].url == f"https://{connect_target}/api/relaxed"