# tests/test_b01_tls_interception.py
import pytest
import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch
import scalpel_racer
from scalpel_racer import CaptureServer, TUNNEL_IDLE_TIMEOUT
try:
    from scalpel_racer import TLS_HANDSHAKE_TIMEOUT
except ImportError:
    TLS_HANDSHAKE_TIMEOUT = 10.0

# B01: Compatibility import for StreamReaderProtocol
try:
    from asyncio import StreamReaderProtocol
except ImportError:
    try:
        from asyncio.streams import StreamReaderProtocol
    except ImportError:
        StreamReaderProtocol = None

# Create a concrete mock class based on the imported protocol
class MockStreamReaderProtocol(StreamReaderProtocol):
    def __init__(self, reader, client_connected_cb=None, loop=None):
        super().__init__(reader, client_connected_cb, loop)
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        # Simplified connection_made for the test context

@pytest.mark.asyncio
async def test_b01_handle_connect_stream_rebinding(monkeypatch):
    """
    Verify B01 Fix: Ensure StreamReader/Writer are correctly rebound to the new TLS transport after upgrade.
    """
    if StreamReaderProtocol is None:
        pytest.skip("StreamReaderProtocol not available for testing B01 fix.")

    server = CaptureServer(port=8000, enable_tunneling=False)
    loop = asyncio.get_running_loop()

    # 1. Mock Dependencies (CA_MANAGER and loop.start_tls)
    mock_ca = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ca.get_ssl_context.return_value = mock_ssl_context

    # Mock loop.start_tls
    mock_start_tls = AsyncMock()
    mock_tls_transport = MagicMock(name="TLSTransport")
    mock_start_tls.return_value = mock_tls_transport
    
    # Patch environment for loop.start_tls
    monkeypatch.setattr("asyncio.get_running_loop", lambda: loop)
    # We need to patch the method on the actual loop object
    monkeypatch.setattr(loop, 'start_tls', mock_start_tls)


    # 2. Mock Initial Reader/Writer and Protocol
    initial_reader = asyncio.StreamReader(loop=loop)
    
    # Use the concrete mock protocol instance
    mock_protocol = MockStreamReaderProtocol(initial_reader, loop=loop)
    
    initial_transport = MagicMock(name="RawTransport")
    initial_transport.get_protocol.return_value = mock_protocol

    initial_writer = asyncio.StreamWriter(initial_transport, mock_protocol, initial_reader, loop)

    # 3. Configure Mocks for the interaction
    
    # Patch CA_MANAGER globally
    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        # We mock asyncio.wait_for to control the flow and inject data into the *new* reader.
        async def mock_wait_for(coro, timeout):
            # Check if this is the readline() call inside the tunnel loop
            if timeout == TUNNEL_IDLE_TIMEOUT:
                # Get the current reader from the protocol (this should be the new TLS reader)
                current_reader = mock_protocol._stream_reader
                
                # B01 Verification: Ensure the reader has changed
                assert current_reader != initial_reader, "B01 Regression: Reader was not replaced after start_tls."

                # Feed data into the new reader if not already done
                if not getattr(current_reader, '_test_data_fed', False):
                    current_reader.feed_data(b"GET /api/data HTTP/1.1\r\n")
                    current_reader.feed_data(b"Host: secure.example.com\r\n\r\n")
                    # Test relaxed parsing (second request)
                    current_reader.feed_data(b"GET /api/relaxed\r\n")
                    current_reader.feed_data(b"Host: secure.example.com\r\n\r\n")
                    current_reader.feed_eof()
                    current_reader._test_data_fed = True

            # Await the original coroutine (start_tls or readline or read_headers/body)
            return await coro

        # Call the handler
        connect_target = "secure.example.com:443"
        with patch('asyncio.wait_for', side_effect=mock_wait_for):
            # Run handle_connect. It will wait inside mock_wait_for where we inject data.
            await server.handle_connect(initial_reader, initial_writer, connect_target)

        # 4. Verify Interactions
        
        # Verify both requests inside the tunnel were processed and captured
        assert len(server.request_log) == 2
        captured1 = server.request_log[0]
        assert captured1.url == f"https://{connect_target}/api/data"

        captured2 = server.request_log[1]
        assert captured2.url == f"https://{connect_target}/api/relaxed"


@pytest.mark.asyncio
async def test_b02_handle_connect_h2_preface_detection(monkeypatch):
    """Verify B02 Fix: Detect and reject HTTP/2 preface inside the tunnel."""
    if StreamReaderProtocol is None:
        pytest.skip("StreamReaderProtocol not available.")

    server = CaptureServer(port=8000, enable_tunneling=False)
    loop = asyncio.get_running_loop()

    # 1. Mock Dependencies
    mock_ca = MagicMock()
    mock_ca.get_ssl_context.return_value = MagicMock()
    
    mock_start_tls = AsyncMock()
    mock_start_tls.return_value = MagicMock()

    monkeypatch.setattr("asyncio.get_running_loop", lambda: loop)
    monkeypatch.setattr(loop, 'start_tls', mock_start_tls)

    # 2. Mock Protocol/Reader/Writer
    initial_reader = asyncio.StreamReader(loop=loop)
    mock_protocol = MockStreamReaderProtocol(initial_reader, loop=loop)
    initial_transport = MagicMock()
    initial_transport.get_protocol.return_value = mock_protocol
    initial_writer = asyncio.StreamWriter(initial_transport, mock_protocol, initial_reader, loop)


    with patch.dict('scalpel_racer.__dict__', {'CA_MANAGER': mock_ca}):

        async def mock_wait_for(coro, timeout):
            if timeout == TUNNEL_IDLE_TIMEOUT:
                current_reader = mock_protocol._stream_reader
                # Feed the H2 preface
                if not getattr(current_reader, '_test_data_fed', False):
                    # The exact H2 connection preface
                    current_reader.feed_data(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                    current_reader.feed_eof()
                    current_reader._test_data_fed = True
            return await coro

        # Call the handler
        connect_target = "h2client.com:443"
        with patch('asyncio.wait_for', side_effect=mock_wait_for):
            await server.handle_connect(initial_reader, initial_writer, connect_target)

        # Verify that no request was logged (as it was rejected)
        assert len(server.request_log) == 0