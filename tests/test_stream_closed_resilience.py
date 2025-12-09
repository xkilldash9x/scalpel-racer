
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_core import NativeProxyHandler, ErrorCodes, H2Connection
from h2.exceptions import StreamClosedError, ProtocolError

# -- Test for StreamClosedError Resilience --

@pytest.mark.asyncio
async def test_stream_closed_resilience():
    """
    Verifies that the NativeProxyHandler does NOT terminate the connection
    when encountering a StreamClosedError, and continues to process subsequent frames.
    """

    # 1. Setup Mock Handler
    client_reader = MagicMock()
    client_writer = MagicMock()
    client_writer.drain = AsyncMock()
    client_writer.wait_closed = AsyncMock()
    client_writer.is_closing.return_value = False

    MockSettings = MagicMock()
    MockSettings.ENABLE_CONNECT_PROTOCOL = 8

    with patch("proxy_core.H2_AVAILABLE", True), \
         patch("proxy_core.H2Configuration"), \
         patch("proxy_core.SettingCodes", MockSettings):

        handler = NativeProxyHandler(
            client_reader, client_writer,
            "upstream.com:443", MagicMock(), None, None
        )

        # 2. Setup Connection Mock
        mock_conn = MagicMock(spec=H2Connection)
        handler.downstream_conn = mock_conn

        # Mock writer getter to avoid NoneType errors during flush
        handler.get_writer = MagicMock(return_value=client_writer)

        # 3. Simulate Event Sequence
        # Call 1: Raises StreamClosedError (e.g., late frame for closed stream)
        # Call 2: Returns valid events (e.g., new request on different stream)
        mock_conn.receive_data.side_effect = [
            StreamClosedError(1),
            [MagicMock(stream_id=3)]
        ]

        # 4. Mock Input Data Flow
        f_bad_frame = asyncio.Future(); f_bad_frame.set_result(b"BAD_FRAME")
        f_good_frame = asyncio.Future(); f_good_frame.set_result(b"GOOD_FRAME")
        f_eof = asyncio.Future(); f_eof.set_result(b"")

        client_reader.read.side_effect = [f_bad_frame, f_good_frame, f_eof]

        # 5. Patch Dependencies to prevent actual network calls/hanging
        handler.flush = AsyncMock()
        handler.terminate = AsyncMock()
        handler.graceful_shutdown = AsyncMock()

        # Bypass wait_for
        async def mock_wait_for(coro, timeout):
            return await coro

        with patch("asyncio.wait_for", side_effect=mock_wait_for):

            # 6. Run Read Loop
            async def noop_handler(evt): pass
            await handler.read_loop(client_reader, mock_conn, noop_handler)

            # 7. Assertions

            # Verify we tried to read 3 times (Bad -> Good -> EOF)
            assert client_reader.read.call_count == 3

            # Verify terminate was NOT called
            assert not handler.terminate.called

            # Verify receive_data was called twice (for the data frames)
            assert mock_conn.receive_data.call_count == 2

            # Verify that we actually processed the second frame
            # (In a real scenario, the event handler would be called.
            # We can verify receive_data called with GOOD_FRAME)
            mock_conn.receive_data.assert_any_call(b"GOOD_FRAME")

            print("Test passed: StreamClosedError ignored, processing continued.")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_stream_closed_resilience())
