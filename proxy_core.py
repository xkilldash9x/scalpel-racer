# proxy_core.py
"""
Implements the HTTP/2 Native Proxy Handler using Sans-IO principles.

This module provides the `NativeProxyHandler` class, which manages the lifecycle
of HTTP/2 connections between a client (downstream) and a target server (upstream).
It implements a full-duplex proxy with support for flow control, state machine
synchronization, and traffic interception/capture, adhering to RFC 7540 and
specific requirements for handling race condition testing.

Key features:
    - Sans-IO Architecture (using `h2`).
    - Explicit state management for both upstream and downstream connections.
    - Robust flow control handling (Deadlock prevention, Window Updates).
    - Request capture and analysis.
    - Graceful shutdown and resource cleanup.
"""

import asyncio
import ssl
import socket
import logging
from typing import Dict, Optional, Callable, Tuple, List, Any
from urllib.parse import urljoin, urlunparse
import sys

# Import hyper-h2 (Sans-IO library - PDF Section 1)
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
        SettingsAcknowledged, ConnectionTerminated, TrailersReceived, PingAckReceived,
        ResponseReceived
    )
    from h2.errors import ErrorCodes
    from h2.settings import SettingCodes
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    # Define placeholders for type hinting if h2 is not installed
    H2Connection = object; H2Configuration = object; RequestReceived = object; DataReceived = object; StreamEnded = object; StreamReset = object; WindowUpdated = object; SettingsAcknowledged = object; ConnectionTerminated = object; TrailersReceived = object; PingAckReceived = object; ErrorCodes = object; ResponseReceived = object; SettingCodes = object

# Import structures from the main application (if available)
try:
    # We rely on these structures being available in the environment
    from structures import CapturedRequest, HOP_BY_HOP_HEADERS
except ImportError:
    # Placeholders for independent testing/development
    class CapturedRequest:
        """Mock CapturedRequest for testing/independence."""
        def __init__(self, id, method, url, headers, body):
            self.id = id; self.method = method; self.url = url; self.headers = headers; self.body = body
        def __str__(self): return f"{self.method} {self.url}"
    # Use a robust default list if import fails
    HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection'
    ]

# Setup logging
log = logging.getLogger("proxy_core")

# Configuration Constants (PDF Requirement 7.2: Timeouts)
UPSTREAM_CONNECT_TIMEOUT = 5.0
IDLE_TIMEOUT = 60.0
GRACEFUL_SHUTDOWN_TIMEOUT = 30.0
FLOW_CONTROL_TIMEOUT = 30.0  # Timeout for waiting on WINDOW_UPDATE


class StreamContext:
    """
    Manages the state, synchronization, and capture data for a single proxied stream.

    This class tracks the open/closed status of a stream on both upstream and
    downstream sides, manages flow control events, and buffers request data for capture.

    Attributes:
        stream_id (int): The HTTP/2 stream identifier.
        scheme (str): The URL scheme (http/https).
        downstream_closed (bool): True if the downstream (client) has closed the stream.
        upstream_closed (bool): True if the upstream (server) has closed the stream.
        flow_control_event (asyncio.Event): Event used to pause/resume writing based on window availability.
        request_headers_list (List[Tuple[str, str]]): Accumulator for request headers.
        request_pseudo (Dict[str, str]): Accumulator for pseudo-headers (:method, :path, etc.).
        request_body (bytearray): Accumulator for the request body payload.
        capture_finalized (bool): Flag indicating if the request has been fully captured and processed.
    """
    def __init__(self, stream_id: int, scheme: str):
        self.stream_id = stream_id
        self.scheme = scheme
        
        # (PDF Requirement 4.2: Half-Closed State tracking)
        self.downstream_closed = False
        self.upstream_closed = False
        
        # Synchronization for flow control (PDF Requirement 3.4)
        self.flow_control_event = asyncio.Event()
        self.flow_control_event.set()  # Start open

        # Capture data structures
        self.request_headers_list: List[Tuple[str, str]] = []
        self.request_pseudo: Dict[str, str] = {}
        self.request_body = bytearray()
        self.capture_finalized = False


# (PDF Requirement 1: Sans-IO Architecture Implementation)
class NativeProxyHandler:
    """
    Implements the core HTTP/2 proxy logic using Sans-IO principles (hyper-h2).

    Manages the lifecycle of both downstream (client) and upstream (server) connections,
    mediating events between them while handling interception and modification logic.

    Attributes:
        client_reader (asyncio.StreamReader): The reader for the client connection.
        client_writer (asyncio.StreamWriter): The writer for the client connection.
        explicit_host (str): The hostname requested in the CONNECT method.
        capture_callback (Callable): Function to call with captured request data.
        target_override (Optional[str]): Base URL to override the request target.
        scope_pattern (Optional[Any]): Regex pattern to filter captured requests.
        upstream_reader (Optional[asyncio.StreamReader]): The reader for the upstream connection.
        upstream_writer (Optional[asyncio.StreamWriter]): The writer for the upstream connection.
        upstream_host (str): The resolved upstream hostname.
        upstream_port (int): The resolved upstream port.
        downstream_conn (H2Connection): The H2 state machine for the client side.
        upstream_conn (Optional[H2Connection]): The H2 state machine for the server side.
        streams (Dict[int, StreamContext]): Active stream contexts keyed by stream ID.
        closed (asyncio.Event): Event indicating connection closure.
        tasks (List[asyncio.Task]): List of background tasks (e.g., read loops).
    """

    def __init__(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, 
                 explicit_host: str, capture_callback: Callable, 
                 target_override: Optional[str], scope_pattern: Optional[Any]):
        """
        Initializes the NativeProxyHandler.

        Args:
            client_reader (asyncio.StreamReader): Reader stream from the client.
            client_writer (asyncio.StreamWriter): Writer stream to the client.
            explicit_host (str): The host:port string from the HTTP CONNECT request.
            capture_callback (Callable): Callback function `fn(CapturedRequest)` for saving requests.
            target_override (Optional[str]): If set, rewrites the destination of captured requests.
            scope_pattern (Optional[Any]): Compiled regex object for filtering URL scope.

        Raises:
            RuntimeError: If the `h2` library is not available.
        """
        if not H2_AVAILABLE:
            raise RuntimeError("hyper-h2 is required for NativeProxyHandler.")

        self.client_reader = client_reader
        self.client_writer = client_writer
        self.explicit_host = explicit_host  # Host derived from CONNECT
        self.capture_callback = capture_callback
        self.target_override = target_override
        self.scope_pattern = scope_pattern

        # Upstream connection details
        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None
        self.upstream_host: str = ""
        self.upstream_port: int = 443
        self.upstream_scheme: str = "https"  # H2 interception is always over TLS (h2)

        # H2 State Machines (PDF Requirement 1.2)
        # Downstream (Proxy acts as Server)
        ds_config = H2Configuration(client_side=False, header_encoding='utf-8')
        self.downstream_conn = H2Connection(config=ds_config)
        
        # (PDF Requirement 6.2: Enable Extended CONNECT (RFC 8441) for potential future WebSocket support)
        self.downstream_conn.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})

        # Upstream (Proxy acts as Client) - Initialized after connection
        self.upstream_conn: Optional[H2Connection] = None

        self.streams: Dict[int, StreamContext] = {}
        self.closed = asyncio.Event()
        self.tasks = []

    async def run(self):
        """
        Main execution loop for the proxy connection.

        This method orchestrates the connection setup:
        1. Resolves the upstream target.
        2. Establishes the TLS connection to the upstream server.
        3. Initializes H2 handshakes on both sides.
        4. Spawns concurrent read loops for upstream and downstream data.
        5. Handles cleanup upon completion or error.
        """
        try:
            # 1. Determine Upstream Target
            if not self._resolve_target():
                return

            # 2. Establish Upstream Connection
            await self.connect_upstream()

            # 3. Initialize H2 on both sides
            us_config = H2Configuration(client_side=True, header_encoding='utf-8')
            self.upstream_conn = H2Connection(config=us_config)

            # Send Preface and SETTINGS
            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer)

            self.upstream_conn.initiate_connection()
            await self.flush(self.upstream_conn, self.upstream_writer)

            # 4. Start Concurrent Read Loops (PDF Requirement 3.2: Decoupled Read-Write)
            # (PDF Requirement 2.2: Structured Concurrency via TaskGroup)
            async with asyncio.TaskGroup() as tg:
                self.tasks.append(tg.create_task(self._read_loop_wrapper(self.client_reader, self.downstream_conn, self.handle_downstream_event)))
                self.tasks.append(tg.create_task(self._read_loop_wrapper(self.upstream_reader, self.upstream_conn, self.handle_upstream_event)))

        except (ConnectionError, asyncio.TimeoutError) as e:
            log.debug(f"Proxy connection error: {type(e).__name__}")
            await self.terminate(ErrorCodes.CONNECT_ERROR)
        except Exception as e:
            # Catches exceptions raised within the TaskGroup
            log.error(f"Unexpected error in proxy handler TaskGroup: {type(e).__name__}", exc_info=True)
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally:
            # (PDF Requirement 4.1: Cleanup in finally block)
            await self.cleanup()

    def _resolve_target(self) -> bool:
        """
        Resolves the upstream target based on the explicit host from CONNECT.

        Returns:
            bool: True if resolution was successful, False otherwise.
        """
        try:
            host, port_str = self.explicit_host.split(':', 1)
            port = int(port_str)
        except ValueError:
            # If port is missing (e.g. client sent CONNECT example.com), assume default 443
            host = self.explicit_host
            port = 443
        
        self.upstream_host = host
        self.upstream_port = port
        return True

    async def connect_upstream(self):
        """
        Establishes the TCP/TLS connection to the target server.

        Configures SSL context for H2 (ALPN) and connects. Verification is disabled
        to support interception scenarios.

        Raises:
            ConnectionError: If connection fails or H2 is not negotiated.
        """
        log.debug(f"Connecting upstream to {self.upstream_host}:{self.upstream_port}")

        # (PDF Requirement 5.1: Security Configuration)
        # Use default context which applies strong defaults (TLS 1.2+, secure ciphers)
        ssl_context = ssl.create_default_context()
        
        # For interception tools, verification is typically disabled (matching Scalpel Racer behavior).
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # (PDF Requirement 5.2: ALPN)
        try:
            # We strictly require H2 upstream for this native H2 proxy implementation.
            ssl_context.set_alpn_protocols(["h2"])
        except NotImplementedError:
            log.warning("ALPN not supported by the Python SSL implementation.")

        try:
            # (PDF Requirement 7.2: Handshake/Connect Timeout)
            self.upstream_reader, self.upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port, ssl=ssl_context),
                timeout=UPSTREAM_CONNECT_TIMEOUT
            )

            # Verify H2 negotiation success
            transport = self.upstream_writer.get_extra_info('ssl_object')
            negotiated_protocol = transport.selected_alpn_protocol() if transport else None

            if negotiated_protocol != "h2":
                raise ConnectionError(f"Upstream server did not negotiate HTTP/2 (ALPN: {negotiated_protocol}).")

        except Exception as e:
            raise ConnectionError(f"Failed to connect upstream: {type(e).__name__}")

    # --- Sans-IO Core Loops ---

    async def _read_loop_wrapper(self, reader: asyncio.StreamReader, conn: H2Connection, event_handler: Callable):
        """
        Wrapper for the read loop to ensure exceptions are handled within the TaskGroup context.

        Args:
            reader (asyncio.StreamReader): The stream to read from.
            conn (H2Connection): The H2 connection state machine to feed data into.
            event_handler (Callable): The function to process resulting events.
        """
        try:
            await self.read_loop(reader, conn, event_handler)
        except (ConnectionResetError, ConnectionAbortedError, asyncio.IncompleteReadError):
            # Handle common network disconnections gracefully
            if not self.closed.is_set():
                self.closed.set()
        except Exception as e:
            # Re-raise other exceptions to ensure TaskGroup registers the failure and cancels siblings.
            if not self.closed.is_set():
                log.error(f"Read loop terminated unexpectedly: {type(e).__name__}")
            raise

    async def read_loop(self, reader: asyncio.StreamReader, conn: H2Connection, event_handler: Callable):
        """
        Reads data from the network, feeds it to the H2 state machine, and processes events.

        This loop runs continuously until the connection is closed or an error occurs.
        It implements the Sans-IO pattern: Read Bytes -> Feed to H2 -> Process Events -> Write Bytes.

        Args:
            reader (asyncio.StreamReader): The source of raw bytes.
            conn (H2Connection): The H2 state machine.
            event_handler (Callable): Logic to handle specific H2 events.
        """
        while not self.closed.is_set():
            # (PDF Requirement 7.2: Idle Timeout)
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                log.info("Connection idle timeout reached. Initiating graceful shutdown.")
                await self.graceful_shutdown()
                break

            if not data:
                # EOF
                self.closed.set()
                break

            # (PDF Requirement 1.2: Ingest and Process)
            try:
                events = conn.receive_data(data)
            except Exception as e:
                # Handle H2 protocol violations
                log.warning(f"H2 Protocol error during receive_data: {type(e).__name__}")
                await self.terminate(ErrorCodes.PROTOCOL_ERROR)
                break

            # (PDF Requirement 1.2: Emit and React)
            for event in events:
                await event_handler(event)

            # Flush any data generated during event handling (e.g. ACKs, WINDOW_UPDATEs, forwarded data)
            await self.flush(conn, self.get_writer(conn))


    async def flush(self, conn: H2Connection, writer: Optional[asyncio.StreamWriter]):
        """
        Retrieves data from the H2 state machine and writes it to the network.

        Also performs `writer.drain()` to respect backpressure.

        Args:
            conn (H2Connection): The state machine to check for pending data.
            writer (Optional[asyncio.StreamWriter]): The destination writer.
        """
        if self.closed.is_set() or writer is None or writer.is_closing():
            return

        # (PDF Requirement 1.2: Flush)
        data_to_send = conn.data_to_send()
        if data_to_send:
            try:
                writer.write(data_to_send)
                # (PDF Requirement 3.3: Backpressure implementation via drain)
                await writer.drain()
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                self.closed.set()
            except Exception as e:
                log.error(f"Error during network write/drain (flush): {type(e).__name__}")
                self.closed.set()

    # --- Event Handlers (Mediation Logic) ---

    async def handle_downstream_event(self, event):
        """
        Processes events from the client (Downstream) and mediates them to the server (Upstream).

        Args:
            event: The H2 event object.
        """
        # (PDF Requirement 1.3: State Machine Synchronization)
        if isinstance(event, RequestReceived):
            await self.handle_request_received(event)
        elif isinstance(event, DataReceived):
            await self.handle_data_received(event)
        elif isinstance(event, StreamEnded):
            await self.handle_stream_ended(self.downstream_conn, event)
        elif isinstance(event, StreamReset):
            await self.handle_stream_reset(self.downstream_conn, event)
        elif isinstance(event, WindowUpdated):
            await self.handle_window_updated(event)
        elif isinstance(event, ConnectionTerminated):
            await self.handle_connection_terminated(event)
        # (PDF Requirement 6.3: gRPC Trailers)
        elif isinstance(event, TrailersReceived):
            await self.handle_trailers_received(event)

    async def handle_upstream_event(self, event):
        """
        Processes events from the server (Upstream) and mediates them to the client (Downstream).

        Args:
            event: The H2 event object.
        """
        
        if isinstance(event, ResponseReceived):
             # Forward response headers downstream
             self.downstream_conn.send_headers(event.stream_id, event.headers, end_stream=event.stream_ended)

        elif isinstance(event, DataReceived):
            # Forward response data downstream
            await self.forward_data(self.downstream_conn, event)

        elif isinstance(event, StreamEnded):
            await self.handle_stream_ended(self.upstream_conn, event)
        elif isinstance(event, StreamReset):
            await self.handle_stream_reset(self.upstream_conn, event)
        elif isinstance(event, WindowUpdated):
            await self.handle_window_updated(event)
        elif isinstance(event, ConnectionTerminated):
            await self.handle_connection_terminated(event)
        elif isinstance(event, TrailersReceived):
            # Forward response trailers downstream
            self.downstream_conn.send_headers(event.stream_id, event.headers, end_stream=True)

    # --- Specific Event Logic & Capture Implementation ---

    async def handle_request_received(self, event: RequestReceived):
        """
        Handles new incoming requests (streams) from the client.

        Initializes a new `StreamContext`, buffers headers for capture, and forwards
        headers to the upstream server.

        Args:
            event (RequestReceived): The event containing request headers.
        """
        stream_id = event.stream_id

        if stream_id in self.streams:
            await self.terminate(ErrorCodes.PROTOCOL_ERROR)
            return

        # Initialize Stream Context and Capture Data
        context = StreamContext(stream_id, self.upstream_scheme)
        self.streams[stream_id] = context

        # Parse headers for capture
        for k, v in event.headers:
            try:
                k_str = k.decode('utf-8')
                v_str = v.decode('utf-8')
                if k_str.startswith(':'):
                    context.request_pseudo[k_str] = v_str
                else:
                    context.request_headers_list.append((k_str, v_str))
            except UnicodeDecodeError:
                pass # Ignore non-UTF8 headers

        # Forward headers upstream.
        try:
            self.upstream_conn.send_headers(stream_id, event.headers, end_stream=event.stream_ended)
        except Exception as e:
            log.error(f"Error forwarding headers upstream for stream {stream_id}: {type(e).__name__}")
            self.downstream_conn.reset_stream(stream_id, ErrorCodes.INTERNAL_ERROR)

        if event.stream_ended:
             context.downstream_closed = True
             self.finalize_capture(context)


    async def handle_data_received(self, event: DataReceived):
        """
        Handles data received from the client (request body).

        Buffers the data for capture and forwards it upstream.

        Args:
            event (DataReceived): The event containing payload data.
        """
        stream_id = event.stream_id
        if stream_id in self.streams:
            # Buffer data for capture
            self.streams[stream_id].request_body.extend(event.data)

        # Forward data upstream (handles flow control)
        await self.forward_data(self.upstream_conn, event)

    # (PDF Requirement 3: Flow Control Implementation - The Core Challenge)
    async def forward_data(self, destination_conn: H2Connection, event: DataReceived):
        """
        Forwards data between connections, respecting flow control and implementing Drain-then-Ack.

        This method checks the available window on the destination. If sufficient, it sends
        data, drains the writer, and then acknowledges the data to the source (to open its window).
        If the window is insufficient, it pauses and waits for a WINDOW_UPDATE event.

        Args:
            destination_conn (H2Connection): The connection to send data to.
            event (DataReceived): The data event to forward.
        """
        stream_id = event.stream_id
        data_len = len(event.data)
        flow_controlled_len = event.flow_controlled_length

        if stream_id not in self.streams:
            return

        context = self.streams[stream_id]
        source_conn = self.get_other_conn(destination_conn)

        # Flow Control Strategy: Wait for sufficient window before sending the chunk.
        while True:
            # Check available window (minimum of connection and stream windows)
            # (PDF Requirement 3.4: Connection vs. Stream Windows)
            conn_window = destination_conn.local_flow_control_window(0)
            stream_window = destination_conn.local_flow_control_window(stream_id)
            available_window = min(conn_window, stream_window)

            if available_window >= data_len:
                # (PDF Requirement 3.3: The Algorithm - Steps 1 & 2: Receive and Forward)
                destination_conn.send_data(stream_id, event.data, end_stream=event.stream_ended)

                # (PDF Requirement 3.3: Step 3: Wait for drain)
                # Flush includes await writer.drain(), applying backpressure to this task.
                await self.flush(destination_conn, self.get_writer(destination_conn))

                # (PDF Requirement 3.3: Step 4: Ack)
                # Acknowledge the source data now that it has been successfully forwarded and drained.
                # This propagates backpressure to the source.
                source_conn.acknowledge_received_data(flow_controlled_len, stream_id)
                
                break
            else:
                # (PDF Requirement 3.1/3.2: Deadlock prevention)
                # Window is insufficient. Wait for a WINDOW_UPDATE.
                # The read loop continues to spin independently, ensuring WINDOW_UPDATEs are processed.
                context.flow_control_event.clear()
                log.debug(f"Flow control stalled for stream {stream_id}. Waiting for WINDOW_UPDATE.")

                # Wait until handle_window_updated signals the event.
                try:
                    await asyncio.wait_for(context.flow_control_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                except asyncio.TimeoutError:
                    log.error(f"Flow control timeout on stream {stream_id}. Terminating connection.")
                    await self.terminate(ErrorCodes.FLOW_CONTROL_ERROR)
                    break


    async def handle_window_updated(self, event: WindowUpdated):
        """
        Handles WINDOW_UPDATE frames, potentially unblocking stalled streams.

        Args:
            event (WindowUpdated): The flow control update event.
        """
        stream_id = event.stream_id

        if stream_id == 0:
            # (PDF Requirement 3.4: Connection Window Update)
            # Notify all streams as the global window has opened.
            for context in self.streams.values():
                context.flow_control_event.set()
        elif stream_id in self.streams:
            # Notify the specific stream
            self.streams[stream_id].flow_control_event.set()

    # (PDF Requirement 6.3: gRPC Trailers)
    async def handle_trailers_received(self, event: TrailersReceived):
        """
        Forwards trailers (received downstream).

        Args:
            event (TrailersReceived): The trailers event.
        """
        stream_id = event.stream_id
        if stream_id in self.streams:
             # Forward as HEADERS frame upstream with END_STREAM set.
             self.upstream_conn.send_headers(stream_id, event.headers, end_stream=True)
             # Update state and capture
             context = self.streams[stream_id]
             context.downstream_closed = True
             self.finalize_capture(context)

    # --- Connection Lifecycle Management ---

    async def handle_stream_ended(self, source_conn: H2Connection, event: StreamEnded):
        """
        Handles stream closure (Half-Closed state).

        Updates stream state and cleans up if both sides are closed.

        Args:
            source_conn (H2Connection): The connection where the stream ended.
            event (StreamEnded): The event.
        """
        stream_id = event.stream_id
        if stream_id not in self.streams:
            return

        # (PDF Requirement 4.2: Half-Closed State Management)
        context = self.streams[stream_id]
        dest_conn = self.get_other_conn(source_conn)

        if source_conn == self.downstream_conn:
            context.downstream_closed = True
            # Request is fully received. Finalize capture.
            self.finalize_capture(context)
        else:
            context.upstream_closed = True

        # Ensure END_STREAM is propagated if it wasn't already sent (e.g. via DataReceived(end_stream=True))
        try:
            # Check if the stream is still open on the destination side before attempting to end it.
            if dest_conn and not dest_conn.stream_is_closed(stream_id):
                 dest_conn.end_stream(stream_id)
        except Exception:
             # Stream might already be fully closed or reset (e.g., by a concurrent RST_STREAM)
             pass

        # Clean up context when fully closed (both sides sent END_STREAM)
        if context.downstream_closed and context.upstream_closed:
            if stream_id in self.streams:
                del self.streams[stream_id]

    async def handle_stream_reset(self, source_conn: H2Connection, event: StreamReset):
        """
        Handles stream resets (RST_STREAM).

        Propagates the reset to the peer and removes the stream context.

        Args:
            source_conn (H2Connection): The connection where the reset occurred.
            event (StreamReset): The reset event.
        """
        stream_id = event.stream_id
        if stream_id in self.streams:
            # Forward the reset to the other side
            dest_conn = self.get_other_conn(source_conn)
            try:
                if dest_conn:
                    dest_conn.reset_stream(stream_id, event.error_code)
            except Exception:
                pass
            del self.streams[stream_id]

    async def handle_connection_terminated(self, event: ConnectionTerminated):
        """
        Handles connection termination (GOAWAY).

        Args:
            event (ConnectionTerminated): The GOAWAY event.
        """
        log.info(f"Connection terminated by peer (GOAWAY): {event.error_code}")
        await self.graceful_shutdown(last_stream_id=event.last_stream_id)

    # (PDF Requirement 7.1: Graceful Shutdown - The GOAWAY Dance)
    async def graceful_shutdown(self, last_stream_id=None):
        """
        Performs the graceful shutdown procedure.

        Sends a GOAWAY to stop new streams, waits for existing streams to drain,
        and then closes the connection.

        Args:
            last_stream_id (int, optional): The last stream ID processed by the peer.
        """
        if self.closed.is_set():
            return

        log.info("Initiating graceful shutdown.")

        # 1. Send initial GOAWAY (Max ID) to signal intent to stop accepting new streams.
        max_id = (2**31 - 1)

        try:
            # Check state before sending GOAWAY
            if self.downstream_conn.state_machine.state != 'CLOSED':
                 self.downstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=max_id)
                 await self.flush(self.downstream_conn, self.client_writer)

            if self.upstream_conn and self.upstream_conn.state_machine.state != 'CLOSED':
                self.upstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=max_id)
                await self.flush(self.upstream_conn, self.upstream_writer)
        except Exception:
            pass # Best effort

        # 2. Wait for active streams to drain or timeout
        try:
            await asyncio.wait_for(self.wait_for_streams_to_drain(), timeout=GRACEFUL_SHUTDOWN_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("Graceful shutdown timeout reached. Forcing closure.")

        # 3. Final closure is handled in cleanup()
        self.closed.set()

    async def wait_for_streams_to_drain(self):
        """
        Waits until the streams dictionary is empty.

        This coroutine polls the stream count until it reaches zero.
        """
        while self.streams:
            await asyncio.sleep(0.1)

    async def terminate(self, error_code: ErrorCodes):
        """
        Immediately terminates the connection with an error code.

        Args:
            error_code (ErrorCodes): The H2 error code to send in the GOAWAY frame.
        """
        if self.closed.is_set():
            return

        self.closed.set()

        # Best effort to send a final GOAWAY with the error code
        try:
            if self.downstream_conn.state_machine.state != 'CLOSED':
                self.downstream_conn.close_connection(error_code=error_code)
                await self.flush(self.downstream_conn, self.client_writer)
            if self.upstream_conn and self.upstream_conn.state_machine.state != 'CLOSED':
                self.upstream_conn.close_connection(error_code=error_code)
                await self.flush(self.upstream_conn, self.upstream_writer)
        except Exception:
            pass

    async def cleanup(self):
        """
        Ensures all resources (sockets, tasks) are closed properly.
        """
        self.closed.set()

        # Cancel any remaining background tasks (read loops)
        for task in self.tasks:
            if not task.done():
                task.cancel()

        # (PDF Requirement 4.1: Mandatory wait_closed())
        if self.client_writer and not self.client_writer.is_closing():
            try:
                self.client_writer.close()
                await self.client_writer.wait_closed()
            except (ConnectionError, OSError):
                pass

        if self.upstream_writer and not self.upstream_writer.is_closing():
            try:
                self.upstream_writer.close()
                await self.upstream_writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    # --- Capture Logic Finalization ---

    def finalize_capture(self, context: StreamContext):
        """
        Constructs the CapturedRequest object from the StreamContext.

        This is called when the request is fully received (downstream half-closed).
        It filters headers, checks scope, and invokes the capture callback.

        Args:
            context (StreamContext): The context of the completed stream.
        """
        if context.capture_finalized:
            return
        context.capture_finalized = True

        method = context.request_pseudo.get(':method', 'GET')
        path = context.request_pseudo.get(':path', '/')
        
        # Determine Authority (Host)
        authority = context.request_pseudo.get(':authority')
        if not authority:
            # Fallback to Host header if present (less common in H2 but possible)
            for k, v in context.request_headers_list:
                if k.lower() == 'host':
                    authority = v
                    break
        
        # Fallback to explicit host from CONNECT if still missing
        if not authority:
             authority = self.explicit_host

        if not authority:
            # Cannot capture without a host/authority
            return

        # Construct URL and apply overrides/scope
        try:
            final_url = self.construct_target_url(context.scheme, path, authority)
        except ValueError:
            return

        # Scope filtering
        if self.scope_pattern and not self.scope_pattern.search(final_url):
            return

        # Filter headers for capture (using the standard HOP_BY_HOP list)
        safe_headers = {k: v for k, v in context.request_headers_list
                        if k.lower() not in HOP_BY_HOP_HEADERS}

        captured = CapturedRequest(
            id=0, # ID assigned by the manager (CaptureServer)
            method=method,
            url=final_url,
            headers=safe_headers,
            body=bytes(context.request_body)
        )
        self.capture_callback(captured)

    def construct_target_url(self, scheme: str, path: str, authority: str) -> str:
        """
        Constructs the final URL, applying target overrides.

        Args:
            scheme (str): The URL scheme.
            path (str): The URL path.
            authority (str): The host/authority.

        Returns:
            str: The full URL.
        """
        # 1. Target Override (Highest Priority)
        if self.target_override:
            # Use urljoin to correctly combine the base path and the relative path
            # Ensure target_override has a trailing slash (handled in CaptureServer init)
            return urljoin(self.target_override, path.lstrip('/'))

        # 2. Standard construction
        return urlunparse((scheme, authority, path, '', '', ''))

    # --- Helpers ---
    def get_writer(self, conn: H2Connection) -> Optional[asyncio.StreamWriter]:
        """
        Returns the asyncio StreamWriter corresponding to the given H2 connection.

        Args:
            conn (H2Connection): The connection.

        Returns:
            Optional[asyncio.StreamWriter]: The corresponding writer.
        """
        return self.client_writer if conn == self.downstream_conn else self.upstream_writer

    def get_other_conn(self, conn: H2Connection) -> Optional[H2Connection]:
        """
        Returns the 'other' H2 connection in the proxy pair.

        If given downstream, returns upstream, and vice-versa.

        Args:
            conn (H2Connection): The connection.

        Returns:
            Optional[H2Connection]: The peer connection.
        """
        return self.upstream_conn if conn == self.downstream_conn else self.downstream_conn
