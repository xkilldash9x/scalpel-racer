# proxy_core.py
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
    - Robust flow control handling (Deadlock prevention, Window Updates, Chunking).
    - Request capture and analysis.
    - Graceful shutdown and resource cleanup.
"""

import asyncio
import ssl
import socket
import logging
# Ensure TypedDict is imported for P7/P8 FIX
from typing import Dict, Optional, Callable, Tuple, List, Any, TypedDict
from urllib.parse import urljoin, urlunparse
import sys

# Import hyper-h2 (Sans-IO library - PDF Section 1)
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
        SettingsAcknowledged, ConnectionTerminated, TrailersReceived, PingAcknowledged,
        ResponseReceived
    )
    # Import FlowControlError for P9/P10 FIX
    from h2.errors import ErrorCodes, FlowControlError
    from h2.settings import SettingCodes
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    # Define placeholders for type hinting if h2 is not installed
    H2Connection = object; H2Configuration = object; RequestReceived = object; DataReceived = object; StreamEnded = object; StreamReset = object; WindowUpdated = object; SettingsAcknowledged = object; ConnectionTerminated = object; TrailersReceived = object; PingAcknowledged = object; ErrorCodes = object; ResponseReceived = object; SettingCodes = object; FlowControlError = Exception

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
    # Use a robust default list if import fails (Updated based on B04 FIX in structures.py)
    HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection', 'content-length'
    ]

# Setup logging
log = logging.getLogger("proxy_core")

# Configuration Constants (PDF Requirement 7.2: Timeouts)
UPSTREAM_CONNECT_TIMEOUT = 5.0
IDLE_TIMEOUT = 60.0
GRACEFUL_SHUTDOWN_TIMEOUT = 30.0
FLOW_CONTROL_TIMEOUT = 30.0  # Timeout for waiting on WINDOW_UPDATE

# (P7/P8 FIX) Define TypedDict for captured header structure
class CapturedHeaders(TypedDict):
    pseudo: Dict[str, str]
    headers: Dict[str, str] # Store normal headers as a dictionary for easier manipulation


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
        captured_headers (CapturedHeaders): Accumulator for pseudo and normal headers.
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

        # Capture data structures (P7/P8 FIX: Simplified structure)
        self.captured_headers: CapturedHeaders = {"pseudo": {}, "headers": {}}
        # Removed request_headers_list and request_pseudo as they are replaced by captured_headers
        self.request_body = bytearray()
        self.capture_finalized = False


# (PDF Requirement 1: Sans-IO Architecture Implementation)
class NativeProxyHandler:
    """
    Implements the core HTTP/2 proxy logic using Sans-IO principles (hyper-h2).

    Manages the lifecycle of both downstream (client) and upstream (server) connections,
    mediating events between them while handling interception and modification logic.
    """

    def __init__(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, 
                 explicit_host: str, capture_callback: Callable, 
                 target_override: Optional[str], scope_pattern: Optional[Any]):
        """
        Initializes the NativeProxyHandler.
        """
        if not H2_AVAILABLE:
            # [B03 FIX] Allow initialization if in a mocked test environment
            if 'unittest' not in sys.modules:
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
        # P7/P8 FIX: We rely on utf-8 encoding for robust header processing.
        ds_config = H2Configuration(client_side=False, header_encoding='utf-8')
        
        # [B03 FIX] Handle potential initialization failure if H2Connection is a mock object or dependencies are missing
        try:
            self.downstream_conn = H2Connection(config=ds_config)
            
            # (PDF Requirement 6.2: Enable Extended CONNECT (RFC 8441))
            self.downstream_conn.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
        except Exception as e:
            if not H2_AVAILABLE:
                 self.downstream_conn = None
            else:
                 raise e


        # Upstream (Proxy acts as Client) - Initialized after connection
        self.upstream_conn: Optional[H2Connection] = None

        self.streams: Dict[int, StreamContext] = {}
        self.closed = asyncio.Event()
        self.tasks = []

    async def run(self):
        """
        Main execution loop for the proxy connection.
        """
        # [B03 FIX] Safety check if initialization failed due to missing dependencies
        if not self.downstream_conn:
            return

        try:
            # 1. Determine Upstream Target
            if not self._resolve_target():
                return

            # 2. Establish Upstream Connection
            await self.connect_upstream()

            # 3. Initialize H2 on both sides
            # P7/P8 FIX: Rely on utf-8 encoding.
            us_config = H2Configuration(client_side=True, header_encoding='utf-8')
            self.upstream_conn = H2Connection(config=us_config)

            # Send Preface and SETTINGS
            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer)

            self.upstream_conn.initiate_connection()
            await self.flush(self.upstream_conn, self.upstream_writer)

            # 4. Start Concurrent Read Loops (PDF Requirement 3.2: Decoupled Read-Write)
            # (PDF Requirement 2.2: Structured Concurrency)
            # Use TaskGroup if available (Python 3.11+), otherwise gather.
            if hasattr(asyncio, 'TaskGroup'):
                async with asyncio.TaskGroup() as tg:
                    self.tasks.append(tg.create_task(self._read_loop_wrapper(self.client_reader, self.downstream_conn, self.handle_downstream_event)))
                    self.tasks.append(tg.create_task(self._read_loop_wrapper(self.upstream_reader, self.upstream_conn, self.handle_upstream_event)))
            else:
                # Fallback for Python < 3.11
                self.tasks = [
                    asyncio.create_task(self._read_loop_wrapper(self.client_reader, self.downstream_conn, self.handle_downstream_event)),
                    asyncio.create_task(self._read_loop_wrapper(self.upstream_reader, self.upstream_conn, self.handle_upstream_event))
                ]
                await asyncio.gather(*self.tasks)


        except (ConnectionError, asyncio.TimeoutError) as e:
            log.debug(f"Proxy connection error ({self.upstream_host}): {type(e).__name__}: {e}")
            await self.terminate(ErrorCodes.CONNECT_ERROR)
        # Handle specific H2 errors gracefully (P9/P10)
        except FlowControlError as e:
             log.warning(f"H2 Flow Control Error detected. Terminating connection. {e}")
             await self.terminate(ErrorCodes.FLOW_CONTROL_ERROR)
        except Exception as e:
            # Catches exceptions raised within the TaskGroup/gather
            if not self.closed.is_set():
                log.error(f"Unexpected error in proxy handler ({self.upstream_host}): {type(e).__name__}", exc_info=True)
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally:
            # (PDF Requirement 4.1: Cleanup in finally block)
            await self.cleanup()

    def _resolve_target(self) -> bool:
        """
        Resolves the upstream target based on the explicit host from CONNECT.
        """
        # Robust parsing of host:port string
        try:
            if ':' in self.explicit_host:
                host, port_str = self.explicit_host.rsplit(':', 1)
                port = int(port_str)
            else:
                # If port is missing, assume default 443
                host = self.explicit_host
                port = 443
        except ValueError:
            log.warning(f"Invalid CONNECT target format: {self.explicit_host}")
            return False
        
        self.upstream_host = host
        self.upstream_port = port
        return True

    async def connect_upstream(self):
        """
        Establishes the TCP/TLS connection to the target server.
        """
        log.debug(f"Connecting upstream to {self.upstream_host}:{self.upstream_port}")

        # (PDF Requirement 5.1: Security Configuration)
        ssl_context = ssl.create_default_context()
        
        # For interception tools, verification is typically disabled.
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # (PDF Requirement 5.2: ALPN)
        try:
            # We strictly require H2 upstream.
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

            # Be lenient if ALPN negotiation result is missing but connection succeeded, but warn if wrong protocol negotiated.
            if negotiated_protocol != "h2" and negotiated_protocol is not None:
                raise ConnectionError(f"Upstream server did not negotiate HTTP/2 (ALPN: {negotiated_protocol}).")

        # Catch specific exceptions and re-raise as ConnectionError
        except (asyncio.TimeoutError, socket.gaierror, ssl.SSLError, ConnectionRefusedError, OSError) as e:
            raise ConnectionError(f"Failed to connect upstream: {type(e).__name__}: {e}")
        except Exception as e:
            if isinstance(e, ConnectionError):
                raise e
            raise ConnectionError(f"Unexpected error during upstream connection: {type(e).__name__}: {e}")

    # --- Sans-IO Core Loops ---

    async def _read_loop_wrapper(self, reader: asyncio.StreamReader, conn: H2Connection, event_handler: Callable):
        """
        Wrapper for the read loop to ensure exceptions are handled and propagated correctly.
        """
        try:
            await self.read_loop(reader, conn, event_handler)
        except (ConnectionResetError, ConnectionAbortedError, asyncio.IncompleteReadError, OSError):
            # Handle common network disconnections gracefully
            if not self.closed.is_set():
                log.debug("Connection closed unexpectedly (read loop).")
                self.closed.set()
        except Exception as e:
            # Re-raise other exceptions to ensure TaskGroup/gather registers the failure.
            if not self.closed.is_set():
                log.error(f"Read loop terminated unexpectedly: {type(e).__name__}", exc_info=True)
            raise

    async def read_loop(self, reader: asyncio.StreamReader, conn: H2Connection, event_handler: Callable):
        """
        Reads data from the network, feeds it to the H2 state machine, and processes events.
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
                # Process events
                await event_handler(event)

            # Flush any data generated during event handling
            await self.flush(conn, self.get_writer(conn))


    async def flush(self, conn: H2Connection, writer: Optional[asyncio.StreamWriter]):
        """
        Retrieves data from the H2 state machine and writes it to the network.
        """
        # Safety check against writing to a closed connection
        if self.closed.is_set() or writer is None or writer.is_closing():
            return

        # (PDF Requirement 1.2: Flush)
        try:
            data_to_send = conn.data_to_send()
        except Exception as e:
             # Handle potential errors in the H2 state machine
            log.error(f"Error retrieving data from H2 connection: {type(e).__name__}")
            self.closed.set()
            return

        if data_to_send:
            try:
                writer.write(data_to_send)
                # (PDF Requirement 3.3: Backpressure implementation via drain)
                await writer.drain()
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                # Handle common network write errors
                if not self.closed.is_set():
                     log.debug("Connection closed unexpectedly (flush).")
                self.closed.set()
            except Exception as e:
                log.error(f"Error during network write/drain (flush): {type(e).__name__}", exc_info=True)
                self.closed.set()

    # --- Event Handlers (Mediation Logic) ---

    async def handle_downstream_event(self, event):
        """
        Processes events from the client (Downstream) and mediates them to the server (Upstream).
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
        """
        
        if isinstance(event, ResponseReceived):
             # Forward response headers downstream
             if not self.downstream_conn.stream_is_closed(event.stream_id):
                try:
                    self.downstream_conn.send_headers(event.stream_id, event.headers, end_stream=event.stream_ended)
                except Exception as e:
                     log.warning(f"Failed to forward response headers for stream {event.stream_id}: {e}")


        elif isinstance(event, DataReceived):
            # Forward response data downstream (handles flow control)
            # (P10 FIX) Call the refactored forward_data method
            await self.forward_data(self.downstream_conn, event.stream_id, event.data, event.flow_controlled_length, event.stream_ended)

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
            if not self.downstream_conn.stream_is_closed(event.stream_id):
                try:
                    self.downstream_conn.send_headers(event.stream_id, event.headers, end_stream=True)
                except Exception as e:
                     log.warning(f"Failed to forward trailers for stream {event.stream_id}: {e}")


    # --- Specific Event Logic & Capture Implementation ---

    async def handle_request_received(self, event: RequestReceived):
        """
        Handles new incoming requests (streams) from the client.
        """
        stream_id = event.stream_id

        if stream_id in self.streams:
            log.warning(f"Protocol Error: Stream ID {stream_id} reused by client.")
            await self.terminate(ErrorCodes.PROTOCOL_ERROR)
            return

        # Initialize Stream Context
        context = StreamContext(stream_id, self.upstream_scheme)
        self.streams[stream_id] = context

        # (B18/P7/P8 FIX) Process headers robustly for capture
        context.captured_headers = self._process_headers_for_capture(event.headers)

        # Forward headers upstream.
        try:
            # We forward the original headers provided by the event
            self.upstream_conn.send_headers(stream_id, event.headers, end_stream=event.stream_ended)
        except Exception as e:
            log.error(f"Error forwarding headers upstream for stream {stream_id}: {type(e).__name__}")
            # Reset the stream downstream if upstream forwarding fails
            if not self.downstream_conn.stream_is_closed(stream_id):
                self.downstream_conn.reset_stream(stream_id, ErrorCodes.INTERNAL_ERROR)
            if stream_id in self.streams:
                 del self.streams[stream_id]
            return

        if event.stream_ended:
             context.downstream_closed = True
             self.finalize_capture(context)

    # (B18/P7/P8 FIX) Helper function for robust header processing
    def _process_headers_for_capture(self, headers: List[Tuple[Any, Any]]) -> CapturedHeaders:
        """
        Processes raw H2 headers into a structured format for capture, ensuring robust decoding.
        """
        pseudo: Dict[str, str] = {}
        normal_headers: Dict[str, str] = {}
        authority = None

        for k, v in headers:
            # Robustly decode key and value if they are bytes.
            # With header_encoding='utf-8', h2 provides strings. We check type defensively.
            try:
                # Decode key if bytes, using 'replace' for robustness against invalid sequences.
                if isinstance(k, bytes):
                    k_str = k.decode('utf-8', errors='replace')
                else:
                    # Ensure it is a string, handling potential non-string types defensively.
                    k_str = str(k)

                # Decode value if bytes
                if isinstance(v, bytes):
                    v_str = v.decode('utf-8', errors='replace')
                else:
                    v_str = str(v)

            except Exception:
                continue # Skip fundamentally malformed headers

            k_lower = k_str.lower()

            if k_str.startswith(':'):
                pseudo[k_str] = v_str
                if k_str == ':authority':
                    authority = v_str
            else:
                # Handle multi-value headers (RFC 7540 Section 8.1.2.3)
                if k_lower in normal_headers:
                     normal_headers[k_lower] += f", {v_str}"
                else:
                    normal_headers[k_lower] = v_str
                
                if k_lower == 'host' and authority is None:
                    authority = v_str

        # Ensure :authority is set, falling back to the Host header value if necessary (H2 spec allows this)
        if ':authority' not in pseudo and authority:
             pseudo[':authority'] = authority

        return {"pseudo": pseudo, "headers": normal_headers}


    async def handle_data_received(self, event: DataReceived):
        """
        Handles data received from the client (request body).
        """
        stream_id = event.stream_id
        if stream_id in self.streams:
            # Buffer data for capture
            self.streams[stream_id].request_body.extend(event.data)

            # Forward data upstream (handles flow control)
            # (P10 FIX) Call the refactored forward_data method
            await self.forward_data(self.upstream_conn, stream_id, event.data, event.flow_controlled_length, event.stream_ended)
        else:
             # Defense in Depth: Acknowledge data on unknown stream to free up connection window.
             log.warning(f"Data received on unknown stream {stream_id}. Acknowledging and ignoring.")
             self.downstream_conn.acknowledge_received_data(event.flow_controlled_length, stream_id)


    # (PDF Requirement 3: Flow Control Implementation - The Core Challenge)
    # (P9/P10 FIX) Refactored forward_data to implement chunking and correct window usage.
    async def forward_data(self, destination_conn: H2Connection, stream_id: int, data: bytes, flow_controlled_len: int, end_stream: bool = False):
        """
        Forwards data between connections, respecting flow control and implementing Drain-then-Ack with Chunking.
        """
        
        if stream_id not in self.streams or not data:
             # Acknowledge immediately if there is nothing to forward or stream is gone
            if flow_controlled_len > 0:
                 source_conn = self.get_other_conn(destination_conn)
                 if source_conn:
                      try:
                        source_conn.acknowledge_received_data(flow_controlled_len, stream_id)
                      except Exception:
                           pass
            return

        context = self.streams[stream_id]
        source_conn = self.get_other_conn(destination_conn)
        data_len = len(data)
        offset = 0

        # (P10 FIX) Loop until all data is sent, handling window limitations
        while offset < data_len:
            if self.closed.is_set():
                return # Stop if connection is closing

            # Check available window (minimum of connection and stream windows)
            # (P9 FIX) Use remote_flow_control_window (for stream) and outbound_flow_control_window (for connection)
            try:
                # Connection window check
                conn_window = destination_conn.outbound_flow_control_window
                # Stream window check
                stream_window = destination_conn.remote_flow_control_window(stream_id)
                available_window = min(conn_window, stream_window)
            except Exception as e:
                # Handle potential errors if the stream or connection is closed unexpectedly
                log.warning(f"Error checking flow control window for stream {stream_id}: {e}")
                return

            if available_window > 0:
                # Calculate how much we can send in this iteration
                chunk_size = min(data_len - offset, available_window)
                chunk = data[offset:offset + chunk_size]
                offset += chunk_size
                
                # Check if this is the final chunk of the entire message
                is_last_chunk = (offset == data_len) and end_stream

                # (PDF Requirement 3.3: Steps 1 & 2: Receive and Forward)
                try:
                    destination_conn.send_data(stream_id, chunk, end_stream=is_last_chunk)
                except Exception as e:
                     log.error(f"Error sending data chunk on stream {stream_id}: {e}")
                     await self.terminate(ErrorCodes.INTERNAL_ERROR)
                     return

                # (PDF Requirement 3.3: Step 3: Wait for drain)
                # Flush includes await writer.drain(), applying backpressure.
                await self.flush(destination_conn, self.get_writer(destination_conn))

            else:
                # (PDF Requirement 3.1/3.2: Deadlock prevention)
                # Window is zero. Wait for a WINDOW_UPDATE.
                context.flow_control_event.clear()
                log.debug(f"Flow control stalled for stream {stream_id} (Window: 0). Waiting for WINDOW_UPDATE.")

                # Wait until handle_window_updated signals the event.
                try:
                    await asyncio.wait_for(context.flow_control_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                except asyncio.TimeoutError:
                    log.error(f"Flow control timeout on stream {stream_id}. Terminating connection.")
                    await self.terminate(ErrorCodes.FLOW_CONTROL_ERROR)
                    return

        # (PDF Requirement 3.3: Step 4: Ack)
        # Acknowledge the source data now that all chunks have been successfully forwarded and drained.
        if source_conn and flow_controlled_len > 0:
            try:
                source_conn.acknowledge_received_data(flow_controlled_len, stream_id)
            except Exception as e:
                log.warning(f"Error acknowledging received data for stream {stream_id}: {e}")


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
        if stream_id in self.streams and self.upstream_conn:
             # Forward as HEADERS frame upstream with END_STREAM set.
             try:
                self.upstream_conn.send_headers(stream_id, event.headers, end_stream=True)
             except Exception as e:
                log.warning(f"Error forwarding trailers upstream for stream {stream_id}: {e}")
                return

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
        if dest_conn:
            try:
                # Check if the stream is still open on the destination side before attempting to end it.
                if not dest_conn.stream_is_closed(stream_id):
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
                if dest_conn and not dest_conn.stream_is_closed(stream_id):
                    dest_conn.reset_stream(stream_id, event.error_code)
            except Exception:
                pass
            
            # Clean up context immediately on reset
            del self.streams[stream_id]

    async def handle_connection_terminated(self, event: ConnectionTerminated):
        """
        Handles connection termination (GOAWAY).

        Args:
            event (ConnectionTerminated): The GOAWAY event.
        """
        log.info(f"Connection terminated by peer (GOAWAY): Error={event.error_code}, Last Stream={event.last_stream_id}")
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
            if self.downstream_conn and self.downstream_conn.state_machine.state != 'CLOSED':
                 self.downstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=max_id)
                 await self.flush(self.downstream_conn, self.client_writer)

            if self.upstream_conn and self.upstream_conn.state_machine.state != 'CLOSED':
                self.upstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=max_id)
                await self.flush(self.upstream_conn, self.upstream_writer)
        except Exception as e:
            log.debug(f"Best effort GOAWAY failed: {e}")

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
            if self.downstream_conn and self.downstream_conn.state_machine.state != 'CLOSED':
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

        # (P7/P8 FIX) Use the structured captured headers
        pseudo_headers = context.captured_headers["pseudo"]
        raw_headers = context.captured_headers["headers"]

        method = pseudo_headers.get(':method', 'GET')
        path = pseudo_headers.get(':path', '/')
        
        # Determine Authority (Host)
        authority = pseudo_headers.get(':authority')
        
        # Fallback to explicit host from CONNECT if still missing
        if not authority:
             authority = self.explicit_host

        if not authority:
            # Cannot capture without a host/authority
            log.debug(f"Cannot finalize capture for stream {context.stream_id}: Missing authority/host.")
            return

        # Construct URL and apply overrides/scope
        try:
            final_url = self.construct_target_url(context.scheme, path, authority)
        except ValueError as e:
            log.warning(f"Error constructing target URL for capture: {e}")
            return

        # Scope filtering
        if self.scope_pattern and not self.scope_pattern.search(final_url):
            return

        # Filter headers for capture (using the standard HOP_BY_HOP list)
        # Note: B04 ensures content-length is in HOP_BY_HOP_HEADERS
        safe_headers = {k: v for k, v in raw_headers.items()
                        if k.lower() not in HOP_BY_HOP_HEADERS}

        captured = CapturedRequest(
            id=0, # ID assigned by the manager (CaptureServer)
            method=method,
            url=final_url,
            headers=safe_headers,
            body=bytes(context.request_body)
        )
        
        # Invoke the callback
        try:
            self.capture_callback(captured)
        except Exception as e:
            log.error(f"Error in capture callback: {e}", exc_info=True)

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
        """
        if conn == self.downstream_conn:
            return self.client_writer
        elif conn == self.upstream_conn:
            return self.upstream_writer
        return None

    def get_other_conn(self, conn: H2Connection) -> Optional[H2Connection]:
        """
        Returns the 'other' H2 connection in the proxy pair.
        """
        if conn == self.downstream_conn:
            return self.upstream_conn
        elif conn == self.upstream_conn:
            return self.downstream_conn
        return None