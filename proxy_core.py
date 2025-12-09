# proxy_core.py
"""
Implements the HTTP/2 Native Proxy Handler using Sans-IO principles.

This module provides the `NativeProxyHandler` class, which manages the lifecycle
of HTTP/2 connections between a client (downstream) and a target server (upstream).
It implements a full-duplex proxy with support for flow control, state machine
synchronization, and traffic interception/capture.

REFACTORING REPORT (2025 Audit):
- Enforced RFC 9113 Strictness (validate_inbound_headers=True, Fail-Fast).
- Implemented RFC 8441 (Extended CONNECT) for WebSocket bootstrapping.
- Migrated concurrency to asyncio.TaskGroup (Python 3.11+).
- Implemented 'Drain-then-ACK' flow control with Bounded Queues to prevent deadlocks/OOM.
- Added HPACK Bomb mitigation (max_header_list_size).
- Hardened wait_closed() with timeouts.
- [REFACTORED] Replaced print/traceback with logging calls.
- [FIX] Restored Standard HTTP/2 Graceful Shutdown (Double GOAWAY).
"""

import asyncio
import ssl
import socket
import logging
from typing import Dict, Optional, Callable, Tuple, List, Any, TypedDict
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
    from h2.exceptions import FlowControlError, ProtocolError
    from h2.settings import SettingCodes
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    # Define placeholders as classes to satisfy type checkers (Pylance/MyPy)
    class H2Connection: pass
    class H2Configuration: pass
    class RequestReceived: pass
    class DataReceived: pass
    class StreamEnded: pass
    class StreamReset: pass
    class WindowUpdated: pass
    class SettingsAcknowledged: pass 
    class ConnectionTerminated: pass
    class TrailersReceived: pass
    class PingAckReceived: pass 
    class ResponseReceived: pass
    
    class ErrorCodes:
        NO_ERROR = 0x0
        PROTOCOL_ERROR = 0x1
        INTERNAL_ERROR = 0x2
        FLOW_CONTROL_ERROR = 0x3
        SETTINGS_TIMEOUT = 0x4
        STREAM_CLOSED = 0x5
        FRAME_SIZE_ERROR = 0x6
        REFUSED_STREAM = 0x7
        CANCEL = 0x8
        COMPRESSION_ERROR = 0x9
        CONNECT_ERROR = 0xa
        ENHANCE_YOUR_CALM = 0xb
        INADEQUATE_SECURITY = 0xc
        HTTP_1_1_REQUIRED = 0xd

    class SettingCodes:
        HEADER_TABLE_SIZE = 0x1
        ENABLE_PUSH = 0x2
        MAX_CONCURRENT_STREAMS = 0x3
        INITIAL_WINDOW_SIZE = 0x4
        MAX_FRAME_SIZE = 0x5
        MAX_HEADER_LIST_SIZE = 0x6
        ENABLE_CONNECT_PROTOCOL = 0x8

    class FlowControlError(Exception): pass
    class ProtocolError(Exception): pass

# Import structures from the main application (if available)
try:
    # We rely on these structures being available in the environment
    from structures import CapturedRequest, HOP_BY_HOP_HEADERS
except ImportError:
    # Placeholders for independent testing/development
    class CapturedRequest:
        """Mock CapturedRequest for testing/independence."""
        def __init__(self, id, method, url, headers, body):
            self.id = id; self.method = method; self.url = url; self.headers = headers;
            self.body = body
        def __str__(self): return f"{self.method} {self.url}"
    # Use a robust default list if import fails
    HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection', 'content-length', 'http2-settings'
    ]

# Setup logging
log = logging.getLogger("proxy_core")

# Configuration Constants (PDF Requirement 7.2: Timeouts)
UPSTREAM_CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
GRACEFUL_SHUTDOWN_TIMEOUT = 10.0 # Reduced from 30s for fail-fast
FLOW_CONTROL_TIMEOUT = 30.0  # Timeout for waiting on WINDOW_UPDATE
SOCKET_CLOSE_TIMEOUT = 5.0 # Prevent wait_closed() hangs
MAX_HEADER_LIST_SIZE = 65536  # 64KB (RFC 9113 Security: Prevent HPACK Bomb)
QUEUE_MAX_SIZE = 1000 # Backpressure limit (Audit 5.3.1)
MAX_STREAM_ID = 2147483647 # 2^31 - 1 (RFC 7540)

# Define TypedDict for captured header structure
class CapturedHeaders(TypedDict):
    pseudo: Dict[str, str]
    headers: Dict[str, str] # Store normal headers as a dictionary for easier manipulation


class StreamContext:
    """
    Manages the state, synchronization, and capture data for a single proxied stream.
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
        self.captured_headers: CapturedHeaders = {"pseudo": {}, "headers": {}}
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
                 target_override: Optional[str], scope_pattern: Optional[Any],
                 enable_tunneling: bool = True):
        """
        Initializes the NativeProxyHandler.
        """
        if not H2_AVAILABLE:
            # Allow initialization if in a mocked test environment
            if 'unittest' not in sys.modules and 'pytest' not in sys.modules:
                raise RuntimeError("hyper-h2 is required for NativeProxyHandler.")

        self.client_reader = client_reader
        self.client_writer = client_writer
        
        self.explicit_host = explicit_host # Host derived from CONNECT
        self.capture_callback = capture_callback
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling

        # Upstream connection details
        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None
        self.upstream_host: str = ""
        self.upstream_port: int = 443
        
        self.upstream_scheme: str = "https"  # H2 interception is always over TLS (h2)

        # H2 State Machines (PDF Requirement 1.2)
        # [AUDIT FIX] Enforce strictness: validate=True, normalize=True (RFC 9113)
        ds_config = H2Configuration(
            client_side=False, 
            header_encoding='utf-8', 
            validate_inbound_headers=True, 
            validate_outbound_headers=True,
            normalize_inbound_headers=True,
            normalize_outbound_headers=True
        )
        
        # Handle potential initialization failure if H2Connection is a mock object or dependencies are missing
        try:
            self.downstream_conn = H2Connection(config=ds_config)
            
            # [AUDIT FIX] HPACK Bomb Protection (Audit 4.3.1)
            self.downstream_conn.local_settings.max_header_list_size = MAX_HEADER_LIST_SIZE

            # (PDF Requirement 6.2: Enable Extended CONNECT (RFC 8441))
            self.downstream_conn.local_settings.enable_connect_protocol = 1
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

        # [DEADLOCK & MEMORY FIX] Bounded queues for outbound data.
        # Queue Items: (stream_id, data, end_stream, ack_target_connection, ack_length)
        # Bounded size applies backpressure to the read loop when the write loop (network) is slow.
        self.upstream_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.downstream_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)

    async def run(self):
        """
        Main execution loop for the proxy connection.
        """
        # Safety check if initialization failed due to missing dependencies
        if not self.downstream_conn:
            return

        try:
            # 1. Determine Upstream Target
            if not self._resolve_target():
                return

            # 2. Establish Upstream Connection (Only if tunneling is enabled)
            if self.enable_tunneling:
                await self.connect_upstream()

                # 3. Initialize H2 on upstream side
                # [AUDIT FIX] Enforce strictness for upstream too
                us_config = H2Configuration(
                    client_side=True, 
                    header_encoding='utf-8', 
                    validate_inbound_headers=True,
                    validate_outbound_headers=True,
                    normalize_inbound_headers=True,
                    normalize_outbound_headers=True
                )
                self.upstream_conn = H2Connection(config=us_config)
                # [AUDIT FIX] Security Settings
                self.upstream_conn.local_settings.max_header_list_size = MAX_HEADER_LIST_SIZE
                self.upstream_conn.local_settings.enable_connect_protocol = 1
                
                self.upstream_conn.initiate_connection()
                await self.flush(self.upstream_conn, self.upstream_writer)

            # Send Preface and SETTINGS to downstream
            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer)

            # 4. Start Concurrent Loops
            # [AUDIT FIX] Use asyncio.TaskGroup for Structured Concurrency (Python 3.11+)
            # This prevents zombie tasks and ensures exceptions propagate correctly.
            if hasattr(asyncio, 'TaskGroup'):
                async with asyncio.TaskGroup() as tg:
                    # Downstream Tasks
                    tg.create_task(self._read_loop_wrapper(
                        self.client_reader, self.downstream_conn, self.handle_downstream_event
                    ))
                    tg.create_task(self._sender_loop(
                        self.downstream_queue, self.downstream_conn, self.client_writer
                    ))

                    # Upstream Tasks (if tunneling)
                    if self.enable_tunneling and self.upstream_conn:
                        tg.create_task(self._read_loop_wrapper(
                            self.upstream_reader, self.upstream_conn, self.handle_upstream_event
                        ))
                        tg.create_task(self._sender_loop(
                            self.upstream_queue, self.upstream_conn, self.upstream_writer
                        ))
            else:
                # Fallback for older Python (discouraged by audit, but kept for compatibility)
                loop_tasks = [
                    self._read_loop_wrapper(self.client_reader, self.downstream_conn, self.handle_downstream_event),
                    self._sender_loop(self.downstream_queue, self.downstream_conn, self.client_writer)
                ]
                if self.enable_tunneling and self.upstream_conn:
                    loop_tasks.append(self._read_loop_wrapper(self.upstream_reader, self.upstream_conn, self.handle_upstream_event))
                    loop_tasks.append(self._sender_loop(self.upstream_queue, self.upstream_conn, self.upstream_writer))
                
                self.tasks = [asyncio.create_task(t) for t in loop_tasks]
                await asyncio.gather(*self.tasks)

        except (ConnectionError, asyncio.TimeoutError) as e:
            # log.debug(f"Proxy connection error ({self.upstream_host}): {type(e).__name__}: {e}")
            await self.terminate(ErrorCodes.CONNECT_ERROR)
        # Handle specific H2 errors gracefully
        except FlowControlError as e:
             log.error(f"H2 Flow Control Error (Global): {e}")
             await self.terminate(ErrorCodes.FLOW_CONTROL_ERROR)
        except Exception as e:
            # Catches exceptions raised within the TaskGroup/gather
            if not self.closed.is_set():
                log.error(f"Unexpected error in proxy handler ({self.upstream_host}): {type(e).__name__}: {e}", exc_info=True)
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally:
            # (PDF Requirement 4.1: Cleanup in finally block)
            # Use shield to ensure cleanup runs even if cancelled
            await asyncio.shield(self.cleanup())

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
        # log.debug(f"Connecting upstream to {self.upstream_host}:{self.upstream_port}")

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

            # [FIX] Strict ALPN check to avoid H1 fallback causing ProtocolError
            if negotiated_protocol != "h2":
                raise ConnectionError(f"Upstream server did not negotiate HTTP/2 (ALPN: {negotiated_protocol}). Aborting to prevent protocol mismatch.")

        # Catch specific exceptions and re-raise as ConnectionError
        except (asyncio.TimeoutError, socket.gaierror, ssl.SSLError, ConnectionRefusedError, OSError) as e:
            raise ConnectionError(f"Failed to connect upstream: {type(e).__name__}: {e}")
        except Exception as e:
            if isinstance(e, ConnectionError):
                raise e
            raise ConnectionError(f"Unexpected error during upstream connection: {type(e).__name__}: {e}")

    # -- Sans-IO Core Loops --

    async def _read_loop_wrapper(self, reader: asyncio.StreamReader, conn: H2Connection, event_handler: Callable):
        """
        Wrapper for the read loop to ensure exceptions are handled and propagated correctly.
        """
        try:
            await self.read_loop(reader, conn, event_handler)
        except (ConnectionResetError, ConnectionAbortedError, asyncio.IncompleteReadError, OSError) as e:
            # Handle common network disconnections gracefully
            if not self.closed.is_set():
                # [FIX] Improve visibility of connection drops
                log.warning(f"Connection closed unexpectedly (read loop): {type(e).__name__}: {e}")
                self.closed.set()
        except Exception as e:
            # Re-raise other exceptions to ensure TaskGroup/gather registers the failure.
            if not self.closed.is_set():
                log.error(f"Read loop terminated unexpectedly: {type(e).__name__}: {e}", exc_info=True)
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
            
            # [AUDIT FIX] Fail-Fast on ProtocolError as per RFC 9113
            except ProtocolError as e:
                msg = str(e)
                if "ConnectionState.CLOSED" in msg:
                    self.closed.set()
                    break
                log.error(f"H2 Protocol error during receive_data: {type(e).__name__}: {e}")
                await self.terminate(ErrorCodes.PROTOCOL_ERROR)
                break
            
            except Exception as e:
                log.error(f"Generic error during receive_data: {type(e).__name__}: {e}", exc_info=True)
                await self.terminate(ErrorCodes.INTERNAL_ERROR)
                break

            # (PDF Requirement 1.2: Emit and React)
            for event in events:
                # Process events
                await event_handler(event)

            # Flush immediately after processing inputs to send ACKs/Updates
            await self.flush(conn, self.get_writer(conn))

    async def _sender_loop(self, queue: asyncio.Queue, conn: H2Connection, writer: asyncio.StreamWriter):
        """
        [Flow Control] Dequeues data, writes to socket, drains, and THEN acknowledges.
        This "Drain-then-ACK" pattern prevents memory blooms and deadlocks (PDF 4.2).
        """
        dead_streams = set()

        while not self.closed.is_set():
            try:
                item = await queue.get()
                if item is None:
                    break # Signal to stop

                stream_id, data, end_stream, ack_target_conn, ack_length = item

                # Optimization: Drop data for known dead streams immediately
                if stream_id in dead_streams:
                    queue.task_done()
                    continue

                # Liveness Check: If the H2 state machine says it's closed, don't try to send
                try:
                    # stream_is_closed returns True if stream is IDLE or CLOSED. 
                    if conn.stream_is_closed(stream_id):
                        dead_streams.add(stream_id)
                        queue.task_done()
                        continue
                except Exception:
                    # If stream_id doesn't exist in state machine, it's dead/invalid
                    dead_streams.add(stream_id)
                    queue.task_done()
                    continue

                try:
                    await self.forward_data_internal(conn, writer, stream_id, data, end_stream)
                    
                    # [FLOW CONTROL] Acknowledge data to the *source* connection only after
                    # it has been successfully written to the *destination* connection.
                    # This prevents memory blooms if the network is slow.
                    if ack_target_conn and ack_length > 0:
                        try:
                            ack_target_conn.acknowledge_received_data(ack_length, stream_id)
                            await self.flush(ack_target_conn, self.get_writer(ack_target_conn))
                        except Exception: pass

                except ProtocolError:
                    # If we hit a protocol error (e.g. writing to closed), mark stream as dead
                    dead_streams.add(stream_id)
                except Exception as e:
                    log.error(f"Error in sender loop: {e}")
                    if not self.closed.is_set():
                        self.closed.set()
                    break
                
                queue.task_done()
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Critical error in sender loop: {e}")
                break

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
                    pass
                self.closed.set()
            except Exception as e:
                log.error(f"Error during network write/drain (flush): {type(e).__name__}: {e}")
                self.closed.set()

    # -- Event Handlers (Mediation Logic) --

    def _filter_headers(self, headers: List[Tuple[Any, Any]]) -> List[Tuple[str, str]]:
        """
        RFC 9113 Sanitizer: Removes connection-specific headers and rejects invalid chars.
        """
        safe_headers = []
        for k, v in headers:
            try:
                # Robust decode
                if isinstance(k, bytes): k_str = k.decode('utf-8', errors='replace')
                else: k_str = str(k)
                if isinstance(v, bytes): v_str = v.decode('utf-8', errors='replace')
                else: v_str = str(v)
                
                # [RFC 9113 8.2.1] Strict Field Validity
                if '\r' in v_str or '\n' in v_str or '\0' in v_str:
                    log.warning(f"Rejected invalid header chars in {k_str}")
                    continue 

                k_lower = k_str.lower()
                if k_lower in HOP_BY_HOP_HEADERS:
                    # Exception: 'TE: trailers' is allowed in H2
                    if k_lower == 'te' and 'trailers' in v_str.lower():
                        safe_headers.append((k_str, v_str))
                    continue
                
                safe_headers.append((k_str, v_str))
            except Exception:
                continue
        return safe_headers

    async def handle_downstream_event(self, event):
        """
        Processes events from the client (Downstream) and mediates them to the server (Upstream).
        """
        # (PDF Requirement 1.3: State Machine Synchronization)
        if isinstance(event, RequestReceived):
            await self.handle_request_received(event)
        elif isinstance(event, DataReceived):
            # [FLOW CONTROL] Defer ACK to sender loop. 
            # We put the data into the upstream queue. When it's drained, downstream is ACKed.
            if self.enable_tunneling:
                await self.upstream_queue.put((
                    event.stream_id, 
                    event.data, 
                    event.stream_ended, 
                    self.downstream_conn, 
                    event.flow_controlled_length
                ))
            
            if event.stream_id in self.streams:
                 # Safety limit on capture size
                 if len(self.streams[event.stream_id].request_body) < 10*1024*1024:
                    self.streams[event.stream_id].request_body.extend(event.data)
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
            if self.enable_tunneling:
                 try:
                    # Filter trailers as well
                    safe_headers = self._filter_headers(event.headers)
                    self.upstream_conn.send_headers(event.stream_id, safe_headers, end_stream=True)
                    await self.flush(self.upstream_conn, self.upstream_writer)
                 except Exception: pass
            
            # Update state
            if event.stream_id in self.streams:
                context = self.streams[event.stream_id]
                context.downstream_closed = True
                self.finalize_capture(context)
                
                # Handle non-tunneling response trigger
                if not self.enable_tunneling:
                    await self.send_synthetic_captured_response(event.stream_id)

    async def handle_upstream_event(self, event):
        """
        Processes events from the server (Upstream) and mediates them to the client (Downstream).
        """
        
        if isinstance(event, ResponseReceived):
             # Forward response headers downstream
             try:
                safe_headers = self._filter_headers(event.headers)
                self.downstream_conn.send_headers(event.stream_id, safe_headers, end_stream=event.stream_ended)
             except (ProtocolError, Exception) as e:
                 pass

        elif isinstance(event, DataReceived):
            # [FLOW CONTROL] Defer ACK to sender loop.
            await self.downstream_queue.put((event.stream_id, event.data, event.stream_ended, self.upstream_conn, event.flow_controlled_length))

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
            try:
                safe_headers = self._filter_headers(event.headers)
                self.downstream_conn.send_headers(event.stream_id, safe_headers, end_stream=True)
            except (ProtocolError, Exception) as e:
                 pass


    # -- Specific Event Logic & Capture Implementation --

    async def handle_request_received(self, event: RequestReceived):
        """
        Handles new incoming requests (streams) from the client.
        Includes RFC 8441 Validation logic.
        """
        stream_id = event.stream_id

        if stream_id in self.streams:
            log.error(f"Protocol Error: Stream ID {stream_id} reused by client.")
            await self.terminate(ErrorCodes.PROTOCOL_ERROR)
            return

        # RFC 8441 / Extended CONNECT Validation
        # H2 config with encoding='utf-8' returns strings.
        headers_dict = dict(event.headers)
        # Decode keys if bytes
        decoded_headers = {}
        for k, v in headers_dict.items():
            k_s = k.decode('utf-8') if isinstance(k, bytes) else k
            v_s = v.decode('utf-8') if isinstance(v, bytes) else v
            decoded_headers[k_s] = v_s
            
        method = decoded_headers.get(':method')
        protocol = decoded_headers.get(':protocol')
        
        if method == 'CONNECT':
            if protocol:
                # Extended CONNECT: MUST contain :scheme and :path
                if ':scheme' not in decoded_headers or ':path' not in decoded_headers:
                     log.warning("Violation: Extended CONNECT missing scheme/path")
                     self.downstream_conn.reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR)
                     return
            else:
                # Standard CONNECT: MUST NOT contain :scheme or :path
                if ':scheme' in decoded_headers or ':path' in decoded_headers:
                     log.warning("Violation: Standard CONNECT contains scheme/path")
                     self.downstream_conn.reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR)
                     return

        # Initialize Stream Context
        context = StreamContext(stream_id, self.upstream_scheme)
        self.streams[stream_id] = context

        # Process headers robustly for capture
        context.captured_headers = self._process_headers_for_capture(event.headers)

        # Forward headers upstream (Only if tunneling).
        if self.enable_tunneling:
            try:
                forward_headers = []
                
                # Construct correct upstream authority
                authority = self.upstream_host
                if self.upstream_port not in (80, 443):
                    authority += f":{self.upstream_port}"

                # Filter headers before forwarding
                safe_headers = self._filter_headers(event.headers)

                for k, v in safe_headers:
                    # Ensure strings
                    if isinstance(k, bytes): k = k.decode('utf-8', errors='replace')
                    if isinstance(v, bytes): v = v.decode('utf-8', errors='replace')

                    if k == ':authority':
                        forward_headers.append((k, authority))
                    elif k == 'host':
                        # Skip 'Host' in H2, rely on :authority
                        continue
                    else:
                        forward_headers.append((k, v))
                
                # Ensure :authority is present
                if not any(k == ':authority' for k, v in forward_headers):
                     forward_headers.insert(0, (':authority', authority))

                # We forward the filtered headers
                self.upstream_conn.send_headers(stream_id, forward_headers, end_stream=event.stream_ended)
                await self.flush(self.upstream_conn, self.upstream_writer)

            except Exception as e:
                log.error(f"Error forwarding headers upstream for stream {stream_id}: {type(e).__name__}")
                # Reset the stream downstream if upstream forwarding fails
                try:
                    self.downstream_conn.reset_stream(stream_id, ErrorCodes.INTERNAL_ERROR)
                except Exception:
                    pass
                
                if stream_id in self.streams:
                     del self.streams[stream_id]
                return

        if event.stream_ended:
             context.downstream_closed = True
             self.finalize_capture(context)
             
             if not self.enable_tunneling:
                 await self.send_synthetic_captured_response(stream_id)

    # Helper function for robust header processing
    def _process_headers_for_capture(self, headers: List[Tuple[Any, Any]]) -> CapturedHeaders:
        """
        Processes raw H2 headers into a structured format for capture, ensuring robust decoding.
        Ref: RFC 7540 Section 8.1.2.5 (Cookie concatenation rules).
        """
        pseudo: Dict[str, str] = {}
        normal_headers: Dict[str, str] = {}
        authority = None

        for k, v in headers:
            try:
                if isinstance(k, bytes): k_str = k.decode('utf-8', errors='replace')
                else: k_str = str(k)
                if isinstance(v, bytes): v_str = v.decode('utf-8', errors='replace')
                else: v_str = str(v)
            except Exception:
                continue

            k_lower = k_str.lower()

            if k_str.startswith(':'):
                pseudo[k_str] = v_str
                if k_str == ':authority':
                    authority = v_str
            else:
                # Handle multi-value headers (RFC 7540 Section 8.1.2.3 and 8.1.2.5)
                if k_lower in normal_headers:
                    #  Cookies must be joined by semi-colon (RFC 7540 Sec 8.1.2.5)
                    # All other headers are joined by comma (RFC 7230 Sec 3.2.2)
                    separator = "; " if k_lower == 'cookie' else ", "
                    normal_headers[k_lower] += f"{separator}{v_str}"
                else:
                    normal_headers[k_lower] = v_str
                
                if k_lower == 'host' and authority is None:
                    authority = v_str

        # Ensure :authority is set, falling back to the Host header value if necessary (H2 spec allows this)
        if ':authority' not in pseudo and authority:
             pseudo[':authority'] = authority

        return {"pseudo": pseudo, "headers": normal_headers}


    # (PDF Requirement 3: Flow Control Implementation - The Core Challenge)
    async def forward_data_internal(self, destination_conn: H2Connection, writer: asyncio.StreamWriter, stream_id: int, data: bytes, end_stream: bool):
        """
        Forwards data between connections, respecting flow control.
        [DEADLOCK FIX] Internal function called by sender loops to write data to the socket.
        """
        
        if stream_id not in self.streams:
             # Stream might have closed while data was in queue
             return

        context = self.streams[stream_id]

        data_len = len(data)
        offset = 0

        # Loop until all data is sent, handling window limitations
        while offset < data_len:
            if self.closed.is_set():
                return # Stop if connection is closing

            # --- LIVENESS CHECK ---
            try:
                if destination_conn.stream_is_closed(stream_id):
                    raise ProtocolError(f"Stream {stream_id} is closed")
            except (KeyError, AttributeError):
                 raise ProtocolError(f"Stream {stream_id} invalid")
            # ----------------------

            # Check available window (minimum of connection and stream windows)
            try:
                # Connection window check
                conn_window = destination_conn.outbound_flow_control_window
                # Stream window check
                stream_window = destination_conn.remote_flow_control_window(stream_id)
                available_window = min(conn_window, stream_window)
            except Exception as e:
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
                except ProtocolError as e:
                     raise e 
                except Exception as e:
                     log.error(f"Error sending data chunk on stream {stream_id}: {e}")
                     await self.terminate(ErrorCodes.INTERNAL_ERROR)
                     return

                # (PDF Requirement 3.3: Step 3: Wait for drain)
                await self.flush(destination_conn, writer)

            else:
                # (PDF Requirement 3.1/3.2: Deadlock prevention)
                # Window is zero. Wait for a WINDOW_UPDATE.
                context.flow_control_event.clear()
                
                # Wait until handle_window_updated signals the event.
                try:
                    await asyncio.wait_for(context.flow_control_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                except asyncio.TimeoutError:
                    log.error(f"Flow control timeout on stream {stream_id}. Terminating connection.")
                    await self.terminate(ErrorCodes.FLOW_CONTROL_ERROR)
                    return
                
                if self.closed.is_set():
                    return
        
        # Handle zero-length data frames that just carry the END_STREAM flag
        if data_len == 0 and end_stream:
            try:
                destination_conn.send_data(stream_id, b'', end_stream=True)
                await self.flush(destination_conn, writer)
            except Exception: pass


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

    # -- Connection Lifecycle Management --

    async def handle_stream_ended(self, source_conn: H2Connection, event: StreamEnded):
        """
        Handles stream closure (Half-Closed state).
        Updates stream state and cleans up if both sides are closed.
        """
        stream_id = event.stream_id
        if stream_id not in self.streams:
            return

        # (PDF Requirement 4.2: Half-Closed State Management)
        context = self.streams[stream_id]
        
        if source_conn == self.downstream_conn:
            context.downstream_closed = True
            # Request is fully received. Finalize capture.
            self.finalize_capture(context)
            
            # If not tunneling, we must now send the response to the client
            if not self.enable_tunneling:
                await self.send_synthetic_captured_response(stream_id)
                # Mark upstream as closed (conceptually) since we won't interact with it
                context.upstream_closed = True
                
        else:
            context.upstream_closed = True

        # Ensure END_STREAM is propagated if it wasn't already sent
        dest_conn = self.get_other_conn(source_conn)
        if dest_conn and self.enable_tunneling:
            try:
                dest_conn.end_stream(stream_id)
            except (Exception) as e:
                # Stream might already be fully closed or reset
                pass

        # Clean up context when fully closed (both sides sent END_STREAM)
        if context.downstream_closed and context.upstream_closed:
            if stream_id in self.streams:
                del self.streams[stream_id]

    async def send_synthetic_captured_response(self, stream_id: int):
        try:
            headers = [
                (':status', '200'),
                ('content-length', '9'),
                ('content-type', 'text/plain'),
                ('server', 'Scalpel-Racer/H2-Capture')
            ]
            self.downstream_conn.send_headers(stream_id, headers, end_stream=False)
            self.downstream_conn.send_data(stream_id, b"Captured.", end_stream=True)
            await self.flush(self.downstream_conn, self.client_writer)
        except Exception as e:
            log.error(f"Error sending synthetic response on stream {stream_id}: {e}")
   
    async def handle_stream_reset(self, source_conn: H2Connection, event: StreamReset):
        """
        Handles stream resets (RST_STREAM).
        """
        stream_id = event.stream_id
        if stream_id in self.streams:
            # Forward the reset to the other side
            dest_conn = self.get_other_conn(source_conn)
            try:
                dest_conn.reset_stream(stream_id, event.error_code)
                await self.flush(dest_conn, self.get_writer(dest_conn))
            except (ProtocolError, Exception):
                pass
            
            del self.streams[stream_id]

    async def handle_connection_terminated(self, event: ConnectionTerminated):
        await self.graceful_shutdown(last_stream_id=event.last_stream_id)

    # (PDF Requirement 7.1: Graceful Shutdown - The GOAWAY Dance)
    async def graceful_shutdown(self, last_stream_id=None):
        if self.closed.is_set():
            return

        # 1. Send initial GOAWAY (Max ID) to signal intent to stop accepting new streams.
        try:
            # [FIX] Send Max Stream ID (2^31-1) to signal graceful shutdown start (RFC 7540)
            if self.downstream_conn and self.downstream_conn.state_machine.state != 'CLOSED':
                 self.downstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=MAX_STREAM_ID)
                 await self.flush(self.downstream_conn, self.client_writer)

            if self.upstream_conn and self.upstream_conn.state_machine.state != 'CLOSED':
                self.upstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=MAX_STREAM_ID)
                await self.flush(self.upstream_conn, self.upstream_writer)
        except Exception:
            pass 

        # 2. Wait for active streams to drain or timeout
        try:
            await asyncio.wait_for(self.wait_for_streams_to_drain(), timeout=GRACEFUL_SHUTDOWN_TIMEOUT)
        except asyncio.TimeoutError:
            pass

        # 3. Send final GOAWAY with actual last stream ID
        try:
            if self.downstream_conn and self.downstream_conn.state_machine.state != 'CLOSED':
                 self.downstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR)
                 await self.flush(self.downstream_conn, self.client_writer)
            
            if self.upstream_conn and self.upstream_conn.state_machine.state != 'CLOSED':
                self.upstream_conn.close_connection(error_code=ErrorCodes.NO_ERROR)
                await self.flush(self.upstream_conn, self.upstream_writer)
        except Exception:
            pass

        self.closed.set()

    async def wait_for_streams_to_drain(self):
        while self.streams:
            await asyncio.sleep(0.1)

    async def terminate(self, error_code: ErrorCodes):
        """
        Immediately terminates the connection with an error code.
        """
        if self.closed.is_set():
            return

        self.closed.set()

        # Unblock all streams waiting on flow control.
        for context in self.streams.values():
            context.flow_control_event.set()

        try:
            if self.downstream_conn:
                self.downstream_conn.close_connection(error_code=error_code)
                await self.flush(self.downstream_conn, self.client_writer)
        except Exception:
            pass

    async def cleanup(self):
        """
        Ensures all resources (sockets, tasks) are closed properly.
        """
        self.closed.set()

        for context in self.streams.values():
            context.flow_control_event.set()
            
        await self.upstream_queue.put(None)
        await self.downstream_queue.put(None)

        # (PDF Requirement 4.1: Mandatory wait_closed() with timeout)
        for w in [self.client_writer, self.upstream_writer]:
            if w and not w.is_closing():
                try:
                    w.close()
                    # Hardened wait_closed to prevent hangs
                    await asyncio.wait_for(w.wait_closed(), timeout=SOCKET_CLOSE_TIMEOUT)
                except (ConnectionError, OSError, asyncio.TimeoutError):
                    pass

    # -- Capture Logic Finalization --

    def finalize_capture(self, context: StreamContext):
        if context.capture_finalized:
            return
        context.capture_finalized = True

        pseudo_headers = context.captured_headers["pseudo"]
        raw_headers = context.captured_headers["headers"]

        method = pseudo_headers.get(':method', 'GET')
        path = pseudo_headers.get(':path', '/')
        
        authority = pseudo_headers.get(':authority')
        if not authority: authority = self.explicit_host
        if not authority: authority = raw_headers.get('host')

        if not authority:
            return

        try:
            final_url = self.construct_target_url(context.scheme, path, authority)
        except ValueError as e:
            log.warning(f"Error constructing target URL for capture: {e}")
            return

        if self.scope_pattern and not self.scope_pattern.search(final_url):
            return

        safe_headers = {k: v for k, v in raw_headers.items()
                        if k.lower() not in HOP_BY_HOP_HEADERS}

        captured = CapturedRequest(
            id=0,
            method=method,
            url=final_url,
            headers=safe_headers,
            body=bytes(context.request_body)
        )
        
        try:
            self.capture_callback(captured)
        except Exception as e:
            log.error(f"Error in capture callback: {e}")

    def construct_target_url(self, scheme: str, path: str, authority: str) -> str:
        if self.target_override:
            return urljoin(self.target_override, path.lstrip('/'))
        return urlunparse((scheme, authority, path, '', '', ''))

    def get_writer(self, conn: H2Connection) -> Optional[asyncio.StreamWriter]:
        if conn == self.downstream_conn:
            return self.client_writer
        elif conn == self.upstream_conn:
            return self.upstream_writer
        return None

    def get_other_conn(self, conn: H2Connection) -> Optional[H2Connection]:
        if conn == self.downstream_conn:
            return self.upstream_conn
        elif conn == self.upstream_conn:
            return self.downstream_conn
        return None