#Filename: proxy_h2.py
"""
HTTP/2 PROXY HANDLER (RFC 9113)
Handles multiplexed streams, flow control, and HPACK state.
Strict type safety and cleanup logic included.
Compliant with RFC 9113 (obsoletes RFC 7540) regarding strict validation,
Server Push deprecation, and Priority deprecation.
"""

import asyncio
import ssl
import time
import re
from typing import Dict, Optional, Callable, Tuple, List, Union, cast
from urllib.parse import urlunparse, urljoin

# -- Internal Modules --
from proxy_common import (
    BaseProxyHandler, QueueItem, H2StreamContext,
    IDLE_TIMEOUT, KEEPALIVE_INTERVAL, FLOW_CONTROL_TIMEOUT,
    MAX_HEADER_LIST_SIZE, GOAWAY_MAX_FRAME, H2_FORBIDDEN_HEADERS,
    convert_h2_to_h1, prepare_forwarded_headers, process_h2_headers_for_capture
)
from structures import (
    CapturedRequest, MAX_CAPTURE_BODY_SIZE
)

# -- Compatibility Layer --
from compat import (
    H2Connection, H2Configuration, ErrorCodes, SettingCodes,
    RequestReceived, DataReceived, StreamEnded, StreamReset,
    WindowUpdated, ConnectionTerminated, TrailersReceived,
    ResponseReceived, Event
)

class NativeProxyHandler(BaseProxyHandler):
    """
    Handles HTTP/2 connections (RFC 9113).
    Manages H2 frame parsing, stream multiplexing, and flow control.
    """
    __slots__ = (
        'client_reader', 'client_writer', 'target_override', 'scope_pattern', 'enable_tunneling',
        'initial_data', 'upstream_reader', 'upstream_writer', 'upstream_scheme', 'ds_h2_lock',
        'us_h2_lock', 'ds_socket_lock', 'us_socket_lock', 'downstream_conn', 'upstream_conn',
        'streams', 'closed', 'draining', 'upstream_protocol', 'upstream_connecting'
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        explicit_host: str,
        manager_callback: Callable[[str, object], None],
        target_override: Optional[str],
        scope_pattern: Optional[re.Pattern[str]],
        enable_tunneling: bool = True,
        upstream_verify_ssl: bool = False,
        upstream_ca_bundle: Optional[str] = None,
        initial_data: bytes = b"",
        ssl_context_factory: Optional[Callable[[str], ssl.SSLContext]] = None
    ):
        """Initializes the HTTP/2 proxy handler."""
        raw_addr = writer.get_extra_info('peername') if writer else None
        client_addr = None
        if isinstance(raw_addr, tuple) and len(raw_addr) >= 2:
            client_addr = (str(raw_addr[0]), int(raw_addr[1]))

        super().__init__(
            explicit_host, upstream_verify_ssl, upstream_ca_bundle,
            manager_callback, ssl_context_factory, client_addr
        )

        self.client_reader = reader
        self.client_writer = writer
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling
        self.initial_data = initial_data
        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None
        self.upstream_scheme = "https"
        self.upstream_protocol = "h2"

        self.ds_h2_lock = asyncio.Lock()
        self.us_h2_lock = asyncio.Lock()
        self.ds_socket_lock = asyncio.Lock()
        self.us_socket_lock = asyncio.Lock()
        self.upstream_connecting = asyncio.Lock()

        # RFC 9113: Strict header validation is mandated.
        ds_config = H2Configuration(
            client_side=False, header_encoding='utf-8',
            validate_inbound_headers=True, validate_outbound_headers=True
        )
        self.downstream_conn = H2Connection(config=ds_config)

        # RFC 9113 Section 8.4: Server Push is deprecated. Explicitly disabled.
        self.downstream_conn.local_settings[SettingCodes.ENABLE_PUSH] = 0
        self.downstream_conn.local_settings[SettingCodes.MAX_HEADER_LIST_SIZE] = (
            MAX_HEADER_LIST_SIZE
        )
        self.downstream_conn.local_settings[SettingCodes.ENABLE_CONNECT_PROTOCOL] = 1

        self.upstream_conn: Optional[H2Connection] = None
        self.streams: Dict[int, H2StreamContext] = {}
        self.closed = asyncio.Event()
        self.draining = False

    async def run(self) -> None:
        """Executes the HTTP/2 Proxy loop."""
        try:
            try:
                self.upstream_host, self.upstream_port = self._parse_target(self.explicit_host)
            except ValueError:
                pass

            if self.enable_tunneling and self.upstream_host:
                await self._init_upstream_connection(self.upstream_host, self.upstream_port)

            self.downstream_conn.initiate_connection()
            await self.flush(
                self.downstream_conn, self.client_writer,
                self.ds_h2_lock, self.ds_socket_lock, True
            )

            if self.initial_data:
                async with self.ds_h2_lock:
                    events = self.downstream_conn.receive_data(self.initial_data)
                for e in events:
                    await self.handle_downstream_event(e)
                await self.flush(
                    self.downstream_conn, self.client_writer,
                    self.ds_h2_lock, self.ds_socket_lock
                )

            tasks = [
                asyncio.create_task(self._monitor_shutdown()),
                asyncio.create_task(self._read_loop_wrapper(
                    self.client_reader, self.downstream_conn, self.ds_h2_lock,
                    self.client_writer, self.ds_socket_lock, self.handle_downstream_event
                )),
                asyncio.create_task(self._keepalive_loop())
            ]

            if self.upstream_reader and self.upstream_protocol == "h2":
                tasks.append(asyncio.create_task(self._start_upstream_reader()))

            await asyncio.gather(*tasks)
        except Exception as e: # pylint: disable=broad-exception-caught
            if not self.closed.is_set():
                self.log("ERROR", f"H2 Proxy Error: {e}")
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally:
            await self.cleanup()

    async def _init_upstream_connection(self, host: str, port: int) -> None:
        """Initializes the upstream connection, negotiating ALPN."""
        try:
            self.upstream_reader, self.upstream_writer = await self._connect_upstream(
                host, port, alpn_protocols=["h2", "http/1.1"]
            )
            transport = self.upstream_writer.get_extra_info('ssl_object')
            if transport and transport.selected_alpn_protocol() == "http/1.1":
                self.upstream_protocol = "http/1.1"

            if self.upstream_protocol == "h2":
                us_config = H2Configuration(client_side=True, header_encoding='utf-8')
                self.upstream_conn = H2Connection(config=us_config)
                self.upstream_conn.initiate_connection()
                await self.flush(
                    self.upstream_conn, self.upstream_writer,
                    self.us_h2_lock, self.us_socket_lock, True
                )
            else:
                # If HTTP/1.1 is selected, we close the H2-spec connection handle
                # and rely on the gateway bridge spawning later.
                if self.upstream_writer:
                    self.upstream_writer.close()
                    await self.upstream_writer.wait_closed()
                    self.upstream_reader = None
                    self.upstream_writer = None
        except Exception as e:
            self.log("ERROR", f"Upstream Connect Failed: {e}")
            raise

    async def _ensure_upstream_connected(self, authority: str) -> None:
        """Ensures an upstream connection exists for the given authority."""
        async with self.upstream_connecting:
            if self.upstream_conn or (self.upstream_protocol == "http/1.1" and self.upstream_host):
                return
            host, port = self._parse_target(authority)
            self.upstream_host = host
            self.upstream_port = port
            await self._init_upstream_connection(host, port)
            if self.upstream_reader and self.upstream_protocol == "h2":
                asyncio.create_task(self._start_upstream_reader())

    async def _start_upstream_reader(self) -> None:
        """Starts the read loop for the upstream connection."""
        if self.upstream_reader:
            await self._read_loop_wrapper(
                self.upstream_reader, self.upstream_conn, self.us_h2_lock,
                self.upstream_writer, self.us_socket_lock, self.handle_upstream_event
            )

    async def _read_loop_wrapper(
        self, reader: asyncio.StreamReader, conn: Optional[H2Connection], h2_lock: asyncio.Lock,
        writer: Optional[asyncio.StreamWriter], socket_lock: asyncio.Lock,
        event_handler: Callable[[Event], asyncio.Future[None]]
    ) -> None:
        """Wrapper to safely launch the read loop."""
        try:
            if conn and writer:
                await self.read_loop(reader, conn, h2_lock, writer, socket_lock, event_handler)
        except Exception: # pylint: disable=broad-exception-caught
            self.closed.set()

    async def read_loop(
        self, reader: asyncio.StreamReader, conn: H2Connection, h2_lock: asyncio.Lock,
        writer: asyncio.StreamWriter, socket_lock: asyncio.Lock,
        event_handler: Callable[[Event], asyncio.Future[None]]
    ) -> None:
        """Continuously reads frames from the stream and dispatches events."""
        while not self.closed.is_set():
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                if not self.draining:
                    asyncio.create_task(self.graceful_shutdown())
                continue

            if not data:
                self.closed.set()
                break

            async with h2_lock:
                try:
                    events = conn.receive_data(data)
                except Exception: # pylint: disable=broad-exception-caught
                    # RFC 9113: Malformed requests (padding errors, etc) MUST cause connection error
                    await self.terminate(ErrorCodes.PROTOCOL_ERROR)
                    break
                bytes_to_send = conn.data_to_send()

            if bytes_to_send:
                async with socket_lock:
                    try:
                        writer.write(bytes_to_send)
                    except OSError:
                        break

            # RFC 9113: Deprecated frames (like PRIORITY) are parsed but ignored.
            for event in events:
                await event_handler(cast(Event, event))

    async def _stream_sender(
        self, stream_id: int, conn: H2Connection, writer: asyncio.StreamWriter,
        queue: asyncio.Queue[Optional[QueueItem]], flow_event: asyncio.Event,
        h2_lock: asyncio.Lock, socket_lock: asyncio.Lock,
        ack_conn: Optional[H2Connection], ack_h2_lock: Optional[asyncio.Lock],
        ack_writer: Optional[asyncio.StreamWriter], ack_socket_lock: Optional[asyncio.Lock]
    ) -> None:
        """
        Consumes the stream queue and sends data frames or headers.
        Implements H2 flow control waiting logic.
        """
        while not self.closed.is_set():
            try:
                # Batch processing for efficiency
                items = [await queue.get()]
                try:
                    for _ in range(10):
                        items.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    pass

                for item in items:
                    if item is None:
                        queue.task_done()
                        return

                    payload, end_stream, ack_length = item
                    await self._process_stream_item(
                        stream_id, conn, writer, payload, end_stream, ack_length,
                        flow_event, h2_lock, socket_lock
                    )

                    if (
                        ack_conn and ack_length > 0
                        and ack_h2_lock and ack_socket_lock and ack_writer
                    ):
                        await self._send_ack(
                            ack_conn, ack_h2_lock, ack_writer,
                            ack_socket_lock, ack_length, stream_id
                        )

                    queue.task_done()
                    if end_stream:
                        return
            except Exception as e: # pylint: disable=broad-exception-caught
                self.log("ERROR", f"Stream sender {stream_id} error: {e}")
                break

        try:
            queue.task_done()
        except Exception: # pylint: disable=broad-exception-caught
            pass

    async def _process_stream_item(
        self, stream_id: int, conn: H2Connection, writer: asyncio.StreamWriter,
        payload: Union[List[Tuple[bytes, bytes]], bytes],
        end_stream: bool, ack_length: int, flow_event: asyncio.Event,
        h2_lock: asyncio.Lock, socket_lock: asyncio.Lock
    ) -> None:
        """Processes a single item (headers or data) from the stream queue."""
        _ = ack_length # Unused explicitly to avoid linter warning
        if isinstance(payload, list):
            async with h2_lock:
                try:
                    conn.send_headers(stream_id, payload, end_stream=end_stream)
                    bytes_to_send = conn.data_to_send()
                except Exception: # pylint: disable=broad-exception-caught
                    bytes_to_send = None
            if bytes_to_send:
                async with socket_lock:
                    writer.write(bytes_to_send)
                    await writer.drain()
        else:
            await self._send_data_payload(
                stream_id, conn, writer, payload, end_stream, flow_event, h2_lock, socket_lock
            )

    async def _send_data_payload(
        self, stream_id: int, conn: H2Connection, writer: asyncio.StreamWriter,
        data: bytes, end_stream: bool, flow_event: asyncio.Event,
        h2_lock: asyncio.Lock, socket_lock: asyncio.Lock
    ) -> None:
        """Sends data payload respecting flow control windows."""
        view = memoryview(data)
        offset = 0
        total_len = len(data)

        while offset < total_len or (total_len == 0 and end_stream):
            if self.closed.is_set():
                break

            bytes_to_send = None
            break_loop = False
            wait_for_flow = False

            async with h2_lock:
                try:
                    avail = min(
                        conn.outbound_flow_control_window,
                        conn.remote_flow_control_window(stream_id)
                    )
                    if avail <= 0 and not (total_len == 0 and end_stream):
                        flow_event.clear()
                        wait_for_flow = True
                    else:
                        chunk_size = max(0, min(total_len - offset, avail))
                        chunk = view[offset:offset+chunk_size]
                        conn.send_data(
                            stream_id, chunk.tobytes(),
                            end_stream=(offset+chunk_size == total_len) and end_stream
                        )
                        bytes_to_send = conn.data_to_send()
                        offset += chunk_size
                        if offset >= total_len:
                            break_loop = True
                except Exception: # pylint: disable=broad-exception-caught
                    break_loop = True

            if wait_for_flow:
                try:
                    await asyncio.wait_for(flow_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                except asyncio.TimeoutError:
                    break
                continue

            if bytes_to_send:
                async with socket_lock:
                    writer.write(bytes_to_send)
                    await writer.drain()

            if break_loop:
                break

    async def _send_ack(
        self, ack_conn: H2Connection, ack_h2_lock: asyncio.Lock,
        ack_writer: asyncio.StreamWriter, ack_socket_lock: asyncio.Lock,
        ack_length: int, stream_id: int
    ) -> None:
        """Sends flow control acknowledgments."""
        ack_bytes = None
        async with ack_h2_lock:
            try:
                ack_conn.acknowledge_received_data(ack_length, stream_id)
                ack_bytes = ack_conn.data_to_send()
            except Exception: # pylint: disable=broad-exception-caught
                pass

        if ack_bytes:
            async with ack_socket_lock:
                ack_writer.write(ack_bytes)

    async def handle_request_received(self, event: RequestReceived) -> None:
        """Handles a new stream request from the client."""
        sid = event.stream_id
        if sid in self.streams:
            async with self.ds_h2_lock:
                self.downstream_conn.reset_stream(sid, ErrorCodes.PROTOCOL_ERROR)
            return

        ctx = H2StreamContext(sid, self.upstream_scheme, self.client_addr)
        self.streams[sid] = ctx
        ctx.captured_headers = process_h2_headers_for_capture(event.headers)

        headers, protocol = self._prepare_forwarded_headers(event.headers, True)
        ctx.method = next((v.decode() for k, v in headers if k == b':method'), "GET")
        authority = next((v.decode() for k, v in headers if k == b':authority'), "")

        if self.enable_tunneling:
            await self._setup_tunneling(ctx, sid, headers, protocol, authority, event.stream_ended)

        if event.stream_ended:
            ctx.downstream_closed = True
            self.finalize_capture(ctx)
            if self.enable_tunneling:
                ctx.upstream_queue.put_nowait(None)

    async def _setup_tunneling(
        self, ctx: H2StreamContext, sid: int, headers: List[Tuple[bytes, bytes]],
        protocol: Optional[bytes], authority: str, end_stream: bool
    ) -> None:
        """Sets up the tunnel (H2 or H1 gateway) for the stream."""
        if not self.upstream_conn and self.upstream_protocol == "h2" and ctx.method != 'CONNECT':
            try:
                await self._ensure_upstream_connected(authority)
            except Exception: # pylint: disable=broad-exception-caught
                async with self.ds_h2_lock:
                    self.downstream_conn.reset_stream(sid, ErrorCodes.CONNECT_ERROR)
                return

        if ctx.method == 'CONNECT' and not protocol:
            await self._handle_h2_connect(sid, authority, ctx)
            return

        if self.upstream_protocol == "h2" and self.upstream_conn:
            if protocol:
                if not self.upstream_conn.remote_settings.get(
                    SettingCodes.ENABLE_CONNECT_PROTOCOL, 0
                ):
                    async with self.ds_h2_lock:
                        self.downstream_conn.reset_stream(sid, ErrorCodes.CONNECT_ERROR)
                    self._cleanup_stream(sid, force_close=True)
                    return

            async with self.us_h2_lock:
                self.upstream_conn.send_headers(sid, headers, end_stream=end_stream)
            await self.flush(
                self.upstream_conn, self.upstream_writer,
                self.us_h2_lock, self.us_socket_lock, True
            )
            self._spawn_h2_tunnel(ctx, sid)
        elif self.upstream_protocol == "http/1.1":
            ctx.upstream_queue.put_nowait((headers, end_stream, 0))
            self._spawn_h1_gateway(ctx, authority)

    async def _handle_h2_connect(self, sid: int, authority: str, ctx: H2StreamContext) -> None:
        """Handles HTTP/2 CONNECT requests for tunneling."""
        async with self.ds_h2_lock:
            self.downstream_conn.send_headers(sid, [(b':status', b'200')], end_stream=False)
        await self.flush(
            self.downstream_conn, self.client_writer,
            self.ds_h2_lock, self.ds_socket_lock, True
        )

        try:
            h, p = self._parse_target(authority)
            tr, tw = await self._connect_upstream(h, p)
        except Exception: # pylint: disable=broad-exception-caught
            async with self.ds_h2_lock:
                self.downstream_conn.reset_stream(sid, ErrorCodes.CONNECT_ERROR)
            return

        ctx.sender_tasks.extend([
            asyncio.create_task(self._raw_tcp_bridge_task(ctx, tr, tw)),
            asyncio.create_task(self._stream_sender(
                sid, self.downstream_conn, self.client_writer, ctx.downstream_queue,
                ctx.downstream_flow_event, self.ds_h2_lock, self.ds_socket_lock,
                None, None, None, None
            ))
        ])

    def _spawn_h2_tunnel(self, ctx: H2StreamContext, sid: int) -> None:
        """Spawns bidirectional tasks for H2-to-H2 stream bridging."""
        ctx.sender_tasks.extend([
            asyncio.create_task(self._stream_sender(
                sid, self.downstream_conn, self.client_writer, ctx.downstream_queue,
                ctx.downstream_flow_event, self.ds_h2_lock, self.ds_socket_lock,
                self.upstream_conn, self.us_h2_lock, self.upstream_writer, self.us_socket_lock
            )),
            asyncio.create_task(self._stream_sender(
                sid, self.upstream_conn, self.upstream_writer, ctx.upstream_queue,
                ctx.upstream_flow_event, self.us_h2_lock, self.us_socket_lock,
                self.downstream_conn, self.ds_h2_lock, self.client_writer, self.ds_socket_lock
            ))
        ])

    def _spawn_h1_gateway(self, ctx: H2StreamContext, authority: str) -> None:
        """Spawns tasks for H2-to-H1 stream gateway."""
        ctx.sender_tasks.extend([
            asyncio.create_task(self._h1_bridge_task(ctx, authority)),
            asyncio.create_task(self._stream_sender(
                ctx.stream_id, self.downstream_conn, self.client_writer,
                ctx.downstream_queue, ctx.downstream_flow_event, self.ds_h2_lock,
                self.ds_socket_lock, None, None, None, None
            ))
        ])

    async def _h1_bridge_task(self, ctx: H2StreamContext, authority: str) -> None:
        """Manages the lifecycle of an H2-to-H1 translation bridge."""
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            h, p = self._parse_target(authority if authority else self.upstream_host)
            reader, writer = await self._connect_upstream(h, p)

            await self._process_h1_upstream_send(ctx, writer, authority)
            await self._process_h1_upstream_receive(ctx, reader)

        except Exception: # pylint: disable=broad-exception-caught
            async with self.ds_h2_lock:
                try:
                    self.downstream_conn.reset_stream(ctx.stream_id, ErrorCodes.INTERNAL_ERROR)
                except Exception: # pylint: disable=broad-exception-caught
                    pass
        finally:
            if writer:
                writer.close()
            self._cleanup_stream(ctx.stream_id, upstream_closed=True)

    async def _process_h1_upstream_send(
        self, ctx: H2StreamContext, writer: asyncio.StreamWriter, authority: str
    ) -> None:
        """Translates H2 frames to H1 and sends to upstream."""
        item = await ctx.upstream_queue.get()
        if item:
            headers, end_stream, _ = item
            if isinstance(headers, list):
                req_line, h1_headers = convert_h2_to_h1(headers, authority)
                writer.write(req_line)
                for k, v in h1_headers:
                    if not end_stream and k.lower() == b'content-length':
                        continue
                    writer.write(k + b": " + v + b"\r\n")

                writer.write(b"\r\n" if end_stream else b"Transfer-Encoding: chunked\r\n\r\n")
                await writer.drain()
            ctx.upstream_queue.task_done()

            if not end_stream:
                while True:
                    item = await ctx.upstream_queue.get()
                    if item is None:
                        break
                    data, is_fin, _ = item
                    if isinstance(data, bytes) and data:
                        writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                    if is_fin:
                        writer.write(b"0\r\n\r\n")
                        await writer.drain()
                        ctx.upstream_queue.task_done()
                        break
                    await writer.drain()
                    ctx.upstream_queue.task_done()

    async def _process_h1_upstream_receive(
        self, ctx: H2StreamContext, reader: asyncio.StreamReader
    ) -> None:
        """Translates H1 response to H2 frames and enqueues for downstream."""
        buffer = bytearray()
        line = await self._read_line_h1_bridge(reader, buffer)
        if not line:
            raise ConnectionError("Empty response")

        status = line.split(b' ', 2)[1]
        resp_headers: List[Tuple[bytes, bytes]] = [(b':status', status)]

        while True:
            h = await self._read_line_h1_bridge(reader, buffer)
            if not h:
                break
            if b':' in h:
                k, v = h.split(b':', 1)
                k_lower = k.strip().lower()
                if k_lower in H2_FORBIDDEN_HEADERS:
                    continue
                resp_headers.append((k_lower, v.strip()))

        await ctx.downstream_queue.put((resp_headers, False, 0))

        while not reader.at_eof():
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not chunk:
                break
            await ctx.downstream_queue.put((chunk, False, 0))
        await ctx.downstream_queue.put((b"", True, 0))

    def _convert_h2_to_h1(
        self, headers: List[Tuple[bytes, bytes]], default_auth: str
    ) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
        """Converts H2 pseudo-headers to H1 request line and headers."""
        return convert_h2_to_h1(headers, default_auth)

    async def _read_line_h1_bridge(
        self, reader: asyncio.StreamReader, buffer: bytearray
    ) -> bytes:
        """Reads a line from the H1 stream for bridge processing."""
        while True:
            idx = buffer.find(b'\n')
            if idx >= 0:
                line = buffer[:idx+1]
                del buffer[:idx+1]
                return line.strip()
            data = await reader.read(8192)
            if not data:
                return b""
            buffer.extend(data)

    async def _raw_tcp_bridge_task(
        self, ctx: H2StreamContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Bridges raw TCP data for CONNECT tunnels."""
        async def c2u() -> None:
            try:
                while True:
                    item = await ctx.upstream_queue.get()
                    if item is None:
                        break
                    data, end, ack = item
                    if isinstance(data, bytes) and data:
                        writer.write(data)
                        await writer.drain()
                    if ack:
                        async with self.ds_h2_lock:
                            self.downstream_conn.acknowledge_received_data(ack, ctx.stream_id)
                        async with self.ds_socket_lock:
                            self.client_writer.write(self.downstream_conn.data_to_send())
                    ctx.upstream_queue.task_done()
                    if end:
                        break
            except Exception: # pylint: disable=broad-exception-caught
                pass

        async def u2c() -> None:
            try:
                while not reader.at_eof():
                    data = await reader.read(65536)
                    if not data:
                        break
                    await ctx.downstream_queue.put((data, False, 0))
            finally:
                await ctx.downstream_queue.put((b"", True, 0))

        await asyncio.gather(c2u(), u2c())
        writer.close()
        self._cleanup_stream(ctx.stream_id, upstream_closed=True, downstream_closed=True)

    def _prepare_forwarded_headers(
        self, headers: List[Tuple[bytes, bytes]], is_upstream: bool = True
    ) -> Tuple[List[Tuple[bytes, bytes]], Optional[bytes]]:
        """Cleans and filters headers for forwarding."""
        return prepare_forwarded_headers(headers, is_upstream, self.upstream_host)

    async def handle_downstream_event(self, event: Event) -> None:
        """Dispatches H2 events received from the client (downstream)."""
        if isinstance(event, RequestReceived):
            await self.handle_request_received(event)
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                ctx = self.streams[event.stream_id]
                if not ctx.truncated:
                    ctx.current_body_size += len(event.data)
                    if ctx.current_body_size > MAX_CAPTURE_BODY_SIZE:
                        ctx.truncated = True
                    else:
                        ctx.request_body_chunks.append(event.data)
                if self.enable_tunneling:
                    try:
                        ctx.upstream_queue.put_nowait(
                            (event.data, False, event.flow_controlled_length)
                        )
                    except asyncio.QueueFull:
                        self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, TrailersReceived):
            if event.stream_id in self.streams and self.enable_tunneling:
                try:
                    h, _ = self._prepare_forwarded_headers(event.headers, True)
                    ctx = self.streams[event.stream_id]
                    ctx.upstream_queue.put_nowait((h, event.stream_ended, 0))
                except asyncio.QueueFull:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded):
            self._cleanup_stream(event.stream_id, downstream_closed=True)
        elif isinstance(event, StreamReset):
            self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, WindowUpdated):
            await self.handle_window_updated(event, 'downstream')
        elif isinstance(event, ConnectionTerminated):
            self.closed.set()

    async def handle_upstream_event(self, event: Event) -> None:
        """Dispatches H2 events received from the upstream server."""
        if isinstance(event, ResponseReceived):
            if event.stream_id in self.streams:
                h, _ = self._prepare_forwarded_headers(event.headers, False)
                self.streams[event.stream_id].downstream_queue.put_nowait(
                    (h, event.stream_ended, 0)
                )
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                try:
                    self.streams[event.stream_id].downstream_queue.put_nowait(
                        (event.data, False, event.flow_controlled_length)
                    )
                except asyncio.QueueFull:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, TrailersReceived):
            if event.stream_id in self.streams and self.enable_tunneling:
                try:
                    h, _ = self._prepare_forwarded_headers(event.headers, False)
                    self.streams[event.stream_id].downstream_queue.put_nowait(
                        (h, event.stream_ended, 0)
                    )
                except asyncio.QueueFull:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded):
            self._cleanup_stream(event.stream_id, upstream_closed=True)
        elif isinstance(event, StreamReset):
            self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, WindowUpdated):
            await self.handle_window_updated(event, 'upstream')
        elif isinstance(event, ConnectionTerminated):
            self.closed.set()

        await self.flush(
            self.downstream_conn, self.client_writer,
            self.ds_h2_lock, self.ds_socket_lock, False
        )

    async def handle_window_updated(self, event: WindowUpdated, direction: str) -> None:
        """Handles window update events, notifying blocked streams."""
        sid = event.stream_id
        snapshot = list(self.streams.values())
        if sid == 0:
            for ctx in snapshot:
                if direction == 'upstream':
                    ctx.upstream_flow_event.set()
                else:
                    ctx.downstream_flow_event.set()
        elif sid in self.streams:
            ctx = self.streams[sid]
            if direction == 'upstream':
                ctx.upstream_flow_event.set()
            else:
                ctx.downstream_flow_event.set()

    def finalize_capture(self, ctx: H2StreamContext) -> None:
        """Finalizes the request capture and emits the log."""
        if ctx.capture_finalized:
            return
        ctx.capture_finalized = True
        pseudo = ctx.captured_headers["pseudo"]
        try:
            if self.target_override:
                url = urljoin(self.target_override, pseudo.get(':path', '/').lstrip('/'))
            else:
                url = urlunparse((
                    ctx.scheme,
                    pseudo.get(':authority', self.explicit_host),
                    pseudo.get(':path', '/'), '', '', ''
                ))
        except Exception: # pylint: disable=broad-exception-caught
            return

        captured = CapturedRequest(
            0, pseudo.get(':method', 'GET'), url, ctx.captured_headers["headers"],
            b"".join(ctx.request_body_chunks), ctx.truncated, "HTTP/2", None,
            ctx.start_time, time.time(), ctx.client_addr,
            (self.upstream_host, self.upstream_port)
        )
        self.log("CAPTURE", captured)

    async def _monitor_shutdown(self) -> None:
        """Monitors the closed event and tears down queues."""
        await self.closed.wait()
        for ctx in list(self.streams.values()):
            ctx.upstream_queue.put_nowait(None)
            ctx.downstream_queue.put_nowait(None)

    async def _keepalive_loop(self) -> None:
        """Sends periodic PING frames to keep connections alive."""
        while not self.closed.is_set():
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if self.upstream_conn and self.upstream_protocol == "h2":
                async with self.us_h2_lock:
                    try:
                        self.upstream_conn.ping(b'KeepAliv')
                    except Exception: # pylint: disable=broad-exception-caught
                        break
                await self.flush(
                    self.upstream_conn, self.upstream_writer,
                    self.us_h2_lock, self.us_socket_lock
                )

            async with self.ds_h2_lock:
                try:
                    self.downstream_conn.ping(b'KeepAliv')
                except Exception: # pylint: disable=broad-exception-caught
                    break
            await self.flush(
                self.downstream_conn, self.client_writer,
                self.ds_h2_lock, self.ds_socket_lock
            )

    async def cleanup(self) -> None:
        """Cleans up sockets and tasks."""
        self.closed.set()
        for w in [self.client_writer, self.upstream_writer]:
            if w:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception: # pylint: disable=broad-exception-caught
                    pass
        for ctx in list(self.streams.values()):
            for t in ctx.sender_tasks:
                t.cancel()

    async def terminate(self, code: int) -> None:
        """Terminates the connection with an error code."""
        self.closed.set()
        async with self.ds_h2_lock:
            try:
                self.downstream_conn.close_connection(code)
            except Exception: # pylint: disable=broad-exception-caught
                pass
        await self.flush(
            self.downstream_conn, self.client_writer,
            self.ds_h2_lock, self.ds_socket_lock, True
        )

    async def graceful_shutdown(self) -> None:
        """Performs a graceful GOAWAY shutdown."""
        if self.draining or self.closed.is_set():
            return
        self.draining = True
        async with self.ds_socket_lock:
            try:
                self.client_writer.write(GOAWAY_MAX_FRAME)
            except Exception: # pylint: disable=broad-exception-caught
                pass
        await asyncio.sleep(0.1)
        self.closed.set()
        async with self.ds_h2_lock:
            try:
                self.downstream_conn.close_connection(ErrorCodes.NO_ERROR)
            except Exception: # pylint: disable=broad-exception-caught
                pass
        await self.flush(
            self.downstream_conn, self.client_writer,
            self.ds_h2_lock, self.ds_socket_lock, True
        )

    async def flush(
        self, conn: H2Connection, writer: Optional[asyncio.StreamWriter],
        h2_lock: asyncio.Lock, socket_lock: asyncio.Lock, drain: bool = False
    ) -> None:
        """Flushes pending data from the H2 connection to the socket."""
        if self.closed.is_set() or not writer:
            return
        async with h2_lock:
            try:
                bytes_to_send = conn.data_to_send()
            except Exception: # pylint: disable=broad-exception-caught
                return
        if bytes_to_send:
            async with socket_lock:
                try:
                    writer.write(bytes_to_send)
                except Exception: # pylint: disable=broad-exception-caught
                    self.closed.set()
            if drain:
                try:
                    await writer.drain()
                except Exception: # pylint: disable=broad-exception-caught
                    self.closed.set()

    def _cleanup_stream(
        self, stream_id: int, downstream_closed: bool = False,
        upstream_closed: bool = False, force_close: bool = False
    ) -> None:
        """Releases resources associated with a stream."""
        if stream_id not in self.streams:
            return
        ctx = self.streams[stream_id]
        if downstream_closed:
            ctx.downstream_closed = True
        if upstream_closed:
            ctx.upstream_closed = True
        if ctx.downstream_closed:
            self.finalize_capture(ctx)
        if force_close or (ctx.downstream_closed and ctx.upstream_closed):
            ctx.upstream_flow_event.set()
            ctx.downstream_flow_event.set()
            for t in ctx.sender_tasks:
                t.cancel()
            del self.streams[stream_id]
