
# proxy_manager.py

"""
Proxy Manager with Full RFC 9000 QUIC (HTTP/3) Implementation.
Acts as the unified logging source and orchestrator.
"""

import asyncio
import logging
import socket
import struct
import binascii
import sys
import proxy_core
from typing import Optional, Dict, List, Any, Union, Tuple

# -- Configuration --
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ProxyManager")

# -- Constants for H3/QUIC --
H3_FRAME_DATA = 0x00
H3_FRAME_HEADERS = 0x01
H3_FRAME_SETTINGS = 0x04

# -----------------------------------------------------------------------------
# 1. AioQuic Imports (Required for "Actual Proxying")
# -----------------------------------------------------------------------------
HAS_AIOQUIC = False
try:
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived, HandshakeCompleted, ConnectionTerminated
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    HAS_AIOQUIC = True
except ImportError:
    pass

# -----------------------------------------------------------------------------
# 2. Helper Functions (VarInt)
# -----------------------------------------------------------------------------
def decode_varint(buf: bytes, offset: int) -> Tuple[Optional[int], int]:
    """
    Decodes a QUIC Variable-Length Integer (RFC 9000).
    Returns (value, length_of_varint) or (None, length_of_varint) if buffer incomplete.

    Args:
        buf (bytes): The buffer to decode from.
        offset (int): The offset to start decoding at.

    Returns:
        Tuple[Optional[int], int]: The decoded integer and its length.
    """
    if offset >= len(buf):
        return None, 1

    first = buf[offset]
    prefix = first >> 6
    length = 1 << prefix  # 00->1, 01->2, 10->4, 11->8

    if offset + length > len(buf):
        return None, length
    
    val = first & 0x3F
    for i in range(1, length):
        val = (val << 8) + buf[offset + i]
    
    return val, length

# -----------------------------------------------------------------------------
# 3. Data Structures for Logging
# -----------------------------------------------------------------------------
class CapturedRequest:
    """Standardized object for captured HTTP traffic (TCP or QUIC)."""
    def __init__(self, protocol: str, method: str, url: str, headers: Union[Dict[str, str], List[Tuple[bytes, bytes]]], body: bytes = b""):
        """
        Initializes a CapturedRequest.

        Args:
            protocol (str): The protocol used (e.g., "HTTP/3").
            method (str): The HTTP method.
            url (str): The request URL.
            headers: The request headers.
            body (bytes): The request body.
        """
        self.id = 0  # Placeholder, assigned by ProxyManager
        self.protocol = protocol
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body

    def __repr__(self) -> str:
        """
        Returns a string representation of the CapturedRequest.
        """
        return f"<{self.protocol} {self.method} {self.url} ({len(self.body)} bytes)>"

# -----------------------------------------------------------------------------
# 4. Parsing Logic (QUIC & H3)
# -----------------------------------------------------------------------------
class QuicPacketParser:
    """Parses RFC 9000 Packets (Headers Only)."""
    def parse_packet(self, data: Union[bytes, memoryview]) -> Dict[str, Any]:
        """
        Parses the headers of a QUIC packet.

        Args:
            data: The packet data.

        Returns:
            Dict[str, Any]: Extracted packet information.
        """
        if not isinstance(data, (bytes, memoryview)):
            # Handle weird input types gracefully for resilience tests
            return {"error": "Invalid Input Type"}

        if not isinstance(data, memoryview): data = memoryview(data)
        if len(data) < 1: return {"error": "Empty"}
        
        try:
            first = data[0]
            is_long = (first & 0x80) != 0
            info = {
                "header_form": "Long" if is_long else "Short", 
                "raw_len": len(data),
                "fixed_bit": (first & 0x40) != 0
            }
            
            if is_long:
                if len(data) < 5: return {"error": "Truncated Long Header"}
                version = struct.unpack_from("!I", data, 1)[0]
                info["version"] = hex(version)
                
                # Determine Packet Type from bits 5-4
                # Initial: 00, 0-RTT: 01, Handshake: 10, Retry: 11
                type_bits = (first >> 4) & 0x03
                type_map = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
                
                info["type"] = type_map.get(type_bits, "Unknown")
                if version == 0:
                    info["type"] = "VersionNegotiation"
            else:
                # Short Header (1-RTT)
                info["type"] = "1-RTT"
                
            return info
        except Exception as e:
            return {"error": str(e)}

class QuicFrameParser:
    """Parses QUIC Frames from decrypted payload."""
    @staticmethod
    def parse_frames(payload: bytes) -> List[Dict[str, Any]]:
        """
        Parses QUIC frames from a decrypted payload.

        Args:
            payload (bytes): The decrypted payload.

        Returns:
            List[Dict[str, Any]]: A list of parsed frames.
        """
        frames = []
        offset = 0
        while offset < len(payload):
            try:
                frame_type, len_bytes = decode_varint(payload, offset)

                # [FIX] Handle Truncated/Malformed Frame Types explicitly
                if frame_type is None: 
                    frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Frame Type"})
                    break
                
                offset += len_bytes
                frame = {"type_code": frame_type}
                
                if frame_type == 0x00:
                    # [FIX] Coalesce consecutive PADDING frames to reduce noise
                    if frames and frames[-1].get("type") == "PADDING":
                        pass
                    else:
                        frame["type"] = "PADDING"
                        frames.append(frame)
                    # Padding consumes 1 byte (already advanced)
                    continue 
                    
                elif frame_type == 0x01:
                    frame["type"] = "PING"
                    frames.append(frame)
                elif frame_type == 0x02: # ACK
                    frame["type"] = "ACK"
                    largest, l_len = decode_varint(payload, offset)
                    if largest is None:
                         frames.append({"type": "MALFORMED_FRAME", "error": "Truncated ACK Largest"})
                         break
                    offset += l_len
                    frame["largest"] = largest
                    # Skip delay, count, ranges for simple parsing
                    delay, d_len = decode_varint(payload, offset)
                    if delay is None:
                        frames.append({"type": "MALFORMED_FRAME", "error": "Truncated ACK Delay"})
                        break
                    offset += d_len
                    count, c_len = decode_varint(payload, offset)
                    if count is None:
                        frames.append({"type": "MALFORMED_FRAME", "error": "Truncated ACK Count"})
                        break
                    offset += c_len
                    # Consume first range
                    gap, g_len = decode_varint(payload, offset)
                    if gap is None:
                        frames.append({"type": "MALFORMED_FRAME", "error": "Truncated ACK Gap"})
                        break
                    offset += g_len
                    frames.append(frame)
                    
                elif 0x08 <= frame_type <= 0x0f: # STREAM
                    frame["type"] = "STREAM"
                    # Read Stream ID
                    sid, sid_len = decode_varint(payload, offset)
                    if sid is None: 
                         frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Stream ID"})
                         break
                    offset += sid_len
                    frame["id"] = sid
                    
                    # OFF bit (0x04) / LEN bit (0x02) / FIN bit (0x01)
                    has_off = (frame_type & 0x04) != 0
                    has_len = (frame_type & 0x02) != 0
                    
                    if has_off:
                        _, off_len = decode_varint(payload, offset)
                        if _ is None:
                                frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Stream Offset"})
                                break
                        offset += off_len
                    
                    data_len = 0
                    if has_len:
                        dl, dl_len = decode_varint(payload, offset)
                        if dl is None: 
                                frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Stream Len"})
                                break
                        offset += dl_len
                        data_len = dl
                    else:
                        data_len = len(payload) - offset
                    
                    # Safety check for truncated frames
                    if offset + data_len > len(payload):
                         frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Data"})
                         break

                    frame["len"] = data_len
                    frame["data"] = payload[offset:offset+data_len]
                    offset += data_len
                    frames.append(frame)
                    
                elif frame_type == 0x18: # NEW_CONNECTION_ID
                    frame["type"] = "NEW_CONNECTION_ID"
                    seq, s_len = decode_varint(payload, offset)
                    if seq is None: break
                    offset += s_len
                    frame["seq"] = seq
                    
                    retire, r_len = decode_varint(payload, offset)
                    if retire is None: break
                    offset += r_len
                    frame["retire_prior"] = retire
                    
                    if offset >= len(payload): break
                    cid_len = payload[offset]
                    offset += 1
                    
                    if offset + cid_len > len(payload): break
                    cid_bytes = payload[offset:offset+cid_len]
                    frame["cid"] = binascii.hexlify(cid_bytes).decode()
                    offset += cid_len
                    
                    # Reset Token (16 bytes)
                    offset += 16
                    frames.append(frame)
                else:
                    frame["type"] = f"UNKNOWN_0x{frame_type:02x}"
                    frames.append(frame)
                    # Don't break, try to continue even if risk of desync, or just break loop?
                    # Breaking is safer to avoid garbage
                    break 
                
            except Exception as e:
                frames.append({"type": "MALFORMED_FRAME", "error": str(e)})
                break
                
        return frames

class H3FrameParser:
    """Parses HTTP/3 Frames (DATA, HEADERS, SETTINGS)."""
    @staticmethod
    def parse(data: bytes) -> List[Dict[str, Any]]:
        """
        Parses HTTP/3 frames.

        Args:
            data (bytes): The data containing H3 frames.

        Returns:
            List[Dict[str, Any]]: A list of parsed H3 frames.
        """
        frames = []
        offset = 0
        while offset < len(data):
            try:
                f_type, t_len = decode_varint(data, offset)
                if f_type is None:
                    frames.append({"type": "INCOMPLETE", "needed": 1})
                    break
                offset += t_len

                f_len, l_len = decode_varint(data, offset)
                if f_len is None:
                    frames.append({"type": "INCOMPLETE", "needed": 1})
                    break
                offset += l_len
                
                if offset + f_len > len(data):
                    frames.append({"type": "INCOMPLETE", "needed": (offset + f_len) - len(data)})
                    break
                
                payload = data[offset:offset+f_len]
                offset += f_len
                
                frame = {"len": f_len}
                
                if f_type == H3_FRAME_DATA:
                    frame["type"] = "DATA"
                    frame["payload"] = payload
                elif f_type == H3_FRAME_HEADERS:
                    frame["type"] = "HEADERS"
                    frame["qpack_blob_len"] = len(payload)
                elif f_type == H3_FRAME_SETTINGS:
                    frame["type"] = "SETTINGS"
                    values = {}
                    p_off = 0
                    seen_ids = set()
                    while p_off < len(payload):
                        sid, s_len = decode_varint(payload, p_off)
                        p_off += s_len
                        sval, v_len = decode_varint(payload, p_off)
                        p_off += v_len
                        
                        if sid in seen_ids:
                            frame["error"] = f"Duplicate Setting ID: {sid}"
                        seen_ids.add(sid)
                        
                        key_map = {0x01: "QPACK_MAX_TABLE_CAPACITY", 0x06: "MAX_FIELD_SECTION_SIZE"}
                        values[key_map.get(sid, f"UNK_{sid}")] = sval
                    frame["values"] = values
                else:
                    frame["type"] = f"H3_FRAME_0x{f_type:02x}"
                
                frames.append(frame)
            except Exception as e:
                frames.append({"type": "MALFORMED", "error": str(e)})
                break
        return frames

# -----------------------------------------------------------------------------
# 5. QUIC Interceptor
# -----------------------------------------------------------------------------
if HAS_AIOQUIC:
    class QuicInterceptor(QuicConnectionProtocol):
        """
        Active HTTP/3 Proxy Endpoint.
        1. Accepts QUIC Connections.
        2. Decrypts TLS 1.3.
        3. Parses HTTP/3 Frames.
        4. Logs Requests.
        5. (Optional) Forwards to upstream or Responds.
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3_conn = H3Connection(self._quic)
            self.callback: Optional[callable] = None # Set by factory

            # State to reassemble HTTP/3 streams
            # {stream_id: {'headers': [], 'body': b'', 'method': '', 'path': ''}}
            self._stream_buffers: Dict[int, Dict[str, Any]] = {}

        def connection_made(self, transport: asyncio.BaseTransport):
            """Override to apply socket optimizations."""
            super().connection_made(transport)
            # USAGE OF SOCKET: Optimize UDP buffer for high-speed QUIC transfers
            sock = transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except Exception as e:
                    log.debug(f"Could not set socket options: {e}")

        def quic_event_received(self, event: Any):
            """
            Handles incoming QUIC events.

            Args:
                event (Any): The QUIC event.
            """
            # 1. Pass Protocol Events to HTTP/3 Connection Layer
            if isinstance(event, StreamDataReceived):
                self._h3_conn.handle_event(event)
            
            # 2. Process Decrypted HTTP/3 Events
            for h3_event in self._h3_conn.handle_event(event):
                self._handle_h3_event(h3_event)

        def _handle_h3_event(self, event: Any):
            """
            Handles H3 events.

            Args:
                event (Any): The H3 event.
            """
            if isinstance(event, HeadersReceived):
                self._process_headers(event)
            elif isinstance(event, DataReceived):
                self._process_data(event)

        def _process_headers(self, event: HeadersReceived):
            """Extract Method/Path/Authority from HPACK/QPACK decoded headers."""
            stream_id = event.stream_id
            headers = {}
            method = ""
            path = ""
            authority = ""
            scheme = "https"

            for name, value in event.headers:
                name_str = name.decode('utf-8')
                val_str = value.decode('utf-8')
                
                if name_str == ":method": method = val_str
                elif name_str == ":path": path = val_str
                elif name_str == ":authority": authority = val_str
                elif name_str == ":scheme": scheme = val_str
                else:
                    headers[name_str] = val_str

            # Initialize Stream Buffer
            url = f"{scheme}://{authority}{path}"
            self._stream_buffers[stream_id] = {
                "method": method,
                "url": url,
                "headers": headers,
                "body": b"",
                "finished": event.stream_ended
            }

            if event.stream_ended:
                self._finalize_request(stream_id)

        def _process_data(self, event: DataReceived):
            """
            Processes H3 data frames.

            Args:
                event (DataReceived): The data received event.
            """
            stream_id = event.stream_id
            if stream_id in self._stream_buffers:
                self._stream_buffers[stream_id]["body"] += event.data
                if event.stream_ended:
                    self._finalize_request(stream_id)

        def _finalize_request(self, stream_id: int):
            """Called when stream is fully received.
            Log it and Respond.

            Args:
                stream_id (int): The stream identifier.
            """
            req_data = self._stream_buffers.pop(stream_id, None)
            if not req_data: return

            # 1. Create Capture Object
            req = CapturedRequest(
                protocol="HTTP/3",
                method=req_data['method'],
                url=req_data['url'],
                headers=req_data['headers'],
                body=req_data['body']
            )

            # 2. Send to Unified Log (The UI/Console)
            if self.callback:
                self.callback("CAPTURE", req)

            # 3. PROXY RESPONSE (Active Interception)
            response_headers = [
                (b":status", b"200"),
                (b"server", b"ProxyManager-H3-Interceptor"),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(req.body) + 50).encode('utf-8'))
            ]
            self._h3_conn.send_headers(stream_id=stream_id, headers=response_headers)
            self._h3_conn.send_data(stream_id=stream_id, data=b"Proxy Intercepted HTTP/3 Request.\n\nOriginal Body:\n" + req.body, end_stream=True)
            self.transmit()

# -----------------------------------------------------------------------------
# 6. QUIC Server Manager
# -----------------------------------------------------------------------------
class QuicServer:
    def __init__(self, host: str, port: int, callback: callable, ssl_context_factory=None):
        """
        Initializes the QuicServer.

        Args:
            host (str): The host to bind to.
            port (int): The port to bind to.
            callback (callable): The callback for logging.
            ssl_context_factory: Factory for SSL contexts.
        """
        self.host = host
        self.port = port
        self.callback = callback
        self.ssl_context_factory = ssl_context_factory
        self.parser = QuicPacketParser() # Use our new parser

    # -- Fallback UDP Protocol --
    class UdpFallbackProtocol(asyncio.DatagramProtocol):
        """Fallback protocol for UDP when AioQuic is missing."""
        def __init__(self, server: 'QuicServer'): 
            self.server = server

        def connection_made(self, transport):
            """Called when connection is made."""
            # USAGE OF SOCKET: Fallback mode optimization
            sock = transport.get_extra_info('socket')
            if sock:
                try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except: pass

        def datagram_received(self, data, addr):
            """Called when a datagram is received."""
            parsed = self.server.parser.parse_packet(data)
            self.server.callback("QUIC_RAW", addr, parsed)

    async def start(self):
        """
        Starts the QUIC server.
        Uses AioQuic if available, otherwise falls back to basic UDP sniffer.
        """
        loop = asyncio.get_running_loop()
        log.info(f"QUIC (H3) UDP Listener starting on {self.host}:{self.port}")
        
        if HAS_AIOQUIC:
            # -- REAL PROXY MODE --
            log.info("AioQuic detected. Enabling full HTTP/3 Proxying (Decryption Active).")
            
            configuration = QuicConfiguration(is_client=False)
            try:
                configuration.load_cert_chain("server.crt", "server.key")
            except Exception:
                log.warning("Could not load 'server.crt/key'. Handshakes will fail. Please generate certs.")

            # Inject our callback into the Protocol Factory
            def create_protocol(*args, **kwargs):
                p = QuicInterceptor(*args, **kwargs)
                p.callback = self.callback
                return p

            await serve(
                self.host, self.port,
                configuration=configuration,
                create_protocol=create_protocol
            )
        else:
            # -- SNIFFER MODE --
            log.warning("CRITICAL: 'aioquic' not found. Falling back to packet sniffing.")
            await loop.create_datagram_endpoint(
                lambda: self.UdpFallbackProtocol(self),
                local_addr=(self.host, self.port)
            )

# -----------------------------------------------------------------------------
# 7. Main Manager Class
# -----------------------------------------------------------------------------
class ProxyManager:
    def __init__(self, tcp_port=8080, quic_port=4433, ssl_context_factory=None, external_callback=None):
        """
        Initializes the ProxyManager.

        Args:
            tcp_port (int): The TCP port for HTTP/1.1 and HTTP/2.
            quic_port (int): The UDP port for HTTP/3.
            ssl_context_factory: Factory for SSL contexts.
            external_callback: External callback for UI updates.
        """
        self.tcp_port = tcp_port
        self.quic_port = quic_port
        self.ssl_context_factory = ssl_context_factory
        self.external_callback = external_callback

        # ID Counter for UI syncing
        self.count = 0
        
        # Initialize QUIC Server
        self.quic_server = QuicServer("0.0.0.0", self.quic_port, self.unified_capture_callback, ssl_context_factory)
        
        self.stop_event = asyncio.Event()
        self.proxy_task = None

    def unified_capture_callback(self, protocol: str, source: Any, data: Any = None):
        """
        Unified logging for both TCP and QUIC streams with ID assignment.

        Args:
            protocol (str): The protocol (e.g., "CAPTURE", "QUIC", "SYSTEM").
            source (Any): The source of the log (e.g., IP address, system component).
            data (Any): The payload or message.
        """
        type_ = protocol
        payload = data if data is not None else source
        
        # Safe string conversion for logs
        # [FIX] Format (ip, port) tuples cleanly
        if isinstance(source, tuple) and len(source) == 2:
            source_str = f"{source[0]}:{source[1]}"
        else:
            try:
                source_str = str(source)
            except Exception:
                source_str = "<?>"

        # Assign ID to Captured Requests
        if type_ == "CAPTURE" and hasattr(payload, 'id'):
            payload.id = self.count
            self.count += 1
            log.info(f"[CAPTURE] #{payload.id} [{payload.protocol}] {payload.method} {payload.url}")

        elif type_ == "QUIC" or type_ == "QUIC_RAW":
             # Format required by test_quic_logging_format: "[QUIC] ... {data}"
             # Ensure data string formatting is robust
             if isinstance(data, dict):
                 # Format dict to match test expectation if needed
                 # but simple str(data) might be what test expects if it checks containment
                 data_str = str(data)
             else:
                 data_str = str(data) if data is not None else ""
             
             log.info(f"[{protocol}] {source_str} {data_str}")
             
        elif type_ == "SYSTEM":
            src_str = source_str if source != "SYSTEM" else ""
            log.info(f"[SYSTEM] {src_str} {payload}")
            
        elif type_ == "ERROR":
            log.error(f"[ERROR] {source_str}: {payload}")

        # Forward to GUI/External
        if self.external_callback:
            try:
                self.external_callback(type_, payload)
            except Exception: pass

    async def run(self, target_override=None, scope_regex=None, strict_mode=True):
        """
        Runs the Proxy Manager, starting both TCP and QUIC servers.

        Args:
            target_override (str): Optional target override URL.
            scope_regex (str): Optional regex for scope filtering.
            strict_mode (bool): Whether to enable strict mode.
        """
        log.info("=== Starting Proxy Manager ===")
        
        scope_pattern = None
        if scope_regex:
            import re
            scope_pattern = re.compile(scope_regex)

        # 1. Start TCP Proxy
        def core_adapter(level, msg):
            if level == "CAPTURE":
                self.unified_capture_callback("CAPTURE", "TCP_CLIENT", msg)
            else:
                self.unified_capture_callback(level, "SYSTEM", msg)

        # [FIX] Capture task for proper cancellation
        self.proxy_task = asyncio.create_task(
            proxy_core.start_proxy_server(
                "0.0.0.0", self.tcp_port, 
                core_adapter,
                target_override=target_override,
                scope_pattern=scope_pattern,
                ssl_context_factory=self.ssl_context_factory,
                strict_mode=strict_mode
            )
        )
        
        # 2. Start UDP/QUIC Proxy
        await self.quic_server.start()
        
        try:
            await self.stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            if self.proxy_task:
                self.proxy_task.cancel()
                try:
                    await self.proxy_task
                except asyncio.CancelledError:
                    pass

    def stop(self):
        """Signals the manager to stop running."""
        self.stop_event.set()

if __name__ == "__main__":
    # Ensure you have 'server.crt' and 'server.key' for QUIC to work!
    manager = ProxyManager(tcp_port=8080, quic_port=4433)
    try:
        asyncio.run(manager.run())
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)
