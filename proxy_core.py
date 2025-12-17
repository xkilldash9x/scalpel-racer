# proxy_core.py

"""
[VECTOR] ASYNC PROXY CORE - SCALPEL RACER
RFC-Compliant Dual-Stack (HTTP/1.1 and HTTP/2) Proxy Handler.

Refactored for Manager Integration and Scalpel Racer MITM capabilities.
Includes full logic for recursive TLS upgrading, strict HTTP parsing,
and defense-in-depth security measures against Request Smuggling and DoS.

VECTOR OPTIMIZATIONS:
- IO: TCP_NODELAY enabled on upstream sockets.
- MEMORY: MemoryView slicing in strict line reader to avoid copying.
- IO: 64KB Read Chunks.
- MEMORY: __slots__ usage for high-frequency objects.
"""

import asyncio
import ssl
import re
import socket
import time
from typing import Dict, Optional, Callable, Tuple, List, Any, Set, TypedDict, TYPE_CHECKING
from urllib.parse import urljoin, urlunparse, urlparse

# --- Data Structures & Imports ---
try:
    from structures import CapturedRequest, CapturedHeaders
except ImportError:
    from dataclasses import dataclass
    
    @dataclass
    class CapturedRequest:
        id: int
        method: str
        url: str
        headers: List[Tuple[str, str]]
        body: bytes
        truncated: bool = False
        protocol: str = "HTTP/1.1"
        edited_body: Optional[bytes] = None
    
    class CapturedHeaders(TypedDict):
        pseudo: Dict[str, str]
        headers: List[Tuple[str, str]]

if TYPE_CHECKING:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
        SettingsAcknowledged, ConnectionTerminated, TrailersReceived,
        ResponseReceived, RemoteSettingsChanged, PingReceived, PriorityUpdated
    )
    from h2.errors import ErrorCodes
    from h2.exceptions import FlowControlError, ProtocolError, StreamClosedError
    from h2.settings import SettingCodes

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
        SettingsAcknowledged, ConnectionTerminated, TrailersReceived,
        ResponseReceived, RemoteSettingsChanged, PingReceived, PriorityUpdated
    )
    from h2.errors import ErrorCodes
    from h2.exceptions import FlowControlError, ProtocolError, StreamClosedError
    from h2.settings import SettingCodes
except ImportError:
    # Allow import without h2 for testing/linting purposes
    H2Connection = None

try:
    import hpack
except ImportError:
    hpack = None

# --- Constants ---

# Headers that must be removed when forwarding (RFC 7230 / RFC 7540)
HOP_BY_HOP_HEADERS = frozenset({
    'connection', 'keep-alive', 'proxy-connection', 'te', 'transfer-encoding', 
    'upgrade', 'proxy-authenticate', 'proxy-authorization', 'trailers'
})

# H2 Specific forbidden headers (RFC 7540)
H2_FORBIDDEN_HEADERS = frozenset({
    'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade'
})

SENSITIVE_HEADERS = frozenset({
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-auth-token'
})

# Regex for strict header validation (No whitespace before colon, strict tokens)
STRICT_HEADER_PATTERN = re.compile(rb'^([!#$%&\'*+\-.^_`|~0-9a-zA-Z]+):[ \t]*(.*)$')

# Security & Performance Limits
UPSTREAM_CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
KEEPALIVE_INTERVAL = 10.0
FLOW_CONTROL_TIMEOUT = 30.0
MAX_HEADER_LIST_SIZE = 262144        # 256KB
MAX_CAPTURE_BODY_SIZE = 10 * 1024 * 1024 # 10MB
STREAM_QUEUE_SIZE = 100
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
GOAWAY_MAX_FRAME = b'\x00\x00\x08\x07\x00\x00\x00\x00\x00\x7f\xff\xff\xff\x00\x00\x00\x00'

#  IO Tuning - Read Chunks
READ_CHUNK_SIZE = 65536        # 64KB Read Buffer (vs 4KB)
COMPACTION_THRESHOLD = 16384   # 16KB Threshold for lazy compaction

class StreamContext:
    """
    Maintains state for a single HTTP/2 stream. 
    Optimized for memory with __slots__ to handle high concurrency.
    """
    __slots__ = (
        'stream_id', 'scheme', 'downstream_closed', 'upstream_closed',
        'upstream_flow_event', 'downstream_flow_event',
        'upstream_queue', 'downstream_queue', 'sender_tasks',
        'captured_headers', 'request_body', 'capture_finalized', 'truncated'
    )

    def __init__(self, stream_id: int, scheme: str):
        self.stream_id = stream_id
        self.scheme = scheme
        self.downstream_closed = False
        self.upstream_closed = False
        
        # Flow control events - Start set to True (open)
        self.upstream_flow_event = asyncio.Event()
        self.downstream_flow_event = asyncio.Event()
        self.upstream_flow_event.set()
        self.downstream_flow_event.set()
        
        # Queues for passing data between reader/writer loops
        self.upstream_queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE)
        self.downstream_queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE)
        
        self.sender_tasks: List[asyncio.Task] = []
        self.captured_headers = {"pseudo": {}, "headers": []}
        self.request_body = bytearray()
        self.capture_finalized = False
        self.truncated = False

    def __repr__(self):
        return f"<StreamContext id={self.stream_id} scheme={self.scheme}>"

class ProxyError(Exception):
    pass
class PayloadTooLargeError(ProxyError):
    pass

class BaseProxyHandler:
    """Shared logic for Upstream Connection and Logging."""
    
    __slots__ = (
        'explicit_host', 'upstream_verify_ssl', 'upstream_ca_bundle', 
        'callback', 'ssl_context_factory', 'upstream_host', 'upstream_port'
    )

    def __init__(self, explicit_host: str, upstream_verify_ssl: bool, 
                 upstream_ca_bundle: Optional[str], manager_callback: Callable,
                 ssl_context_factory: Optional[Callable] = None):
        self.explicit_host = explicit_host
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.callback = manager_callback
        self.ssl_context_factory = ssl_context_factory
        self.upstream_host: str = ""
        self.upstream_port: int = 443

    def log(self, level: str, msg: Any):
        if self.callback:
            try:
                self.callback(level, msg)
            except Exception:
                pass 

    def _parse_target(self, explicit_host: str, default_port: int = 443) -> Tuple[str, int]:
        """
        Robust parsing of host:port strings, handling IPv6 brackets.
        Accepts a dynamic default_port based on scheme (80 vs 443).
        """
        if not explicit_host:
            return "", 0
            
        if explicit_host.startswith('['):
            end_bracket = explicit_host.find(']')
            if end_bracket != -1:
                host = explicit_host[1:end_bracket]
                remaining = explicit_host[end_bracket+1:]
                if remaining.startswith(':'):
                    try: return host, int(remaining[1:])
                    except ValueError: pass
                else: return host, default_port
        
        if ':' in explicit_host:
            host, port_str = explicit_host.rsplit(':', 1)
            try: return host, int(port_str)
            except ValueError: pass
            
        return explicit_host, default_port

    async def _connect_upstream(self, host: str, port: int, alpn_protocols: List[str] = None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ctx = ssl.create_default_context()
        if self.upstream_verify_ssl:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            if self.upstream_ca_bundle:
                ctx.load_verify_locations(cafile=self.upstream_ca_bundle)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        if alpn_protocols:
            try: ctx.set_alpn_protocols(alpn_protocols)
            except NotImplementedError: pass

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            
            # [OPTIMIZATION] Disable Nagle's algorithm on the socket to ensure
            # low latency for forwarded packets.
            try:
                sock = writer.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
                
            return reader, writer
            
        except asyncio.TimeoutError:
            raise

    def _is_url_allowed(self, url: str, scope_pattern: Optional[Any]) -> bool:
        if not scope_pattern:
            return True
        return bool(scope_pattern.search(url))

class Http11ProxyHandler(BaseProxyHandler):
    """
    HTTP/1.1 Proxy Handler.
    
    Features:
    - Strict Request Line & Header Parsing (No Bare LF).
    - Chunked Encoding support.
    - CONNECT tunneling with optional MITM.
    - Security checks for Request Smuggling (CL.TE conflicts).
    """
    
    __slots__ = (
        'reader', 'writer', 'target_override', 'scope_pattern', 
        'buffer', '_buffer_offset', 'enable_tunneling', 
        'strict_mode', '_previous_byte_was_cr'
    )

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                 explicit_host: str, manager_callback, target_override, scope_pattern,
                 upstream_verify_ssl=False, upstream_ca_bundle=None, initial_data=b"",
                 ssl_context_factory=None, enable_tunneling=True, strict_mode=True):
        
        super().__init__(explicit_host, upstream_verify_ssl, upstream_ca_bundle, manager_callback, ssl_context_factory)
        self.reader = reader
        self.writer = writer
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.buffer = bytearray(initial_data)
        self._buffer_offset = 0 # Offset for consumed bytes
        self.enable_tunneling = enable_tunneling
        self.strict_mode = strict_mode
        self._previous_byte_was_cr = False

    async def _read_strict_line(self) -> bytes:
        """
        Reads a line strictly terminated by CRLF, but allows lenient fallback for Bare LF.
        Optimization: Uses smart compaction to avoid O(N^2) buffer resizing on large streams.
        """
        while True:
            try:
                # Search for LF starting from the current offset
                lf_index = self.buffer.index(b'\n', self._buffer_offset)
            except ValueError:
                # LF not found in current buffer
                if len(self.buffer) - self._buffer_offset > 0:
                    self._previous_byte_was_cr = (self.buffer[-1] == 0x0D)
                
                if (len(self.buffer) - self._buffer_offset) > MAX_HEADER_LIST_SIZE:
                    raise ProxyError("Header Line Exceeded Max Length")
                
                # Optimization: Lazy In-Place Compaction
                # Only compact if wasted space > 16KB AND represents > 50% of the buffer.
                if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                     del self.buffer[:self._buffer_offset]
                     self._buffer_offset = 0

                try:
                    # Larger chunk size for fewer syscalls
                    data = await asyncio.wait_for(self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    raise ProxyError("Read Timeout (Idle)")
                
                if not data:
                    if len(self.buffer) - self._buffer_offset > 0:
                        raise ProxyError("Incomplete message")
                    return b""
                self.buffer.extend(data)
                continue
            
            # LF found. The index is absolute.
            line_len = lf_index - self._buffer_offset

            if line_len > MAX_HEADER_LIST_SIZE:
                raise ProxyError("Header Line Exceeded Max Length")

            is_crlf = False
            # Check byte before LF
            if lf_index > self._buffer_offset:
                if self.buffer[lf_index - 1] == 0x0D:
                    is_crlf = True
            elif lf_index == self._buffer_offset:
                if self._previous_byte_was_cr:
                    is_crlf = True
            
            # --- LENIENT FIX START ---
            # Instead of raising ProxyError for Bare LF, we handle it gracefully.
            if is_crlf:
                # Standard HTTP: Strip the CR (last char before LF)
                line_end = lf_index - 1
            else:
                # Lenient Mode: Bare LF detected. Keep content up to the LF.
                line_end = lf_index
            # --- LENIENT FIX END ---
            
            # Extract line (excluding the terminator)
            if line_end > self._buffer_offset:
                line = self.buffer[self._buffer_offset:line_end]
            else:
                line = b"" 
            
            # Advance offset past LF
            self._buffer_offset = lf_index + 1
            self._previous_byte_was_cr = False 

            return line

    async def run(self):
        try:
            while True:
                try:
                    line = await self._read_strict_line()
                except ProxyError as e:
                    self.log("ERROR", f"Framing Error: {e}")
                    if "Timeout" not in str(e) and "Incomplete" not in str(e):
                        await self._send_error(400, "Bad Request")
                    return

                if not line: break 

                try:
                    parts = line.split(b' ', 2)
                    if len(parts) != 3: raise ValueError
                    method_b, target_b, version_b = parts
                    method = method_b.decode('ascii')
                    target = target_b.decode('ascii')
                    http_version = version_b.decode('ascii').upper()
                except ValueError:
                    await self._send_error(400, "Malformed Request Line")
                    return

                headers = []
                headers_dict = {}
                
                # Header Parsing Loop
                try:
                    while True:
                        h_line = await self._read_strict_line()
                        if not h_line: break 
                        if h_line[0] in (0x20, 0x09):
                            raise ProxyError("Obsolete Line Folding Rejected")
                        
                        match = STRICT_HEADER_PATTERN.match(h_line)
                        if not match:
                            raise ProxyError("Invalid Header Syntax")
                        
                        key = match.group(1).decode('ascii')
                        val = match.group(2).decode('ascii').strip() 
                        headers.append((key, val))
                        headers_dict[key.lower()] = val
                except ProxyError as e:
                    await self._send_error(400, str(e))
                    return

                # Validation & Security Checks
                if not await self._validate_request(method, headers_dict):
                    return

                # Transfer-Encoding & Content-Length Logic (Anti-Smuggling)
                te_header = headers_dict.get('transfer-encoding')
                cl_header = headers_dict.get('content-length')
                
                if te_header:
                    # RFC 7230 Section 3.3.3: If both present, TE overrides. 
                    if cl_header:
                        if self.strict_mode:
                            # Security: Remove CL to avoid ambiguity downstream (Safe Mode)
                            self.log("WARN", "Ambiguous Request: CL and TE both present. Stripping CL (Strict Mode).")
                            headers = [h for h in headers if h[0].lower() != 'content-length']
                            if 'content-length' in headers_dict:
                                del headers_dict['content-length']
                        else:
                            # Attack Mode: Forward both to test downstream Desync
                            self.log("WARN", "Ambiguous Request: CL and TE both present. Forwarding both (Strict Mode OFF).")
                    
                    encodings = [e.strip().lower() for e in te_header.split(',')]
                    if 'chunked' in encodings and encodings[-1] != 'chunked':
                        await self._send_error(400, "Bad Transfer-Encoding")
                        return
                elif cl_header:
                    # Validate CL is a non-negative integer
                    try:
                        cl_val = int(cl_header)
                        if cl_val < 0: raise ValueError
                    except ValueError:
                        await self._send_error(400, "Invalid Content-Length")
                        return

                conn_header = headers_dict.get('connection', '').lower()
                keep_alive = True
                if http_version == 'HTTP/1.0':
                    if 'keep-alive' not in conn_header: keep_alive = False
                elif 'close' in conn_header:
                    keep_alive = False

                if method == 'CONNECT':
                    await self._handle_connect(target)
                    return 
                else:
                    await self._handle_request(method, target, version_b, headers, headers_dict)
                    if not keep_alive: break

        except Exception as e:
            self.log("ERROR", f"HTTP/1.1 Proxy Error: {e}")
        finally:
            if not self.writer.is_closing():
                self.writer.close()

    async def _validate_request(self, method: str, headers_dict: Dict[str, str]) -> bool:
        """Validates specific protocol requirements."""
        if method == 'OPTIONS' and 'access-control-request-method' not in headers_dict:
             pass # Optional in some contexts
        
        if method == 'CONNECT' and 'host' not in headers_dict:
            await self._send_error(400, "CONNECT requires Host header")
            return False
            
        if any(k.startswith(':') for k in headers_dict):
             await self._send_error(400, "Pseudo-header in HTTP/1.1")
             return False
        
        return True

    async def _send_error(self, code, message):
        try:
            self.writer.write(f"HTTP/1.1 {code} {message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
            await self.writer.drain()
        except Exception: pass

    async def _handle_request(self, method, target, version_b, headers, headers_dict):
        req_host = self.explicit_host

        # RFC 7230 Section 5.4: If the target URI includes an authority component,
        # then a client-generated request-target would override the Host header field.
        if not req_host:
            parsed = urlparse(target)
            if parsed.scheme and parsed.netloc:
                req_host = parsed.netloc

        if not req_host:
            req_host = headers_dict.get('host')

        # Fallback if both missing (technically 400 Bad Request if HTTP/1.1)
        if not req_host:
             parsed = urlparse(target)
             req_host = parsed.netloc

        scheme = "https" if self.upstream_verify_ssl else "http"
        default_port = 443 if scheme == "https" else 80

        # Pass the context-aware default port to the parser
        host, port = self._parse_target(req_host, default_port=default_port)
        
        # URL Construction for Capture/Scope
        full_url = ""
        if self.target_override:
            full_url = urljoin(self.target_override, target.lstrip('/'))
        else:
            if target.startswith("http"):
                full_url = target
            else:
                full_url = f"{scheme}://{host}:{port}{target}"

        if not self._is_url_allowed(full_url, self.scope_pattern):
            self.log("WARN", f"Blocked Request to {full_url} (Scope Violation)")
            await self._send_error(403, "Forbidden by Proxy Scope")
            return

        # Body Reading
        body = b""
        transfer_encoding = headers_dict.get('transfer-encoding', '').lower()
        content_length = headers_dict.get('content-length')

        if 'chunked' in transfer_encoding:
            body = await self._read_chunked_body()
        elif content_length:
            try:
                length = int(content_length)
                body = await self._read_bytes(length)
            except ValueError:
                pass 

        self._record_capture(method, target, headers, body, scheme, host)

        if not self.enable_tunneling:
            msg = b"Captured."
            self.writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
            await self.writer.drain()
            return

        # Upstream Connection
        try:
            u_reader, u_writer = await self._connect_upstream(host, port)
        except asyncio.TimeoutError:
            await self._send_error(504, "Gateway Timeout")
            return
        except Exception:
            await self._send_error(502, "Bad Gateway")
            return

        # Forwarding
        req_line = f"{method} {target} {version_b.decode()}\r\n".encode()
        u_writer.write(req_line)
        
        final_headers = []
        for k, v in headers:
            if k.lower() not in HOP_BY_HOP_HEADERS:
                final_headers.append((k, v))
        
        final_headers.append(('Content-Length', str(len(body))))
        final_headers.append(('Connection', 'close')) 

        for k, v in final_headers:
            u_writer.write(f"{k}: {v}\r\n".encode())
        u_writer.write(b"\r\n")
        
        if body:
            u_writer.write(body)
        await u_writer.drain()

        await self._pipe(u_reader, self.writer)
        u_writer.close()

    async def _read_chunked_body(self) -> bytes:
        body_parts = []
        while True:
            line = await self._read_strict_line()
            if b';' in line: line, _ = line.split(b';', 1)
            try: 
                chunk_size = int(line.strip(), 16)
            except ValueError: 
                raise ProxyError("Invalid chunk size")
            
            if chunk_size == 0:
                # Read trailers
                while True:
                    trailer = await self._read_strict_line()
                    if not trailer: break
                break
            
            data = await self._read_bytes(chunk_size)
            body_parts.append(data)
            # Consume CRLF after chunk
            await self._read_strict_line() 
        return b"".join(body_parts)
    
    async def _read_bytes(self, n: int) -> bytes:
        while (len(self.buffer) - self._buffer_offset) < n:
            try:
                # Larger chunk size for fewer syscalls for performance
                data = await asyncio.wait_for(self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                raise ProxyError("Read Timeout (Idle) in Body")
                
            if not data: raise ProxyError("Incomplete read")

            # Optimization: Lazy In-Place Compaction
            if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                 del self.buffer[:self._buffer_offset]
                 self._buffer_offset = 0

            self.buffer.extend(data)
        
        chunk = self.buffer[self._buffer_offset : self._buffer_offset + n]
        self._buffer_offset += n

        return bytes(chunk)

    async def _handle_connect(self, target: str):
        check_url = f"https://{target}/"
        if not self._is_url_allowed(check_url, self.scope_pattern):
            self.log("WARN", f"Blocked CONNECT to {target} (Scope Violation)")
            await self._send_error(403, "Forbidden by Proxy Scope")
            return

        host, port = self._parse_target(target)
        
        if self.ssl_context_factory:
            # MITM Path
            try:
                ssl_ctx = self.ssl_context_factory(host)
                self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await self.writer.drain()
                await self.writer.start_tls(ssl_ctx)
                
                handler = DualProtocolHandler(
                    self.reader, self.writer, 
                    explicit_host=target, 
                    manager_callback=self.callback,
                    target_override=self.target_override,
                    scope_pattern=self.scope_pattern,
                    enable_tunneling=self.enable_tunneling,
                    upstream_verify_ssl=self.upstream_verify_ssl,
                    upstream_ca_bundle=self.upstream_ca_bundle,
                    ssl_context_factory=self.ssl_context_factory,
                    strict_mode=self.strict_mode # Propagate flag
                )
                await handler.run()
                return

            except Exception as e:
                self.log("ERROR", f"MITM Handshake Failed for {target}: {e}")
                return

        # Blind Tunnel Path
        try:
            u_reader, u_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self.writer.drain()
            await asyncio.gather(
                self._pipe(self.reader, u_writer, flush_buffer=True),
                self._pipe(u_reader, self.writer),
                return_exceptions=True
            )
        except Exception:
            await self._send_error(502, "Bad Gateway")

    async def _send_error(self, code, message):
        try:
            self.writer.write(f"HTTP/1.1 {code} {message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
            await self.writer.drain()
        except Exception as e:
            # [LOGGING FIX] Log this as debug, often just means client went away
            self.log("DEBUG", f"Failed to send error {code} to client: {e}")

    async def _pipe(self, r, w, flush_buffer=False):
        """
        Pipes data between streams.
        [LOGGING FIX] Now reports why a pipe broke.
        """
        try:
            if flush_buffer and (len(self.buffer) - self._buffer_offset) > 0:
                w.write(self.buffer[self._buffer_offset:])
                await w.drain()
                self._buffer_offset = 0
                del self.buffer[:]
            
            while not r.at_eof():
                data = await r.read(65536)
                if not data: break
                w.write(data)
                await w.drain()
                
        except (ConnectionResetError, BrokenPipeError):
            # Normal connection termination, usually verbose/debug only
            pass 
        except Exception as e:
            # Actual unexpected errors
            self.log("ERROR", f"Pipe transfer error: {e}")
        finally:
            try: 
                w.close()
                await w.wait_closed()
            except Exception: 
                pass

    def _record_capture(self, method, path, headers, body, scheme, authority):
        if self.target_override:
            url = urljoin(self.target_override, path.lstrip('/'))
        else:
            url = f"{scheme}://{authority}{path}"
        
        if self.scope_pattern and not self.scope_pattern.search(url): return

        captured = CapturedRequest(
            id=0, method=method, url=url,
            headers=headers, body=body, truncated=(len(body) > MAX_CAPTURE_BODY_SIZE),
            protocol="HTTP/1.1"
        )
        self.log("CAPTURE", captured)

class NativeProxyHandler(BaseProxyHandler):
    """
    Native HTTP/2 Proxy Handler.
    
    Manages complex state machinery for H2 frames, streams, and flow control.
    Supports Tunneling, Capture, and MITM.
    """
    
    __slots__ = (
        'client_reader', 'client_writer', 'target_override', 'scope_pattern',
        'enable_tunneling', 'initial_data', 'upstream_reader', 'upstream_writer',
        'upstream_scheme', 'ds_h2_lock', 'us_h2_lock', 'ds_socket_lock',
        'us_socket_lock', 'downstream_conn', 'upstream_conn', 'streams',
        'closed', 'draining'
    )

    def __init__(self, client_reader, client_writer, explicit_host, manager_callback, 
                 target_override, scope_pattern, enable_tunneling=True, 
                 upstream_verify_ssl=False, upstream_ca_bundle=None, initial_data=b"",
                 ssl_context_factory=None):
        
        super().__init__(explicit_host, upstream_verify_ssl, upstream_ca_bundle, manager_callback, ssl_context_factory)
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling
        self.initial_data = initial_data

        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None
        self.upstream_scheme: str = "https" 

        # Locks for H2 State and Socket Access
        self.ds_h2_lock = asyncio.Lock()
        self.us_h2_lock = asyncio.Lock()
        self.ds_socket_lock = asyncio.Lock()
        self.us_socket_lock = asyncio.Lock()

        # [SECURITY] Enforce max header list size to prevent HPACK bombs
        if not H2Connection:
            raise ImportError("h2 library not found")

        ds_config = H2Configuration(
            client_side=False, header_encoding='utf-8', 
            validate_inbound_headers=True, validate_outbound_headers=True,
            normalize_inbound_headers=True, normalize_outbound_headers=True
        )
        self.downstream_conn = H2Connection(config=ds_config)
        self.downstream_conn.local_settings.enable_push = 0
        self.downstream_conn.local_settings.max_header_list_size = MAX_HEADER_LIST_SIZE
        self.downstream_conn.local_settings.enable_connect_protocol = 1

        self.upstream_conn: Optional[Any] = None
        self.streams: Dict[int, StreamContext] = {}
        self.closed = asyncio.Event()
        self.draining = False

    async def run(self):
        try:
            try:
                self.upstream_host, self.upstream_port = self._parse_target(self.explicit_host)
            except ValueError:
                pass

            if self.enable_tunneling and self.upstream_host:
                check_url = f"https://{self.upstream_host}:{self.upstream_port}/"
                if not self._is_url_allowed(check_url, self.scope_pattern):
                     self.log("WARN", f"Blocked H2 Connection to {self.upstream_host} (Scope Violation)")
                     await self.terminate(ErrorCodes.REFUSED_STREAM)
                     return

                try:
                    await self.connect_upstream()
                    us_config = H2Configuration(
                        client_side=True, header_encoding='utf-8', 
                        validate_inbound_headers=True, validate_outbound_headers=True,
                        normalize_inbound_headers=True, normalize_outbound_headers=True
                    )
                    self.upstream_conn = H2Connection(config=us_config)
                    self.upstream_conn.initiate_connection()
                    await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
                except Exception as e:
                    self.log("ERROR", f"H2 Upstream Connection Failed: {e}")
                    await self.terminate(ErrorCodes.CONNECT_ERROR)
                    return

            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

            if self.initial_data:
                async with self.ds_h2_lock:
                    events = self.downstream_conn.receive_data(self.initial_data)
                for event in events:
                    await self.handle_downstream_event(event)
                await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

            tasks = [
                asyncio.create_task(self._monitor_shutdown()),
                asyncio.create_task(self._read_loop_wrapper(
                    self.client_reader, self.downstream_conn, self.ds_h2_lock,
                    self.client_writer, self.ds_socket_lock, self.handle_downstream_event
                )),
                asyncio.create_task(self._keepalive_loop())
            ]
            if self.enable_tunneling and self.upstream_conn:
                tasks.append(asyncio.create_task(self._read_loop_wrapper(
                    self.upstream_reader, self.upstream_conn, self.us_h2_lock,
                    self.upstream_writer, self.us_socket_lock, self.handle_upstream_event
                )))
            await asyncio.gather(*tasks)

        except Exception as e:
            if not self.closed.is_set():
                self.log("ERROR", f"H2 Proxy Error: {e}")
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally:
            await self.cleanup()

    async def connect_upstream(self):
        self.upstream_reader, self.upstream_writer = await self._connect_upstream(
            self.upstream_host, self.upstream_port, alpn_protocols=["h2"]
        )
        transport = self.upstream_writer.get_extra_info('ssl_object')
        if transport and transport.selected_alpn_protocol() != "h2":
            raise ConnectionError("Upstream did not negotiate HTTP/2")

    async def _read_loop_wrapper(self, reader, conn, h2_lock, writer, socket_lock, handler):
        try:
            await self.read_loop(reader, conn, h2_lock, writer, socket_lock, handler)
        except Exception:
            self.closed.set()

    async def read_loop(self, reader, conn, h2_lock, writer, socket_lock, event_handler):
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
                try: events = conn.receive_data(data)
                except Exception:
                    await self.terminate(ErrorCodes.PROTOCOL_ERROR)
                    break
                bytes_to_send = conn.data_to_send()

            if bytes_to_send:
                async with socket_lock:
                    writer.write(bytes_to_send)
                    await writer.drain()

            for event in events:
                await event_handler(event)

    async def _stream_sender(self, stream_id, conn, writer, queue, flow_event, h2_lock, socket_lock, 
                             ack_conn, ack_h2_lock, ack_writer, ack_socket_lock):
        """
        Consumes payloads from a queue and sends them to the respective connection.
        Handles Flow Control Backpressure correctly.
        [VECTOR OPTIMIZED] Batches writes to reduce syscall overhead.
        """
        while not self.closed.is_set():
            try:
                # Optimization: Queue Batching
                # Reduces await/loop overhead by grabbing multiple available items
                items = [await queue.get()]
                
                # Drain up to 10 more items if immediately available
                try:
                    for _ in range(10):
                        items.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    pass

                for item in items:
                    if item is None:
                        # Termination signal received
                        queue.task_done()
                        return

                    payload, end_stream, ack_length = item

                    if isinstance(payload, list):
                        # Headers
                        conn_data = None
                        async with h2_lock:
                            try:
                                conn.send_headers(stream_id, payload, end_stream=end_stream)
                                conn_data = conn.data_to_send()
                            except Exception: break
                        if conn_data:
                            async with socket_lock:
                                try:
                                    writer.write(conn_data)
                                    await writer.drain()
                                except: break
                    else:
                        # Data Body
                        data = payload
                        view = memoryview(data)
                        offset = 0
                        total_len = len(data)

                        while offset < total_len or (total_len == 0 and end_stream):
                            if self.closed.is_set(): break
                            chunk_data = None
                            break_loop = False
                            
                            async with h2_lock:
                                try:
                                    conn_window = conn.outbound_flow_control_window
                                    stream_window = conn.remote_flow_control_window(stream_id)
                                    available = min(conn_window, stream_window)

                                    if available > 0 or (total_len == 0 and end_stream):
                                        chunk_size = min(total_len - offset, available)
                                        chunk = view[offset:offset+chunk_size]
                                        is_last = (offset + chunk_size == total_len) and end_stream
                                        conn.send_data(stream_id, chunk.tobytes(), end_stream=is_last)
                                        chunk_data = conn.data_to_send()
                                        offset += chunk_size
                                        if offset >= total_len: break_loop = True
                                    else:
                                        flow_event.clear()
                                except Exception: break_loop = True

                            if chunk_data:
                                async with socket_lock:
                                    try:
                                        writer.write(chunk_data)
                                        await writer.drain()
                                    except: break
                            
                            if break_loop: break
                            
                            if not chunk_data and not break_loop:
                                try: 
                                    await asyncio.wait_for(flow_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                                except (asyncio.TimeoutError, asyncio.CancelledError):
                                    async with h2_lock:
                                        try: conn.reset_stream(stream_id, ErrorCodes.FLOW_CONTROL_ERROR)
                                        except: pass
                                    break

                    if ack_conn and ack_length > 0:
                        ack_bytes = None
                        async with ack_h2_lock:
                            try:
                                ack_conn.acknowledge_received_data(ack_length, stream_id)
                                ack_bytes = ack_conn.data_to_send()
                            except: pass
                        if ack_bytes:
                            async with ack_socket_lock:
                                try:
                                    ack_writer.write(ack_bytes)
                                    await ack_writer.drain()
                                except: pass

                    queue.task_done()
                    if end_stream: return

            except Exception as e:
                self.log("ERROR", f"Stream sender error: {e}")
                break
        
        try: queue.task_done()
        except: pass

    async def handle_request_received(self, event: RequestReceived):
        stream_id = event.stream_id
        if stream_id in self.streams:
             async with self.ds_h2_lock:
                 self.downstream_conn.reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR)
             return

        ctx = StreamContext(stream_id, self.upstream_scheme)
        self.streams[stream_id] = ctx
        ctx.captured_headers = self._process_headers_for_capture(event.headers)

        if self.enable_tunneling and self.upstream_conn:
            try:
                headers, protocol = self._prepare_forwarded_headers(event.headers, is_upstream=True)
                
                if protocol:
                      enabled = self.upstream_conn.remote_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL, 0)
                      if not enabled:
                          self.log("WARN", f"Client requested CONNECT protocol={protocol} but upstream disabled it.")
                          async with self.ds_h2_lock:
                              self.downstream_conn.reset_stream(stream_id, ErrorCodes.CONNECT_ERROR)
                          self._cleanup_stream(stream_id, force_close=True)
                          return

                async with self.us_h2_lock:
                    self.upstream_conn.send_headers(stream_id, headers, end_stream=event.stream_ended)
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
            except ValueError as e:
                self.log("ERROR", f"Header Validation Failed: {e}")
                async with self.ds_h2_lock:
                    self.downstream_conn.reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR)
                self._cleanup_stream(stream_id, force_close=True)
                return

        if self.enable_tunneling and self.upstream_conn:
            t_down = asyncio.create_task(self._stream_sender(
                stream_id, self.downstream_conn, self.client_writer, 
                ctx.downstream_queue, ctx.downstream_flow_event,
                self.ds_h2_lock, self.ds_socket_lock,
                self.upstream_conn, self.us_h2_lock, self.upstream_writer, self.us_socket_lock
            ))
            t_up = asyncio.create_task(self._stream_sender(
                stream_id, self.upstream_conn, self.upstream_writer,
                ctx.upstream_queue, ctx.upstream_flow_event,
                self.us_h2_lock, self.us_socket_lock,
                self.downstream_conn, self.ds_h2_lock, self.client_writer, self.ds_socket_lock
            ))
            ctx.sender_tasks.extend([t_down, t_up])

        if event.stream_ended:
            ctx.downstream_closed = True
            self.finalize_capture(ctx)
            if self.enable_tunneling:
                ctx.upstream_queue.put_nowait(None)

    async def handle_downstream_event(self, event):
        if isinstance(event, RequestReceived):
            await self.handle_request_received(event)
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                ctx = self.streams[event.stream_id]
                if not ctx.truncated:
                    if len(ctx.request_body) + len(event.data) > MAX_CAPTURE_BODY_SIZE:
                        ctx.request_body.extend(event.data[:MAX_CAPTURE_BODY_SIZE - len(ctx.request_body)])
                        ctx.truncated = True
                    else:
                        ctx.request_body.extend(event.data)

                async with self.ds_h2_lock:
                    self.downstream_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)
                if self.enable_tunneling and self.upstream_conn:
                    await ctx.upstream_queue.put((event.data, event.stream_ended, 0))
        elif isinstance(event, TrailersReceived):
            if event.stream_id in self.streams and self.enable_tunneling and self.upstream_conn:
                try:
                    safe_headers, _ = self._prepare_forwarded_headers(event.headers, is_upstream=True)
                    ctx = self.streams[event.stream_id]
                    await ctx.upstream_queue.put((safe_headers, event.stream_ended, 0))
                except ValueError:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded):
            if event.stream_id in self.streams:
                self._cleanup_stream(event.stream_id, downstream_closed=True)
        elif isinstance(event, StreamReset):
            if event.stream_id in self.streams:
                self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, WindowUpdated):
            await self.handle_window_updated(event, 'downstream')
        elif isinstance(event, RemoteSettingsChanged):
            self.log("INFO", f"Downstream Settings Updated: {event.changed_settings}")
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

    async def handle_upstream_event(self, event):
        if isinstance(event, ResponseReceived):
             try:
                 safe, _ = self._prepare_forwarded_headers(event.headers, is_upstream=False)
                 async with self.ds_h2_lock:
                     self.downstream_conn.send_headers(event.stream_id, safe, end_stream=event.stream_ended)
                 await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)
             except ValueError:
                 async with self.ds_h2_lock:
                     self.downstream_conn.reset_stream(event.stream_id, ErrorCodes.PROTOCOL_ERROR)
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                ctx = self.streams[event.stream_id]
                async with self.us_h2_lock:
                    self.upstream_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
                await ctx.downstream_queue.put((event.data, event.stream_ended, 0))
        elif isinstance(event, TrailersReceived):
            if event.stream_id in self.streams:
                try:
                    safe, _ = self._prepare_forwarded_headers(event.headers, is_upstream=False)
                    ctx = self.streams[event.stream_id]
                    await ctx.downstream_queue.put((safe, event.stream_ended, 0))
                except ValueError:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded):
             if event.stream_id in self.streams:
                self._cleanup_stream(event.stream_id, upstream_closed=True)
        elif isinstance(event, WindowUpdated):
             await self.handle_window_updated(event, 'upstream')
        elif isinstance(event, RemoteSettingsChanged):
             self.log("INFO", f"Upstream Settings Updated: {event.changed_settings}")
             await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)

    def _prepare_forwarded_headers(self, headers, is_upstream=True):
        decoded_headers = []
        method = None
        protocol = None
        host_header_value = None
        
        for k, v in headers:
            k_s = k.decode('utf-8') if isinstance(k, bytes) else k
            v_s = v.decode('utf-8') if isinstance(v, bytes) else v
            if '\n' in v_s or '\r' in v_s: raise ValueError(f"Illegal header value: {k_s}")
            if k_s == ':method': method = v_s
            elif k_s == ':protocol': protocol = v_s
            elif k_s.lower() == 'host': host_header_value = v_s
            decoded_headers.append((k_s, v_s))

        out = []
        seen_regular = False
        is_connect = (method == 'CONNECT')
        is_extended_connect = is_connect and (protocol is not None)
        pseudo_headers = {}

        for k_s, v_s in decoded_headers:
            k_lower = k_s.lower()
            if k_s.startswith(':'):
                if seen_regular: raise ValueError("Pseudo-header found after regular header")
                pseudo_headers[k_s] = v_s
                continue
            else:
                seen_regular = True

            if k_lower in H2_FORBIDDEN_HEADERS: continue
            if k_lower == 'te':
                if v_s.lower() == 'trailers': out.append((k_s, v_s))
                continue
            if k_lower == 'host': continue
            out.append((k_s, v_s))
        
        final_headers = []
        if is_upstream:
            if ':authority' in pseudo_headers: pass
            elif host_header_value: pseudo_headers[':authority'] = host_header_value
            elif self.upstream_host:
                authority = self.upstream_host
                if self.upstream_port not in (80, 443): authority += f":{self.upstream_port}"
                pseudo_headers[':authority'] = authority

        for k, v in pseudo_headers.items():
            if k == ':authority' and not is_upstream and ':authority' not in pseudo_headers: continue
            if is_connect and not is_extended_connect and k in (':scheme', ':path'): continue
            final_headers.append((k, v))
        final_headers.extend(out)
        return self._wrap_security(final_headers), protocol

    def _process_headers_for_capture(self, headers: List[Tuple[Any, Any]]) -> CapturedHeaders:
        pseudo = {}
        normal = []
        cookies = []
        authority = None
        for k, v in headers:
            k_s = k.decode('utf-8') if isinstance(k, bytes) else k
            v_s = v.decode('utf-8') if isinstance(v, bytes) else v
            k_lower = k_s.lower()
            if k_lower == 'host' and not authority: authority = v_s
            if k_lower in H2_FORBIDDEN_HEADERS: continue 
            if k_s.startswith(':'):
                pseudo[k_s] = v_s
                if k_s == ':authority': authority = v_s
            elif k_lower == 'cookie':
                cookies.append(v_s)
            else:
                normal.append((k_s, v_s))
        if cookies:
            normal.append(('cookie', '; '.join(cookies)))
        if ':authority' not in pseudo and authority: pseudo[':authority'] = authority
        return {"pseudo": pseudo, "headers": normal}

    def _wrap_security(self, headers):
        if not hpack: return headers
        return [hpack.NeverIndexedHeaderTuple(k, v) if k.lower() in SENSITIVE_HEADERS else (k, v) for k, v in headers]

    async def handle_window_updated(self, event, direction):
        sid = event.stream_id
        streams_snapshot = list(self.streams.values())
        if sid == 0:
            for ctx in streams_snapshot:
                if direction == 'upstream': ctx.upstream_flow_event.set()
                else: ctx.downstream_flow_event.set()
        elif sid in self.streams:
            ctx = self.streams[sid]
            if direction == 'upstream': ctx.upstream_flow_event.set()
            else: ctx.downstream_flow_event.set()

    def finalize_capture(self, ctx: StreamContext):
        if ctx.capture_finalized: return
        ctx.capture_finalized = True
        
        pseudo = ctx.captured_headers["pseudo"]
        method = pseudo.get(':method', 'GET')
        path = pseudo.get(':path', '/')
        authority = pseudo.get(':authority', self.explicit_host)
        
        try:
            if self.target_override:
                url = urljoin(self.target_override, path.lstrip('/'))
            else:
                url = urlunparse((ctx.scheme, authority, path, '', '', ''))
        except: return

        if self.scope_pattern and not self.scope_pattern.search(url): return

        captured = CapturedRequest(
            id=0, method=method, url=url,
            headers=ctx.captured_headers["headers"],
            body=bytes(ctx.request_body),
            truncated=ctx.truncated,
            protocol="HTTP/2"
        )
        self.log("CAPTURE", captured)

    async def _monitor_shutdown(self):
        await self.closed.wait()
        for ctx in list(self.streams.values()):
            try: ctx.upstream_queue.put_nowait(None)
            except asyncio.QueueFull: pass
            try: ctx.downstream_queue.put_nowait(None)
            except asyncio.QueueFull: pass

    async def _keepalive_loop(self):
        while not self.closed.is_set():
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if self.upstream_conn:
                async with self.us_h2_lock:
                    try: self.upstream_conn.ping(b'KeepAliv')
                    except Exception: break
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
            async with self.ds_h2_lock:
                try: self.downstream_conn.ping(b'KeepAliv')
                except Exception: break
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

    async def cleanup(self):
        self.closed.set()
        for w in [self.client_writer, self.upstream_writer]:
            if w:
                try: w.close(); await w.wait_closed()
                except Exception: pass
        for ctx in list(self.streams.values()):
            for t in ctx.sender_tasks: t.cancel()

    async def terminate(self, code):
        self.closed.set()
        async with self.ds_h2_lock:
            try: self.downstream_conn.close_connection(code)
            except Exception: pass
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)
        
    async def graceful_shutdown(self):
        if self.draining or self.closed.is_set(): return
        self.draining = True
        async with self.ds_socket_lock:
            try: self.client_writer.write(GOAWAY_MAX_FRAME); await self.client_writer.drain()
            except Exception: pass
        start_time = time.time()
        while self.streams and (time.time() - start_time < 1.0):
            try: await asyncio.sleep(0.1)
            except asyncio.CancelledError: break
        self.closed.set()
        async with self.ds_h2_lock:
            try: self.downstream_conn.close_connection(ErrorCodes.NO_ERROR)
            except Exception: pass
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

    async def flush(self, conn, writer, h2_lock, socket_lock):
        if self.closed.is_set(): return
        bytes_to_send = None
        async with h2_lock:
            try: bytes_to_send = conn.data_to_send()
            except: pass
        if bytes_to_send:
            async with socket_lock:
                try:
                    writer.write(bytes_to_send)
                    await writer.drain()
                except Exception:
                    self.closed.set()

    def _cleanup_stream(self, stream_id: int, downstream_closed=False, upstream_closed=False, force_close=False):
        if stream_id not in self.streams: return
        ctx = self.streams[stream_id]
        if downstream_closed: ctx.downstream_closed = True
        if upstream_closed: ctx.upstream_closed = True
        
        if ctx.downstream_closed:
            self.finalize_capture(ctx)

        if force_close or (ctx.downstream_closed and ctx.upstream_closed):
            ctx.upstream_flow_event.set()
            ctx.downstream_flow_event.set()
            for t in ctx.sender_tasks:
                t.cancel()
            del self.streams[stream_id]

class DualProtocolHandler:
    __slots__ = (
        'reader', 'writer', 'explicit_host', 'callback', 'target_override',
        'scope_pattern', 'enable_tunneling', 'upstream_verify_ssl',
        'upstream_ca_bundle', 'ssl_context_factory', 'strict_mode'
    )

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                 explicit_host: str, manager_callback: Callable, 
                 target_override: Optional[str], scope_pattern: Optional[Any],
                 enable_tunneling: bool = True,
                 upstream_verify_ssl: bool = False,
                 upstream_ca_bundle: Optional[str] = None,
                 ssl_context_factory: Optional[Callable] = None,
                 strict_mode: bool = True):
        
        self.reader = reader
        self.writer = writer
        self.explicit_host = explicit_host
        self.callback = manager_callback
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.ssl_context_factory = ssl_context_factory
        self.strict_mode = strict_mode

    async def run(self):
        protocol, initial_data = await self._detect_protocol()
        
        handler = None
        if protocol == "h2":
            handler = NativeProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback,
                self.target_override, self.scope_pattern, self.enable_tunneling,
                self.upstream_verify_ssl, self.upstream_ca_bundle,
                initial_data=initial_data,
                ssl_context_factory=self.ssl_context_factory
            )
        else:
            handler = Http11ProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback,
                self.target_override, self.scope_pattern,
                self.upstream_verify_ssl, self.upstream_ca_bundle,
                initial_data=initial_data,
                ssl_context_factory=self.ssl_context_factory,
                enable_tunneling=self.enable_tunneling,
                strict_mode=self.strict_mode
            )
        await handler.run()

    async def _detect_protocol(self) -> Tuple[str, bytes]:
        ssl_obj = self.writer.get_extra_info('ssl_object')
        if ssl_obj:
            alpn_proto = ssl_obj.selected_alpn_protocol()
            if alpn_proto == "h2": return "h2", b""
            if alpn_proto == "http/1.1": return "http/1.1", b""
        
        try:
            preface_len = len(H2_PREFACE)
            data = await asyncio.wait_for(self.reader.read(preface_len), timeout=5.0)
            
            if data.startswith(H2_PREFACE[:4]):
                if len(data) == preface_len and data == H2_PREFACE:
                    return "h2", data
                if b'HTTP/2.0' in data:
                    return "h2", data
            return "http/1.1", data
        except Exception as e:
            return "http/1.1", b""

async def start_proxy_server(host, port, manager_callback, target_override=None, scope_pattern=None, ssl_context_factory=None, strict_mode=True):
    async def _handle_client(reader, writer):
        handler = DualProtocolHandler(
            reader, writer, explicit_host="", manager_callback=manager_callback,
            target_override=target_override, scope_pattern=scope_pattern,
            ssl_context_factory=ssl_context_factory,
            strict_mode=strict_mode
        )
        await handler.run()

    server = await asyncio.start_server(_handle_client, host, port)
    manager_callback("SYSTEM", f"TCP (H1/H2) Proxy listening on {host}:{port}")
    
    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            manager_callback("SYSTEM", "TCP (H1/H2) Proxy stopped")
            server.close()
            await server.wait_closed()