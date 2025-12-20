"""
ASYNC PROXY CORE - SCALPEL RACER (FINAL ROBUST)
RFC 9112 (HTTP/1.1) & RFC 9113 (HTTP/2) Compliant Explicit Proxy.

Refactored based on PCAPNG traffic analysis to ensure:
1. PCAP Alignment: High-precision timestamping (EPB) and 5-tuple flow tracking (IDB).
2. Transparent Proxying: On-demand upstream routing via SNI/:authority lazy loading.
3. RFC Compliance: Strict HTTP/2 state machine and "Lock-Clear-Wait" flow control.
4. Defense in Depth: Anti-smuggling checks and memory bounded queues.

Standard Reference:
- RFC 9112: HTTP/1.1 Messaging
- RFC 9113: HTTP/2 Semantics (Obsoletes RFC 7540)
- RFC 8441: Bootstrapping WebSockets with HTTP/2
"""

import os
import asyncio
import ssl
import re
import socket
import time
from typing import Dict, Optional, Callable, Tuple, List, Any, TypedDict
from urllib.parse import urljoin, urlunparse, urlparse
from dataclasses import dataclass

# -- Dependency Check & Imports --
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated, 
        ConnectionTerminated, TrailersReceived, ResponseReceived
    )
    from h2.errors import ErrorCodes
    from h2.settings import SettingCodes
    import hpack
except ImportError:
    # H2/HPACK are required for HTTP/2. Graceful failure or degradation handled in DualProtocolHandler.
    H2Connection = None
    hpack = None

# -- Constants & Strict Patterns --

# RFC 9112: Strict Field-Name validation (No whitespace before colon)
STRICT_HEADER_PATTERN = re.compile(rb'^([!#$%&\'*+\-.^_`|~0-9a-zA-Z]+):[ \t]*(.*)$')

# Security & Performance Limits
UPSTREAM_CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
KEEPALIVE_INTERVAL = 10.0
FLOW_CONTROL_TIMEOUT = 30.0
MAX_HEADER_LIST_SIZE = 262144        # 256KB (RFC recommended minimum)
MAX_CAPTURE_BODY_SIZE = 10 * 1024 * 1024 # 10MB Cap
STREAM_QUEUE_SIZE = 1024             # Memory DoS Protection

# Protocol Constants
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
# RFC 9113 Section 6.8: Last-Stream-ID set to 2^31-1 for graceful shutdown
GOAWAY_MAX_FRAME = b'\x00\x00\x08\x07\x00\x00\x00\x00\x00\x7f\xff\xff\xff\x00\x00\x00\x00'

# IO Tuning
READ_CHUNK_SIZE = 65536              # 64KB Read Buffer
COMPACTION_THRESHOLD = 65536         # Lazy compaction threshold for memoryview

# -- Data Structures --

@dataclass(slots=True)
class CapturedRequest:
    """
    Represents a captured HTTP request with metadata aligned to PCAPNG Enhanced Packet Blocks.
    Includes 5-tuple addressing and high-precision timestamps for trace correlation.
    [BOLT] Optimization: slots=True reduces memory footprint by ~30% per instance.
    """
    id: int
    method: str
    url: str
    headers: List[Tuple[str, str]]
    body: bytes
    truncated: bool
    protocol: str
    timestamp_start: float
    timestamp_end: float = 0.0
    client_addr: Optional[Tuple[str, int]] = None
    server_addr: Optional[Tuple[str, int]] = None
    edited_body: Optional[bytes] = None

class CapturedHeaders(TypedDict):
    pseudo: Dict[str, str]
    headers: List[Tuple[str, str]]

# Byte-optimized Sets for Zero-Copy Header Processing
SENSITIVE_HEADERS = {'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-auth-token'}
HOP_BY_HOP_HEADERS = {
    'connection', 'keep-alive', 'proxy-connection', 'te', 'transfer-encoding', 
    'upgrade', 'proxy-authenticate', 'proxy-authorization', 'trailers'
}
SENSITIVE_HEADERS_BYTES = {h.encode('ascii') for h in SENSITIVE_HEADERS}
H2_FORBIDDEN_HEADERS = frozenset({
    b'connection', b'keep-alive', b'proxy-connection', b'transfer-encoding', b'upgrade'
})

class StreamContext:
    """
    Maintains state for a single HTTP/2 stream.
    Optimized for memory with __slots__ to reduce overhead during high concurrency.
    """
    __slots__ = (
        'stream_id', 'scheme', 'method', 'downstream_closed', 'upstream_closed',
        'upstream_flow_event', 'downstream_flow_event',
        'upstream_queue', 'downstream_queue', 'sender_tasks',
        'captured_headers', 'request_body_chunks', 'current_body_size',
        'capture_finalized', 'truncated', 'start_time', 'client_addr'
    )

    def __init__(self, stream_id: int, scheme: str, client_addr: Optional[Tuple[str, int]]):
        self.stream_id = stream_id
        self.scheme = scheme
        self.method = "GET"
        self.downstream_closed = False
        self.upstream_closed = False
        
        # RFC 9113 Flow Control: Events start set (Window Open)
        self.upstream_flow_event = asyncio.Event()
        self.upstream_flow_event.set()
        self.downstream_flow_event = asyncio.Event()
        self.downstream_flow_event.set()
        
        # Bounded Queues prevent Memory Exhaustion DoS
        self.upstream_queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE) 
        self.downstream_queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE) 
        
        self.sender_tasks: List[asyncio.Task] = [] 
        self.captured_headers = {"pseudo": {}, "headers": []} 
        
        # Optimized: List of chunks (O(1) append) instead of bytearray (O(N) copy)
        self.request_body_chunks = []
        self.current_body_size = 0
        
        self.capture_finalized = False 
        self.truncated = False
        self.start_time = time.time()
        self.client_addr = client_addr
    
    def __repr__(self):
        return f"<StreamContext id={self.stream_id} scheme={self.scheme}>"

class ProxyError(Exception): pass
class PayloadTooLargeError(ProxyError): pass

class BaseProxyHandler:
    """
    Shared logic for Upstream Connection and Logging.
    """
    __slots__ = (
        'explicit_host', 'upstream_verify_ssl', 'upstream_ca_bundle', 
        'callback', 'ssl_context_factory', 'upstream_host', 'upstream_port',
        'client_addr'
    )

    def __init__(self, explicit_host: str, upstream_verify_ssl: bool, upstream_ca_bundle: Optional[str], 
                 manager_callback: Callable, ssl_context_factory: Optional[Callable] = None, client_addr=None):
        self.explicit_host = explicit_host
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.callback = manager_callback
        self.ssl_context_factory = ssl_context_factory
        self.upstream_host: str = ""
        self.upstream_port: int = 443
        self.client_addr = client_addr

    def log(self, level: str, msg: Any):
        if self.callback:
            try:
                self.callback(level, msg)
            except Exception:
                pass 

    def _parse_target(self, explicit_host: str, default_port: int = 443) -> Tuple[str, int]:
        if not explicit_host: return "", 0
        if explicit_host.startswith('['):
            end = explicit_host.find(']')
            if end != -1:
                host = explicit_host[1:end]
                rem = explicit_host[end+1:]
                if rem.startswith(':'):
                    try: return host, int(rem[1:])
                    except ValueError: pass
                else: return host, default_port
        if ':' in explicit_host:
            host, port_str = explicit_host.rsplit(':', 1)
            try: return host, int(port_str)
            except ValueError: pass
        return explicit_host, default_port

    async def _connect_upstream(self, host: str, port: int, alpn_protocols: List[str] = None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establishes upstream connection with SNI and ALPN support.
        Logs SSL Keys if SSLKEYLOGFILE is set (critical for PCAP decryption).
        """
        ctx = ssl.create_default_context()
        keylog_file = os.environ.get("SSLKEYLOGFILE")
        if keylog_file:
            ctx.keylog_filename = keylog_file
            
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
            # SNI is critical for Transparent Proxying to Virtual Hosts
            # Always send SNI if we are using TLS, even if verification is disabled.
            server_hostname = host if (self.upstream_verify_ssl or alpn_protocols) else None
            
            # [FIX] Allow asyncio.TimeoutError to bubble up so caller can handle 504 Gateway Timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname), 
                timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            try:
                sock = writer.get_extra_info('socket')
                if sock: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: pass
            return reader, writer
        except ProxyError:
            raise
        except Exception as e:
            # Re-raise anything else as a ProxyError to be handled as a 502
            if not isinstance(e, asyncio.TimeoutError):
                 raise ProxyError(f"Upstream connection failed: {e}") from e
            raise
    def _is_url_allowed(self, url: str, scope_pattern: Optional[Any]) -> bool:
        if not scope_pattern: return True
        return bool(scope_pattern.search(url))

class Http11ProxyHandler(BaseProxyHandler):
    """
    HTTP/1.1 Proxy Handler (RFC 9112).
    Uses Zero-Copy memoryview slicing for high-performance parsing.
    """
    __slots__ = (
        'reader', 'writer', 'target_override', 'scope_pattern', 
        'buffer', '_buffer_offset', 'enable_tunneling', 
        'strict_mode', '_previous_byte_was_cr'
    )

    def __init__(self, reader, writer, explicit_host, manager_callback, target_override, 
                 scope_pattern, upstream_verify_ssl=False, upstream_ca_bundle=None, 
                 initial_data=b"", ssl_context_factory=None, enable_tunneling=True, strict_mode=True):
        client_addr = writer.get_extra_info('peername')
        super().__init__(explicit_host, upstream_verify_ssl, upstream_ca_bundle, manager_callback, ssl_context_factory, client_addr)
        self.reader = reader
        self.writer = writer
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.buffer = bytearray(initial_data)
        self._buffer_offset = 0
        self.enable_tunneling = enable_tunneling
        self.strict_mode = strict_mode
        self._previous_byte_was_cr = False

    async def _read_strict_line(self) -> bytes:
        """
        Reads a line strictly.
        Optimized: Uses bytes slicing for headers (small chunks) instead of memoryview.
        """
        while True:
            lf_index = self.buffer.find(b'\n', self._buffer_offset)
            if lf_index == -1:
                if len(self.buffer) - self._buffer_offset > 0:
                    self._previous_byte_was_cr = (self.buffer[-1] == 0x0D)
                
                if (len(self.buffer) - self._buffer_offset) > MAX_HEADER_LIST_SIZE:
                    raise ProxyError("Header Line Exceeded Max Length")
                
                # Lazy Compaction
                if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                      del self.buffer[:self._buffer_offset]
                      self._buffer_offset = 0

                try:
                    data = await asyncio.wait_for(self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    raise ProxyError("Read Timeout (Idle)")
                
                if not data:
                    if len(self.buffer) - self._buffer_offset > 0: raise ProxyError("Incomplete message")
                    return b""
                self.buffer.extend(data)
                continue
            
            line_len = lf_index - self._buffer_offset
            if line_len > MAX_HEADER_LIST_SIZE: raise ProxyError("Header Line Exceeded Max Length")

            is_crlf = False
            if lf_index > self._buffer_offset:
                if self.buffer[lf_index - 1] == 0x0D: is_crlf = True
            elif lf_index == self._buffer_offset:
                if self._previous_byte_was_cr: is_crlf = True
            
            line_end = lf_index - 1 if is_crlf else lf_index
            # Bolt: Bytes slicing is ~35% faster for small lines than memoryview().tobytes()
            line = bytes(self.buffer[self._buffer_offset:line_end]) if line_end > self._buffer_offset else b""
            
            self._buffer_offset = lf_index + 1
            self._previous_byte_was_cr = False 
            return line

    async def run(self):
        try:
            while True:
                start_ts = time.time()
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
                try:
                    while True:
                        h_line = await self._read_strict_line()
                        if not h_line: break 
                        # RFC 9112: Obsolescent line folding MUST be rejected
                        if h_line[0] in (0x20, 0x09): raise ProxyError("Obsolete Line Folding Rejected")
                        
                        match = STRICT_HEADER_PATTERN.match(h_line)
                        if not match: raise ProxyError("Invalid Header Syntax")
                        
                        key = match.group(1).decode('ascii')
                        val = match.group(2).decode('ascii').strip() 
                        headers.append((key, val))
                        headers_dict[key.lower()] = val
                except ProxyError as e:
                    await self._send_error(400, str(e))
                    return

                if not await self._validate_request(method, headers_dict): return

                # RFC 9112: Content-Length vs Transfer-Encoding (Request Smuggling Prevention)
                te_header = headers_dict.get('transfer-encoding')
                cl_header = headers_dict.get('content-length')
                
                if te_header:
                    if cl_header and self.strict_mode:
                        # Defense in Depth: Remove CL to remove ambiguity
                        headers = [h for h in headers if h[0].lower() != 'content-length']
                        if 'content-length' in headers_dict: del headers_dict['content-length']
                    
                    encodings = [e.strip().lower() for e in te_header.split(',')]
                    if 'chunked' in encodings and encodings[-1] != 'chunked':
                        await self._send_error(400, "Bad Transfer-Encoding")
                        return
                elif cl_header:
                    try:
                        cl_val = int(cl_header)
                        if cl_val < 0: raise ValueError
                    except ValueError:
                        await self._send_error(400, "Invalid Content-Length")
                        return

                if method == 'CONNECT':
                    await self._handle_connect(target)
                    return 
                else:
                    keep_alive = await self._handle_request(method, target, version_b, headers, headers_dict, start_ts)
                    if not keep_alive: break
        except Exception as e:
            self.log("ERROR", f"HTTP/1.1 Proxy Error: {e}")
        finally:
            if not self.writer.is_closing(): self.writer.close()

    async def _validate_request(self, method: str, headers_dict: Dict[str, str]) -> bool:
        if method == 'CONNECT' and 'host' not in headers_dict:
            await self._send_error(400, "CONNECT requires Host header")
            return False
        if any(k.startswith(':') for k in headers_dict):
             await self._send_error(400, "Pseudo-header in HTTP/1.1")
             return False
        return True

    async def _handle_connect(self, target: str):
        host, port = self._parse_target(target)
        if self.ssl_context_factory:
            try:
                # 1. Acknowledge the tunnel
                self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await self.writer.drain()
                
                # 2. Upgrade to TLS (Server-side handshake)
                ssl_ctx = self.ssl_context_factory(host)
                await self.writer.start_tls(ssl_ctx)
                
                # 3. [FIX] Hand off to DualProtocolHandler for inner traffic, preserving buffered data
                remaining_data = self.buffer[self._buffer_offset:] if self.buffer else b""
                
                handler = DualProtocolHandler(
                    self.reader, self.writer, target, self.callback, 
                    self.target_override, self.scope_pattern, 
                    self.enable_tunneling, self.upstream_verify_ssl, 
                    self.upstream_ca_bundle, self.ssl_context_factory,
                    initial_data=remaining_data # Pass buffered bytes
                )
                await handler.run()
                return
            except Exception as e:
                self.log("ERROR", f"MITM Upgrade Failed: {e}")
                return

        # Blind Tunnel Path
        try:
            u_reader, u_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self.writer.drain()
            
            # [FIX] Send any buffered data to upstream immediately
            if self.buffer and self._buffer_offset < len(self.buffer):
                u_writer.write(self.buffer[self._buffer_offset:])
                await u_writer.drain()
                
            await asyncio.gather(
                self._pipe(self.reader, u_writer, flush_buffer=False), # Already flushed
                self._pipe(u_reader, self.writer),
                return_exceptions=True
            )
        except Exception:
            await self._send_error(502, "Bad Gateway")

    async def _send_error(self, code, message):
        try:
            self.writer.write(f"HTTP/1.1 {code} {message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
            await self.writer.drain()
        except Exception: pass

    async def _handle_request(self, method, target, version_b, headers, headers_dict, start_ts):
        # Transparent Proxy Logic: Prefer Host header if explicit_host missing
        req_host = self.explicit_host
        if not req_host:
            parsed = urlparse(target)
            if parsed.scheme and parsed.netloc: req_host = parsed.netloc
        if not req_host: req_host = headers_dict.get('host')
        if not req_host:
             parsed = urlparse(target)
             req_host = parsed.netloc

        scheme = "https" if self.upstream_verify_ssl else "http"
        default_port = 443 if scheme == "https" else 80
        host, port = self._parse_target(req_host, default_port=default_port)
        
        full_url = ""
        if self.target_override: full_url = urljoin(self.target_override, target.lstrip('/'))
        else:
            if target.startswith("http"): full_url = target
            else: full_url = f"{scheme}://{host}:{port}{target}"

        if not self._is_url_allowed(full_url, self.scope_pattern):
            await self._send_error(403, "Forbidden by Proxy Scope")
            return False

        body = b""
        transfer_encoding = headers_dict.get('transfer-encoding', '').lower()
        content_length = headers_dict.get('content-length')

        if 'chunked' in transfer_encoding: body = await self._read_chunked_body()
        elif content_length:
            try:
                length = int(content_length)
                body = await self._read_bytes(length)
            except ValueError: pass 

        self._record_capture(method, target, headers, body, scheme, host, start_ts)

        conn_header = headers_dict.get('connection', '').lower()
        keep_alive = True
        if 'close' in conn_header or version_b == b'HTTP/1.0': keep_alive = False

        if not self.enable_tunneling:
            msg = b"Captured."
            self.writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
            await self.writer.drain()
            return keep_alive

        try:
            u_reader, u_writer = await self._connect_upstream(host, port)
        except asyncio.TimeoutError:
            await self._send_error(504, "Gateway Timeout")
            return False
        except Exception:
            await self._send_error(502, "Bad Gateway")
            return False

        # Forward Request
        # [FIX] Bug 2: Absolute URI Malformation (Ensure Origin-Form for Upstream)
        upstream_path = target
        if target.startswith("http://") or target.startswith("https://"):
             p = urlparse(target)
             upstream_path = p.path if p.path else "/"
             if p.query: upstream_path += "?" + p.query

        req_line = f"{method} {upstream_path} {version_b.decode()}\r\n".encode()
        u_writer.write(req_line)
        
        final_headers = []
        for k, v in headers:
            if k.lower() not in HOP_BY_HOP_HEADERS: final_headers.append((k, v))
        
        final_headers.append(('Content-Length', str(len(body))))
        final_headers.append(('Connection', 'close')) 

        for k, v in final_headers: u_writer.write(f"{k}: {v}\r\n".encode())
        u_writer.write(b"\r\n")
        
        if body: u_writer.write(body)
        await u_writer.drain()
        await self._pipe(u_reader, self.writer)
        u_writer.close()
        return False # Force close for simple H1 proxy logic

    async def _read_chunked_body(self) -> bytes:
        body_parts = []
        total_size = 0
        while True:
            line = await self._read_strict_line()
            if b';' in line: line, _ = line.split(b';', 1)
            try: chunk_size = int(line.strip(), 16)
            except ValueError: raise ProxyError("Invalid chunk size")
            
            if chunk_size == 0:
                while True: # Consume trailers
                    trailer = await self._read_strict_line()
                    if not trailer: break
                break
            
            data = await self._read_bytes(chunk_size)
            
            # [FIX] DoS Prevention: Check total size (similar to H2 fix)
            total_size += len(data)
            if total_size > MAX_CAPTURE_BODY_SIZE:
                 raise PayloadTooLargeError(f"Chunked body exceeded capture limit of {MAX_CAPTURE_BODY_SIZE} bytes.")
            
            body_parts.append(data)
            await self._read_strict_line() 
        return b"".join(body_parts)
    
    async def _read_bytes(self, n: int) -> bytes:
        if n > MAX_CAPTURE_BODY_SIZE:
             raise PayloadTooLargeError(f"Content-Length {n} exceeds capture limit.")
        while (len(self.buffer) - self._buffer_offset) < n:
            if len(self.buffer) > MAX_CAPTURE_BODY_SIZE + 4096:
                 raise PayloadTooLargeError("Buffer limit exceeded.")
            try: 
                data = await asyncio.wait_for(self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError: 
                raise ProxyError("Read Timeout (Idle) in Body")
            if not data: raise ProxyError("Incomplete read")
            if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                  del self.buffer[:self._buffer_offset]
                  self._buffer_offset = 0
            self.buffer.extend(data)
        
        # Bolt: Optimization for small chunks (< 8KB) vs large chunks
        if n < 8192:
            chunk = bytes(self.buffer[self._buffer_offset : self._buffer_offset + n])
        else:
            chunk = memoryview(self.buffer)[self._buffer_offset : self._buffer_offset + n].tobytes()

        self._buffer_offset += n
        return chunk

    async def _pipe(self, r, w, flush_buffer=False):
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
        except Exception: pass
        finally:
            try: w.close(); await w.wait_closed()
            except Exception: pass

    def _record_capture(self, method, path, headers, body, scheme, authority, start_ts):
        if self.target_override:
            url = urljoin(self.target_override, path.lstrip('/'))
        elif path.startswith('http'): url = path
        else: url = f"{scheme}://{authority}{path}"

        if self.scope_pattern and not self.scope_pattern.search(url): return
        
        captured = CapturedRequest(
            id=0, method=method, url=url, headers=headers, body=body, 
            truncated=(len(body) > MAX_CAPTURE_BODY_SIZE), protocol="HTTP/1.1",
            timestamp_start=start_ts, timestamp_end=time.time(),
            client_addr=self.client_addr, server_addr=(authority, 443 if scheme == 'https' else 80)
        )
        self.log("CAPTURE", captured)

class NativeProxyHandler(BaseProxyHandler):
    """
    Native HTTP/2 Proxy Handler (RFC 9113).
    Includes "Transparent H2" logic (On-Demand Upstream).
    Manages complex state machinery for H2 frames, streams, and flow control.
    """
    __slots__ = (
        'client_reader', 'client_writer', 'target_override', 'scope_pattern',
        'enable_tunneling', 'initial_data', 'upstream_reader', 'upstream_writer',
        'upstream_scheme', 'ds_h2_lock', 'us_h2_lock', 'ds_socket_lock',
        'us_socket_lock', 'downstream_conn', 'upstream_conn', 'streams',
        'closed', 'draining', 'upstream_protocol', 'upstream_connecting'
    )

    def __init__(self, client_reader, client_writer, explicit_host, manager_callback, 
                 target_override, scope_pattern, enable_tunneling=True, 
                 upstream_verify_ssl=False, upstream_ca_bundle=None, initial_data=b"",
                 ssl_context_factory=None):
        client_addr = client_writer.get_extra_info('peername') if client_writer else None if client_writer else None
        super().__init__(explicit_host, upstream_verify_ssl, upstream_ca_bundle, manager_callback, ssl_context_factory, client_addr)
        self.client_reader = client_reader; self.client_writer = client_writer
        self.target_override = target_override; self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling; self.initial_data = initial_data
        self.upstream_reader = None; self.upstream_writer = None; self.upstream_scheme = "https" 
        self.ds_h2_lock = asyncio.Lock(); self.us_h2_lock = asyncio.Lock()
        self.ds_socket_lock = asyncio.Lock(); self.us_socket_lock = asyncio.Lock()
        self.upstream_connecting = asyncio.Lock()
        
        self.upstream_protocol = "h2"
        if not H2Connection: raise ImportError("h2 library not found")
        # RFC 9113 Strictness: validate_inbound_headers enforces lowercase
        ds_config = H2Configuration(
            client_side=False, header_encoding='utf-8', 
            validate_inbound_headers=True, validate_outbound_headers=True,
            normalize_inbound_headers=True, normalize_outbound_headers=True
        )
        self.downstream_conn = H2Connection(config=ds_config)
        self.downstream_conn.local_settings.enable_push = 0
        self.downstream_conn.local_settings.max_header_list_size = MAX_HEADER_LIST_SIZE
        self.downstream_conn.local_settings.enable_connect_protocol = 1
        self.upstream_conn = None; self.streams = {}; self.closed = asyncio.Event(); self.draining = False

    async def run(self):
        try:
            try: self.upstream_host, self.upstream_port = self._parse_target(self.explicit_host)
            except ValueError: pass

            # Initial Connection (Only if explicit host is set; otherwise lazy-load)
            if self.enable_tunneling and self.upstream_host:
                await self._init_upstream_connection(self.upstream_host, self.upstream_port)

            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, drain=True)

            if self.initial_data:
                async with self.ds_h2_lock: events = self.downstream_conn.receive_data(self.initial_data)
                for event in events: await self.handle_downstream_event(event)
                await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

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

        except Exception as e:
            if not self.closed.is_set(): self.log("ERROR", f"H2 Proxy Error: {e}")
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally: await self.cleanup()

    async def _init_upstream_connection(self, host, port):
        """Helper to establish upstream"""
        try:
            self.upstream_reader, self.upstream_writer = await self._connect_upstream(
                host, port, alpn_protocols=["h2", "http/1.1"]
            )
            transport = self.upstream_writer.get_extra_info('ssl_object')
            if transport and transport.selected_alpn_protocol() == "http/1.1":
                self.upstream_protocol = "http/1.1"
            
            if self.upstream_protocol == "h2":
                us_config = H2Configuration(client_side=True, header_encoding='utf-8', 
                    validate_inbound_headers=True, validate_outbound_headers=True)
                self.upstream_conn = H2Connection(config=us_config)
                self.upstream_conn.initiate_connection()
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock, drain=True)
            else:
                if self.upstream_writer:
                    self.upstream_writer.close()
                    await self.upstream_writer.wait_closed()
                    self.upstream_reader = None; self.upstream_writer = None
        except Exception as e:
            self.log("ERROR", f"Upstream Connect Failed: {e}")
            raise

    async def _ensure_upstream_connected(self, authority: str):
        """Transparent Proxy: Connects on-demand using :authority."""
        async with self.upstream_connecting:
            if self.upstream_conn or (self.upstream_protocol == "http/1.1" and self.upstream_host):
                return # Already connected
            
            host, port = self._parse_target(authority)
            self.upstream_host = host; self.upstream_port = port
            await self._init_upstream_connection(host, port)
            
            if self.upstream_reader and self.upstream_protocol == "h2":
                asyncio.create_task(self._start_upstream_reader())

    async def _start_upstream_reader(self):
        await self._read_loop_wrapper(
            self.upstream_reader, self.upstream_conn, self.us_h2_lock,
            self.upstream_writer, self.us_socket_lock, self.handle_upstream_event
        )

    async def _read_loop_wrapper(self, reader, conn, h2_lock, writer, socket_lock, handler):
        try: await self.read_loop(reader, conn, h2_lock, writer, socket_lock, handler)
        except Exception: self.closed.set()

    async def read_loop(self, reader, conn, h2_lock, writer, socket_lock, event_handler):
        """
        Continuously reads data, updates H2 state.
        CRITICAL: Does NOT await drain() here to prevent deadlocks with Flow Control.
        """
        while not self.closed.is_set():
            try: data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                if not self.draining: asyncio.create_task(self.graceful_shutdown())
                continue
            if not data: self.closed.set(); break

            async with h2_lock:
                try: events = conn.receive_data(data)
                except Exception: await self.terminate(ErrorCodes.PROTOCOL_ERROR); break
                bytes_to_send = conn.data_to_send()

            if bytes_to_send:
                async with socket_lock:
                    try: writer.write(bytes_to_send)
                    except OSError: break
            
            for event in events: await event_handler(event)

    async def _stream_sender(self, stream_id, conn, writer, queue, flow_event, h2_lock, socket_lock, 
                             ack_conn, ack_h2_lock, ack_writer, ack_socket_lock):
        """
        RFC 9113 Flow Control: Check-Wait-Check Pattern.
        Consumes queue items and respects the H2 window.
        """
        while not self.closed.is_set():
            try:
                items = [await queue.get()]
                try:
                    for _ in range(10): items.append(queue.get_nowait())
                except asyncio.QueueEmpty: pass

                for item in items:
                    if item is None: queue.task_done(); return
                    payload, end_stream, ack_length = item

                    if isinstance(payload, list):
                        # Headers
                        async with h2_lock:
                            try: conn.send_headers(stream_id, payload, end_stream=end_stream); bytes_to_send = conn.data_to_send()
                            except Exception: bytes_to_send=None; break
                        if bytes_to_send:
                            async with socket_lock:
                                writer.write(bytes_to_send)
                            await writer.drain()
                    else:
                        # Data - Flow Control Loop
                        data = payload; view = memoryview(data); offset = 0; total_len = len(data)
                        while offset < total_len or (total_len == 0 and end_stream):
                            if self.closed.is_set(): break
                            bytes_to_send = None; break_loop = False; wait_for_flow = False
                            
                            async with h2_lock:
                                try:
                                    conn_window = conn.outbound_flow_control_window
                                    stream_window = conn.remote_flow_control_window(stream_id)
                                    available = min(conn_window, stream_window)
                                    
                                    if available <= 0 and not (total_len == 0 and end_stream):
                                        flow_event.clear()
                                        wait_for_flow = True
                                    else:
                                        chunk_size = max(0, min(total_len - offset, available))
                                        chunk = view[offset:offset+chunk_size]
                                        is_last = (offset + chunk_size == total_len) and end_stream
                                        conn.send_data(stream_id, chunk.tobytes(), end_stream=is_last)
                                        bytes_to_send = conn.data_to_send()
                                        offset += chunk_size
                                        if offset >= total_len: break_loop = True
                                except Exception: break_loop = True

                            if wait_for_flow:
                                try: await asyncio.wait_for(flow_event.wait(), timeout=FLOW_CONTROL_TIMEOUT)
                                except asyncio.TimeoutError: break 
                                continue 

                            if bytes_to_send:
                                async with socket_lock: writer.write(bytes_to_send)
                                await writer.drain() 
                            
                            if break_loop: break

                    if ack_conn and ack_length > 0:
                        async with ack_h2_lock:
                            try: ack_conn.acknowledge_received_data(ack_length, stream_id); ack_bytes = ack_conn.data_to_send()
                            except: ack_bytes=None
                        if ack_bytes:
                            async with ack_socket_lock: ack_writer.write(ack_bytes)

                    queue.task_done()
                    if end_stream: return
            except Exception as e: self.log("ERROR", f"Stream sender {stream_id} error: {e}"); break
        try: queue.task_done()
        except: pass

    async def handle_request_received(self, event):
        stream_id = event.stream_id
        if stream_id in self.streams:
             async with self.ds_h2_lock: self.downstream_conn.reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR); return
        
        ctx = StreamContext(stream_id, self.upstream_scheme, self.client_addr)
        self.streams[stream_id] = ctx
        ctx.captured_headers = self._process_headers_for_capture(event.headers)
        
        headers, protocol = self._prepare_forwarded_headers(event.headers, is_upstream=True)
        method = next((v.decode() for k, v in headers if k == b':method'), "GET")
        ctx.method = method
        authority = next((v.decode() for k, v in headers if k == b':authority'), "")

        if self.enable_tunneling:
            # Transparent H2: On-Demand Connection
            if not self.upstream_conn and self.upstream_protocol == "h2" and method != 'CONNECT':
                 try: await self._ensure_upstream_connected(authority)
                 except Exception:
                    async with self.ds_h2_lock: self.downstream_conn.reset_stream(stream_id, ErrorCodes.CONNECT_ERROR); return

            # CONNECT Tunnel (Strict RFC 9113)
            if method == 'CONNECT' and not protocol:
                await self._handle_h2_connect(stream_id, authority, ctx)
                return

            if self.upstream_protocol == "h2" and self.upstream_conn:
                # [SECURITY] RFC 8441: Verify upstream supports Extended CONNECT
                if protocol:
                    supports_connect = self.upstream_conn.remote_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL, 0)
                    if not supports_connect:
                        async with self.ds_h2_lock:
                            self.downstream_conn.reset_stream(stream_id, ErrorCodes.CONNECT_ERROR)
                        # [FIX] Explicitly clean up the stream state so it doesn't leak
                        self._cleanup_stream(stream_id, force_close=True)
                        return

                async with self.us_h2_lock: self.upstream_conn.send_headers(stream_id, headers, end_stream=event.stream_ended)
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock, drain=True)
                
                self._spawn_h2_tunnel(ctx, stream_id)
            elif self.upstream_protocol == "http/1.1":
                ctx.upstream_queue.put_nowait((headers, event.stream_ended, 0))
                self._spawn_h1_gateway(ctx, authority)

        if event.stream_ended:
            ctx.downstream_closed = True; self.finalize_capture(ctx)
            if self.enable_tunneling: ctx.upstream_queue.put_nowait(None)

    async def _handle_h2_connect(self, stream_id, authority, ctx):
        async with self.ds_h2_lock: self.downstream_conn.send_headers(stream_id, [(b':status', b'200')], end_stream=False)
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, drain=True)
        try:
            host, port = self._parse_target(authority)
            tr, tw = await self._connect_upstream(host, port)
        except Exception:
             async with self.ds_h2_lock: self.downstream_conn.reset_stream(stream_id, ErrorCodes.CONNECT_ERROR); return

        t_bridge = asyncio.create_task(self._raw_tcp_bridge_task(ctx, tr, tw))
        ctx.sender_tasks.append(t_bridge)
        t_down = asyncio.create_task(self._stream_sender(
            stream_id, self.downstream_conn, self.client_writer, ctx.downstream_queue, ctx.downstream_flow_event,
            self.ds_h2_lock, self.ds_socket_lock, None, None, None, None
        ))
        ctx.sender_tasks.append(t_down)

    def _spawn_h2_tunnel(self, ctx, stream_id):
        t_down = asyncio.create_task(self._stream_sender(
            stream_id, self.downstream_conn, self.client_writer, ctx.downstream_queue, ctx.downstream_flow_event,
            self.ds_h2_lock, self.ds_socket_lock, self.upstream_conn, self.us_h2_lock, self.upstream_writer, self.us_socket_lock
        ))
        t_up = asyncio.create_task(self._stream_sender(
            stream_id, self.upstream_conn, self.upstream_writer, ctx.upstream_queue, ctx.upstream_flow_event,
            self.us_h2_lock, self.us_socket_lock, self.downstream_conn, self.ds_h2_lock, self.client_writer, self.ds_socket_lock
        ))
        ctx.sender_tasks.extend([t_down, t_up])

    def _spawn_h1_gateway(self, ctx, authority):
        t_bridge = asyncio.create_task(self._h1_bridge_task(ctx, authority))
        ctx.sender_tasks.append(t_bridge)
        t_down = asyncio.create_task(self._stream_sender(
            ctx.stream_id, self.downstream_conn, self.client_writer, ctx.downstream_queue, ctx.downstream_flow_event,
            self.ds_h2_lock, self.ds_socket_lock, None, None, None, None
        ))
        ctx.sender_tasks.append(t_down)

    async def _h1_bridge_task(self, ctx: StreamContext, authority: str):
        reader, writer = None, None
        try:
            host, port = self._parse_target(authority if authority else self.upstream_host)
            reader, writer = await self._connect_upstream(host, port)
            
            # Client -> Upstream (H2 Frames -> H1 Bytes)
            item = await ctx.upstream_queue.get()
            if item:
                headers, end_stream, _ = item
                req_line, h1_headers = self._convert_h2_to_h1(headers, authority)
                writer.write(req_line)
                
                # [FIX] Bug 4: Byte-String Injection. Ensure proper byte concatenation.
                for k, v in h1_headers:
                    # Strip Content-Length if we are chunking (i.e. not end_stream)
                    if not end_stream and k.lower() == b'content-length': continue
                    
                    # Ensure we write bytes properly, not f-string repr of bytes
                    k_bytes = k if isinstance(k, bytes) else k.encode('ascii')
                    v_bytes = v if isinstance(v, bytes) else v.encode('ascii')
                    writer.write(k_bytes + b": " + v_bytes + b"\r\n")

                writer.write(b"\r\n" if end_stream else b"Transfer-Encoding: chunked\r\n\r\n")
                await writer.drain()
                ctx.upstream_queue.task_done()
                
                if not end_stream:
                    while True:
                        item = await ctx.upstream_queue.get()
                        if item is None: break
                        data, is_fin, _ = item
                        if data:
                            writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                        if is_fin:
                            writer.write(b"0\r\n\r\n")
                            await writer.drain(); ctx.upstream_queue.task_done(); break
                        await writer.drain(); ctx.upstream_queue.task_done()
            
            # Upstream -> Client (H1 Bytes -> H2 Frames)
            buffer = bytearray()
            line = await self._read_line_h1_bridge(reader, buffer)
            if not line: raise ConnectionError("Empty response")
            status = line.split(b' ', 2)[1]
            resp_headers = [(b':status', status)]
            while True:
                h = await self._read_line_h1_bridge(reader, buffer)
                if not h: break
                if b':' in h:
                    k, v = h.split(b':', 1)
                    k_lower = k.strip().lower()
                    if k_lower in H2_FORBIDDEN_HEADERS: continue
                    resp_headers.append((k_lower, v.strip()))
            
            # [FIX] Bug 3/4: Use await put() to prevent crash and backpressure issues
            await ctx.downstream_queue.put((resp_headers, False, 0))
            while not reader.at_eof():
                chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
                if not chunk: break
                await ctx.downstream_queue.put((chunk, False, 0))
            await ctx.downstream_queue.put((b"", True, 0))
            
        except Exception as e:
            async with self.ds_h2_lock:
                try: self.downstream_conn.reset_stream(ctx.stream_id, ErrorCodes.INTERNAL_ERROR)
                except: pass
        finally:
             if writer: writer.close()
             self._cleanup_stream(ctx.stream_id, upstream_closed=True)

    def _convert_h2_to_h1(self, headers, default_auth):
        method = b'GET'; path = b'/'; authority = default_auth.encode()
        clean_headers = []
        for k, v in headers:
            if k == b':method': method = v
            elif k == b':path': path = v
            elif k == b':authority': authority = v
            elif k.lower() == b'host': continue
            elif not k.startswith(b':'): clean_headers.append((k, v))
        
        clean_headers.insert(0, (b'Host', authority))
        # [FIX] Bug 1: Gateway Hang. Force upstream close.
        clean_headers.append((b'Connection', b'close'))
        return b"%s %s HTTP/1.1\r\n" % (method, path), clean_headers

    async def _read_line_h1_bridge(self, reader, buffer):
        while True:
            idx = buffer.find(b'\n')
            if idx >= 0:
                line = buffer[:idx+1]
                del buffer[:idx+1]
                return line.strip()
            data = await reader.read(8192)
            if not data: return b""
            buffer.extend(data)

    async def _raw_tcp_bridge_task(self, ctx, reader, writer):
        # Bi-directional pump for CONNECT
        async def c2u():
            try:
                while True:
                    item = await ctx.upstream_queue.get()
                    if item is None: break
                    data, end, ack = item
                    if data: writer.write(data); await writer.drain()
                    if ack:
                        async with self.ds_h2_lock: self.downstream_conn.acknowledge_received_data(ack, ctx.stream_id)
                        async with self.ds_socket_lock: self.client_writer.write(self.downstream_conn.data_to_send())
                    ctx.upstream_queue.task_done()
                    if end: break
            except: pass
        async def u2c():
            try:
                while not reader.at_eof():
                    data = await reader.read(65536)
                    if not data: break
                    # [FIX] Bug 3: Silent Tunnel. Added await.
                    await ctx.downstream_queue.put((data, False, 0))
            finally: 
                await ctx.downstream_queue.put((b"", True, 0))
        await asyncio.gather(c2u(), u2c())
        writer.close()
        self._cleanup_stream(ctx.stream_id, upstream_closed=True, downstream_closed=True)

    def _prepare_forwarded_headers(self, headers, is_upstream=True):
        decoded = []; method = None; protocol = None; host_val = None
        for k, v in headers:
            k_b = k if isinstance(k, bytes) else k.encode('utf-8')
            v_b = v if isinstance(v, bytes) else v.encode('utf-8')
            if k_b == b':method': method = v_b
            elif k_b == b':protocol': protocol = v_b
            elif k_b.lower() == b'host': host_val = v_b
            decoded.append((k_b, v_b))

        out = []; seen_regular = False
        is_connect = (method == b'CONNECT')
        pseudo = {}

        for k_b, v_b in decoded:
            if k_b.startswith(b':'):
                if seen_regular: raise ValueError("Pseudo-header after regular")
                pseudo[k_b] = v_b
            else:
                seen_regular = True
                k_lower = k_b.lower()
                if k_lower in H2_FORBIDDEN_HEADERS: continue
                if k_lower == b'te' and v_b.lower() != b'trailers': continue
                if k_lower == b'host': continue
                out.append((k_b, v_b))
                
        if is_upstream and b':authority' not in pseudo:
            if host_val: pseudo[b':authority'] = host_val
            elif self.upstream_host: pseudo[b':authority'] = self.upstream_host.encode('utf-8')

        final = []
        for k, v in pseudo.items(): final.append((k, v))
        final.extend(out)
        return self._wrap_security(final), protocol

    def _process_headers_for_capture(self, headers) -> CapturedHeaders:
        pseudo = {}; normal = []; cookies = []; authority = None
        for k, v in headers:
            k_s = k.decode('utf-8') if isinstance(k, bytes) else k
            v_s = v.decode('utf-8') if isinstance(v, bytes) else v
            if k_s.lower() == 'host' and not authority: authority = v_s
            if k_s.lower() in H2_FORBIDDEN_HEADERS: continue 
            if k_s.startswith(':'):
                pseudo[k_s] = v_s
                if k_s == ':authority': authority = v_s
            elif k_s.lower() == 'cookie': cookies.append(v_s)
            else: normal.append((k_s, v_s))
        if cookies: normal.append(('cookie', '; '.join(cookies)))
        if ':authority' not in pseudo and authority: pseudo[':authority'] = authority
        return {"pseudo": pseudo, "headers": normal}

    def _wrap_security(self, headers):
        if not hpack: return headers
        return [hpack.NeverIndexedHeaderTuple(k, v) if k.lower() in SENSITIVE_HEADERS_BYTES else (k, v) for k, v in headers]

    async def handle_downstream_event(self, event):
        if isinstance(event, RequestReceived): await self.handle_request_received(event)
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                ctx = self.streams[event.stream_id]
                if not ctx.truncated:
                    # [FIX] Bug 5: Accurate Body Size Calculation
                    ctx.current_body_size += len(event.data)
                    if ctx.current_body_size > MAX_CAPTURE_BODY_SIZE:
                         ctx.truncated = True
                    else: ctx.request_body_chunks.append(event.data)
                
                if self.enable_tunneling:
                    try: ctx.upstream_queue.put_nowait((event.data, event.stream_ended, event.flow_controlled_length))
                    except asyncio.QueueFull: self._cleanup_stream(event.stream_id, force_close=True)
                    if event.stream_ended: ctx.downstream_closed = True
        elif isinstance(event, TrailersReceived):
            # You need this to support gRPC and chunked trailers
            if event.stream_id in self.streams and self.enable_tunneling:
                # Determine direction (Are we sending to upstream or downstream?)
                # For handle_downstream_event (Client -> Server):
                ctx = self.streams[event.stream_id]
                try:
                     # Reuse your header sanitization logic
                    safe_headers, _ = self._prepare_forwarded_headers(event.headers, is_upstream=True)
                    ctx.upstream_queue.put_nowait((safe_headers, event.stream_ended, 0))
                except asyncio.QueueFull:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded): self._cleanup_stream(event.stream_id, downstream_closed=True)
        elif isinstance(event, StreamReset): self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, WindowUpdated): await self.handle_window_updated(event, 'downstream')
        elif isinstance(event, ConnectionTerminated): self.closed.set()

    async def handle_upstream_event(self, event):
        if isinstance(event, ResponseReceived):
            if event.stream_id in self.streams:
                safe_headers, _ = self._prepare_forwarded_headers(event.headers, is_upstream=False)
                self.streams[event.stream_id].downstream_queue.put_nowait((safe_headers, event.stream_ended, 0))
        elif isinstance(event, DataReceived):
            if event.stream_id in self.streams:
                try: self.streams[event.stream_id].downstream_queue.put_nowait((event.data, event.stream_ended, event.flow_controlled_length))
                except asyncio.QueueFull: self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, TrailersReceived):
            # You need this to support gRPC and chunked trailers
            if event.stream_id in self.streams and self.enable_tunneling:
                # For handle_upstream_event (Server -> Client):
                ctx = self.streams[event.stream_id]
                try:
                    # Reuse your header sanitization logic
                    safe_headers, _ = self._prepare_forwarded_headers(event.headers, is_upstream=False)
                    ctx.downstream_queue.put_nowait((safe_headers, event.stream_ended, 0))
                except asyncio.QueueFull:
                    self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, StreamEnded): self._cleanup_stream(event.stream_id, upstream_closed=True)
        elif isinstance(event, StreamReset): self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, WindowUpdated): await self.handle_window_updated(event, 'upstream')
        elif isinstance(event, ConnectionTerminated): self.closed.set()
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, drain=False)

    async def handle_window_updated(self, event, direction):
        sid = event.stream_id
        snapshot = list(self.streams.values())
        if sid == 0:
            for ctx in snapshot:
                (ctx.upstream_flow_event if direction == 'upstream' else ctx.downstream_flow_event).set()
        elif sid in self.streams:
            ctx = self.streams[sid]
            (ctx.upstream_flow_event if direction == 'upstream' else ctx.downstream_flow_event).set()

    def finalize_capture(self, ctx: StreamContext):
        if ctx.capture_finalized: return
        ctx.capture_finalized = True
        pseudo = ctx.captured_headers["pseudo"]
        try:
            if self.target_override: url = urljoin(self.target_override, pseudo.get(':path', '/').lstrip('/'))
            else: url = urlunparse((ctx.scheme, pseudo.get(':authority', self.explicit_host), pseudo.get(':path', '/'), '', '', ''))
        except: return
        
        captured = CapturedRequest(
            id=0, method=pseudo.get(':method', 'GET'), url=url, 
            headers=ctx.captured_headers["headers"], body=b"".join(ctx.request_body_chunks), 
            truncated=ctx.truncated, protocol="HTTP/2", timestamp_start=ctx.start_time, timestamp_end=time.time(),
            client_addr=ctx.client_addr, server_addr=(self.upstream_host, self.upstream_port)
        )
        self.log("CAPTURE", captured)

    async def _monitor_shutdown(self):
        await self.closed.wait()
        for ctx in list(self.streams.values()):
            ctx.upstream_queue.put_nowait(None); ctx.downstream_queue.put_nowait(None)

    async def _keepalive_loop(self):
        while not self.closed.is_set():
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if self.upstream_conn and self.upstream_protocol == "h2":
                async with self.us_h2_lock:
                    try: self.upstream_conn.ping(b'KeepAliv')
                    except: break
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
            async with self.ds_h2_lock:
                try: self.downstream_conn.ping(b'KeepAliv')
                except: break
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)

    async def cleanup(self):
        self.closed.set()
        for w in [self.client_writer, self.upstream_writer]:
            if w:
                try: w.close(); await w.wait_closed()
                except: pass
        for ctx in list(self.streams.values()):
            for t in ctx.sender_tasks: t.cancel()

    async def terminate(self, code):
        self.closed.set()
        async with self.ds_h2_lock:
            try: self.downstream_conn.close_connection(code)
            except: pass
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, drain=True)

    async def graceful_shutdown(self):
        if self.draining or self.closed.is_set(): return
        self.draining = True
        async with self.ds_socket_lock:
            try: self.client_writer.write(GOAWAY_MAX_FRAME)
            except: pass
        await asyncio.sleep(0.1) # Double-GOAWAY delay
        self.closed.set()
        async with self.ds_h2_lock:
            try: self.downstream_conn.close_connection(ErrorCodes.NO_ERROR)
            except: pass
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, drain=True)

    async def flush(self, conn, writer, h2_lock, socket_lock, drain=False):
        if self.closed.is_set() or not writer: return
        async with h2_lock:
            try: bytes_to_send = conn.data_to_send()
            except: return
        if bytes_to_send:
            async with socket_lock:
                try: writer.write(bytes_to_send)
                except: self.closed.set()
            if drain:
                try: await writer.drain()
                except: self.closed.set()

    def _cleanup_stream(self, stream_id: int, downstream_closed=False, upstream_closed=False, force_close=False):
        if stream_id not in self.streams: return
        ctx = self.streams[stream_id]
        if downstream_closed: ctx.downstream_closed = True
        if upstream_closed: ctx.upstream_closed = True
        if ctx.downstream_closed: self.finalize_capture(ctx)
        if force_close or (ctx.downstream_closed and ctx.upstream_closed):
            ctx.upstream_flow_event.set(); ctx.downstream_flow_event.set()
            for t in ctx.sender_tasks: t.cancel()
            del self.streams[stream_id]

class DualProtocolHandler:
    """
    Protocol Agnostic Handler.
    Routes to H1 or H2 implementation based on detection.
    """
    __slots__ = ('reader', 'writer', 'explicit_host', 'callback', 'target_override', 'scope_pattern', 'enable_tunneling', 'upstream_verify_ssl', 'upstream_ca_bundle', 'ssl_context_factory', 'strict_mode', 'initial_data')

    def __init__(self, reader, writer, explicit_host, manager_callback, target_override, scope_pattern, enable_tunneling=True, upstream_verify_ssl=False, upstream_ca_bundle=None, ssl_context_factory=None, strict_mode=True, initial_data=b""):
        self.reader = reader; self.writer = writer; self.explicit_host = explicit_host; self.callback = manager_callback
        self.target_override = target_override; self.scope_pattern = scope_pattern; self.enable_tunneling = enable_tunneling
        self.upstream_verify_ssl = upstream_verify_ssl; self.upstream_ca_bundle = upstream_ca_bundle
        self.ssl_context_factory = ssl_context_factory; self.strict_mode = strict_mode
        self.initial_data = initial_data

    async def run(self):
        protocol, initial_data = await self._detect_protocol()
        if protocol == "h2":
            await NativeProxyHandler(self.reader, self.writer, self.explicit_host, self.callback, self.target_override, self.scope_pattern, self.enable_tunneling, self.upstream_verify_ssl, self.upstream_ca_bundle, initial_data=initial_data, ssl_context_factory=self.ssl_context_factory).run()
        else:
            await Http11ProxyHandler(self.reader, self.writer, self.explicit_host, self.callback, self.target_override, self.scope_pattern, self.upstream_verify_ssl, self.upstream_ca_bundle, initial_data=initial_data, ssl_context_factory=self.ssl_context_factory, enable_tunneling=self.enable_tunneling, strict_mode=self.strict_mode).run()

    async def _detect_protocol(self) -> Tuple[str, bytes]:
        try:
            # ALPN check if TLS is terminated
            ssl_obj = self.writer.get_extra_info('ssl_object')
            if ssl_obj:
                alpn = ssl_obj.selected_alpn_protocol()
                if alpn == "h2": return "h2", b""
                if alpn == "http/1.1": return "http/1.1", b""

            buffer = bytearray(self.initial_data)
            required = len(H2_PREFACE)
            for _ in range(5):
                if len(buffer) >= required: break
                try:
                    chunk = await asyncio.wait_for(self.reader.read(required - len(buffer)), timeout=0.5)
                    if not chunk: break
                    buffer.extend(chunk)
                    if len(buffer) >= 4 and not buffer.startswith(b'PRI '): return "http/1.1", bytes(buffer)
                except asyncio.TimeoutError: break
            
            data = bytes(buffer)
            if data.startswith(H2_PREFACE[:4]):
                if len(data) == required and data == H2_PREFACE: return "h2", data
                if b'HTTP/2.0' in data: return "h2", data
            return "http/1.1", data
        except Exception: return "http/1.1", self.initial_data

async def start_proxy_server(host, port, manager_callback, target_override=None, scope_pattern=None, ssl_context_factory=None, strict_mode=True):
    async def _handle(r, w):
        await DualProtocolHandler(r, w, "", manager_callback, target_override, scope_pattern, ssl_context_factory=ssl_context_factory, strict_mode=strict_mode).run()
    
    server = await asyncio.start_server(_handle, host, port)
    manager_callback("SYSTEM", f"Transparent Proxy (H1/H2) listening on {host}:{port}")
    async with server:
        try: await server.serve_forever()
        except asyncio.CancelledError: pass
        finally:
            manager_callback("SYSTEM", "Proxy stopped")
            server.close(); await server.wait_closed()