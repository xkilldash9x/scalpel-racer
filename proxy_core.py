#Filename: proxy_core.py
"""
ASYNC PROXY CORE - SCALPEL RACER
Refactored to use SSOT and Compat.
Splits massive methods into logical helper blocks.
"""

import os
import asyncio
import ssl
import re
import socket
import time
from typing import Dict, Optional, Callable, Tuple, List, Any, TypedDict, cast, Union
from urllib.parse import urljoin, urlunparse, urlparse

# [APEX] Imports
from structures import (
    CapturedRequest, 
    CapturedHeaders, 
    SENSITIVE_HEADERS_BYTES, 
    HOP_BY_HOP_HEADERS, 
    MAX_CAPTURE_BODY_SIZE
)

from compat import (
    H2Connection, 
    H2Configuration, 
    ErrorCodes, 
    SettingCodes, 
    RequestReceived, 
    DataReceived, 
    StreamEnded, 
    StreamReset, 
    WindowUpdated, 
    ConnectionTerminated, 
    TrailersReceived, 
    ResponseReceived, 
    Event,
    hpack
)

# Constants & Strict Patterns
STRICT_HEADER_PATTERN = re.compile(rb'^([!#$%&\'*+\-.^_`|~0-9a-zA-Z]+):[ \t]*(.*)$')
UPSTREAM_CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
KEEPALIVE_INTERVAL = 10.0
FLOW_CONTROL_TIMEOUT = 30.0
MAX_HEADER_LIST_SIZE = 262144
STREAM_QUEUE_SIZE = 1024
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
GOAWAY_MAX_FRAME = b'\x00\x00\x08\x07\x00\x00\x00\x00\x00\x7f\xff\xff\xff\x00\x00\x00\x00'
READ_CHUNK_SIZE = 65536
COMPACTION_THRESHOLD = 65536
H2_FORBIDDEN_HEADERS = frozenset({
    b'connection', b'keep-alive', b'proxy-connection', b'transfer-encoding', b'upgrade'
})

class StreamContext:
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
        self.upstream_flow_event = asyncio.Event(); self.upstream_flow_event.set()
        self.downstream_flow_event = asyncio.Event(); self.downstream_flow_event.set()
        self.upstream_queue: asyncio.Queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE) 
        self.downstream_queue: asyncio.Queue = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE) 
        self.sender_tasks: List[asyncio.Task] = [] 
        self.captured_headers: CapturedHeaders = {"pseudo": {}, "headers": []} 
        self.request_body_chunks: List[bytes] = []
        self.current_body_size = 0
        self.capture_finalized = False 
        self.truncated = False
        self.start_time = time.time()
        self.client_addr = client_addr

class ProxyError(Exception): 
    pass
class PayloadTooLargeError(ProxyError): 
    pass

class BaseProxyHandler:
    __slots__ = (
        'explicit_host', 'upstream_verify_ssl', 'upstream_ca_bundle', 'callback', 
        'ssl_context_factory', 'upstream_host', 'upstream_port', 'client_addr'
    )
    
    def __init__(
        self, 
        explicit_host: str, 
        upstream_verify_ssl: bool, 
        upstream_ca_bundle: Optional[str], 
        manager_callback: Callable, 
        ssl_context_factory: Optional[Callable] = None, 
        client_addr: Optional[Tuple[str, int]] = None
    ):
        self.explicit_host = explicit_host
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.callback = manager_callback
        self.ssl_context_factory = ssl_context_factory
        self.upstream_host: str = ""
        self.upstream_port: int = 443
        self.client_addr = client_addr
    
    def log(self, level: str, msg: Any) -> None:
        if self.callback:
            try: 
                self.callback(level, msg)
            except Exception: 
                pass 
    
    def _parse_target(self, explicit_host: str, default_port: int = 443) -> Tuple[str, int]:
        if not explicit_host: 
            return "", 0
        if explicit_host.startswith('['):
            end = explicit_host.find(']')
            if end != -1:
                host = explicit_host[1:end]
                rem = explicit_host[end+1:]
                if rem.startswith(':'):
                    try: 
                        return host, int(rem[1:])
                    except ValueError: 
                        pass
                else: 
                    return host, default_port
        if ':' in explicit_host:
            host, port_str = explicit_host.rsplit(':', 1)
            try: 
                return host, int(port_str)
            except ValueError: 
                pass
        return explicit_host, default_port
    
    async def _connect_upstream(self, host: str, port: int, alpn_protocols: Optional[List[str]] = None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ctx = ssl.create_default_context()
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog: 
            ctx.keylog_filename = keylog
        
        if self.upstream_verify_ssl:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            if self.upstream_ca_bundle: 
                ctx.load_verify_locations(cafile=self.upstream_ca_bundle)
        else: 
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        if alpn_protocols:
            try: 
                ctx.set_alpn_protocols(alpn_protocols)
            except NotImplementedError: 
                pass
        
        try:
            server_hostname = host if (self.upstream_verify_ssl or alpn_protocols) else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname), 
                timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            try:
                sock = writer.get_extra_info('socket')
                if sock: 
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: 
                pass
            return reader, writer
        except ProxyError: 
            raise
        except Exception as e:
            if not isinstance(e, asyncio.TimeoutError): 
                raise ProxyError(f"Upstream connection failed: {e}") from e
            raise
    
    def _is_url_allowed(self, url: str, scope_pattern: Optional[re.Pattern]) -> bool:
        if not scope_pattern: 
            return True
        return bool(scope_pattern.search(url))

class Http11ProxyHandler(BaseProxyHandler):
    __slots__ = (
        'reader', 'writer', 'target_override', 'scope_pattern', 'buffer', 
        '_buffer_offset', 'enable_tunneling', 'strict_mode', '_previous_byte_was_cr'
    )
    
    def __init__(
        self, 
        reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter, 
        explicit_host: str, 
        manager_callback: Callable, 
        target_override: Optional[str], 
        scope_pattern: Optional[re.Pattern], 
        upstream_verify_ssl: bool = False, 
        upstream_ca_bundle: Optional[str] = None, 
        initial_data: bytes = b"", 
        ssl_context_factory: Optional[Callable] = None, 
        enable_tunneling: bool = True, 
        strict_mode: bool = True
    ):
        raw_addr = writer.get_extra_info('peername')
        client_addr = (str(raw_addr[0]), int(raw_addr[1])) if isinstance(raw_addr, tuple) and len(raw_addr) >= 2 else None
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
        while True:
            lf_index = self.buffer.find(b'\n', self._buffer_offset)
            if lf_index == -1:
                if len(self.buffer) - self._buffer_offset > 0: 
                    self._previous_byte_was_cr = (self.buffer[-1] == 0x0D)
                if (len(self.buffer) - self._buffer_offset) > MAX_HEADER_LIST_SIZE: 
                    raise ProxyError("Header Line Exceeded Max Length")
                if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                      del self.buffer[:self._buffer_offset]
                      self._buffer_offset = 0
                try: 
                    data = await asyncio.wait_for(self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError: 
                    raise ProxyError("Read Timeout (Idle)")
                if not data:
                    if len(self.buffer) - self._buffer_offset > 0: 
                        raise ProxyError("Incomplete message")
                    return b""
                self.buffer.extend(data)
                continue
            
            line_len = lf_index - self._buffer_offset
            if line_len > MAX_HEADER_LIST_SIZE: 
                raise ProxyError("Header Line Exceeded Max Length")
            
            is_crlf = False
            if lf_index > self._buffer_offset:
                if self.buffer[lf_index - 1] == 0x0D: 
                    is_crlf = True
            elif lf_index == self._buffer_offset:
                if self._previous_byte_was_cr: 
                    is_crlf = True
            
            line_end = lf_index - 1 if is_crlf else lf_index
            line = bytes(self.buffer[self._buffer_offset:line_end]) if line_end > self._buffer_offset else b""
            self._buffer_offset = lf_index + 1
            self._previous_byte_was_cr = False
            return line
    
    async def run(self) -> None:
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
                
                if not line: 
                    break 
                
                try:
                    parts = line.split(b' ', 2)
                    if len(parts) != 3: 
                        raise ValueError
                    method_b, target_b, version_b = parts
                    method = method_b.decode('ascii')
                    target = target_b.decode('ascii')
                except ValueError: 
                    await self._send_error(400, "Malformed Request Line")
                    return
                
                headers = []
                headers_dict = {}
                try:
                    while True:
                        h_line = await self._read_strict_line()
                        if not h_line: 
                            break 
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
                
                if not await self._validate_request(method, headers_dict): 
                    return
                
                # Transfer-Encoding & Content-Length handling
                te = headers_dict.get('transfer-encoding')
                cl = headers_dict.get('content-length')
                if te:
                    if cl and self.strict_mode:
                        headers = [h for h in headers if h[0].lower() != 'content-length']
                        if 'content-length' in headers_dict: 
                            del headers_dict['content-length']
                    enc = [e.strip().lower() for e in te.split(',')]
                    if 'chunked' in enc and enc[-1] != 'chunked': 
                        await self._send_error(400, "Bad Transfer-Encoding")
                        return
                elif cl:
                    try:
                        if int(cl) < 0: 
                            raise ValueError
                    except ValueError: 
                        await self._send_error(400, "Invalid Content-Length")
                        return
                
                if method == 'CONNECT': 
                    await self._handle_connect(target)
                    return 
                else:
                    keep_alive = await self._handle_request(method, target, version_b, headers, headers_dict, start_ts)
                    if not keep_alive: 
                        break
        except Exception as e: 
            self.log("ERROR", f"HTTP/1.1 Proxy Error: {e}")
        finally:
            if not self.writer.is_closing(): 
                self.writer.close()
    
    async def _validate_request(self, method: str, headers_dict: Dict[str, str]) -> bool:
        if method == 'CONNECT' and 'host' not in headers_dict: 
            await self._send_error(400, "CONNECT requires Host header")
            return False
        if any(k.startswith(':') for k in headers_dict): 
            await self._send_error(400, "Pseudo-header in HTTP/1.1")
            return False
        return True
    
    async def _handle_connect(self, target: str) -> None:
        host, port = self._parse_target(target)
        if self.enable_tunneling:
            factory = self.ssl_context_factory
            if factory:
                try:
                    self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await self.writer.drain()
                    ssl_ctx = factory(host)
                    await self.writer.start_tls(ssl_ctx)
                    rem = self.buffer[self._buffer_offset:] if self.buffer else b""
                    handler = DualProtocolHandler(
                        self.reader, self.writer, target, self.callback, 
                        self.target_override, self.scope_pattern, self.enable_tunneling, 
                        self.upstream_verify_ssl, self.upstream_ca_bundle, 
                        self.ssl_context_factory, initial_data=bytes(rem)
                    )
                    await handler.run()
                    return
                except Exception as e: 
                    self.log("ERROR", f"MITM Upgrade Failed: {e}")
                    return
        try:
            u_r, u_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=UPSTREAM_CONNECT_TIMEOUT)
            self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self.writer.drain()
            if self.buffer and self._buffer_offset < len(self.buffer): 
                u_w.write(self.buffer[self._buffer_offset:])
                await u_w.drain()
            await asyncio.gather(self._pipe(self.reader, u_w, False), self._pipe(u_r, self.writer), return_exceptions=True)
        except Exception: 
            await self._send_error(502, "Bad Gateway")
    
    async def _send_error(self, code: int, message: str) -> None:
        try: 
            self.writer.write(f"HTTP/1.1 {code} {message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
            await self.writer.drain()
        except Exception: 
            pass
    
    async def _handle_request(
        self, method: str, target: str, version_b: bytes, 
        headers: List[Tuple[str, str]], headers_dict: Dict[str, str], start_ts: float
    ) -> bool:
        req_host = self.explicit_host
        if not req_host:
            p = urlparse(target)
            if p.scheme and p.netloc: 
                req_host = p.netloc
        if not req_host: 
            req_host = headers_dict.get('host')
        if not req_host: 
            p = urlparse(target)
            req_host = p.netloc or ""
            
        scheme = "https" if self.upstream_verify_ssl else "http"
        default_port = 443 if scheme == "https" else 80
        host, port = self._parse_target(req_host if req_host else "", default_port=default_port)
        
        full_url = urljoin(self.target_override, target.lstrip('/')) if self.target_override else (target if target.startswith("http") else f"{scheme}://{host}:{port}{target}")
        
        if not self._is_url_allowed(full_url, self.scope_pattern): 
            await self._send_error(403, "Forbidden by Proxy Scope")
            return False
            
        body = b""
        te = headers_dict.get('transfer-encoding', '').lower()
        cl = headers_dict.get('content-length')
        
        if 'chunked' in te: 
            body = await self._read_chunked_body()
        elif cl:
            try: 
                body = await self._read_bytes(int(cl))
            except ValueError: 
                pass 
                
        self._record_capture(method, target, headers, body, scheme, host, start_ts)
        
        conn = headers_dict.get('connection', '').lower()
        keep_alive = True
        if 'close' in conn or version_b == b'HTTP/1.0': 
            keep_alive = False
            
        if not self.enable_tunneling:
            msg = b"Captured."
            self.writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
            await self.writer.drain()
            return keep_alive
            
        try: 
            u_r, u_w = await self._connect_upstream(host, port)
        except asyncio.TimeoutError: 
            await self._send_error(504, "Gateway Timeout")
            return False
        except Exception: 
            await self._send_error(502, "Bad Gateway")
            return False
            
        up_path = target
        if target.startswith("http"): 
            p = urlparse(target)
            up_path = p.path if p.path else "/"
            up_path += ("?" + p.query) if p.query else ""
            
        u_w.write(f"{method} {up_path} {version_b.decode()}\r\n".encode())
        for k, v in headers:
            if k.lower() not in HOP_BY_HOP_HEADERS: 
                u_w.write(f"{k}: {v}\r\n".encode())
        u_w.write(f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode())
        
        if body: 
            u_w.write(body)
        await u_w.drain()
        await self._pipe(u_r, self.writer)
        u_w.close()
        return False
    
    async def _read_chunked_body(self) -> bytes:
        parts = []
        total = 0
        while True:
            line = await self._read_strict_line()
            if b';' in line: 
                line, _ = line.split(b';', 1)
            try: 
                size = int(line.strip(), 16)
            except ValueError: 
                raise ProxyError("Invalid chunk size")
            
            if size == 0:
                while True: 
                    t = await self._read_strict_line()
                    if not t: 
                        break
                break
            
            data = await self._read_bytes(size)
            total += len(data)
            if total > MAX_CAPTURE_BODY_SIZE: 
                raise PayloadTooLargeError(f"Chunked body exceeded {MAX_CAPTURE_BODY_SIZE} bytes.")
            parts.append(data)
            await self._read_strict_line() 
        return b"".join(parts)
    
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
            if not data: 
                raise ProxyError("Incomplete read")
            
            if self._buffer_offset > COMPACTION_THRESHOLD and self._buffer_offset > (len(self.buffer) // 2):
                  del self.buffer[:self._buffer_offset]
                  self._buffer_offset = 0
            self.buffer.extend(data)
        
        chunk = bytes(self.buffer[self._buffer_offset : self._buffer_offset + n])
        self._buffer_offset += n
        return chunk
    
    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, flush_buffer: bool = False) -> None:
        try:
            if flush_buffer and (len(self.buffer) - self._buffer_offset) > 0:
                w.write(self.buffer[self._buffer_offset:])
                await w.drain()
                self._buffer_offset = 0
                del self.buffer[:]
            
            while not r.at_eof():
                data = await r.read(65536)
                if not data: 
                    break
                w.write(data)
                await w.drain()
        except Exception: 
            pass
        finally:
            try: 
                w.close()
                await w.wait_closed()
            except Exception: 
                pass
    
    def _record_capture(
        self, method: str, path: str, headers: List[Tuple[str, str]], body: bytes, 
        scheme: str, authority: str, start_ts: float
    ) -> None:
        if self.target_override: 
            url = urljoin(self.target_override, path.lstrip('/'))
        elif path.startswith('http'): 
            url = path
        else: 
            url = f"{scheme}://{authority}{path}"
            
        if self.scope_pattern and not self.scope_pattern.search(url): 
            return
            
        captured = CapturedRequest(
            0, method, url, headers, body, 
            (len(body) > MAX_CAPTURE_BODY_SIZE), "HTTP/1.1", None, 
            start_ts, time.time(), self.client_addr, 
            (authority, 443 if scheme == 'https' else 80)
        )
        self.log("CAPTURE", captured)

class NativeProxyHandler(BaseProxyHandler):
    __slots__ = (
        'client_reader', 'client_writer', 'target_override', 'scope_pattern', 'enable_tunneling', 
        'initial_data', 'upstream_reader', 'upstream_writer', 'upstream_scheme', 'ds_h2_lock', 
        'us_h2_lock', 'ds_socket_lock', 'us_socket_lock', 'downstream_conn', 'upstream_conn', 
        'streams', 'closed', 'draining', 'upstream_protocol', 'upstream_connecting'
    )
    
    def __init__(
        self, 
        c_r: asyncio.StreamReader, 
        c_w: asyncio.StreamWriter, 
        eh: str, 
        cb: Callable, 
        to: Optional[str], 
        sp: Optional[re.Pattern], 
        et: bool = True, 
        uvs: bool = False, 
        ucb: Optional[str] = None, 
        id_bytes: bytes = b"", 
        ssf: Optional[Callable] = None
    ):
        raw_addr = c_w.get_extra_info('peername') if c_w else None
        client_addr = (str(raw_addr[0]), int(raw_addr[1])) if isinstance(raw_addr, tuple) and len(raw_addr) >= 2 else None
        super().__init__(eh, uvs, ucb, cb, ssf, client_addr)
        
        self.client_reader = c_r
        self.client_writer = c_w
        self.target_override = to
        self.scope_pattern = sp
        self.enable_tunneling = et
        self.initial_data = id_bytes
        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None
        self.upstream_scheme = "https"
        self.upstream_protocol = "h2"
        
        self.ds_h2_lock = asyncio.Lock()
        self.us_h2_lock = asyncio.Lock()
        self.ds_socket_lock = asyncio.Lock()
        self.us_socket_lock = asyncio.Lock()
        self.upstream_connecting = asyncio.Lock()
        
        ds_config = H2Configuration(
            client_side=False, header_encoding='utf-8', 
            validate_inbound_headers=True, validate_outbound_headers=True
        )
        self.downstream_conn = H2Connection(config=ds_config)
        self.downstream_conn.local_settings[SettingCodes.ENABLE_PUSH] = 0
        self.downstream_conn.local_settings[SettingCodes.MAX_HEADER_LIST_SIZE] = MAX_HEADER_LIST_SIZE
        self.downstream_conn.local_settings[SettingCodes.ENABLE_CONNECT_PROTOCOL] = 1
        
        self.upstream_conn: Optional[H2Connection] = None
        self.streams: Dict[int, StreamContext] = {}
        self.closed = asyncio.Event()
        self.draining = False
    
    async def run(self) -> None:
        try:
            try: 
                self.upstream_host, self.upstream_port = self._parse_target(self.explicit_host)
            except ValueError: 
                pass
            
            if self.enable_tunneling and self.upstream_host: 
                await self._init_upstream_connection(self.upstream_host, self.upstream_port)
            
            self.downstream_conn.initiate_connection()
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, True)
            
            if self.initial_data:
                async with self.ds_h2_lock: 
                    events = self.downstream_conn.receive_data(self.initial_data)
                for e in events: 
                    await self.handle_downstream_event(e)
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
            if not self.closed.is_set(): 
                self.log("ERROR", f"H2 Proxy Error: {e}")
            await self.terminate(ErrorCodes.INTERNAL_ERROR)
        finally: 
            await self.cleanup()
    
    async def _init_upstream_connection(self, host: str, port: int) -> None:
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
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock, True)
            else:
                if self.upstream_writer: 
                    self.upstream_writer.close()
                    await self.upstream_writer.wait_closed()
                    self.upstream_reader = None
                    self.upstream_writer = None
        except Exception as e: 
            self.log("ERROR", f"Upstream Connect Failed: {e}")
            raise
    
    async def _ensure_upstream_connected(self, authority: str) -> None:
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
        await self._read_loop_wrapper(
            self.upstream_reader, self.upstream_conn, self.us_h2_lock, 
            self.upstream_writer, self.us_socket_lock, self.handle_upstream_event
        )
    
    async def _read_loop_wrapper(
        self, reader: Any, conn: H2Connection, h2_lock: asyncio.Lock, 
        writer: asyncio.StreamWriter, socket_lock: asyncio.Lock, event_handler: Callable
    ) -> None:
        try: 
            await self.read_loop(reader, conn, h2_lock, writer, socket_lock, event_handler)
        except Exception: 
            self.closed.set()
    
    async def read_loop(
        self, reader: asyncio.StreamReader, conn: H2Connection, h2_lock: asyncio.Lock, 
        writer: asyncio.StreamWriter, socket_lock: asyncio.Lock, event_handler: Callable
    ) -> None:
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
                except Exception: 
                    await self.terminate(ErrorCodes.PROTOCOL_ERROR)
                    break
                bytes_to_send = conn.data_to_send()
            
            if bytes_to_send:
                async with socket_lock:
                    try: 
                        writer.write(bytes_to_send)
                    except OSError: 
                        break
            
            for event in events: 
                await event_handler(event)
    
    async def _stream_sender(
        self, stream_id: int, conn: H2Connection, writer: asyncio.StreamWriter, 
        queue: asyncio.Queue, flow_event: asyncio.Event, h2_lock: asyncio.Lock, 
        socket_lock: asyncio.Lock, ack_conn: Optional[H2Connection], 
        ack_h2_lock: Optional[asyncio.Lock], ack_writer: Optional[asyncio.StreamWriter], 
        ack_socket_lock: Optional[asyncio.Lock]
    ) -> None:
        while not self.closed.is_set():
            try:
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
                    
                    if ack_conn and ack_length > 0 and ack_h2_lock and ack_socket_lock and ack_writer:
                        await self._send_ack(ack_conn, ack_h2_lock, ack_writer, ack_socket_lock, ack_length, stream_id)
                        
                    queue.task_done()
                    if end_stream: 
                        return
            except Exception as e: 
                self.log("ERROR", f"Stream sender {stream_id} error: {e}")
                break
        
        try: 
            queue.task_done()
        except Exception: 
            pass

    async def _process_stream_item(
        self, stream_id: int, conn: H2Connection, writer: asyncio.StreamWriter, 
        payload: Any, end_stream: bool, ack_length: int, flow_event: asyncio.Event, 
        h2_lock: asyncio.Lock, socket_lock: asyncio.Lock
    ) -> None:
        if isinstance(payload, list):
            async with h2_lock:
                try: 
                    conn.send_headers(stream_id, payload, end_stream=end_stream)
                    bytes_to_send = conn.data_to_send()
                except Exception: 
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
                    avail = min(conn.outbound_flow_control_window, conn.remote_flow_control_window(stream_id))
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
                except Exception: 
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
        ack_bytes = None
        async with ack_h2_lock:
            try: 
                ack_conn.acknowledge_received_data(ack_length, stream_id)
                ack_bytes = ack_conn.data_to_send()
            except Exception: 
                pass
        
        if ack_bytes:
            async with ack_socket_lock: 
                ack_writer.write(ack_bytes)

    async def handle_request_received(self, event: RequestReceived) -> None:
        sid = event.stream_id
        if sid in self.streams:
             async with self.ds_h2_lock: 
                 self.downstream_conn.reset_stream(sid, ErrorCodes.PROTOCOL_ERROR)
             return
        
        ctx = StreamContext(sid, self.upstream_scheme, self.client_addr)
        self.streams[sid] = ctx
        ctx.captured_headers = self._process_headers_for_capture(event.headers)
        
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
        self, ctx: StreamContext, sid: int, headers: List[Tuple[bytes, bytes]], 
        protocol: Optional[bytes], authority: str, end_stream: bool
    ) -> None:
        if not self.upstream_conn and self.upstream_protocol == "h2" and ctx.method != 'CONNECT':
             try: 
                 await self._ensure_upstream_connected(authority)
             except Exception:
                 async with self.ds_h2_lock: 
                     self.downstream_conn.reset_stream(sid, ErrorCodes.CONNECT_ERROR)
                 return

        if ctx.method == 'CONNECT' and not protocol: 
            await self._handle_h2_connect(sid, authority, ctx)
            return

        if self.upstream_protocol == "h2" and self.upstream_conn:
            if protocol:
                if not self.upstream_conn.remote_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL, 0):
                    async with self.ds_h2_lock: 
                        self.downstream_conn.reset_stream(sid, ErrorCodes.CONNECT_ERROR)
                    self._cleanup_stream(sid, force_close=True)
                    return
            
            async with self.us_h2_lock: 
                self.upstream_conn.send_headers(sid, headers, end_stream=end_stream)
            await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock, True)
            self._spawn_h2_tunnel(ctx, sid)
        elif self.upstream_protocol == "http/1.1":
            ctx.upstream_queue.put_nowait((headers, end_stream, 0))
            self._spawn_h1_gateway(ctx, authority)
    
    async def _handle_h2_connect(self, sid: int, authority: str, ctx: StreamContext) -> None:
        async with self.ds_h2_lock: 
            self.downstream_conn.send_headers(sid, [(b':status', b'200')], end_stream=False)
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, True)
        
        try: 
            h, p = self._parse_target(authority)
            tr, tw = await self._connect_upstream(h, p)
        except Exception:
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
    
    def _spawn_h2_tunnel(self, ctx: StreamContext, sid: int) -> None:
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
    
    def _spawn_h1_gateway(self, ctx: StreamContext, authority: str) -> None:
        ctx.sender_tasks.extend([
            asyncio.create_task(self._h1_bridge_task(ctx, authority)), 
            asyncio.create_task(self._stream_sender(
                ctx.stream_id, self.downstream_conn, self.client_writer, 
                ctx.downstream_queue, ctx.downstream_flow_event, self.ds_h2_lock, 
                self.ds_socket_lock, None, None, None, None
            ))
        ])
    
    async def _h1_bridge_task(self, ctx: StreamContext, authority: str) -> None:
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            h, p = self._parse_target(authority if authority else self.upstream_host)
            reader, writer = await self._connect_upstream(h, p)
            
            await self._process_h1_upstream_send(ctx, writer, authority)
            await self._process_h1_upstream_receive(ctx, reader)

        except Exception:
            async with self.ds_h2_lock:
                try: 
                    self.downstream_conn.reset_stream(ctx.stream_id, ErrorCodes.INTERNAL_ERROR)
                except Exception: 
                    pass
        finally:
            if writer: 
                writer.close()
            self._cleanup_stream(ctx.stream_id, upstream_closed=True)

    async def _process_h1_upstream_send(self, ctx: StreamContext, writer: asyncio.StreamWriter, authority: str) -> None:
        item = await ctx.upstream_queue.get()
        if item:
            headers, end_stream, _ = item
            req_line, h1_headers = self._convert_h2_to_h1(headers, authority)
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
                    if data: 
                        writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                    if is_fin: 
                        writer.write(b"0\r\n\r\n")
                        await writer.drain()
                        ctx.upstream_queue.task_done()
                        break
                    await writer.drain()
                    ctx.upstream_queue.task_done()

    async def _process_h1_upstream_receive(self, ctx: StreamContext, reader: asyncio.StreamReader) -> None:
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
    
    def _convert_h2_to_h1(self, headers: List[Tuple[bytes, bytes]], default_auth: str) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
        method = b'GET'
        path = b'/'
        authority = default_auth.encode()
        clean = []
        for k, v in headers:
            if k == b':method': 
                method = v
            elif k == b':path': 
                path = v
            elif k == b':authority': 
                authority = v
            elif k.lower() == b'host': 
                continue
            elif not k.startswith(b':'): 
                clean.append((k, v))
        clean.insert(0, (b'Host', authority))
        clean.append((b'Connection', b'close'))
        return b"%s %s HTTP/1.1\r\n" % (method, path), clean
    
    async def _read_line_h1_bridge(self, reader: asyncio.StreamReader, buffer: bytearray) -> bytes:
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
    
    async def _raw_tcp_bridge_task(self, ctx: StreamContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async def c2u() -> None:
            try:
                while True:
                    item = await ctx.upstream_queue.get()
                    if item is None: 
                        break
                    data, end, ack = item
                    if data: 
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
    
    def _prepare_forwarded_headers(self, headers: List[Tuple[bytes, bytes]], is_upstream: bool = True) -> Tuple[List[Tuple[bytes, bytes]], Optional[bytes]]:
        decoded = []
        method = None
        protocol = None
        host_val = None
        
        for k, v in headers:
            k_b = k if isinstance(k, bytes) else k.encode('utf-8')
            v_b = v if isinstance(v, bytes) else v.encode('utf-8')
            if k_b == b':method': 
                method = v_b
            elif k_b == b':protocol': 
                protocol = v_b
            elif k_b.lower() == b'host': 
                host_val = v_b
            decoded.append((k_b, v_b))
            
        out = []
        pseudo = {}
        for k_b, v_b in decoded:
            if k_b.startswith(b':'): 
                pseudo[k_b] = v_b
            else:
                k_lower = k_b.lower()
                if k_lower in H2_FORBIDDEN_HEADERS: 
                    continue
                if k_lower == b'te' and v_b.lower() != b'trailers': 
                    continue
                if k_lower == b'host': 
                    continue
                out.append((k_b, v_b))
                
        if is_upstream and b':authority' not in pseudo:
            if host_val: 
                pseudo[b':authority'] = host_val
            elif self.upstream_host: 
                pseudo[b':authority'] = self.upstream_host.encode('utf-8')
        
        final = [(k, v) for k, v in pseudo.items()]
        final.extend(out)
        return self._wrap_security(final), protocol
    
    def _process_headers_for_capture(self, headers: List[Tuple[Any, Any]]) -> CapturedHeaders:
        pseudo: Dict[str, str] = {}
        normal: List[Tuple[str, str]] = []
        cookies: List[str] = []
        authority: Optional[str] = None
        
        for k, v in headers:
            k_s = k.decode('utf-8') if isinstance(k, bytes) else k
            v_s = v.decode('utf-8') if isinstance(v, bytes) else v
            
            if k_s.lower() == 'host' and not authority: 
                authority = v_s
            if k_s.lower() in H2_FORBIDDEN_HEADERS: 
                continue 
            
            if k_s.startswith(':'):
                pseudo[k_s] = v_s
                if k_s == ':authority': 
                    authority = v_s
            elif k_s.lower() == 'cookie': 
                cookies.append(v_s)
            else: 
                normal.append((k_s, v_s))
                
        if cookies: 
            normal.append(('cookie', '; '.join(cookies)))
        if ':authority' not in pseudo and authority: 
            pseudo[':authority'] = authority
            
        return cast(CapturedHeaders, {"pseudo": pseudo, "headers": normal})
    
    def _wrap_security(self, headers: List[Tuple[bytes, bytes]]) -> List[Tuple[bytes, bytes]]:
        if not hpack: 
            return headers
        return [
            hpack.NeverIndexedHeaderTuple(k, v) if k.lower() in SENSITIVE_HEADERS_BYTES else (k, v) 
            for k, v in headers
        ]
    
    async def handle_downstream_event(self, event: Any) -> None:
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
                        ctx.upstream_queue.put_nowait((event.data, False, event.flow_controlled_length))
                    except asyncio.QueueFull: 
                        self._cleanup_stream(event.stream_id, force_close=True)
        elif isinstance(event, TrailersReceived):
            if event.stream_id in self.streams and self.enable_tunneling:
                try:
                    h, _ = self._prepare_forwarded_headers(event.headers, True)
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
    
    async def handle_upstream_event(self, event: Any) -> None:
        if isinstance(event, ResponseReceived):
            if event.stream_id in self.streams:
                h, _ = self._prepare_forwarded_headers(event.headers, False)
                self.streams[event.stream_id].downstream_queue.put_nowait((h, event.stream_ended, 0))
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
                     self.streams[event.stream_id].downstream_queue.put_nowait((h, event.stream_ended, 0))
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
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, False)
    
    async def handle_window_updated(self, event: Any, direction: str) -> None:
        sid = event.stream_id
        snapshot = list(self.streams.values())
        if sid == 0:
            for ctx in snapshot: 
                (ctx.upstream_flow_event if direction == 'upstream' else ctx.downstream_flow_event).set()
        elif sid in self.streams:
            ctx = self.streams[sid]
            (ctx.upstream_flow_event if direction == 'upstream' else ctx.downstream_flow_event).set()
    
    def finalize_capture(self, ctx: StreamContext) -> None:
        if ctx.capture_finalized: 
            return
        ctx.capture_finalized = True
        pseudo = ctx.captured_headers["pseudo"]
        try:
            if self.target_override: 
                url = urljoin(self.target_override, pseudo.get(':path', '/').lstrip('/'))
            else: 
                url = urlunparse((ctx.scheme, pseudo.get(':authority', self.explicit_host), pseudo.get(':path', '/'), '', '', ''))
        except Exception: # pylint: disable=broad-exception-caught
            return
            
        captured = CapturedRequest(
            0, pseudo.get(':method', 'GET'), url, ctx.captured_headers["headers"], 
            b"".join(ctx.request_body_chunks), ctx.truncated, "HTTP/2", None, 
            ctx.start_time, time.time(), ctx.client_addr, (self.upstream_host, self.upstream_port)
        )
        self.log("CAPTURE", captured)
    
    async def _monitor_shutdown(self) -> None:
        await self.closed.wait()
        for ctx in list(self.streams.values()): 
            ctx.upstream_queue.put_nowait(None)
            ctx.downstream_queue.put_nowait(None)
    
    async def _keepalive_loop(self) -> None:
        while not self.closed.is_set():
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if self.upstream_conn and self.upstream_protocol == "h2":
                async with self.us_h2_lock:
                    try: 
                        self.upstream_conn.ping(b'KeepAliv')
                    except Exception: 
                        break
                await self.flush(self.upstream_conn, self.upstream_writer, self.us_h2_lock, self.us_socket_lock)
            
            async with self.ds_h2_lock:
                try: 
                    self.downstream_conn.ping(b'KeepAliv')
                except Exception: 
                    break
            await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock)
    
    async def cleanup(self) -> None:
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
        self.closed.set()
        async with self.ds_h2_lock:
            try: 
                self.downstream_conn.close_connection(code)
            except Exception: # pylint: disable=broad-exception-caught
                pass
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, True)
    
    async def graceful_shutdown(self) -> None:
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
        await self.flush(self.downstream_conn, self.client_writer, self.ds_h2_lock, self.ds_socket_lock, True)
    
    async def flush(self, conn: H2Connection, writer: asyncio.StreamWriter, 
                    h2_lock: asyncio.Lock, socket_lock: asyncio.Lock, drain: bool = False) -> None:
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
    
    def _cleanup_stream(self, stream_id: int, downstream_closed: bool = False, 
                        upstream_closed: bool = False, force_close: bool = False) -> None:
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

class DualProtocolHandler:
    """Detects protocol (HTTP/1.1 vs HTTP/2) and delegates."""
    __slots__ = (
        'reader', 'writer', 'explicit_host', 'callback', 'target_override', 
        'scope_pattern', 'enable_tunneling', 'upstream_verify_ssl', 
        'upstream_ca_bundle', 'ssl_context_factory', 'strict_mode', 'initial_data'
    )
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                 explicit_host: str, manager_callback: Callable, target_override: Optional[str], 
                 scope_pattern: Optional[re.Pattern], enable_tunneling: bool = True, 
                 upstream_verify_ssl: bool = False, upstream_ca_bundle: Optional[str] = None, 
                 ssl_context_factory: Optional[Callable] = None, strict_mode: bool = True, 
                 initial_data: bytes = b"") -> None:
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
        self.initial_data = initial_data
    
    async def run(self) -> None:
        protocol, initial_data = await self._detect_protocol()
        if protocol == "h2": 
            await NativeProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback, 
                self.target_override, self.scope_pattern, self.enable_tunneling, 
                self.upstream_verify_ssl, self.upstream_ca_bundle, 
                id_bytes=initial_data, ssf=self.ssl_context_factory
            ).run()
        else: 
            await Http11ProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback, 
                self.target_override, self.scope_pattern, self.upstream_verify_ssl, 
                self.upstream_ca_bundle, initial_data=initial_data, 
                ssl_context_factory=self.ssl_context_factory, 
                enable_tunneling=self.enable_tunneling, strict_mode=self.strict_mode
            ).run()
    
    async def _detect_protocol(self) -> Tuple[str, bytes]:
        try:
            ssl_obj = self.writer.get_extra_info('ssl_object')
            if ssl_obj:
                alpn = ssl_obj.selected_alpn_protocol()
                if alpn == "h2": 
                    return "h2", b""
                if alpn == "http/1.1": 
                    return "http/1.1", b""
            
            buffer = bytearray(self.initial_data)
            required = len(H2_PREFACE)
            for _ in range(5):
                if len(buffer) >= required: 
                    break
                try:
                    chunk = await asyncio.wait_for(self.reader.read(required - len(buffer)), timeout=0.5)
                    if not chunk: 
                        break
                    buffer.extend(chunk)
                    if len(buffer) >= 4 and not buffer.startswith(b'PRI '): 
                        return "http/1.1", bytes(buffer)
                except asyncio.TimeoutError: 
                    break
            
            data = bytes(buffer)
            if data.startswith(H2_PREFACE[:4]):
                if len(data) == required and data == H2_PREFACE: 
                    return "h2", data
                if b'HTTP/2.0' in data: 
                    return "h2", data
            return "http/1.1", data
        except Exception: # pylint: disable=broad-exception-caught
            return "http/1.1", self.initial_data

async def start_proxy_server(host: str, port: int, manager_callback: Callable, 
                             target_override: Optional[str] = None, 
                             scope_pattern: Optional[re.Pattern] = None, 
                             ssl_context_factory: Optional[Callable] = None, 
                             strict_mode: bool = True) -> Any:
    """
    Starts the TCP server on the given host/port and handles incoming connections.
    """
    async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await DualProtocolHandler(
            r, w, "", manager_callback, target_override, scope_pattern, 
            ssl_context_factory=ssl_context_factory, strict_mode=strict_mode
        ).run()
        
    server = await asyncio.start_server(_handle, host, port)
    manager_callback("SYSTEM", f"Transparent Proxy (H1/H2) listening on {host}:{port}")
    
    async with server:
        try: 
            await server.serve_forever()
        except asyncio.CancelledError: 
            pass
        finally:
            manager_callback("SYSTEM", "Proxy stopped")
            server.close()
            await server.wait_closed()
    return server
    