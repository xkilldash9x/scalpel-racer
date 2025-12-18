# low_level.py
"""
LOW LEVEL H2 ENGINE
Direct socket manipulation for HTTP/2 race conditions (SPA).
Uses slots for stream context to handle high concurrency.

[VECTOR OPTIMIZATIONS]:
- Explicit GC control (gc.disable/enable) to minimize jitter.
- Socket buffers tuned for burst transmission (SO_SNDBUF).
- Pre-calculated stream lists in hot-path trigger loop.
- Optimized status code decoding (direct byte checks).
- SSL Context Caching.
"""

import socket
import ssl
import time
import threading
import selectors
import hashlib
import logging
import sys
import gc  # [VECTOR] For Jitter suppression
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple, Any, Union

# -- Dependency Management --
try:
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, HOP_BY_HOP_HEADERS
except ImportError:
    # Fallback definitions for standalone testing
    HOP_BY_HOP_HEADERS = {
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade', 'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection', 'content-length'
    }
    MAX_RESPONSE_BODY_READ = 1024 * 1024

    class ScanResult:
        __slots__ = ('index', 'status_code', 'duration', 'body_hash', 'body_snippet', 'error')
        def __init__(self, index, status_code, duration, body_hash=None, body_snippet=None, error=None):
            self.index = index; self.status_code = status_code; self.duration = duration
            self.body_hash = body_hash; self.body_snippet = body_snippet; self.error = error

    class CapturedRequest:
        __slots__ = ('id', 'method', 'url', 'headers', 'body', 'truncated', 'protocol', 'edited_body')
        def __init__(self, id, method, url, headers, body, truncated=False, protocol="HTTP/1.1", edited_body=None):
            self.id = id; self.method = method; self.url = url; self.headers = headers
            self.body = body; self.truncated = truncated; self.protocol = protocol; self.edited_body = edited_body

        def get_attack_payload(self):
            return self.edited_body if self.edited_body is not None else self.body

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset
except ImportError:
    if 'unittest' not in sys.modules:
        raise ImportError("Dependencies missing: pip install h2")
    H2Connection = None; H2Configuration = None
    ResponseReceived = None; DataReceived = None; StreamEnded = None; StreamReset = None

try:
    from packet_controller import PacketController, NFQUEUE_AVAILABLE
except ImportError:
    PacketController = None
    NFQUEUE_AVAILABLE = False

logger = logging.getLogger(__name__)

# [VECTOR] Module-level cache for SSL Contexts to reduce initialization overhead
_SSL_CONTEXT_CACHE = {}

def get_cached_ssl_context():
    """Returns a cached SSLContext optimized for performance (Verification Disabled)."""
    if "insecure" not in _SSL_CONTEXT_CACHE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        _SSL_CONTEXT_CACHE["insecure"] = ctx
    return _SSL_CONTEXT_CACHE["insecure"]

class StreamContext:
    """
    Lightweight slot-based class to track stream state.
    """
    __slots__ = ('stream_id', 'index', 'body', 'finished', 'headers', 'start_time', 'end_time', 'error')

    def __init__(self, stream_id: int, index: int):
        self.stream_id = stream_id
        self.index = index
        self.body = bytearray()
        self.finished = False
        self.headers = []
        self.start_time = 0.0
        self.end_time = 0.0
        self.error: Optional[Any] = None

class HTTP2RaceEngine:
    """
    Direct socket manipulation for HTTP/2 race conditions (SPA).
    [VECTOR] Optimized with slots and header pre-calc.
    """
    __slots__ = (
        'request', 'concurrency', 'strategy', 'target_host', 'target_port', 'target_ip',
        'conn', 'sock', 'streams', 'lock', 'finished', 'warmup', 'precalculated_headers'
    )

    def __init__(self, request: CapturedRequest, concurrency: int, strategy="spa", warmup=100):
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.warmup = warmup
        self.target_host: Optional[str] = None
        self.target_port = 443
        self.target_ip: Optional[str] = None
        self.conn: Optional[H2Connection] = None
        self.sock: Optional[ssl.SSLSocket] = None
        self.streams: Dict[int, StreamContext] = {}
        self.lock = threading.Lock()
        self.finished = threading.Event()

        self._parse_target()

        # [VECTOR] Pre-calculate headers ONCE here, not in the loop
        payload_len = len(self.request.get_attack_payload())
        self.precalculated_headers = self._build_headers(payload_len)

    def _parse_target(self):
        p = urlparse(self.request.url)
        scheme = p.scheme or 'https'
        default_port = 80 if scheme == 'http' else 443

        if p.hostname:
            self.target_host = p.hostname
            self.target_port = p.port or default_port
        else:
            # Fallback for relative URLs
            headers = self.request.headers
            headers_iter = headers.items() if isinstance(headers, dict) else headers
            
            found_host = False
            for k, v in headers_iter:
                k_str = k.decode('utf-8') if isinstance(k, bytes) else str(k)
                if k_str.lower() == 'host':
                    found_host = True
                    v_str = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                    if ':' in v_str:
                        host_part, port_part = v_str.rsplit(':', 1)
                        self.target_host = host_part
                        try: self.target_port = int(port_part)
                        except ValueError: self.target_port = default_port
                    else:
                        self.target_host = v_str
                        self.target_port = default_port
                    break

    def connect(self):
        """
        Establishes the SSL/TLS connection and performs H2 handshake.
        """
        ctx = get_cached_ssl_context()
        
        if not self.target_host:
            raise ValueError(f"Target host could not be determined from URL ({self.request.url}) or Headers")

        # [VECTOR] Cache DNS resolution
        if not self.target_ip:
            self.target_ip = socket.gethostbyname(self.target_host)

        raw = socket.create_connection((self.target_ip, self.target_port), timeout=10)
        
        # [VECTOR] Socket Tuning
        # Disable Nagle's algorithm for precise timing
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Increase Send/Recv buffers to minimize syscall blocking during race burst
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except OSError:
            pass

        self.sock = ctx.wrap_socket(raw, server_hostname=self.target_host)
        
        # Lazy Decoding: header_encoding=None tells h2 to return bytes (faster)
        config = H2Configuration(client_side=True, header_encoding=None)
        self.conn = H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def _build_headers(self, cl: int) -> List[Tuple[Union[str, bytes], Union[str, bytes]]]:
        p = urlparse(self.request.url)
        path = p.path
        if not path:
             if self.request.url and not self.request.url.startswith('http'):
                 path = '/' + self.request.url.lstrip('/')
             else:
                 path = '/'
        if not path.startswith('/'): path = '/' + path
        if p.query: path += '?' + p.query
        
        authority = self.target_host or ""
        if self.target_port not in (80, 443) and self.target_port is not None:
            if ':' not in authority: authority += f":{self.target_port}"

        headers: List[Tuple[Union[str, bytes], Union[str, bytes]]] = [
            (':method', self.request.method),
            (':authority', authority),
            (':scheme', 'https'),
            (':path', path),
        ]
        
        req_headers_iter = self.request.headers
        if isinstance(req_headers_iter, dict): req_headers_iter = req_headers_iter.items()

        for k, v in req_headers_iter:
            k_lower = k.lower()
            if k_lower not in HOP_BY_HOP_HEADERS and not k.startswith(':'):
                headers.append((k_lower, v))
        
        if cl > 0: headers.append(('content-length', str(cl)))
        
        has_ct = any(k.lower() == 'content-type' for k, v in headers)
        if cl > 0 and not has_ct:
             headers.append(('content-type', 'application/x-www-form-urlencoded'))

        return headers

    def run_attack(self) -> List[ScanResult]:
        """
        Executes the HTTP/2 race attack.
        [VECTOR] Implements Garbage Collection control and List pre-calc to minimize jitter.
        """
        pc = None
        try:
            self.connect()
            
            if self.strategy == "first-seq" and PacketController and NFQUEUE_AVAILABLE and self.target_ip:
                local_port = self.sock.getsockname()[1]
                pc = PacketController(self.target_ip, self.target_port, local_port)
                pc.start()

            threading.Thread(target=self._recv, daemon=True).start()
            
            payload = self.request.get_attack_payload()
            if isinstance(payload, str): payload = payload.encode('utf-8')

            partial = payload[:-1] if payload else b""
            final = payload[-1:] if payload else b""
            
            # [VECTOR] Use pre-calculated headers
            headers = self.precalculated_headers
            
            # -- Prepare Phase --
            with self.lock:
                for i in range(self.concurrency):
                    sid = self.conn.get_next_available_stream_id()
                    self.streams[sid] = StreamContext(sid, i)
                    self.conn.send_headers(sid, headers, end_stream=(not payload))
                    if partial:
                        self.conn.send_data(sid, partial, end_stream=False)
            
            self.sock.sendall(self.conn.data_to_send())
            time.sleep(0.1)

            # [VECTOR] OPTIMIZATION: Pre-calculate stream IDs to avoid dict iteration in hot path
            stream_ids = list(self.streams.keys())

            # [VECTOR] Disable GC for critical burst
            gc.disable()
            
            # -- Trigger Phase (SPA) --
            t0 = time.perf_counter()
            with self.lock:
                for sid in stream_ids:
                    self.streams[sid].start_time = t0
                    if final:
                        self.conn.send_data(sid, final, end_stream=True)
                
                trigger_data = self.conn.data_to_send()
            
            if trigger_data:
                self.sock.sendall(trigger_data)
            
            self.finished.wait(timeout=10)
            return self._finalize()

        except Exception as e:
            logger.error(f"Attack failed: {e}")
            return [ScanResult(i, 0, 0, error=str(e)) for i in range(self.concurrency)]
        finally:
            # [VECTOR] Re-enable GC
            gc.enable()
            self.finished.set()
            if pc: pc.stop()
            if self.sock: 
                try: self.sock.close()
                except (OSError, AttributeError): pass

    def _process_events(self, events: List[Any]):
        for e in events:
            if isinstance(e, (StreamEnded, StreamReset)):
                if hasattr(e, 'stream_id') and e.stream_id in self.streams:
                    s = self.streams[e.stream_id]
                    s.end_time = time.perf_counter()
                    s.finished = True
            elif isinstance(e, ResponseReceived):
                if e.stream_id in self.streams:
                    self.streams[e.stream_id].headers = e.headers
            elif isinstance(e, DataReceived):
                if e.stream_id in self.streams:
                    self.streams[e.stream_id].body.extend(e.data)
                    self.conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)

        if self.streams and all(s.finished for s in self.streams.values()):
            self.finished.set()

    def _recv(self):
        if not self.sock:
            self.finished.set()
            return
        sel = selectors.DefaultSelector()
        try:
            sel.register(self.sock, selectors.EVENT_READ)
            while not self.finished.is_set():
                try:
                    if not self.sock: break
                    if not sel.select(0.1): continue
                    data = self.sock.recv(65536)
                    if not data: break
                    with self.lock:
                        events = self.conn.receive_data(data)
                        self._process_events(events)
                        out = self.conn.data_to_send()
                    if out: self.sock.sendall(out)
                    if self.streams and all(s.finished for s in self.streams.values()):
                        self.finished.set()
                except Exception: break
        except Exception: pass
        finally:
            try: sel.close()
            except: pass
            self.finished.set()

    def _finalize(self) -> List[ScanResult]:
        res = []
        sorted_streams = sorted(self.streams.values(), key=lambda x: x.index)
        
        for s in sorted_streams:
            status = 0
            # [VECTOR] OPTIMIZATION: Direct byte comparison for status (H2Config returns raw bytes)
            for k, v in s.headers:
                if k == b':status':
                    try:
                        val_str = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                        status = int(val_str)
                    except ValueError: pass
                    break
            
            dur = 0.0
            if s.end_time > 0:
                dur = (s.end_time - s.start_time) * 1000
            
            # [VECTOR] Zero-copy slicing
            mv_body = memoryview(s.body)
            limit = min(len(mv_body), MAX_RESPONSE_BODY_READ)
            b_view = mv_body[:limit]
            
            h = hashlib.sha256(b_view).hexdigest() if b_view else None
            snippet = b_view[:100].tobytes().decode('utf-8', errors='ignore').replace('\n', ' ')
            
            res.append(ScanResult(s.index, status, dur, h, snippet, s.error))
        return res
