# low_level.py
"""
LOW LEVEL H2 ENGINE
Direct socket manipulation for HTTP/2 race conditions (SPA).
Uses slots for stream context to handle high concurrency.
"""

import socket
import ssl
import time
import threading
import selectors
import hashlib
import logging
import sys
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple, Any, Union

# -- Dependency Management --
try:
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, HOP_BY_HOP_HEADERS
except ImportError:
    # Fallback definitions for standalone testing if structures.py is missing
    HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade', 'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection', 'content-length'
    ]
    MAX_RESPONSE_BODY_READ = 1024 * 1024  # 1MB default

    class ScanResult:
        __slots__ = ('index', 'status_code', 'duration', 'body_hash', 'body_snippet', 'error')
        def __init__(self, index, status_code, duration, body_hash=None, body_snippet=None, error=None):
            self.index = index
            self.status_code = status_code
            self.duration = duration
            self.body_hash = body_hash
            self.body_snippet = body_snippet
            self.error = error

    class CapturedRequest:
        __slots__ = ('id', 'method', 'url', 'headers', 'body', 'truncated', 'protocol', 'edited_body')
        def __init__(self, id, method, url, headers, body, truncated=False, protocol="HTTP/1.1", edited_body=None):
            self.id = id
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body
            self.truncated = truncated
            self.protocol = protocol
            self.edited_body = edited_body

        def get_attack_payload(self):
            return self.edited_body if self.edited_body is not None else self.body

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset
except ImportError:
    if 'unittest' not in sys.modules:
        raise ImportError("Dependencies missing: pip install h2")
    # Define None for optional typing to allow class definition without crashing
    H2Connection = None
    H2Configuration = None
    ResponseReceived = None
    DataReceived = None
    StreamEnded = None
    StreamReset = None

try:
    from packet_controller import PacketController, NFQUEUE_AVAILABLE
except ImportError:
    PacketController = None
    NFQUEUE_AVAILABLE = False

logger = logging.getLogger(__name__)

class StreamContext:
    """
    Lightweight slot-based class to track stream state.
    Significantly reduces memory overhead compared to using a dict for every stream.
    """
    __slots__ = ('stream_id', 'index', 'body', 'finished', 'headers', 'start_time', 'end_time', 'error')

    def __init__(self, stream_id: int, index: int):
        """
        Initializes the StreamContext.

        Args:
            stream_id (int): The HTTP/2 stream identifier.
            index (int): The index of this request in the batch.
        """
        self.stream_id = stream_id
        self.index = index
        self.body = bytearray()
        self.finished = False
        # Headers can be bytes (from h2) or strings (if manually set), so we use Union
        self.headers = []
        self.start_time = 0.0
        self.end_time = 0.0
        # Error can be a string message or an Exception object
        self.error: Optional[Any] = None

class HTTP2RaceEngine:
    """
    Direct socket manipulation for HTTP/2 race conditions (SPA).
    """
    def __init__(self, request: CapturedRequest, concurrency: int, strategy="spa"):
        """
        Initializes the HTTP2RaceEngine.

        Args:
            request (CapturedRequest): The request to attack with.
            concurrency (int): The number of concurrent requests.
            strategy (str): The attack strategy ('spa' or 'first-seq').
        """
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.target_host: Optional[str] = None
        self.target_port = 443
        self.conn: Optional[H2Connection] = None
        self.sock: Optional[ssl.SSLSocket] = None
        self.streams: Dict[int, StreamContext] = {}
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self._parse_target()

    def _parse_target(self):
        """
        Parses the target host and port from the URL.
        Includes aggressive fallback to Host header if URL is relative.
        """
        p = urlparse(self.request.url)
        
        # Determine scheme/port defaults
        scheme = p.scheme or 'https'  # Default to https if missing in relative URL
        default_port = 80 if scheme == 'http' else 443

        if p.hostname:
            self.target_host = p.hostname
            self.target_port = p.port or default_port
        else:
            # Fallback: If URL is relative (e.g., "v1/api"), look for Host header
            headers = self.request.headers
            # Handle list of tuples or dict
            if isinstance(headers, dict):
                headers_iter = headers.items()
            else:
                headers_iter = headers
            
            found_host = False
            for k, v in headers_iter:
                # Robust check for bytes or str keys
                k_str = k.decode('utf-8') if isinstance(k, bytes) else str(k)
                if k_str.lower() == 'host':
                    found_host = True
                    v_str = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                    # Parse host:port
                    if ':' in v_str:
                        host_part, port_part = v_str.rsplit(':', 1)
                        self.target_host = host_part
                        try:
                            self.target_port = int(port_part)
                        except ValueError:
                            self.target_port = default_port
                    else:
                        self.target_host = v_str
                        self.target_port = default_port
                    break
            
            if not found_host:
                # If we absolutely cannot find a host, we can't run.
                # Leave self.target_host as None, run_attack will handle the error.
                pass

    def connect(self):
        """
        Establishes the SSL/TLS connection and performs H2 handshake.
        Includes socket tuning for race condition performance.

        Raises:
            ValueError: If the target host cannot be determined.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Intentional: Tool is used against various targets
        ctx.set_alpn_protocols(["h2"])
        
        if not self.target_host:
            raise ValueError(f"Target host could not be determined from URL ({self.request.url}) or Headers")

        ip = socket.gethostbyname(self.target_host)
        raw = socket.create_connection((ip, self.target_port), timeout=10)
        
        # Socket Tuning
        # Disable Nagle's algorithm for precise timing
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Increase Send/Recv buffers to minimize syscall blocking during race burst
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except OSError:
            pass

        self.sock = ctx.wrap_socket(raw, server_hostname=self.target_host)
        
        # Lazy Decoding Optimization
        # header_encoding=None tells h2 to return bytes.
        # This prevents the receiver thread from burning CPU decoding headers 
        # inside the lock. We decode later in _finalize.
        config = H2Configuration(client_side=True, header_encoding=None)
        self.conn = H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def _build_headers(self, cl: int) -> List[Tuple[Union[str, bytes], Union[str, bytes]]]:
        """
        Builds the HTTP/2 headers for the request.

        Args:
            cl (int): The content length of the request body.

        Returns:
            List[Tuple[Union[str, bytes], Union[str, bytes]]]: A list of header tuples.
        """
        p = urlparse(self.request.url)
        path = p.path
        
        # If path is empty because it's relative, ensure we start with / or use the raw url
        if not path:
             if self.request.url and not self.request.url.startswith('http'):
                 path = '/' + self.request.url.lstrip('/')
             else:
                 path = '/'
        
        # [FIX] Ensure path starts with slash for H2 compliance (fixes relative URL test)
        if not path.startswith('/'):
            path = '/' + path

        if p.query:
            path += '?' + p.query
        
        authority = self.target_host or ""
        # RFC compliance: Authority usually shouldn't contain default ports, but 
        # for hacking tools, being explicit is often safer unless it breaks WAFs.
        # We will append port if it's non-standard.
        if self.target_port not in (80, 443) and self.target_port is not None:
            if ':' not in authority:
                authority += f":{self.target_port}"

        headers: List[Tuple[Union[str, bytes], Union[str, bytes]]] = [
            (':method', self.request.method),
            (':authority', authority),
            (':scheme', 'https'),
            (':path', path),
        ]
        
        req_headers_iter = self.request.headers
        if isinstance(req_headers_iter, dict):
            req_headers_iter = req_headers_iter.items()

        for k, v in req_headers_iter:
            k_lower = k.lower()
            if k_lower not in HOP_BY_HOP_HEADERS and not k.startswith(':'):
                headers.append((k_lower, v))
        
        if cl > 0:
            headers.append(('content-length', str(cl)))
        
        # Ensure content-type if missing and body exists
        has_ct = any(k.lower() == 'content-type' for k, v in headers)
        if cl > 0 and not has_ct:
             headers.append(('content-type', 'application/x-www-form-urlencoded'))

        return headers

    def run_attack(self) -> List[ScanResult]:
        """
        Executes the HTTP/2 race attack.

        Connects to the target, sets up streams, sends headers and partial body,
        and then triggers the race by sending the final byte for all streams.

        Returns:
            List[ScanResult]: A list of results for each stream.
        """
        pc = None
        try:
            self.connect()
            
            # Setup PacketController for First-Seq strategy
            if self.strategy == "first-seq" and PacketController and NFQUEUE_AVAILABLE and self.target_host:
                local_port = self.sock.getsockname()[1]
                target_ip = socket.gethostbyname(self.target_host)
                pc = PacketController(target_ip, self.target_port, local_port)
                pc.start()

            # Start receiver thread
            threading.Thread(target=self._recv, daemon=True).start()
            
            payload = self.request.get_attack_payload()
            # Handle string payloads gracefully if needed
            if isinstance(payload, str):
                payload = payload.encode('utf-8')

            partial = payload[:-1] if payload else b""
            final = payload[-1:] if payload else b""
            
            headers = self._build_headers(len(payload))
            
            # -- Prepare Phase: Send headers + partial body --
            with self.lock:
                for i in range(self.concurrency):
                    sid = self.conn.get_next_available_stream_id()
                    self.streams[sid] = StreamContext(sid, i)
                    
                    # Send headers
                    self.conn.send_headers(sid, headers, end_stream=(not payload))
                    
                    # Send partial body if exists
                    if partial:
                        self.conn.send_data(sid, partial, end_stream=False)
            
            self.sock.sendall(self.conn.data_to_send())
            time.sleep(0.1) # Stabilization wait to allow frames to settle
            
            # -- Trigger Phase (SPA): Send final byte for all streams in one packet --
            t0 = time.perf_counter()
            with self.lock:
                for sid in self.streams:
                    self.streams[sid].start_time = t0
                    if final:
                        self.conn.send_data(sid, final, end_stream=True)
                
                trigger_data = self.conn.data_to_send()
            
            if trigger_data:
                self.sock.sendall(trigger_data)
            
            # Wait for results
            self.finished.wait(timeout=10)
            return self._finalize()

        except Exception as e:
            logger.error(f"Attack failed: {e}")
            return [ScanResult(i, 0, 0, error=str(e)) for i in range(self.concurrency)]
        finally:
            self.finished.set() # Ensure we always unblock tests
            if pc:
                pc.stop()
            if self.sock: 
                try:
                    self.sock.close()
                except (OSError, AttributeError):
                    pass

    def _process_events(self, events: List[Any]):
        """
        Processes H2 events and updates stream state.
        Separated from _recv to allow isolated unit testing (resolves Ghost Methods).

        Args:
            events (List[Any]): A list of h2 events to process.
        """
        for e in events:
            if isinstance(e, (StreamEnded, StreamReset)):
                if hasattr(e, 'stream_id') and e.stream_id in self.streams:
                    s = self.streams[e.stream_id]
                    s.end_time = time.perf_counter()
                    s.finished = True
            
            elif isinstance(e, ResponseReceived):
                if e.stream_id in self.streams:
                    # Just store bytes, decode later
                    self.streams[e.stream_id].headers = e.headers
            
            elif isinstance(e, DataReceived):
                if e.stream_id in self.streams:
                    self.streams[e.stream_id].body.extend(e.data)
                    self.conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)

        # Check termination condition
        if self.streams and all(s.finished for s in self.streams.values()):
            self.finished.set()

    def _recv(self):
        """
        Continuously reads from the socket and updates h2 state.
        OPTIMIZATION: Uses selectors for efficient I/O waiting.
        """
        if not self.sock:
            self.finished.set()
            return

        sel = selectors.DefaultSelector()
        try:
            sel.register(self.sock, selectors.EVENT_READ)
            
            while not self.finished.is_set():
                try:
                    if not self.sock:
                        break
                    
                    if not sel.select(0.1):
                        continue
                        
                    data = self.sock.recv(65536)
                    if not data:
                        # [FIX] Handle server disconnect gracefully
                        break
                    
                    with self.lock:
                        events: List[Any] = self.conn.receive_data(data)
                        self._process_events(events)
                        out = self.conn.data_to_send()
                    
                    if out:
                        self.sock.sendall(out)
                    
                    # Check termination condition
                    if self.streams and all(s.finished for s in self.streams.values()):
                        self.finished.set()

                except Exception:
                    break
        except Exception:
             pass
        finally:
            try:
                sel.close()
            except Exception:
                pass
            self.finished.set()

    def _finalize(self) -> List[ScanResult]:
        """
        Compiles results from the StreamContext objects.
        This runs off the hot-path, so we can do our decoding and hashing here.

        Returns:
            List[ScanResult]: The finalized results of the race.
        """
        res = []
        # Sort by index to maintain logical order of race attempts
        sorted_streams = sorted(self.streams.values(), key=lambda x: x.index)
        
        for s in sorted_streams:
            status = 0
            # Decode Status Code from raw bytes
            for k, v in s.headers:
                # Handle bytes vs string comparison if necessary, though h2 usually returns bytes here
                if k == b':status' or k == ':status': 
                    try:
                        # Ensure v is decoded if it's bytes
                        val_str = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                        status = int(val_str)
                    except ValueError:
                        pass
                    break
            
            dur = 0.0
            if s.end_time > 0:
                dur = (s.end_time - s.start_time) * 1000
            
            # Handle Body Truncation & Hashing
            b = s.body[:MAX_RESPONSE_BODY_READ]
            h = hashlib.sha256(b).hexdigest() if b else None
            snippet = b[:100].decode('utf-8', errors='ignore').replace('\n', ' ')
            
            res.append(ScanResult(s.index, status, dur, h, snippet, s.error))
            
        return res
