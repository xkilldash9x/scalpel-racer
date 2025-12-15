# low_level.py
"""
Implements the Low-Level HTTP/2 Race Engine.
Uses raw sockets and hyper-h2 for frame-level control (SPA).
"""

import socket
import ssl
import time
import threading
import select
import hashlib
import sys
import logging
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Any

# -- Dependency Management --
try:
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, HOP_BY_HOP_HEADERS
except ImportError:
    HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host', 'accept-encoding', 'upgrade-insecure-requests',
        'proxy-connection', 'content-length'
    ]

    class ScanResult:
        def __init__(self, index, status_code, duration, body_hash=None, body_snippet=None, error=None):
            self.index = index
            self.status_code = status_code
            self.duration = duration
            self.body_hash = body_hash
            self.error = error

    class CapturedRequest:
        def __init__(self, id, method, url, headers, body):
            self.id = id
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body

        def get_attack_payload(self):
            return self.body if isinstance(self.body, bytes) else self.body.encode('utf-8')

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset
except ImportError:
    if 'unittest' not in sys.modules:
        raise ImportError("The 'h2' library is required.")

try:
    from packet_controller import PacketController, NFQUEUE_AVAILABLE
except ImportError:
    PacketController = None
    NFQUEUE_AVAILABLE = False

logger = logging.getLogger(__name__)


class HTTP2RaceEngine:
    def __init__(self, request: CapturedRequest, concurrency: int, strategy="spa", warmup_ms=100):
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.warmup_ms = warmup_ms
        self.target_host = None
        self.target_port = 443
        self.target_ip = None
        self.conn = None
        self.sock = None
        self.streams = {}
        # Optimization: Track active streams to avoid O(N) check in _process
        self.active_streams_count = 0 
        self.lock = threading.Lock()
        self.all_streams_finished = threading.Event()
        self._parse_target()

    def _parse_target(self):
        """
        Parses the target host and port from the URL.
        Falls back to the 'Host' or ':authority' header if the URL is relative.
        """
        parsed = urlparse(self.request.url)
        self.target_host = parsed.hostname
        self.target_port = parsed.port

        # Fallback: If URL is relative (no hostname), try to find Host in headers
        if not self.target_host:
            host_header_val = None
            headers_iter = self.request.headers
            if isinstance(headers_iter, dict):
                headers_iter = headers_iter.items()
            
            for k, v in headers_iter:
                if k.lower() in ('host', ':authority'):
                    host_header_val = v
                    break
            
            if host_header_val:
                # Use urlparse with dummy scheme to safely parse host:port and ipv6
                # Prepending // forces urlparse to treat it as netloc
                try:
                    p2 = urlparse(f"//{host_header_val}")
                    self.target_host = p2.hostname
                    self.target_port = p2.port
                except ValueError:
                    pass
        
        # Default Port Logic
        if not self.target_port:
            self.target_port = 80 if parsed.scheme == 'http' else 443

    def _construct_h2_headers(self, content_length: int) -> List[Tuple[str, str]]:
        parsed = urlparse(self.request.url)
        
        # Ensure path starts with / (fixes relative URL issues)
        path = parsed.path or '/'
        if not path.startswith('/'):
            path = '/' + path
            
        if parsed.query:
            path += '?' + parsed.query
        
        authority = self.target_host
        if self.target_port not in (80, 443) and self.target_port is not None:
            authority += f":{self.target_port}"
        
        headers = [
            (':method', self.request.method),
            (':authority', authority),
            (':scheme', 'https'),
            (':path', path),
        ]
        
        req_headers_iter = self.request.headers
        if isinstance(req_headers_iter, dict):
            req_headers_iter = req_headers_iter.items()
        
        header_keys = set()
        for k, v in req_headers_iter:
            k_lower = k.lower()
            if k_lower in HOP_BY_HOP_HEADERS:
                continue
            header_keys.add(k_lower)
            headers.append((k_lower, v))

        # Ensure content-type for methods with bodies if missing
        if 'content-type' not in header_keys and self.request.method in ["POST", "PUT", "PATCH"] and content_length > 0:
            headers.append(('content-type', 'application/x-www-form-urlencoded'))
        
        if content_length > 0:
            headers.append(('content-length', str(content_length)))
        
        if 'user-agent' not in header_keys:
            headers.append(('user-agent', 'Scalpel-CLI/LowLevelH2'))
            
        return headers

    def connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE # Intentional: Tool is used against various targets
        ctx.set_alpn_protocols(["h2"])
        
        # Safety Check: Prevent crash if host could not be determined
        if not self.target_host:
            raise ValueError(f"Target host could not be determined from URL ({self.request.url}) or Headers")

        try:
            self.target_ip = socket.gethostbyname(self.target_host)
        except socket.gaierror as e:
            raise ConnectionError(f"DNS resolution failed for {self.target_host}: {e}")

        raw_sock = socket.create_connection((self.target_ip, self.target_port), timeout=10)
        # Disable Nagle's algorithm for precise timing
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.target_host)
        
        if self.sock.selected_alpn_protocol() != "h2":
            raise ConnectionError("ALPN Negotiation failed: Target does not support h2")
            
        config = H2Configuration(client_side=True, header_encoding='utf-8')
        self.conn = H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def run_attack(self) -> List[ScanResult]:
        packet_controller = None
        try:
            self.connect()
            
            # Setup PacketController for First-Seq strategy
            if self.strategy == "first-seq" and NFQUEUE_AVAILABLE and PacketController:
                local_port = self.sock.getsockname()[1]
                packet_controller = PacketController(self.target_ip, self.target_port, local_port)
                packet_controller.start()

            # Start receiver thread
            t = threading.Thread(target=self._receive_loop, daemon=True)
            t.start()
            
            payload = self.request.get_attack_payload()
            partial = payload[:-1] if payload else b""
            final = payload[-1:] if payload else b""
            
            # -- Prepare Phase --
            self.active_streams_count = 0
            
            for i in range(self.concurrency):
                sid = self.conn.get_next_available_stream_id()
                headers = self._construct_h2_headers(len(payload))
                
                self.conn.send_headers(sid, headers, end_stream=False)
                if partial:
                    self.conn.send_data(sid, partial, end_stream=False)
                
                with self.lock:
                    self.streams[sid] = {
                        "index": i,
                        "body": bytearray(),
                        "finished": False,
                        "headers": {},
                        "error": None
                    }
                    self.active_streams_count += 1
            
            self.sock.sendall(self.conn.data_to_send())
            
            # -- Warmup Phase --
            if self.warmup_ms:
                time.sleep(self.warmup_ms / 1000.0)
            
            # -- Trigger Phase (SPA) --
            start = time.perf_counter()
            for sid in list(self.streams.keys()):
                self.conn.send_data(sid, final, end_stream=True)
                with self.lock:
                    self.streams[sid]["start_time"] = start
            
            self.sock.sendall(self.conn.data_to_send())
            
            # Wait for results
            self.all_streams_finished.wait(timeout=10)
            return self._finalize_results()

        except Exception as e:
            logger.error(f"Attack failed: {e}")
            return [ScanResult(i, 0, 0, error=str(e)) for i in range(self.concurrency)]
        finally:
            if packet_controller:
                packet_controller.stop()
            if self.sock: 
                try:
                    self.sock.close()
                except (OSError, AttributeError):
                    pass

    def _receive_loop(self):
        """
        Continuously reads from the socket and updates h2 state.
        """
        while not self.all_streams_finished.is_set():
            try:
                if not self.sock:
                    break
                
                ready, _, _ = select.select([self.sock], [], [], 0.1)
                if not ready:
                    continue
                
                data = self.sock.recv(65536)
                if not data:
                    break
                
                events = self.conn.receive_data(data)
                self._process(events)
                
                to_send = self.conn.data_to_send()
                if to_send:
                    self.sock.sendall(to_send)
            except Exception:
                break
        
        self.all_streams_finished.set()

    def _process(self, events):
        """
        Process H2 events and update stream state.
        """
        with self.lock:
            for e in events:
                if not hasattr(e, 'stream_id') or e.stream_id not in self.streams:
                    continue
                
                s = self.streams[e.stream_id]
                
                if isinstance(e, ResponseReceived):
                    for k, v in e.headers:
                        key = k.decode('utf-8') if isinstance(k, bytes) else k
                        val = v.decode('utf-8') if isinstance(v, bytes) else v
                        s["headers"][key] = val
                
                elif isinstance(e, DataReceived):
                    s["body"].extend(e.data)
                    self.conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                
                elif isinstance(e, (StreamEnded, StreamReset)):
                    if not s["finished"]:
                        s["finished"] = True
                        self.active_streams_count -= 1
            
            # Check termination condition efficiently
            if self.active_streams_count <= 0:
                self.all_streams_finished.set()

    def _finalize_results(self):
        res = []
        with self.lock:
            for sid, data in self.streams.items():
                dur = (time.perf_counter() - data.get("start_time", 0)) * 1000
                sc = int(data["headers"].get(":status", 0))
                b = bytes(data["body"])
                h = hashlib.sha256(b).hexdigest() if b else None
                
                res.append(ScanResult(data["index"], sc, dur, h))
        
        return sorted(res, key=lambda x: x.index)