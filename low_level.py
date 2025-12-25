#Filename: low_level.py
"""
LOW LEVEL H2 ENGINE
Direct socket manipulation for HTTP/2 race conditions (SPA).
"""
import socket
import ssl
import time
import threading
import selectors
import logging
import gc
from urllib.parse import urlparse
from typing import List, Dict, Optional, Any

# [APEX] Imports from Foundation & Compat
from structures import ScanResult, CapturedRequest
from compat import (
    H2Connection, H2Configuration, DataReceived, StreamEnded, StreamReset,
    NFQUEUE_AVAILABLE, MockPacketController
)

try:
    from packet_controller import PacketController
except ImportError:
    from compat import MockPacketController as PacketController # type: ignore

logger = logging.getLogger(__name__)
_SSL_CONTEXT_CACHE: Dict[str, ssl.SSLContext] = {}

class StreamContext:
    __slots__ = ('stream_id', 'index', 'body', 'finished', 'headers', 'start_time', 'end_time', 'error')
    
    def __init__(self, stream_id: int, index: int):
        self.stream_id = stream_id
        self.index = index
        self.body = bytearray()
        self.finished = False
        self.headers: List[Any] = []
        self.start_time = 0.0
        self.end_time = 0.0
        self.error: Optional[str] = None

class HTTP2RaceEngine:
    def __init__(
        self, request: CapturedRequest, concurrency: int, strategy: str = "spa", warmup: int = 0
    ):
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.warmup = warmup
        self.target_host: Optional[str] = None
        self.target_port = 443
        self.conn: H2Connection
        self.sock: Optional[ssl.SSLSocket] = None
        self.streams: Dict[int, StreamContext] = {}
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self._parse_target()

    def _parse_target(self) -> None:
        p = urlparse(self.request.url)
        self.target_host = p.hostname
        self.target_port = p.port or (443 if p.scheme != 'http' else 80)

    def connect(self) -> None:
        if "insecure" not in _SSL_CONTEXT_CACHE:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try: 
                ctx.set_alpn_protocols(["h2"])
            except NotImplementedError: 
                pass
            _SSL_CONTEXT_CACHE["insecure"] = ctx
        
        ip = socket.gethostbyname(self.target_host) if self.target_host else "127.0.0.1"
        try:
            raw = socket.create_connection((ip, self.target_port), timeout=10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            self.sock = _SSL_CONTEXT_CACHE["insecure"].wrap_socket(
                raw, server_hostname=self.target_host
            )
            
            self.conn = H2Connection(
                config=H2Configuration(client_side=True, header_encoding=None)
            )
            self.conn.initiate_connection()
            if self.sock: 
                self.sock.sendall(self.conn.data_to_send())
        except Exception as e:
            raise ConnectionError(f"Failed to establish H2 connection to {ip}:{self.target_port}") from e

    def run_attack(self) -> List[ScanResult]:
        pc: Optional[PacketController] = None
        try:
            self.connect()
            if (
                self.strategy == "first-seq" 
                and NFQUEUE_AVAILABLE 
                and PacketController is not MockPacketController 
                and self.target_host 
                and self.sock
            ):
                ip = socket.gethostbyname(self.target_host)
                pc = PacketController(ip, self.target_port, self.sock.getsockname()[1])
                pc.start()

            threading.Thread(target=self._recv, daemon=True).start()
            
            payload = self.request.get_attack_payload()
            if isinstance(payload, str): 
                payload = payload.encode('utf-8')
            
            headers = [
                (b':method', self.request.method.encode()), 
                (b':path', urlparse(self.request.url).path.encode()), 
                (b':scheme', b'https'), 
                (b':authority', self.target_host.encode() if self.target_host else b'')
            ]
            
            with self.lock:
                for i in range(self.concurrency):
                    sid = self.conn.get_next_available_stream_id()
                    self.streams[sid] = StreamContext(sid, i)
                    self.conn.send_headers(sid, headers, end_stream=(not payload))
            
            if self.sock: 
                self.sock.sendall(self.conn.data_to_send())
            
            time.sleep(self.warmup / 1000.0)
            
            gc.disable()
            t0 = time.perf_counter()
            with self.lock:
                for sid in self.streams:
                    self.streams[sid].start_time = t0
                    if payload: 
                        self.conn.send_data(sid, payload, end_stream=True)
                data = self.conn.data_to_send()
            
            if self.sock: 
                self.sock.sendall(data)
            
            self.finished.wait(timeout=10)
            return self._finalize()
        except Exception as e:
            return [
                ScanResult(i, 0, 0.0, error=str(e)) for i in range(self.concurrency)
            ]
        finally:
            gc.enable()
            self.finished.set()
            if pc: 
                pc.stop()
            if self.sock: 
                self.sock.close()

    def _recv(self) -> None:
        if not self.sock:
            return
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ) # type: ignore
        while not self.finished.is_set():
            try:
                if not sel.select(0.1): 
                    continue
                data = self.sock.recv(65536) # type: ignore
                if not data: 
                    break
                with self.lock:
                    events = self.conn.receive_data(data)
                    for e in events:
                        if isinstance(e, (StreamEnded, StreamReset)): 
                            self.streams[e.stream_id].finished = True
                        elif isinstance(e, DataReceived): 
                            self.streams[e.stream_id].body.extend(e.data)
                    if all(s.finished for s in self.streams.values()): 
                        self.finished.set()
            except OSError as e:
                logger.debug("Socket error in _recv: %s", e)
                break
            except Exception as e:
                logger.error("Unexpected error in _recv: %s", e)
                break

    def _finalize(self) -> List[ScanResult]:
        res = []
        for s in sorted(self.streams.values(), key=lambda x: x.index):
            res.append(
                ScanResult(
                    s.index, 
                    200, 
                    (time.perf_counter() - s.start_time) * 1000, 
                    body_snippet=s.body[:50].decode('utf-8', 'ignore')
                )
            )
        return res