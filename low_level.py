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
import hashlib
from urllib.parse import urlparse
from typing import List, Dict, Optional, Any, Tuple

# [APEX] Imports from Foundation & Compat
from structures import ScanResult, CapturedRequest
from compat import (
    H2Connection, H2Configuration, DataReceived, StreamEnded, StreamReset,
    ResponseReceived, NFQUEUE_AVAILABLE, MockPacketController
)

try:
    from packet_controller import PacketController
except ImportError:
    PacketController = MockPacketController  # type: ignore

logger = logging.getLogger(__name__)
_SSL_CONTEXT_CACHE: Dict[str, ssl.SSLContext] = {}


class StreamContext:
    """
    Maintains state for a single HTTP/2 stream.
    """
    __slots__ = (
        'stream_id', 'index', 'body', 'finished', 'headers',
        'start_time', 'end_time', 'error'
    )

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
    """
    Engine to execute HTTP/2 race condition attacks.
    """
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
        """Parses the target URL to extract host and port."""
        p = urlparse(self.request.url)
        self.target_host = p.hostname
        self.target_port = p.port or (443 if p.scheme != 'http' else 80)

        if not self.target_host:
            # Fallback to Host header
            for k, v in self.request.headers:
                if k.lower() == 'host':
                    # Handle host:port
                    if ':' in v and not v.strip().startswith('['):
                        parts = v.rsplit(':', 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            self.target_host = parts[0]
                            self.target_port = int(parts[1])
                        else:
                            self.target_host = v
                    else:
                        self.target_host = v
                    break

    def _build_headers(self, cl: Optional[int] = None) -> List[Tuple[bytes, bytes]]:
        """
        Builds HTTP/2 headers ensuring compliance and handling special headers.
        Returns headers as bytes.
        """
        path = urlparse(self.request.url).path or '/'
        if '?' in self.request.url:
            path += '?' + self.request.url.split('?', 1)[1]

        # Ensure absolute path
        if not path.startswith('/') and path != '*':
            path = '/' + path

        # Construct authority
        authority = self.target_host or ''
        if ':' in authority and not authority.startswith('['):
            authority = f"[{authority}]"

        if self.target_port not in (80, 443):
            authority = f"{authority}:{self.target_port}"

        headers = [
            (b':method', self.request.method.encode()),
            (b':path', path.encode()),
            (b':scheme', b'https'),
            (b':authority', authority.encode())
        ]

        skip = {
            'connection', 'upgrade', 'keep-alive', 'proxy-connection',
            'transfer-encoding', 'host', 'content-length', 'te'
        }

        for k, v in self.request.headers:
            if k.lower() not in skip:
                headers.append((k.lower().encode(), v.encode()))

        if cl is not None:
            headers.append((b'content-length', str(cl).encode()))

        return headers

    def connect(self) -> None:
        """Establishes the SSL/TLS connection and initiates the HTTP/2 handshake."""
        if self.target_host is None:
            raise ValueError("Target host could not be determined")

        if "insecure" not in _SSL_CONTEXT_CACHE:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["h2"])
            except NotImplementedError:
                pass
            _SSL_CONTEXT_CACHE["insecure"] = ctx

        target = self.target_host
        # Check if target is likely an IPv6 literal
        is_ipv6 = ':' in target

        if is_ipv6:
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = target

        try:
            raw = socket.create_connection((ip, self.target_port), timeout=10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # 262144 buffer size for optimization
            try:
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            except OSError:
                pass

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
            if isinstance(e, ValueError):
                raise
            raise ConnectionError(
                f"Failed to establish H2 connection to {ip}:{self.target_port}"
            ) from e

    def run_attack(self) -> List[ScanResult]:
        """
        Executes the race condition attack.
        Sends initial headers, waits (warmup), then sends the final payload for all streams.
        """
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

            headers = self._build_headers(cl=len(payload) if payload else 0)

            with self.lock:
                for i in range(self.concurrency):
                    sid = self.conn.get_next_available_stream_id()
                    self.streams[sid] = StreamContext(sid, i)
                    # Don't end stream if there is a payload
                    self.conn.send_headers(sid, headers, end_stream=not payload)

            if self.sock:
                self.sock.sendall(self.conn.data_to_send())

            time.sleep(self.warmup / 1000.0)

            gc.disable()
            t0 = time.perf_counter()
            with self.lock:
                for sid, stream in self.streams.items():
                    stream.start_time = t0
                    if payload:
                        self.conn.send_data(sid, payload, end_stream=True)
                data = self.conn.data_to_send()

            if self.sock:
                self.sock.sendall(data)

            self.finished.wait(timeout=10)
            return self._finalize()
        except Exception as e:  # pylint: disable=broad-exception-caught
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

    def _process_events(self, events: List[Any]) -> None:
        """Process H2 events received from the connection."""
        for e in events:
            if isinstance(e, (StreamEnded, StreamReset)):
                s = self.streams.get(e.stream_id)
                if s:
                    s.finished = True
                    s.end_time = time.perf_counter()
            elif isinstance(e, DataReceived):
                s = self.streams.get(e.stream_id)
                if s:
                    s.body.extend(e.data)
            elif isinstance(e, ResponseReceived):
                s = self.streams.get(e.stream_id)
                if s:
                    s.headers = e.headers

        if self.streams and all(s.finished for s in self.streams.values()):
            self.finished.set()

    def _recv(self) -> None:
        if not self.sock:
            return
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)  # type: ignore
        try:
            while not self.finished.is_set():
                try:
                    if not sel.select(0.1):
                        continue
                    data = self.sock.recv(65536)  # type: ignore
                    if not data:
                        break
                    with self.lock:
                        events = self.conn.receive_data(data)
                        self._process_events(events)

                        # Send any pending frames (ACKs, etc.)
                        to_send = self.conn.data_to_send()
                        if to_send and self.sock:
                            self.sock.sendall(to_send)
                except OSError as e:
                    logger.debug("Socket error in _recv: %s", e)
                    break
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.error("Unexpected error in _recv: %s", e)
                    break
        finally:
            self.finished.set()

    def _finalize(self) -> List[ScanResult]:
        res = []
        for s in sorted(self.streams.values(), key=lambda x: x.index):
            status = 0
            for k, v in s.headers:
                if k == b':status':
                    status = int(v)
                    break

            if status == 0 and s.finished and not s.error:
                status = 200

            end_t = s.end_time if s.end_time > 0 else time.perf_counter()
            duration = (end_t - s.start_time) * 1000

            body_hash = hashlib.md5(s.body).hexdigest()

            res.append(
                ScanResult(
                    s.index,
                    status,
                    duration,
                    body_hash=body_hash,
                    body_snippet=s.body[:50].decode('utf-8', 'ignore')
                )
            )
        return res
