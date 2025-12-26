#Filename: sync_http11.py
"""
Implements the Synchronous HTTP/1.1 Staged Attack engine.
[VECTOR OPTIMIZED]:
- Supports 'first-seq' Packet Bunching via specialized H1 subclass.
- Robust H1 connection tuning and fail-fast barrier synchronization.
"""

import socket
import ssl
import threading
import logging
import struct
import subprocess
import gc
import hashlib
from urllib.parse import urlparse
from typing import List, Optional, Any
from http.client import HTTPResponse

# [APEX] Centralized Imports
from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, SYNC_MARKER
from compat import NFQUEUE_AVAILABLE, MockPacketController

# Safe Import of PacketController logic
try:
    from packet_controller import PacketController
except ImportError:
    PacketController = MockPacketController  # type: ignore

logger = logging.getLogger(__name__)

CONNECTION_TIMEOUT: float = 10.0
RESPONSE_TIMEOUT: float = 10.0
BARRIER_TIMEOUT: float = 15.0
_STRUCT_H = struct.Struct("!H")

class H1PacketController(PacketController): # type: ignore
    """Specialized PacketController for HTTP/1.1 Multi-Socket Attacks."""
    __slots__ = ('concurrency', 'held_packets', 'release_event', 'lock', 'safety_thread')

    def __init__(self, target_ip: str, target_port: int, concurrency: int):
        # Ensure we have a valid base class before proceeding
        if PacketController is MockPacketController:
            raise RuntimeError("PacketController dependency missing.")

        super().__init__(target_ip, target_port, 0)
        self.concurrency = concurrency
        self.held_packets: List[Any] = []
        self.release_event = threading.Event()
        self.lock = threading.Lock()
        self.safety_thread: Optional[threading.Thread] = None

    def _manage_nftables(self, action: str) -> None:
        # Override to omit source port filtering for bunching
        table = "scalpel_racer_ctx"
        chain = "output_hook"
        if action == 'add':
            cmd = [
                'nft', 'add', 'rule', 'ip', table, chain, 'ip', 'protocol', 'tcp',
                'ip', 'daddr', self.target_ip, 'tcp', 'dport', str(self.target_port),
                'counter', 'queue', 'num', str(self.queue_num)
            ]
            try:
                subprocess.run(
                    ['nft', 'add', 'table', 'ip', table],
                    check=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
                subprocess.run(
                    ['nft', 'add', 'chain', 'ip', table, chain,
                     '{', 'type', 'filter', 'hook', 'output', 'priority', '0', ';', '}'],
                    check=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
                subprocess.run(
                    cmd, check=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except (OSError, subprocess.SubprocessError):
                pass
        elif action == 'delete':
            try:
                subprocess.run(
                    ['nft', 'delete', 'table', 'ip', table],
                    check=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except (OSError, subprocess.SubprocessError):
                pass

    def _queue_callback(self, pkt: Any) -> None:
        if not getattr(self, 'active', False):
            try:
                pkt.accept()
            except (OSError, RuntimeError):
                pass
            return

        try:
            raw = pkt.get_payload()
            if len(raw) < 40:
                pkt.accept()
                return

            ihl = (raw[0] & 0x0F) * 4
            total_len = _STRUCT_H.unpack_from(raw, 2)[0]
            data_off = (raw[ihl + 12] >> 4) * 4

            if total_len - ihl - data_off <= 0:
                pkt.accept()
                return

            with self.lock:
                if self.release_event.is_set():
                    pkt.accept()
                    return
                self.held_packets.append(pkt)
                if len(self.held_packets) >= self.concurrency:
                    self._release_all()
        except Exception: # pylint: disable=broad-exception-caught
            # Callback must not raise
            try:
                pkt.accept()
            except (OSError, RuntimeError):
                pass

    def _release_all(self) -> None:
        self.release_event.set()
        for p in self.held_packets:
            try:
                p.accept()
            except (OSError, RuntimeError):
                pass
        self.held_packets.clear()

    def start(self) -> None:
        super().start()
        self.safety_thread = threading.Thread(target=self._delayed_release, daemon=True)
        self.safety_thread.start()

    def _delayed_release(self) -> None:
        """
        Safety mechanism to release held packets if the concurrency threshold
        is not met within the timeout period.
        """
        if self.release_event.wait(timeout=5.0):
            return
        with self.lock:
            self._release_all()

class HTTP11SyncEngine:
    """Synchronous Staged Attack Engine."""
    __slots__ = (
        'request', 'concurrency', 'strategy', 'target_host', 'target_port',
        'scheme', 'target_ip', 'stages', 'total_payload_len', 'barrier',
        'ssl_context', 'serialized_headers', 'results', 'initial_payload'
    )

    def __init__(self, request: CapturedRequest, concurrency: int, strategy: str = "auto"):
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.target_host: Optional[str] = None
        self.target_port: Optional[int] = None
        self.scheme: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.stages: List[bytes] = []
        self.total_payload_len = 0
        self.barrier: Optional[threading.Barrier] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.serialized_headers: bytes = b""
        self.initial_payload: bytes = b""
        self.results: List[Optional[ScanResult]] = [None] * concurrency

        self._parse_target()
        self._prepare_payload()
        self._prepare_ssl_context()
        self.serialized_headers = self._serialize_headers()

        if self.stages:
            self.initial_payload = self.serialized_headers + self.stages[0]
        else:
            self.initial_payload = self.serialized_headers

    def _parse_target(self) -> None:
        parsed = urlparse(self.request.url)
        self.scheme = parsed.scheme
        if self.scheme and self.scheme not in ('http', 'https'):
            raise ValueError(f"Unsupported URL scheme: {self.scheme}")

        if not self.scheme:
            self.scheme = 'http'

        self.target_host = parsed.hostname
        if not self.target_host:
            # Fallback to Host header
            headers = self.request.headers_dict()
            host_header = headers.get('Host') or headers.get('host')
            if host_header:
                if ':' in host_header:
                    self.target_host, port_str = host_header.split(':', 1)
                    try:
                        self.target_port = int(port_str)
                    except ValueError:
                        pass
                else:
                    self.target_host = host_header

        if self.scheme == 'https':
            self.target_port = self.target_port or parsed.port or 443
        else:
            self.target_port = self.target_port or parsed.port or 80

    def _prepare_payload(self) -> None:
        payload = self.request.get_attack_payload()
        self.total_payload_len = len(payload.replace(SYNC_MARKER, b""))
        if SYNC_MARKER in payload:
            self.stages = payload.split(SYNC_MARKER)
        else:
            if len(payload) > 1:
                self.stages = [payload[:-1], payload[-1:]]
            elif len(payload) == 1:
                self.stages = [b"", payload]
            else:
                self.stages = [payload, b""]

        if len(self.stages) > 1:
            self.barrier = threading.Barrier(self.concurrency)

    def _prepare_ssl_context(self) -> None:
        if self.scheme == 'https':
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            try:
                self.ssl_context.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass

    def run_attack(self) -> List[Optional[ScanResult]]:
        """
        Executes the concurrent race condition attack.

        Resolves target IP, initializes the PacketController (if 'first-seq' strategy
        is selected), and spawns worker threads to send requests. Aggregates and
        returns the results from all threads.
        """
        try:
            if not self.target_ip and self.target_host:
                self.target_ip = socket.gethostbyname(self.target_host)
        except Exception as e: # pylint: disable=broad-exception-caught
            return [
                ScanResult(i, 0, 0.0, error=f"DNS Fail: {e}") for i in range(self.concurrency)
            ]

        pc: Optional[PacketController] = None
        if self.strategy == "first-seq":
            if (
                NFQUEUE_AVAILABLE
                and PacketController is not MockPacketController
                and self.target_ip
                and self.target_port
            ):
                logger.info("[!] Engaging First-Seq H1 Controller...")
                try:
                    pc = H1PacketController(self.target_ip, self.target_port, self.concurrency)
                    pc.start()
                except Exception as e: # pylint: disable=broad-exception-caught
                    logger.error("PC Error: %s", e)
            else:
                logger.warning(
                    "Strategy 'first-seq' unavailable (Requires Linux + NetfilterQueue)."
                )

        gc.disable()
        threads = []
        try:
            for i in range(self.concurrency):
                t = threading.Thread(target=self._attack_thread, args=(i,))
                t.daemon = True
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=RESPONSE_TIMEOUT + 5)
        finally:
            gc.enable()
            if pc:
                pc.stop()
        return self.results

    def _connect(self) -> socket.socket:
        if not self.target_ip or not self.target_port:
            raise ConnectionError("Target invalid")

        try:
            sock = socket.create_connection(
                (self.target_ip, self.target_port), timeout=CONNECTION_TIMEOUT
            )
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if self.scheme == 'https' and self.ssl_context:
                return self.ssl_context.wrap_socket(sock, server_hostname=str(self.target_host))
            return sock
        except Exception as e:
            raise ConnectionError(f"Connection failed: {e}") from e

    def _serialize_headers(self) -> bytes:
        method = self.request.method
        path = urlparse(self.request.url).path or '/'
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {self.target_host}:{self.target_port}"
        ]
        for k, v in self.request.headers:
            if k.lower() not in ['host', 'content-length', 'connection']:
                lines.append(f"{k}: {v}")

        lines.append(f"Content-Length: {self.total_payload_len}")
        lines.append("Connection: keep-alive")
        return ("\r\n".join(lines) + "\r\n\r\n").encode('utf-8')

    def _attack_thread(self, index: int) -> None:
        sock = None
        try:
            sock = self._connect()
            sock.sendall(self.initial_payload)
            if self.barrier:
                self.barrier.wait(timeout=BARRIER_TIMEOUT)
                for i in range(1, len(self.stages)):
                    sock.sendall(self.stages[i])

            resp = HTTPResponse(sock, method=self.request.method) # type: ignore
            resp.begin()
            body = resp.read(MAX_RESPONSE_BODY_READ)

            # Check for truncation (simple heuristic: if we read exactly the limit)
            # In a real scenario, we might try to read one more byte or check Content-Length.
            # But here we stick to the limit.
            if len(body) == MAX_RESPONSE_BODY_READ:
                if not resp.isclosed():
                    try:
                        extra = resp.read(1)
                        if extra:
                            logger.warning("Response truncated for index %s", index)
                    except Exception: # pylint: disable=broad-exception-caught
                        pass

            body_hash = hashlib.md5(body).hexdigest()
            self.results[index] = ScanResult(
                index, resp.status, 0.0,
                body_snippet=body[:50].decode('utf-8', 'ignore'),
                body_hash=body_hash
            )
        except Exception as e: # pylint: disable=broad-exception-caught
            self.results[index] = ScanResult(index, 0, 0.0, error=str(e))
        finally:
            if sock:
                sock.close()
