# sync_http11.py
"""
Implements the Synchronous HTTP/1.1 Staged Attack engine.
[VECTOR OPTIMIZED]: 
- Supports 'first-seq' Packet Bunching via specialized H1 subclass.
- Explicit GC control for jitter suppression during attack bursts.
- Memory optimizations (early buffer release).
- Robust H1 connection tuning and fail-fast barrier synchronization.
"""

import socket
import ssl
import time
import threading
import hashlib
import logging
import struct
import subprocess
import gc
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Union
from http.client import HTTPResponse

logger = logging.getLogger(__name__)

# --- Dependency Handling ---
try:
    from packet_controller import PacketController, NFQUEUE_AVAILABLE
except ImportError:
    PacketController = None
    NFQUEUE_AVAILABLE = False

try:
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, SYNC_MARKER
except ImportError:
    # Fallback structures for standalone testing
    MAX_RESPONSE_BODY_READ = 1024 * 1024
    SYNC_MARKER = b"{{SYNC}}"
    
    class ScanResult:
        __slots__ = ('index', 'status_code', 'duration', 'body_hash', 'body_snippet', 'error')
        def __init__(self, index, status_code, duration, body_hash=None, body_snippet=None, error=None):
            self.index = index; self.status_code = status_code; self.duration = duration
            self.body_hash = body_hash; self.body_snippet = body_snippet; self.error = error

    class CapturedRequest:
        __slots__ = ('id', 'method', 'url', 'headers', 'body', 'edited_body')
        def __init__(self, id=0, method="GET", url="", headers=None, body=b""):
            self.id = id; self.method = method; self.url = url; self.headers = headers or {}; self.body = body; self.edited_body = None
        def get_attack_payload(self) -> bytes:
            return self.edited_body if self.edited_body is not None else self.body
        def headers_dict(self) -> Dict[str, str]:
            return dict(self.headers) if isinstance(self.headers, list) else self.headers

# --- Constants ---
CONNECTION_TIMEOUT = 10.0
RESPONSE_TIMEOUT = 10.0
BARRIER_TIMEOUT = 15.0
_STRUCT_H = struct.Struct("!H")

# --- H1 Specialized Kernel Controller ---
class H1PacketController(PacketController if PacketController else object):
    """
    Specialized PacketController for HTTP/1.1 Multi-Socket Attacks.
    Implements Count-Based Bunching and wildcard source port filtering.
    """
    __slots__ = ('concurrency', 'held_packets', 'release_event', 'lock', 'safety_thread')

    def __init__(self, target_ip: str, target_port: int, concurrency: int):
        if PacketController:
            # Initialize parent with source_port=0 (Wildcard placeholder)
            super().__init__(target_ip, target_port, 0)
        self.concurrency = concurrency
        self.held_packets = []
        self.release_event = threading.Event()
        self.lock = threading.Lock()
        self.safety_thread = None

    def _manage_nftables(self, action: str):
        """
        Overrides parent rule generation.
        CRITICAL: Omits 'tcp sport' to trap ALL outgoing connections to the target IP/Port.
        """
        table_name = "scalpel_racer_ctx"; chain_name = "output_hook"
        if action == 'add':
            cmd_table = ['nft', 'add', 'table', 'ip', table_name]
            cmd_chain = ['nft', 'add', 'chain', 'ip', table_name, chain_name, '{', 'type', 'filter', 'hook', 'output', 'priority', '0', ';', '}']
            # Rule matches DADDR and DPORT only (bunching all sockets to target)
            cmd_rule = ['nft', 'add', 'rule', 'ip', table_name, chain_name, 'ip', 'protocol', 'tcp', 'ip', 'daddr', self.target_ip, 'tcp', 'dport', str(self.target_port), 'counter', 'queue', 'num', str(self.queue_num)]
            try:
                subprocess.call(cmd_table, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.call(cmd_chain, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.call(cmd_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception: pass
        elif action == 'delete':
            try:
                subprocess.call(['nft', 'delete', 'table', 'ip', table_name], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception: pass

    def _queue_callback(self, pkt):
        """
        Count-Based Bunching Logic: Holds packets until 'concurrency' count is reached.
        """
        if not self.active: pkt.accept(); return
        try:
            raw = pkt.get_payload()
            # Basic IPv4/TCP Sanity Check (Version 4, TCP Protocol 6)
            if len(raw) < 20 or (raw[0] >> 4) != 4 or raw[9] != 6: pkt.accept(); return
            
            # Calculate Payload Length (ignore SYN/ACK/Handshakes)
            ihl = (raw[0] & 0x0F) * 4
            total_len = _STRUCT_H.unpack_from(raw, 2)[0]
            data_off = (raw[ihl + 12] >> 4) * 4
            
            # Filter: Only hold packets with Data
            if total_len - ihl - data_off <= 0: pkt.accept(); return
            
            with self.lock:
                if self.release_event.is_set(): pkt.accept(); return
                self.held_packets.append(pkt)
                if len(self.held_packets) >= self.concurrency: self._release_all()
        except: pkt.accept()

    def _release_all(self):
        """Releases all held packets simultaneously."""
        self.release_event.set()
        for p in self.held_packets:
            try: p.accept()
            except: pass
        self.held_packets.clear()

    def _delayed_release(self):
        """Safety timeout override."""
        if self.release_event.wait(timeout=5.0): return
        with self.lock: self._release_all()
    
    def start(self):
        super().start()
        self.safety_thread = threading.Thread(target=self._delayed_release, daemon=True)
        self.safety_thread.start()

# --- Main Engine ---
class HTTP11SyncEngine:
    """
    Implements high-precision Synchronous Staged Attacks over HTTP/1.1.
    """
    __slots__ = ('request', 'concurrency', 'strategy', 'target_host', 'target_port', 'scheme', 'target_ip', 'stages', 'total_payload_len', 'barrier', 'ssl_context', 'serialized_headers', 'results', 'initial_payload')
    
    def __init__(self, request: CapturedRequest, concurrency: int, strategy: str = "auto"):
        self.request = request; self.concurrency = concurrency; self.strategy = strategy
        self.target_host = None; self.target_port = None; self.scheme = None; self.target_ip = None
        self.stages: List[bytes] = []; self.total_payload_len = 0; self.barrier = None
        self.ssl_context: Optional[ssl.SSLContext] = None; self.serialized_headers: Optional[bytes] = None; self.initial_payload: Optional[bytes] = None
        self.results: List[Union[ScanResult, None]] = [None] * concurrency
        
        self._parse_target()
        self._prepare_payload()
        self._prepare_ssl_context()
        self.serialized_headers = self._serialize_headers()
        
        # Pre-calculate initial payload (Headers + Stage 0)
        if self.stages: self.initial_payload = self.serialized_headers + self.stages[0]
        else: self.initial_payload = self.serialized_headers

    def _parse_target(self):
        parsed = urlparse(self.request.url)
        self.target_host = parsed.hostname
        self.scheme = parsed.scheme
        if self.scheme == 'https': self.target_port = parsed.port or 443
        elif self.scheme == 'http': self.target_port = parsed.port or 80
        else:
            # Fallback using headers directly to avoid dict data loss
            headers = self.request.headers_dict()
            if 'host' in headers:
                val = headers['host']
                if ':' in val: self.target_host, port = val.split(':', 1); self.target_port = int(port)
                else: self.target_host = val; self.target_port = 80
                self.scheme = 'http'
            else: raise ValueError(f"Unsupported URL scheme: {self.scheme}")

    def _prepare_payload(self):
        """Prepares payload stages, handling explicit SYNC markers or implicit last-byte sync."""
        payload = self.request.get_attack_payload()
        self.total_payload_len = len(payload.replace(SYNC_MARKER, b""))
        if SYNC_MARKER in payload: self.stages = payload.split(SYNC_MARKER)
        else:
            # Implicit Last-Byte-Sync
            if len(payload) > 1: self.stages = [payload[:-1], payload[-1:]]
            elif len(payload) == 1: self.stages = [b"", payload]
            else: self.stages = [payload, b""]
        if len(self.stages) > 1: self.barrier = threading.Barrier(self.concurrency)

    def _prepare_ssl_context(self):
        if self.scheme == 'https':
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False; self.ssl_context.verify_mode = ssl.CERT_NONE
            try: self.ssl_context.set_alpn_protocols(["http/1.1"])
            except NotImplementedError: pass

    def run_attack(self) -> List[Union[ScanResult, None]]:
        # [FIX] Resolve DNS here. Captures errors in results instead of crashing __init__
        try:
            if not self.target_ip:
                self.target_ip = socket.gethostbyname(self.target_host)
        except Exception as e:
            logger.error(f"DNS Resolution Failed: {e}")
            # Return error results for all threads immediately
            return [ScanResult(i, 0, 0.0, error=f"DNS Resolution Failed: {e}") for i in range(self.concurrency)]

        logger.info(f"Connecting to {self.target_host}:{self.target_port}...")
        
        # [FIX] Engage Specialized Kernel Controller for First-Seq
        pc = None
        if self.strategy == "first-seq":
            if PacketController and NFQUEUE_AVAILABLE:
                logger.info("[!] Engaging Kernel Packet Controller (First-Seq H1 Mode)...")
                try:
                    pc = H1PacketController(self.target_ip, self.target_port, self.concurrency)
                    pc.start()
                except Exception as e: logger.error(f"PacketController Error: {e}")
            else:
                logger.warning("Strategy 'first-seq' unavailable (Requires Linux + NetfilterQueue).")

        # [VECTOR] Disable GC for threaded burst to suppress jitter
        gc.disable()
        threads = []
        try:
            for i in range(self.concurrency):
                t = threading.Thread(target=self._attack_thread, args=(i,))
                t.daemon = True
                threads.append(t); t.start()
            for t in threads: t.join(timeout=RESPONSE_TIMEOUT + BARRIER_TIMEOUT + 5)
        finally:
            # [CRITICAL] Re-enable GC and cleanup Controller
            gc.enable()
            if pc: 
                logger.info("[!] Disengaging Kernel Controller...")
                pc.stop()
        
        for i in range(self.concurrency):
             if self.results[i] is None: self.results[i] = ScanResult(i, 0, 0.0, error="Thread execution timeout or hang.")
        return self.results

    def _connect(self) -> socket.socket:
        try: sock = socket.create_connection((self.target_ip, self.target_port), timeout=CONNECTION_TIMEOUT)
        except socket.error as e: raise ConnectionError(f"Conn failed: {e}")
        
        # Performance Tuning
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        except OSError: pass
        
        if self.scheme == 'https' and self.ssl_context:
            try: return self.ssl_context.wrap_socket(sock, server_hostname=self.target_host)
            except ssl.SSLError as e: sock.close(); raise ConnectionError(f"SSL failed: {e}")
        return sock

    def _serialize_headers(self) -> bytes:
        p = urlparse(self.request.url); path = p.path or '/'
        if p.query: path += '?' + p.query
        req_lines = [f"{self.request.method} {path} HTTP/1.1"]
        
        host = self.target_host
        if (self.scheme == 'https' and self.target_port != 443) or (self.scheme == 'http' and self.target_port != 80):
            host += f":{self.target_port}"
        req_lines.append(f"Host: {host}")
        
        # [FIX] Preserve duplicate headers
        raw = self.request.headers.items() if isinstance(self.request.headers, dict) else self.request.headers
        seen = {k.lower() for k, v in raw}
        for k, v in raw:
            if k.lower() not in ['host', 'connection', 'content-length', 'transfer-encoding']:
                req_lines.append(f"{k}: {v}")
        
        if 'content-type' not in seen and self.request.method in ["POST", "PUT", "PATCH"] and self.total_payload_len > 0:
             req_lines.append("Content-Type: application/x-www-form-urlencoded")
        if self.total_payload_len > 0 or self.request.method in ["POST", "PUT", "PATCH"]:
            req_lines.append(f"Content-Length: {self.total_payload_len}")
        if 'user-agent' not in seen: req_lines.append("User-Agent: Scalpel-Racer/1.1")
        req_lines.append("Connection: keep-alive")
        return ("\r\n".join(req_lines) + "\r\n\r\n").encode('utf-8')

    def _attack_thread(self, index: int):
        sock = None; response = None; start_time = 0.0
        try:
            sock = self._connect()
            sock_sendall = sock.sendall
            start_time = time.perf_counter()
            
            # 1. Send Headers + Stage 0
            sock_sendall(self.initial_payload)
            
            # 2. Synchronize and Send Remaining Stages
            if self.barrier:
                barrier_wait = self.barrier.wait
                for idx in range(1, len(self.stages)):
                    try: barrier_wait(timeout=BARRIER_TIMEOUT)
                    except threading.BrokenBarrierError: raise ConnectionError("Barrier broken")
                    sock_sendall(self.stages[idx])
            
            # 3. Read Response
            sock.settimeout(RESPONSE_TIMEOUT)
            response = HTTPResponse(sock, method=self.request.method); response.begin()
            body = response.read(MAX_RESPONSE_BODY_READ)
            
            # [FIX] Response Truncation Check
            if not response.isclosed() and len(body) == MAX_RESPONSE_BODY_READ:
                 try: 
                     if response.read(1): logger.warning(f"Response truncated (exceeded {MAX_RESPONSE_BODY_READ} bytes).")
                 except: pass
            
            duration = (time.perf_counter() - start_time) * 1000
            
            # [VECTOR] Memory Optimization: Compute hash/snippet and free buffer immediately
            h = hashlib.sha256(body).hexdigest() if body else None
            s = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ') if body else None
            del body # Free potentially large buffer immediately
            
            self.results[index] = ScanResult(index, response.status, duration, h, s)
        except Exception as e:
            dur = (time.perf_counter() - start_time) * 1000 if start_time > 0 else 0.0
            if self.results[index] is None: self.results[index] = ScanResult(index, 0, dur, error=str(e))
        finally:
            try:
                if self.results[index] and self.results[index].error and self.barrier and not self.barrier.broken: self.barrier.abort()
            except: pass
            if response: 
                try: response.close()
                except: pass
            if sock: 
                try: sock.close()
                except: pass