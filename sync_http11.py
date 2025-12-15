# sync_http11.py
"""
Implements the Synchronous HTTP/1.1 Staged Attack engine.

This module provides a specialized attack engine (`HTTP11SyncEngine`) that uses Python
threads and barriers to synchronize the sending of request payloads across multiple
connections. It is designed to achieve higher precision than asyncio-based approaches
by synchronizing threads immediately before the `socket.send` call.

[OPTIMIZED] - Header pre-serialization and pre-concatenation
            - SO_SNDBUF tuning to 256KB
            - Local variable caching in hot loop
"""

import socket
import ssl
import time
import threading
import hashlib
import sys
import logging
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Union
# Import HTTPResponse for robust parsing over raw sockets
from http.client import HTTPResponse
import io

logger = logging.getLogger(__name__)

# Fallback structures for standalone testing
try:
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, SYNC_MARKER
except ImportError:
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
    MAX_RESPONSE_BODY_READ = 1024 * 1024
    SYNC_MARKER = b"{{SYNC}}"

# Configuration Constants
CONNECTION_TIMEOUT = 10.0
RESPONSE_TIMEOUT = 10.0
BARRIER_TIMEOUT = 15.0 # Timeout for synchronization barrier

class HTTP11SyncEngine:
    """
    Implements high-precision Synchronous Staged Attacks over HTTP/1.1 using threads and barriers.
    """
    __slots__ = (
        'request', 'concurrency', 'target_host', 'target_port', 'scheme', 'target_ip',
        'stages', 'total_payload_len', 'barrier', 'ssl_context', 'serialized_headers',
        'results', 'initial_payload'
    )

    def __init__(self, request: CapturedRequest, concurrency: int):
        """
        Initializes the HTTP11SyncEngine.

        Args:
            request (CapturedRequest): The request to attack with.
            concurrency (int): The number of concurrent threads/requests.
        """
        self.request = request
        self.concurrency = concurrency
        
        self.target_host = None
        self.target_port = None
        self.scheme = None
        self.target_ip = None
        
        self.stages: List[bytes] = []
        self.total_payload_len = 0
        
        # Synchronization primitives
        self.barrier: threading.Barrier = None
        
        # SSL Context (Optimized: Created once)
        self.ssl_context: Optional[ssl.SSLContext] = None
        
        # Cache serialized headers
        self.serialized_headers: Optional[bytes] = None
        self.initial_payload: Optional[bytes] = None
        
        # Results tracking
        self.results: List[Optional[ScanResult]] = [None] * concurrency

        self._parse_target()
        self._prepare_payload()
        self._prepare_ssl_context()
        
        # Pre-serialize
        self.serialized_headers = self._serialize_headers()
        
        # VECTOR OPTIMIZATION: Pre-calculate the initial payload (Headers + Stage 1)
        # to avoid concatenation in the thread's hot path.
        if self.stages:
            self.initial_payload = self.serialized_headers + self.stages[0]
        else:
            self.initial_payload = self.serialized_headers

    def _parse_target(self):
        """
        Parses the target URL to extract host, port, and scheme.
        """
        parsed_url = urlparse(self.request.url)
        self.target_host = parsed_url.hostname
        self.scheme = parsed_url.scheme
        
        if self.scheme == 'https':
            self.target_port = parsed_url.port or 443
        elif self.scheme == 'http':
            self.target_port = parsed_url.port or 80
        else:
            raise ValueError(f"Unsupported URL scheme: {self.scheme}")

    def _prepare_payload(self):
        """
        Prepares the payload stages and initializes the synchronization barrier.
        Splits the payload by the `{{SYNC}}` marker.
        """
        payload = self.request.get_attack_payload()
        # The actual length sent over the wire excludes the markers
        self.total_payload_len = len(payload.replace(SYNC_MARKER, b""))
        self.stages = payload.split(SYNC_MARKER)
        
        if len(self.stages) < 2:
            raise ValueError("Synchronous Staged Attack requires at least one {{SYNC}} marker.")
            
        # Initialize barrier for N concurrent requests.
        self.barrier = threading.Barrier(self.concurrency)

    def _prepare_ssl_context(self):
        """
        Initializes the SSL context if required.
        Refactored to run once during init rather than per-connection for efficiency.
        """
        if self.scheme == 'https':
            self.ssl_context = ssl.create_default_context()
            # Mimic 'verify=False' - Essential for attacking targets with self-signed certs
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Force HTTP/1.1 via ALPN if supported
            try:
                self.ssl_context.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass

    def run_attack(self) -> List[ScanResult]:
        """
        Executes the synchronized attack.
        """
        logger.info(f"Connecting to {self.target_host}:{self.target_port}...")
        
        # 1. Resolve IP (Centralized resolution)
        try:
            self.target_ip = socket.gethostbyname(self.target_host)
            logger.info(f"Resolved IP: {self.target_ip}")
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed: {e}")
            # Return error results immediately if DNS fails
            return [ScanResult(i, 0, 0.0, error=f"DNS error: {e}") for i in range(self.concurrency)]

        # 2. Launch threads
        threads = []
        for i in range(self.concurrency):
            t = threading.Thread(target=self._attack_thread, args=(i,))
            threads.append(t)
            t.start()

        # 3. Wait for completion
        for t in threads:
            # Use a timeout for joining threads to prevent infinite hangs
            t.join(timeout=RESPONSE_TIMEOUT + BARRIER_TIMEOUT + 5)

        # 4. Finalize results
        # Ensure None results are converted to errors if applicable
        for i in range(self.concurrency):
             if self.results[i] is None:
                  self.results[i] = ScanResult(i, 0, 0.0, error="Thread execution timeout or hang.")

        return self.results

    def _connect(self) -> socket.socket:
        """
        Establishes a persistent TCP (and optionally SSL) connection.
        """
        try:
            # Connect using the resolved IP
            sock = socket.create_connection((self.target_ip, self.target_port), timeout=CONNECTION_TIMEOUT)
        except socket.error as e:
            raise ConnectionError(f"Connection failed: {type(e).__name__}: {e}")

        # Optimization: Disable Nagle's algorithm (TCP_NODELAY) explicitly
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Optimization: Expand Send Buffer to 256KB to prevent blocking in userspace during the burst
        # This reduces the chance of 'sendall' partially blocking when dumping the payload.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        except OSError:
            pass

        if self.scheme == 'https' and self.ssl_context:
            try:
                # We must pass the original hostname for SNI.
                ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=self.target_host)
                return ssl_sock
            except ssl.SSLError as e:
                sock.close()
                raise ConnectionError(f"SSL Handshake failed: {e}")
        
        return sock

    def _serialize_headers(self) -> bytes:
        """
        Serializes HTTP/1.1 headers for the request.
        """
        parsed_url = urlparse(self.request.url)
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query

        # Start building the request line
        request_lines = [f"{self.request.method} {path} HTTP/1.1"]
        
        # 1. Host Header
        host_header = self.target_host
        if (self.scheme == 'https' and self.target_port != 443) or \
           (self.scheme == 'http' and self.target_port != 80):
            host_header += f":{self.target_port}"
        request_lines.append(f"Host: {host_header}")

        # 2. User-provided headers
        # Use iterator to preserve duplicates and order
        req_headers_iter = self.request.headers
        if isinstance(req_headers_iter, dict):
            req_headers_iter = req_headers_iter.items()

        seen_keys_lower = set()
        
        for k, v in req_headers_iter:
            k_lower = k.lower()
            seen_keys_lower.add(k_lower)
            # Skip headers managed explicitly by this engine
            if k_lower not in ['host', 'connection', 'content-length', 'transfer-encoding']:
                request_lines.append(f"{k}: {v}")

        # 3. Auto-generated headers (only if missing)
        
        # Ensure Content-Type if missing and body exists
        if 'content-type' not in seen_keys_lower and self.request.method in ["POST", "PUT", "PATCH"] and self.total_payload_len > 0:
             request_lines.append("Content-Type: application/x-www-form-urlencoded")

        # Add Content-Length (crucial for HTTP/1.1 persistence)
        if self.total_payload_len > 0 or self.request.method in ["POST", "PUT", "PATCH"]:
            request_lines.append(f"Content-Length: {self.total_payload_len}")
        
        # Add default User-Agent if not present
        if 'user-agent' not in seen_keys_lower:
            # Switched to a standard Chrome User-Agent for better compatibility during testing
            request_lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

        # Ensure Connection: keep-alive for persistence
        request_lines.append("Connection: keep-alive")

        # Finalize headers block with Double CRLF
        return ("\r\n".join(request_lines) + "\r\n\r\n").encode('utf-8')

    def _attack_thread(self, index: int):
        """
        The main logic for a single synchronized attack thread. Implements fail-fast mechanism.
        """
        sock = None
        response = None
        start_time = 0.0
        
        try:
            # 1. Connect
            sock = self._connect()
            
            # [VECTOR OPTIMIZATION] Local variable caching for hot loop
            # Avoids LOAD_ATTR opcodes during the critical sync moment
            sock_sendall = sock.sendall
            barrier_wait = self.barrier.wait
            initial_payload = self.initial_payload
            stages = self.stages

            # Record start time just before the first send
            start_time = time.perf_counter()

            # 3. Send Headers + First Stage (Optimized: Single send call)
            # Using pre-calculated payload avoids concatenation overhead in this hot thread
            sock_sendall(initial_payload)

            # 4. Synchronized subsequent stages
            for stage_index in range(1, len(stages)):
                # Wait for all threads to reach this point
                try:
                    # Use a timeout on the barrier
                    barrier_wait(timeout=BARRIER_TIMEOUT)
                # Handle the case where another thread aborted the barrier
                except threading.BrokenBarrierError:
                    # Raise an exception to be caught by the outer handler.
                    raise ConnectionError("Synchronization barrier broken (fail-fast).")
                
                # Send immediately
                sock_sendall(stages[stage_index])
            
            # 5. Receive response
            # Set timeout for response reading
            sock.settimeout(RESPONSE_TIMEOUT)

            # Use http.client.HTTPResponse to parse the incoming data robustly.
            response = HTTPResponse(sock, method=self.request.method)
            response.begin() # Parses status line and headers

            status_code = response.status
            # Read body up to the limit
            body = response.read(MAX_RESPONSE_BODY_READ)
            
            # Check if more data remains (response too large)
            if response.read(1):
                 logger.warning(f"Response truncated (>{MAX_RESPONSE_BODY_READ} bytes) for probe {index}.")

            duration = (time.perf_counter() - start_time) * 1000

            # Process body for analysis
            body_hash = None
            body_snippet = None
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')

            self.results[index] = ScanResult(index, status_code, duration, body_hash, body_snippet)

        except Exception as e:
            # Capture errors during connection, sending, or receiving
            duration = (time.perf_counter() - start_time) * 1000 if start_time > 0 else 0.0
            error_msg = f"{type(e).__name__}: {e}"
            
            # Only update result if not already set
            if self.results[index] is None:
                self.results[index] = ScanResult(index, 0, duration, error=error_msg)

        finally:
            # Fail-fast mechanism: Ensure the barrier is aborted if an error occurred in this thread
            try:
                # If this thread recorded an error and the barrier is still intact, abort it for others.
                if self.results[index] and self.results[index].error and self.barrier and not self.barrier.broken:
                     self.barrier.abort()
            except Exception:
                 pass

            # Cleanup resources
            if response:
                try:
                    response.close()
                except Exception:
                    pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass