# sync_http11.py
# FILE: ./sync_http11.py
"""
Implements the Synchronous HTTP/1.1 Staged Attack engine.

This module provides a specialized attack engine (`HTTP11SyncEngine`) that uses Python
threads and barriers to synchronize the sending of request payloads across multiple
connections. It is designed to achieve higher precision than asyncio-based approaches
by synchronizing threads immediately before the `socket.send` call.
"""

import socket
import ssl
import time
import threading
import hashlib
import sys
import logging
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional
# Import HTTPResponse for robust parsing over raw sockets
from http.client import HTTPResponse
import io

logger = logging.getLogger(__name__)

# Define placeholders for data structures (similar to low_level.py)
class ScanResult:
    """
    Represents the result of a single race attempt (one probe).
    """
    def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None, body_snippet: str = None, error: str = None):
        self.index = index; self.status_code = status_code; self.duration = duration
        self.body_hash = body_hash; self.body_snippet = body_snippet; self.error = error

class CapturedRequest:
    """
    Represents a captured HTTP request.
    """
    # Add attributes expected by the engine
    def __init__(self, id=0, method="GET", url="", headers=None, body=b""):
        self.id = id; self.method = method; self.url = url; self.headers = headers or {}; self.body = body; self.edited_body = None

    def get_attack_payload(self) -> bytes:
        return self.edited_body if self.edited_body is not None else self.body

MAX_RESPONSE_BODY_READ = 1024 * 1024
SYNC_MARKER = b"{{SYNC}}"

try:
    # Attempt to import the actual definitions when running via scalpel_racer.py
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ, SYNC_MARKER
except ImportError:
    # This is expected if running independently or during tests
    pass

# Configuration Constants
CONNECTION_TIMEOUT = 10.0
RESPONSE_TIMEOUT = 10.0
BARRIER_TIMEOUT = 15.0 # Timeout for synchronization barrier

class HTTP11SyncEngine:
    """
    Implements high-precision Synchronous Staged Attacks over HTTP/1.1 using threads and barriers.
    """

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
        
        # Results tracking
        self.results: List[Optional[ScanResult]] = [None] * concurrency

        self._parse_target()
        self._prepare_payload()

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

        # Optimization: Disable Nagle's algorithm (TCP_NODELAY)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        if self.scheme == 'https':
            context = ssl.create_default_context()
            # Mimic 'verify=False'
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Force HTTP/1.1 via ALPN if supported
            try:
                context.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass

            try:
                # We must pass the original hostname for SNI.
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target_host)
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

        # Start building the request line and headers
        request_lines = [f"{self.request.method} {path} HTTP/1.1"]
        
        headers = {}
        
        # Set Host header
        host_header = self.target_host
        if (self.scheme == 'https' and self.target_port != 443) or \
           (self.scheme == 'http' and self.target_port != 80):
            host_header += f":{self.target_port}"
        headers["Host"] = host_header

        # Add user-provided headers
        header_keys_lower = set()
        for k, v in self.request.headers.items():
            k_lower = k.lower()
            header_keys_lower.add(k_lower)
            # Skip headers managed by this engine or connection protocols
            if k_lower not in ['host', 'connection', 'content-length', 'transfer-encoding']:
                headers[k] = v

        # Ensure Content-Type if missing
        if 'content-type' not in header_keys_lower and self.request.method in ["POST", "PUT", "PATCH"] and self.total_payload_len > 0:
             headers["Content-Type"] = "application/x-www-form-urlencoded"

        # Add Content-Length (crucial for HTTP/1.1 persistence)
        if self.total_payload_len > 0 or self.request.method in ["POST", "PUT", "PATCH"]:
            headers["Content-Length"] = str(self.total_payload_len)
        
        # Add default User-Agent if not present
        if 'user-agent' not in header_keys_lower:
            headers["User-Agent"] = "Scalpel-CLI/5.4-SyncHTTP11"

        # Ensure Connection: keep-alive for persistence
        headers["Connection"] = "keep-alive"

        # Convert dictionary to list of lines
        for k, v in headers.items():
            request_lines.append(f"{k}: {v}")
            
        # Finalize headers block
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
            
            # 2. Prepare Headers
            headers_bytes = self._serialize_headers()

            # Record start time just before the first send
            start_time = time.perf_counter()

            # 3. Send Headers + First Stage
            initial_payload = headers_bytes + self.stages[0]
            sock.sendall(initial_payload)

            # 4. Synchronized subsequent stages
            for stage_index in range(1, len(self.stages)):
                # Wait for all threads to reach this point
                try:
                    # Use a timeout on the barrier
                    self.barrier.wait(timeout=BARRIER_TIMEOUT)
                # Handle the case where another thread aborted the barrier
                except threading.BrokenBarrierError:
                    # Raise an exception to be caught by the outer handler.
                    raise ConnectionError("Synchronization barrier broken (fail-fast).")
                
                # Send immediately
                sock.sendall(self.stages[stage_index])
            
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