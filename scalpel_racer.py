import asyncio
import httpx
import time
import argparse
import sys
import re
import hashlib
import ssl
import os
import datetime
import tempfile
import ipaddress
import platform
import socket
import struct
import threading
from typing import List, AsyncIterator, Optional, Dict, Union
# Step A: Import urlunparse
from urllib.parse import urljoin, urlparse, urlunparse
from collections import defaultdict
import numpy as np

# -- Configuration --
DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100  # ms
MAX_RESPONSE_BODY_READ = 1024 * 1024 # 1MB max read for analysis
SYNC_MARKER = b"{{SYNC}}"
CA_CERT_FILE = "scalpel_ca.pem"
CA_KEY_FILE = "scalpel_ca.key"

# Define RFC 2616 Hop-by-Hop headers + others managed by httpx/proxies.
# 'host' is included because it must be managed by the proxy during forwarding.
HOP_BY_HOP_HEADERS = [
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    'host', 'accept-encoding', 'upgrade-insecure-requests',
    'proxy-connection'
]

# --- Import Libraries ---

# Cryptography
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("[!] 'cryptography' library not found. TLS interception (HTTPS proxy) will be disabled.")
    print("[!] Install it using: pip install cryptography")

# Hyper-h2 (HTTP/2 State Machine)
try:
    import h2.connection
    import h2.events
    import h2.config
    import h2.errors
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    print("[!] 'h2' library not found. Advanced strategies (SPA, First-Seq) will be disabled.")
    print("[!] Install it using: pip install h2")

# NetfilterQueue (Linux Packet Manipulation)
try:
    # Dynamically import NetfilterQueue if available
    from netfilterqueue import NetfilterQueue
    NFQUEUE_AVAILABLE = True
except ImportError:
    NFQUEUE_AVAILABLE = False
    # Define a placeholder if not available, mainly for type hinting and testing mocks
    NetfilterQueue = None
    # Only warn if on Linux, as it's not relevant for Windows/Mac
    if platform.system() == "Linux":
        print("[!] 'NetfilterQueue' not found. 'first-seq' strategy will be disabled.")
        print("[!] Install it using: pip install NetfilterQueue (requires libnetfilter-queue-dev)")
except Exception as e:
    # Catch other potential issues during import (e.g. permission errors if not root)
    NFQUEUE_AVAILABLE = False
    if platform.system() == "Linux":
        print(f"[!] 'NetfilterQueue' import failed: {e}. 'first-seq' strategy will be disabled.")


# Global CA Manager instance (initialized in main)
CA_MANAGER = None

# --- Data Structures ---

class ScanResult:
    """
    Represents the result of a single race attempt (one probe).
    """
    def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None, body_snippet: str = None, error: str = None):
        self.index = index
        self.status_code = status_code
        self.duration = duration
        self.body_hash = body_hash
        self.body_snippet = body_snippet
        self.error = error

class CapturedRequest:
    """
    Represents a captured HTTP request that can be replayed or raced.
    """
    def __init__(self, id: int, method: str, url: str, headers: Dict[str, str], body: bytes):
        """
        Initialize a CapturedRequest.

        Args:
            headers (Dict[str, str]): The HTTP headers (safe for replay, original casing preserved).
        """
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.edited_body: Optional[bytes] = None # Stores modified body for attack

    def __str__(self):
        body_len = len(self.get_attack_payload())
        edited_flag = "[E]" if self.edited_body is not None else ""
        display_url = self.url if len(self.url) < 80 else self.url[:77] + "..."
        return f"{self.id:<5} {self.method:<7} {display_url} ({body_len} bytes) {edited_flag}"

    def get_attack_payload(self) -> bytes:
        return self.edited_body if self.edited_body is not None else self.body

# --- Advanced Engines (PacketController & HTTP2RaceEngine) ---
# (No changes required for PacketController and HTTP2RaceEngine based on the prompt)

class PacketController:
    """
    Manages iptables rules and NetfilterQueue for the 'First Sequence Sync' strategy.
    """
    def __init__(self, target_ip: str, target_port: int):
        if not NFQUEUE_AVAILABLE:
             raise RuntimeError("PacketController initialized but NetfilterQueue is not available.")
        self.target_ip = target_ip
        self.target_port = target_port
        self.queue_num = 1
        self.nfqueue = NetfilterQueue()
        self.first_packet = None
        self.armed = False
        self.lock = threading.Lock()

    def setup_iptables(self):
        print("[*] Setting up iptables rule for traffic interception...")
        # Queue outgoing traffic to specific IP/Port
        cmd = f"iptables -A OUTPUT -d {self.target_ip} -p tcp --dport {self.target_port} -j NFQUEUE --queue-num {self.queue_num}"
        os.system(cmd)

    def teardown_iptables(self):
        print("[*] Cleaning up iptables rules...")
        cmd = f"iptables -D OUTPUT -d {self.target_ip} -p tcp --dport {self.target_port} -j NFQUEUE --queue-num {self.queue_num}"
        os.system(cmd)

    def process_packet(self, packet):
        if not self.armed:
            packet.accept()
            return

        with self.lock:
            if self.first_packet is None:
                print("[*] Intercepted First Sequence Packet. Holding...")
                self.first_packet = packet
                # Do NOT accept or drop yet. It stays in the queue.
            else:
                # This is a subsequent packet (2, 3, ...). Let it pass immediately.
                packet.accept()

    def start(self):
        self.nfqueue.bind(self.queue_num, self.process_packet)
        self.thread = threading.Thread(target=self.nfqueue.run)
        self.thread.daemon = True
        self.thread.start()

    def arm(self):
        with self.lock:
            self.armed = True
            self.first_packet = None

    def release_first_packet(self):
        with self.lock:
            if self.first_packet:
                print("[*] Releasing First Sequence Packet (Trigger)!")
                self.first_packet.accept()
                self.first_packet = None
            self.armed = False

    def stop(self):
        self.nfqueue.unbind()

class HTTP2RaceEngine:
    """
    Custom HTTP/2 engine using hyper-h2 and raw sockets for
    Single Packet Attacks (SPA) and frame manipulation.
    """
    def __init__(self, request: CapturedRequest, concurrency: int, strategy: str, warmup_ms: int):
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.warmup_ms = warmup_ms
        self.results = []
        self.conn = None # H2Connection
        self.sock = None
        self.target_host = urlparse(request.url).hostname
        self.target_port = urlparse(request.url).port or 443

    def _create_connection(self):
        # Create raw TCP socket
        sock = socket.create_connection((self.target_host, self.target_port), timeout=10)
        
        # Wrap in SSL/TLS with ALPN
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        
        self.sock = ctx.wrap_socket(sock, server_hostname=self.target_host)
        
        if self.sock.selected_alpn_protocol() != 'h2':
            raise RuntimeError("Server did not negotiate HTTP/2 via ALPN")

        # Initialize H2 State Machine
        config = h2.config.H2Configuration(client_side=True)
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def run_attack(self) -> List[ScanResult]:
        controller = None
        if self.strategy == "first-seq":
            if not NFQUEUE_AVAILABLE or not sys.platform.startswith("linux"):
                raise RuntimeError("First-Seq strategy requires Linux and NetfilterQueue.")
            
            # Resolve IP for iptables
            target_ip = socket.gethostbyname(self.target_host)
            controller = PacketController(target_ip, self.target_port)
            try:
                controller.setup_iptables()
                controller.start()
            except Exception as e:
                controller.teardown_iptables()
                raise e

        try:
            self._create_connection()
            
            payload = self.request.get_attack_payload()
            path = urlparse(self.request.url).path or "/"
            if urlparse(self.request.url).query:
                path += "?" + urlparse(self.request.url).query

            # 1. Prepare Streams (Send HEADERS for all)
            stream_ids = []
            print(f"[*] Opening {self.concurrency} HTTP/2 streams...")
            
            for i in range(self.concurrency):
                stream_id = self.conn.get_next_available_stream_id()
                stream_ids.append(stream_id)
                
                headers = [
                    (':method', self.request.method),
                    (':authority', self.target_host),
                    (':scheme', 'https'),
                    (':path', path),
                ]
                # Add original headers (excluding forbidden pseudo-headers)
                for k, v in self.request.headers.items():
                    if k.lower() not in [':method', ':authority', ':scheme', ':path', 'connection', 'upgrade', 'host']:
                        headers.append((k, v))

                self.conn.send_headers(stream_id, headers, end_stream=(len(payload) == 0))
            
            # Flush Headers to network
            self.sock.sendall(self.conn.data_to_send())

            # 2. Prepare Partial Body (if applicable)
            if len(payload) > 0:
                print(f"[*] Sending partial bodies (Size: {len(payload)-1} bytes)...")
                for stream_id in stream_ids:
                    # Send all but last byte
                    self.conn.send_data(stream_id, payload[:-1], end_stream=False)
                
                # Flush Partial Data
                self.sock.sendall(self.conn.data_to_send())

            # 3. Wait Warmup
            if self.warmup_ms > 0:
                time.sleep(self.warmup_ms / 1000.0)

            # 4. Prepare Trigger (Last Byte)
            for stream_id in stream_ids:
                if len(payload) > 0:
                    self.conn.send_data(stream_id, payload[-1:], end_stream=True)

            trigger_data = self.conn.data_to_send()

            # 5. Execute Attack
            print(f"[*] Executing Trigger (Size: {len(trigger_data)} bytes)...")
            
            if self.strategy == "first-seq" and controller:
                controller.arm()
                self.sock.sendall(trigger_data)
                
                # Small delay to ensure subsequent packets went out
                time.sleep(0.01) # 10ms
                
                # Release the trigger
                controller.release_first_packet()
            else:
                # Standard SPA
                self.sock.sendall(trigger_data)

            # 6. Read Responses
            print("[*] Reading responses...")
            self.sock.settimeout(5.0)
            
            # Map stream_id to response data
            responses = {sid: {'status': 0, 'body': b'', 'start': 0, 'end': 0} for sid in stream_ids}
            
            while True:
                try:
                    data = self.sock.recv(65535)
                    if not data: break
                    
                    events = self.conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            sid = event.stream_id
                            if sid in responses:
                                status = next((v for k, v in event.headers if k == b':status'), b'0')
                                responses[sid]['status'] = int(status)
                                responses[sid]['start'] = time.perf_counter()
                        elif isinstance(event, h2.events.DataReceived):
                            sid = event.stream_id
                            if sid in responses:
                                responses[sid]['body'] += event.data
                        elif isinstance(event, h2.events.StreamEnded):
                            sid = event.stream_id
                            if sid in responses:
                                responses[sid]['end'] = time.perf_counter()
                    
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[!] Read error: {e}")
                    break
            
            # Compile Results
            for i, sid in enumerate(stream_ids):
                r = responses[sid]
                duration = (r['end'] - r['start']) * 1000 if r['end'] > 0 else 0
                
                body_hash = hashlib.sha256(r['body']).hexdigest() if r['body'] else None
                snippet = r['body'][:100].decode(errors='ignore').replace('\n', ' ') if r['body'] else ""
                
                self.results.append(ScanResult(i, r['status'], duration, body_hash, snippet))

            self.conn.close_connection()
            self.sock.close()

        finally:
            if self.strategy == "first-seq" and controller:
                controller.stop()
                controller.teardown_iptables()

        return self.results

# --- Certificate Authority (CA) Manager ---
# (No changes required for CAManager based on the prompt)

class CAManager:
    """Manages Root CA generation, loading, and signing of forged certificates for MiTM."""
    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache = {} # Cache for generated SSL contexts (host -> ssl_context)

    def initialize(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            return
            
        if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
            self.load_ca()
        else:
            self.generate_ca()

    def load_ca(self):
        print(f"[*] Loading Root CA from {CA_CERT_FILE}")
        try:
            with open(CA_KEY_FILE, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_FILE, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        except Exception as e:
            print(f"[!] Failed to load existing CA: {e}. Regenerating.")
            self.generate_ca()

    def generate_ca(self):
        print(f"[*] Generating new Root CA. Install '{CA_CERT_FILE}' in your browser/OS trust store to intercept HTTPS.")
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Scalpel Racer Debugging CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Scalpel Racer"),
        ])
        
        try:
            # Handle different datetime implementations/versions
            if hasattr(datetime, 'timezone') and hasattr(datetime.datetime, 'now'):
                now = datetime.datetime.now(datetime.timezone.utc)
            else:
                now = datetime.datetime.utcnow()
        except TypeError:
             # Fallback for older Python versions if timezone handling fails
             now = datetime.datetime.utcnow()

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365*5))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

        # Save files
        try:
            with open(CA_KEY_FILE, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                ))
            with open(CA_CERT_FILE, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))
        except IOError as e:
            print(f"[!] Error saving CA files: {e}. TLS interception might fail.")

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        cert, key = self.generate_host_cert(hostname)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
             # Fallback for older OpenSSL versions
             context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass 

        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        cert_path = None
        key_path = None
        try:
            # Use delete=False and clean up manually for robustness
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self.cert_cache[hostname] = context
            return context
        finally:
            if cert_path:
                try: os.remove(cert_path)
                except OSError: pass
            if key_path:
                try: os.remove(key_path)
                except OSError: pass

    def generate_host_cert(self, hostname: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if isinstance(hostname, bytes):
                hostname = hostname.decode('utf-8', errors='ignore')

        try:
            ip = ipaddress.ip_address(hostname)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        try:
            if hasattr(datetime, 'timezone') and hasattr(datetime.datetime, 'now'):
                now = datetime.datetime.now(datetime.timezone.utc)
            else:
                now = datetime.datetime.utcnow()
        except TypeError:
             now = datetime.datetime.utcnow()

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert, key

# --- Proxy Server Logic (Refactored for Robust Parsing) ---

class CaptureServer:
    """
    A simple HTTP/HTTPS proxy server to capture traffic for analysis.
    """
    def __init__(self, port: int, target_override: str = None, scope_regex: str = None, enable_tunneling: bool = True):
        self.port = port
        
        self.target_override = target_override
        # Ensure target override always ends with a slash for safe urljoin (Phase 4)
        if self.target_override and not self.target_override.endswith('/'):
            self.target_override += '/'
            
        self.scope_pattern = re.compile(scope_regex) if scope_regex else None
        self.request_log: List[CapturedRequest] = []
        self.server = None
        self.stop_event = asyncio.Event()
        self.enable_tunneling = enable_tunneling
        self.proxy_client = None

    # Step B: Add the Helper Method
    def construct_target_url(self, scheme: str, request_line_target: str, normalized_headers: Dict[str, str], explicit_host: Optional[str]) -> str:
        """
        Robustly constructs the final target URL based on context, request line, and headers (Phase 4).

        Handles the "Tri-State" logic:
        1. Target Override (Configuration wins)
        2. Absolute-Form (Client specified full URL)
        3. Origin-Form/Authority-Form (Combine Scheme + Host Header/CONNECT host + Path)

        Args:
            scheme (str): The transport/context scheme ('http' or 'https') (Phase 1).
            request_line_target (str): The raw target from the request line (e.g., '/foo', 'http://bar.com/foo').
            normalized_headers (Dict[str, str]): The normalized (lowercase keys) request headers (Phase 3).
            explicit_host (Optional[str]): The host known from a CONNECT tunnel, if applicable (Phase 1).

        Returns:
            str: The final absolute URL.

        Raises:
            ValueError: If the target URL cannot be determined according to RFC 7230.
        """
        
        # 1. Parse the Request Line Target (Phase 2)
        # This handles both origin-form (/path) and absolute-form (http://host/path)
        try:
            parsed_target = urlparse(request_line_target)
        except ValueError:
            raise ValueError(f"Invalid format in request target: {request_line_target}")
        
        target_scheme = parsed_target.scheme
        target_host = parsed_target.netloc
        target_path = parsed_target.path
        target_query = parsed_target.query

        # Ensure path defaults to "/" if the request was absolute but had no path (e.g. "GET http://example.com")
        if (target_scheme or target_host) and not target_path:
             target_path = "/"
        
        # --- The Strategy: Tri-State URL Determination ---

        # 1. Target Override (Highest Priority)
        if self.target_override:
            # If override is active, we ignore the host/scheme from the request line and headers.
            # We only use the path and query from the request line target.
            
            path_to_join = target_path or "/"

            # Reconstruct path + query using urlunparse for safety
            # (scheme, netloc, path, params, query, fragment)
            path_with_query = urlunparse(('', '', path_to_join, parsed_target.params, target_query, ''))
                
            # Phase 4: Use urljoin. .lstrip('/') prevents double slashes.
            return urljoin(self.target_override, path_with_query.lstrip('/'))

        # 2. Absolute-Form in Request Line (RFC 7230 Section 5.3.2)
        if target_scheme and target_host:
            # The client sent "GET http://example.com/foo". Use it directly.
            # Note: We could validate against the Host header here, but generally trust the URI in a proxy context.
            return request_line_target

        # 3. Relative-Form (Origin-Form) (RFC 7230 Section 5.3.1)
        
        # Validation: RFC 7230 Section 5.3.1 dictates origin-form must start with "/" (or be "*")
        if request_line_target != "*" and not request_line_target.startswith("/"):
             raise ValueError(f"Invalid request target format (expected origin-form starting with '/'): {request_line_target}")

        final_scheme = scheme
        final_host = None

        # Determine Host (Phase 1 & 3)
        # Priority: explicit_host (from CONNECT) > Host header
        if explicit_host:
            final_host = explicit_host
        elif 'host' in normalized_headers:
            # Use the Host header (lookup is safe because headers are normalized).
            final_host = normalized_headers['host']
        
        if not final_host:
            # RFC 7230 Section 5.4 requires a Host header for HTTP/1.1 if not absolute URI
            raise ValueError("Cannot determine target host (Missing Host header or CONNECT context).")

        # Phase 4: The URL Builder (using urlunparse)
        return urlunparse((
            final_scheme,
            final_host,
            target_path,
            parsed_target.params,
            target_query,
            '' # fragment
        ))

    async def start(self):
        """
        Starts the proxy server and listens for incoming connections.
        """
        if globals().get('CA_MANAGER'):
            try:
                globals().get('CA_MANAGER').initialize()
            except Exception as e:
                print(f"[!] Failed to initialize CA Manager: {e}. Disabling TLS interception.")
                globals()['CA_MANAGER'] = None

        try:
            self.server = await asyncio.start_server(self.handle_client, '0.0.0.0', self.port)
        except OSError as e:
            print(f"[!] Error: Could not bind to port {self.port}. {e}")
            if __name__ == "__main__":
                sys.exit(1)
            self.stop_event.set()
            return

        print(f"[*] Proxy listening on 0.0.0.0:{self.port}")
        if self.target_override:
            print(f"[*] Target Override Base: {self.target_override}")
        if not self.enable_tunneling:
             print("[*] Tunneling disabled (Test Mode).")
        
        async with self.server:
            await self.stop_event.wait()
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            if self.proxy_client:
                await self.proxy_client.aclose()

    async def handle_client(self, reader, writer):
        """
        Handles an incoming client connection.
        """
        try:
            try:
                # Read the first line (Request Line)
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            except asyncio.TimeoutError:
                writer.close()
                return

            if not line:
                writer.close()
                return

            # Parse the request line (Phase 2)
            parts = line.decode(errors='ignore').strip().split(maxsplit=2)
            
            if not parts:
                 writer.close()
                 return

            method = parts[0].upper()

            if method == "CONNECT":
                # Authority-form (CONNECT host:port)
                if len(parts) != 3: return
                path = parts[1]
                if globals().get('CA_MANAGER'):
                    await self.handle_connect(reader, writer, path)
                else:
                    print("[!] Received CONNECT request but TLS interception is disabled. Dropping connection.")
                    writer.close()
                    return
            elif method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
                 # Origin-form (GET /path) or Absolute-form (GET http://host/path)
                 if len(parts) != 3: return
                 request_target, version = parts[1], parts[2]
                 # Scheme is 'http' for raw connections (Phase 1)
                 await self.process_http_request(reader, writer, method, request_target, version, initial_line=line, scheme="http")
            else:
                if line.startswith(b'\x16\x03'):
                      print("[!] Received direct TLS handshake. Configure client to use HTTP Proxy (CONNECT).")
                writer.close()
                return

        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass 
        except Exception as e:
            print(f"[!] Error handling request: {e}")
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass

    async def handle_connect(self, client_reader, client_writer, path):
        """
        Handles an HTTP CONNECT request for HTTPS tunneling/interception.
        """
        try:
            # Parse Authority-Form (host:port)
            host, port_str = path.split(':', 1)
        except ValueError:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid CONNECT target")
            await client_writer.drain()
            return

        try:
            ssl_context = globals().get('CA_MANAGER').get_ssl_context(host)
        except Exception as e:
            print(f"[!] Failed to generate certificate for {host}: {e}")
            client_writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\nCertificate generation failed")
            await client_writer.drain()
            return

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        loop = asyncio.get_running_loop()

        if not hasattr(loop, 'start_tls'):
            print("[!] Python environment does not support loop.start_tls (required for TLS interception).")
            return

        try:
            transport = client_writer.transport
            protocol = transport.get_protocol()

            await loop.start_tls(transport, protocol, ssl_context, server_side=True)

            # Process requests within the tunnel
            while not client_reader.at_eof() and not client_writer.is_closing():
                try:
                    line = await asyncio.wait_for(client_reader.readline(), timeout=60.0) 
                except asyncio.TimeoutError:
                    break 

                if not line:
                    break

                parts = line.decode(errors='ignore').strip().split(maxsplit=2)
                if len(parts) != 3:
                    break 

                method, request_target_in_tunnel, version = parts
                # Scheme is 'https' inside the tunnel, explicit_host is known (Phase 1)
                # We use the full 'path' (host:port) as the explicit host authority.
                await self.process_http_request(client_reader, client_writer, method, request_target_in_tunnel, version, initial_line=line, scheme="https", explicit_host=path)

        except (ssl.SSLError, ConnectionResetError):
            pass
        except (asyncio.IncompleteReadError):
            pass
        except Exception as e:
            print(f"[!] Unexpected error during TLS interception processing for {host}: {e}")

    # Step C: Update process_http_request
    async def process_http_request(self, reader, writer, method, request_target, version, initial_line, scheme, explicit_host=None):
        """
        Parses headers, body, constructs the URL, logs, and tunnels the request.
        """
        
        # Phase 3: Initialize structures for normalized and original headers
        normalized_headers: Dict[str, str] = {}
        # Keep original casing and order for capture/forwarding fidelity
        original_headers_list: List[tuple[str, str]] = [] 

        content_length = 0
        
        # Determine connection persistence
        connection_close = False
        if version.upper() == "HTTP/1.0":
            connection_close = True

        # --- Header Parsing and Canonicalization (Phase 3) ---
        while True:
            try:
                # Use a timeout for reading headers
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
                # Client disconnected or timed out before sending full headers
                if not writer.is_closing():
                    writer.close()
                return
            
            if line == b'\r\n' or not line: break

            try:
                line_str = line.decode(errors='ignore').strip()
                if ':' in line_str:
                    key, value = line_str.split(':', 1)
                    original_key = key.strip()
                    value = value.strip()
                    key_lower = original_key.lower()

                    # Store normalized and original
                    normalized_headers[key_lower] = value
                    original_headers_list.append((original_key, value))

                    if key_lower == 'content-length':
                        try:
                            content_length = int(value)
                        except ValueError:
                            content_length = 0 # Ignore invalid CL
                    elif key_lower == 'connection':
                        if 'close' in value.lower():
                            connection_close = True
                        elif 'keep-alive' in value.lower():
                            connection_close = False
            except Exception:
                # Tolerate malformed headers
                pass 

        # --- Body Reading (Hardening) ---
        body = b""
        if content_length > 0:
             try:
                 body = await reader.readexactly(content_length)
             except (asyncio.IncompleteReadError, ConnectionResetError) as e:
                 # Handle incomplete body read
                 actual_len = len(e.partial) if isinstance(e, asyncio.IncompleteReadError) else 0
                 print(f"[!] Incomplete body read. Expected {content_length}, got {actual_len}.")
                 
                 # Reject the request with 400
                 if not writer.is_closing():
                    try:
                        msg = b"Incomplete body read."
                        writer.write(f"HTTP/1.1 400 Bad Request\r\nContent-Length: {len(msg)}\r\nConnection: close\r\n\r\n".encode('ascii') + msg)
                        await writer.drain()
                    except ConnectionError:
                        pass
                 if not writer.is_closing():
                    writer.close()
                 return

        # --- URL Construction (Phase 1, 2, 4) ---
        try:
            # Pass normalized headers to the constructor
            final_url = self.construct_target_url(scheme, request_target, normalized_headers, explicit_host)
        except ValueError as e:
            # Handle failure to determine target (e.g., missing Host header, invalid format)
            print(f"[!] URL Construction Error: {e}")
            if not writer.is_closing():
                msg = str(e).encode('utf-8')
                # Send 400 Bad Request
                try:
                    writer.write(f"HTTP/1.1 400 Bad Request\r\nContent-Length: {len(msg)}\r\nConnection: close\r\n\r\n".encode('ascii') + msg)
                    await writer.drain()
                except ConnectionError:
                     pass
            
            if not writer.is_closing():
               writer.close()
            return

        # Create a dictionary from the original headers list for forwarding/capture fidelity
        # Note: If duplicate header keys existed, this conversion might lose some values, 
        # but this matches the behavior of the original code's header handling.
        original_headers_dict = dict(original_headers_list)

        # --- Request Processing (Scope check, Logging, Tunneling) ---

        if self.scope_pattern and not self.scope_pattern.search(final_url):
            if self.enable_tunneling:
                 # Use original headers for tunneling
                 await self.tunnel_request(final_url, method, original_headers_dict, body, writer)
            else:
                 if not writer.is_closing():
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nOut of scope.")
                    await writer.drain()
                 
            if connection_close and not writer.is_closing():
                writer.close()
            return

        req_id = len(self.request_log)
        
        # Filter Hop-by-Hop headers for the CapturedRequest object
        # Use the original casing dictionary for this to preserve fidelity
        safe_headers = {k: v for k, v in original_headers_dict.items()
                        if k.lower() not in HOP_BY_HOP_HEADERS}

        captured = CapturedRequest(req_id, method, final_url, safe_headers, body)
        self.request_log.append(captured)

        print(f"[+] Captured ({scheme.upper()}) {captured}")

        if self.enable_tunneling:
            # Use original headers for tunneling
            await self.tunnel_request(final_url, method, original_headers_dict, body, writer)
        else:
            # Dummy response
            if not writer.is_closing():
                conn_header = "close" if connection_close else "keep-alive"
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: {conn_header}\r\n\r\nCaptured.".encode('ascii'))
                await writer.drain()

        if connection_close and not writer.is_closing():
            writer.close()

    async def tunnel_request(self, url, method, headers, body, client_writer):
        """
        Forwards the request to the upstream server and relays the response back to the client.

        Args:
            headers (Dict): The headers to forward (original casing).
        """
        if self.proxy_client is None:
            self.proxy_client = httpx.AsyncClient(verify=False, timeout=60.0, http2=True)

        # Filter Hop-by-Hop headers before sending upstream
        forward_headers = {k: v for k, v in headers.items()
                           if k.lower() not in HOP_BY_HOP_HEADERS}

        try:
            # httpx will automatically set/update the Host header based on the URL
            async with self.proxy_client.stream(method, url, content=body, headers=forward_headers) as response:
                
                if client_writer.is_closing(): return

                # Relay status line
                response_line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
                client_writer.write(response_line.encode('utf-8'))

                # Relay headers (excluding Hop-by-Hop from response)
                # Using a specific list for response filtering common in proxies.
                response_filter = ['connection', 'keep-alive', 'transfer-encoding', 'proxy-connection', 'upgrade']
                for key, value in response.headers.items():
                    if key.lower() not in response_filter:
                        header_line = f"{key}: {value}\r\n"
                        client_writer.write(header_line.encode('utf-8'))

                client_writer.write(b"\r\n")
                await client_writer.drain()

                # Stream body
                async for chunk in response.aiter_raw():
                    if not chunk: continue
                    if client_writer.is_closing(): break
                    client_writer.write(chunk)
                    await client_writer.drain()

        except httpx.RequestError as e:
            print(f"[!] Upstream request failed: {e} (URL: {url})")
            if not client_writer.is_closing():
                try:
                    msg = b"Upstream request failed"
                    client_writer.write(f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(msg)}\r\n\r\n".encode('ascii') + msg)
                    await client_writer.drain()
                except Exception:
                    pass
        except Exception as e:
            print(f"[!] Error during tunneling: {e}")

# --- Legacy Attack Logic (httpx based) ---
# (No changes required for Attack Logic based on the prompt, except minor updates)

async def Last_Byte_Stream_Body(payload: bytes, barrier: asyncio.Barrier, warmup_ms: int) -> AsyncIterator[bytes]:
    if len(payload) <= 1:
        if warmup_ms > 0:
            await asyncio.sleep(warmup_ms / 1000.0)
        try:
            if barrier: await barrier.wait()
        except asyncio.BrokenBarrierError:
            pass
        yield payload
        return

    yield payload[:-1] 

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        if barrier: await barrier.wait() 
    except asyncio.BrokenBarrierError:
        pass

    yield payload[-1:]

async def Staged_Stream_Body(payload: bytes, barriers: List[asyncio.Barrier]) -> AsyncIterator[bytes]:
    parts = payload.split(SYNC_MARKER)
    barrier_idx = 0
    
    for i, part in enumerate(parts):
        if i > 0:
            if barrier_idx < len(barriers):
                try:
                    await barriers[barrier_idx].wait()
                    barrier_idx += 1
                except asyncio.BrokenBarrierError:
                    pass
        
        if part:
            yield part

async def send_probe_advanced(client: httpx.AsyncClient, request: CapturedRequest, payload: bytes, barriers: List[asyncio.Barrier], warmup_ms: int, index: int, is_staged: bool) -> ScanResult:
    start_time = time.perf_counter()
    body_hash = None
    body_snippet = None

    try:
        # Use copy to avoid modifying the original CapturedRequest headers
        req_headers = request.headers.copy()
        req_headers["User-Agent"] = "Scalpel-CLI/5.1-Refactored"
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        # Add default Content-Type if missing for methods that typically have a body
        # Use case-insensitive check on existing headers (which preserve original casing)
        has_content_type = any(k.lower() == 'content-type' for k in req_headers.keys())
        
        if not has_content_type and request.method in ["POST", "PUT", "PATCH"] and len(payload) > 0:
             req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        content_stream = None
        if is_staged:
            content_stream = Staged_Stream_Body(payload, barriers)
        else:
            barrier = barriers[0] if barriers else None
            content_stream = Last_Byte_Stream_Body(payload, barrier, warmup_ms)
            
        content = content_stream

        # httpx handles Host header automatically based on URL
        async with client.stream(
            method=request.method,
            url=request.url,
            content=content,
            headers=req_headers
        ) as response:

            body = await response.aread(MAX_RESPONSE_BODY_READ)
            
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                try:
                    body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')
                except Exception:
                    body_snippet = repr(body[:100])

            duration = (time.perf_counter() - start_time) * 1000
            return ScanResult(index, response.status_code, duration, body_hash, body_snippet)
        
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, error=str(e))

# --- Main Attack Dispatcher ---
# (No changes required for run_scan, analyze_results, edit_request_body, main based on the prompt)

async def run_scan(request: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str = "auto"):
    
    # 1. Strategy Dispatching
    attack_payload = request.get_attack_payload()
    sync_markers_count = attack_payload.count(SYNC_MARKER)

    use_h2_engine = False
    
    if sync_markers_count > 0:
        # Staged attacks force the 'auto' (httpx) strategy
        if strategy != "auto":
            print("[!] Warning: Staged Attacks ({{SYNC}}) are only supported with the 'auto' strategy. Switching to auto.")
        strategy = "auto"
        
    if strategy in ["spa", "first-seq"]:
        use_h2_engine = True

    # 2. Execution Path: Advanced H2 Engine
    if use_h2_engine:
        if not H2_AVAILABLE:
            print(f"[!] Error: Strategy '{strategy}' requires 'h2' library.")
            return

        print(f"\n[!] REPLAYING ATTACK (Advanced H2 Engine): {request.method} {request.url}")
        print(f"[*] Payload: {len(attack_payload)} bytes | Concurrency: {concurrency} | Strategy: {strategy} | Warmup: {warmup}ms")

        # Run synchronous H2 engine in thread pool
        def synchronous_h2_attack():
            engine = HTTP2RaceEngine(request, concurrency, strategy, warmup)
            try:
                return engine.run_attack()
            except Exception as e:
                return e

        loop = asyncio.get_running_loop()
        result_or_error = await loop.run_in_executor(None, synchronous_h2_attack)

        if isinstance(result_or_error, Exception):
            print(f"[!] Attack failed: {result_or_error}")
            return
        
        analyze_results(result_or_error)
        return

    # 3. Execution Path: Legacy httpx Engine
    # Setup barriers for legacy strategies
    barriers = []
    if sync_markers_count > 0:
        for _ in range(sync_markers_count):
            barriers.append(asyncio.Barrier(concurrency))
        strategy_label = f"Staged ({sync_markers_count} sync points)"
        if warmup > 0:
             print("[*] Note: Warmup delay is ignored in Staged Attack mode.")
             warmup = 0
    elif concurrency > 1:
        barriers.append(asyncio.Barrier(concurrency))
        strategy_label = "Last-Byte Sync (LBS)"
    else:
        strategy_label = "Single Request"

    print(f"\n[!] REPLAYING ATTACK (Standard httpx): {request.method} {request.url}")
    print(f"[*] Payload: {len(attack_payload)} bytes | Concurrency: {concurrency} | Strategy: {strategy_label} | Warmup: {warmup}ms | Mode: {'HTTP/2' if http2 else 'HTTP/1.1'}")

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency*2)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)

    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=timeout, verify=False) as client:
        tasks = [asyncio.create_task(send_probe_advanced(client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0)) for i in range(concurrency)]
        results = await asyncio.gather(*tasks)

    analyze_results(results)

def analyze_results(results: List[ScanResult]):
    """
    Analyzes and prints the results of the race condition scan.
    """
    successful = [r for r in results if r.error is None]
    
    print("\n--- Analysis Summary ---")

    # Group results by (Status Code, Status Code Family, Body Hash)
    signatures = defaultdict(list)
    for r in successful:
        key = (r.status_code, r.status_code//100, r.body_hash) 
        signatures[key].append(r)

    print("\n[Response Signatures]")
    
    if not signatures:
        print("  (No successful responses)")
    else:
        sorted_keys = sorted(signatures.keys(), key=lambda k: k[0])

        print(f"  {'Count':<6} {'Status':<6} {'Hash (SHA256)':<16} {'Snippet (First 100 chars)'}")
        print("  " + "-" * 90)
        for key in sorted_keys:
            status_code, _, body_hash = key
            group = signatures[key]
            count = len(group)
            snippet = group[0].body_snippet if group else ""
            hash_short = body_hash[:16] if body_hash else "N/A (Empty)"
            
            print(f"  {count:<6} {status_code:<6} {hash_short:<16} {snippet}")
            
        print("  " + "-" * 90)

        if len(signatures) > 1:
            print("\n  [!] WARNING: Multiple response signatures detected!")
            print("      This strongly indicates a potential race condition or inconsistent state.")
            
            families = set(k[1] for k in signatures.keys())
            if len(families) > 1:
                print("      Observed different status code families (e.g., success vs error).")
        else:
            print("\n  [+] Consistency: All responses are identical (Status Code and Body).")

    # Timing Analysis
    if successful:
        timings = [r.duration for r in successful]
        if len(timings) > 0:
            avg = sum(timings) / len(timings)
            min_t = min(timings)
            max_t = max(timings)
            
            if len(timings) > 1:
                 std_dev = (sum((t - avg) ** 2 for t in timings) / (len(timings)-1)) ** 0.5
            else:
                 std_dev = 0.0
            
            print("\n[Timing Metrics]")
            print(f"  Average: {avg:.2f}ms")
            print(f"  Min/Max: {min_t:.2f}ms / {max_t:.2f}ms")
            print(f"  Jitter (StdDev): {std_dev:.2f}ms")
            
            if len(timings) > 1:
                print("\n[Timing Distribution (Histogram)]")
                try:
                    bins_count = min(int(len(timings) / 5) + 5, 20) 
                    counts, bins = np.histogram(timings, bins=bins_count)
                    max_count = max(counts) if len(counts) > 0 else 0
                    
                    if max_count > 0:
                        for i in range(len(counts)):
                            bar_len = int((counts[i] / max_count) * 40)
                            print(f"  {bins[i]:>7.2f}ms - {bins[i+1]:>7.2f}ms | {'#' * bar_len} ({counts[i]})")
                except Exception:
                    print("  (Could not generate histogram)")

    errors = [r for r in results if r.error is not None]
    if errors:
        print("\n[Errors]")
        for err in errors:
            print(f"  Probe {err.index}: {err.error} ({err.duration:.2f}ms)")

def edit_request_body(request: CapturedRequest):
    print(f"\nEditing Body for Request {request.id}")
    print("Instructions: Use {{SYNC}} to insert synchronization points for Staged Attacks.")
    print("Current Body Preview (first 500 bytes):")
    current_body = request.get_attack_payload()
    print("-" * 30)
    print(current_body.decode(errors='ignore')[:500])
    print("-" * 30)
    
    print("\nEnter the new body (Stop with Ctrl+D (Unix) or Ctrl+Z+Enter (Windows) on a new line):")
    
    lines = []
    while True:
        try:
            try:
                line = sys.stdin.readline()
                if not line: 
                    break
                lines.append(line)
            except EOFError:
                break
        except KeyboardInterrupt:
            print("\n[!] Editing cancelled.")
            return
    
    new_body_str = "".join(lines)
    
    if not new_body_str.strip() and current_body:
         try:
            if input("Body is empty. Confirm? (y/N): ").lower() != 'y':
                print("[*] Body unchanged.")
                return
         except (EOFError, KeyboardInterrupt):
             print("\n[*] Body unchanged.")
             return

    try:
        new_body = new_body_str.encode('utf-8')
    except UnicodeEncodeError:
        print("[!] Error: Could not encode input as UTF-8. Using 'replace' strategy.")
        new_body = new_body_str.encode('utf-8', errors='replace')

    request.edited_body = new_body
    print(f"\n[*] Body updated. New length: {len(new_body)} bytes. Sync points: {new_body.count(SYNC_MARKER)}")

def main():
    if platform.system() == "Windows":
        try:
            if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception as e:
            print(f"[!] Could not set Windows event loop policy: {e}")

    if CRYPTOGRAPHY_AVAILABLE:
        global CA_MANAGER
        CA_MANAGER = CAManager()

    parser = argparse.ArgumentParser(description="Scalpel Racer v5.1 - Advanced Race Condition Tester with Robust Proxying")

    # Capture Mode
    parser.add_argument("-l", "--listen", type=int, default=8080, help="Listening port (default: 8080)")
    parser.add_argument("-t", "--target", type=str, help="Target Base URL for override (e.g. https://api.example.com/v1).")
    parser.add_argument("-s", "--scope", type=str, help="Regex scope filter.")

    # Attack Config
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrency (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("-w", "--warmup", type=int, default=DEFAULT_WARMUP, help=f"Warm-up delay (ms) (default: {DEFAULT_WARMUP})")
    
    parser.add_argument("--strategy", choices=["auto", "spa", "first-seq"], default="auto",
                        help="Attack strategy:\n"
                             "auto: Use httpx LBS/Staged Attack (Default).\n"
                             "spa: Use HTTP/2 Single Packet Attack (H2 engine).\n"
                             "first-seq: Use HTTP/2 First Sequence Sync (H2 engine, Linux root only).")
    
    parser.add_argument("--http2", action="store_true", help="Force HTTP/2 for 'auto' strategy.")

    args = parser.parse_args()

    # Pre-flight Check for First-Seq
    if args.strategy == 'first-seq':
        is_linux = sys.platform.startswith("linux")
        is_root = False
        # Check for root privileges only if geteuid exists (non-Windows)
        if hasattr(os, 'geteuid'):
            is_root = os.geteuid() == 0
        
        if not is_linux or not is_root:
             print("[!] Warning: 'first-seq' strategy requires Linux and Root privileges.")

    # 1. Start Capture Server
    capture_server = CaptureServer(args.listen, args.target, args.scope, enable_tunneling=True)

    try:
        asyncio.run(capture_server.start())
    except KeyboardInterrupt:
        print("\n[*] Capture stopped. Proceeding to selection menu.")
        capture_server.stop_event.set()
    except SystemExit:
        return
    except Exception as e:
        print(f"\n[!] Capture server stopped unexpectedly: {e}")

    if capture_server.proxy_client:
        try:
            asyncio.run(capture_server.proxy_client.aclose())
        except RuntimeError:
            # Loop might be closed if we exited via exception
            pass
        except Exception as e:
             print(f"[!] Error closing proxy client: {e}")

    # 2. Selection Menu
    log = capture_server.request_log
    if not log:
        print("\n[*] No requests captured matching scope.")
        sys.exit(0)

    def display_menu():
        print("\n\n--- Captured Requests ---")
        print(f"{'ID':<5} {'Method':<7} {'URL (Size) [Status]'} ")
        print("-" * 100)
        for req in log:
            print(f"{str(req)}")
        print("-" * 100)
        print("Commands: [ID] to race | 'e [ID]' to edit body | 'q' to quit")

    while True:
        display_menu()
        
        try:
            choice = input("Enter command: ").strip()
        except (EOFError, KeyboardInterrupt):
             sys.exit(0)
        
        if choice.lower() == 'q':
            sys.exit(0)

        parts = choice.split(maxsplit=1)
        if not parts: continue
        command = parts[0].lower()

        if command == 'e' and len(parts) == 2:
             try:
                 req_id = int(parts[1])
                 selected_req = next((r for r in log if r.id == req_id), None)
                 if selected_req:
                     edit_request_body(selected_req)
                 else:
                     print("Invalid ID.")
             except ValueError:
                 print("Invalid ID format for edit command.")
             continue

        try:
            req_id = int(command)
            selected_req = next((r for r in log if r.id == req_id), None)
            if selected_req:
                try:
                      asyncio.run(run_scan(selected_req, args.concurrency, args.http2, args.warmup, args.strategy))
                except Exception as e:
                      print(f"\n[!] Error during attack execution: {e}")
                
                try:
                    input("\nPress Enter to return to the menu...")
                except (EOFError, KeyboardInterrupt):
                    sys.exit(0)
                
            else:
                print("Invalid ID.")
        except ValueError:
            print("Invalid command.")

if __name__ == "__main__":
    main()