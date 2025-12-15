# scalpel_racer.py
"""
Scalpel Racer -- Advanced Race Condition Testing Tool.
Main entry point orchestrating the Proxy Manager and Race Attacks.
Refactored to utilize ProxyManager and Dual-Stack Proxy Core.

REPORT (2025 Audit - Refactored):
- COMPLIANCE: Upgraded to NIST P-256 (ECC) for 128-bit security (NIST SP 800-131A Rev 2).
- SECURITY: Enforced TLS 1.2+ and Perfect Forward Secrecy (ECDHE).
- ARCHITECTURE: Implemented Supervisor Pattern for asyncio.TaskGroup.
- ARCHITECTURE: Migrated to ProxyManager for modular interception.
- OPTIMIZATION: Integrated uvloop for high-performance event loop policy.
- OPTIMIZATION: Shared Ephemeral Keys for MITM certificates to reduce CPU load.
- FIXED: Replaced deprecated datetime.utcnow() with datetime.now(datetime.UTC).
- FIXED: Secured Windows temporary file handling with TemporaryDirectory.
"""

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
import logging
from typing import List, AsyncIterator, Optional, Dict, Union, Tuple
from collections import defaultdict

# VECTOR OPTIMIZATION: Try importing uvloop for significant performance boost on Unix
try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    uvloop = None
    UVLOOP_AVAILABLE = False

# [Refactor] Graceful degradation if numpy is missing
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

# Updated imports
from structures import (
    ScanResult, 
    CapturedRequest, 
    MAX_RESPONSE_BODY_READ,
    SYNC_MARKER,
    HOP_BY_HOP_HEADERS
)

# New Architecture Import
try:
    from proxy_manager import ProxyManager
except ImportError:
    # Fallback or error if the user hasn't created this file yet
    ProxyManager = None

try:
    from low_level import HTTP2RaceEngine
    H2_AVAILABLE = True
except ImportError:
    HTTP2RaceEngine = None
    H2_AVAILABLE = False

try:
    from packet_controller import NFQUEUE_AVAILABLE
except ImportError:
    NFQUEUE_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    ec = None
    Encoding = None
    PrivateFormat = None
    NoEncryption = None
    NameOID = None
    ExtendedKeyUsageOID = None

# Global Logger
logger = logging.getLogger(__name__)

class Colors:
    """ANSI Color Helper for CLI UX"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @staticmethod
    def style(text, color=RESET, bold=False):
        """Applies color and bold style to text if stdout is a TTY."""
        if not sys.stdout.isatty():
            return text
        prefix = color
        if bold:
            prefix += Colors.BOLD
        return f"{prefix}{text}{Colors.RESET}"

DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100 
CA_CERT_FILE = "scalpel_ca.pem"
CA_KEY_FILE = "scalpel_ca.key"

# Global CA Manager
CA_MANAGER = None

def fix_sudo_ownership(filepath: str):
    """If running with sudo, change file ownership back to original user."""
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        sudo_uid = os.environ.get('SUDO_UID')
        sudo_gid = os.environ.get('SUDO_GID')
        if sudo_uid and sudo_gid:
            try:
                uid = int(sudo_uid)
                gid = int(sudo_gid)
                os.chown(filepath, uid, gid)
                if filepath.endswith('.key'):
                    os.chmod(filepath, 0o600)
                else:
                    os.chmod(filepath, 0o644)
            except Exception as e:
                logger.warning(f"Could not fix ownership for {filepath}: {e}")

def safe_spawn(tg: asyncio.TaskGroup, coro, result_list, index):
    """Supervisor wrapper for tasks to prevent fail-fast cascades."""
    async def wrapper():
        try:
            res = await coro
            result_list[index] = res
        except Exception as e:
            logger.debug(f"Probe {index} failed: {e}")
            result_list[index] = ScanResult(index, 0, 0, error=str(e))
    tg.create_task(wrapper())

class CAManager:
    """
    Manages CA and Host Certificate Generation.
    Uses NIST P-256 (SECP256R1) for 128-bit security compliance.
    """
    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache = {}
        # Optimization: Reuse one ephemeral key for all host certificates to save CPU
        self.shared_leaf_key = None

    def initialize(self):
        if not CRYPTOGRAPHY_AVAILABLE: return
        
        # [Vector Optimization] Generate shared key once
        if not self.shared_leaf_key:
            self.shared_leaf_key = ec.generate_private_key(ec.SECP256R1())

        if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
            self.load_ca()
        else:
            self.generate_ca()

    def load_ca(self):
        logger.info(f"Loading Root CA from {CA_CERT_FILE}")
        try:
            with open(CA_KEY_FILE, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_FILE, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        except Exception:
            logger.warning("Failed to load existing CA. Regenerating.")
            self.generate_ca()

    def generate_ca(self):
        logger.info(f"Generating new Root CA (ECC NIST P-256).")
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Scalpel Racer Debugging CA (ECC)"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Project Scalpel"),
        ])
        
        try: 
            now = datetime.datetime.now(datetime.timezone.utc)
        except AttributeError: 
            now = datetime.datetime.utcnow()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365*5))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )

        if CRYPTOGRAPHY_AVAILABLE:
            builder = builder.add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                              data_encipherment=False, key_agreement=False, key_cert_sign=True,
                              crl_sign=True, encipher_only=False, decipher_only=False),
                critical=True
            )

        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())
        
        with open(CA_KEY_FILE, "wb") as f:
            f.write(self.ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        fix_sudo_ownership(CA_KEY_FILE)
        
        with open(CA_CERT_FILE, "wb") as f:
            f.write(self.ca_cert.public_bytes(Encoding.PEM))
        fix_sudo_ownership(CA_CERT_FILE)

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        if hostname in self.cert_cache: return self.cert_cache[hostname]
        
        cert, key = self.generate_host_cert(hostname)
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try: 
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError: 
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
            
        # FIPS / Security Compliance
        try: 
            context.set_ciphers('ECDHE+AESGCM:!CHACHA20:!kRSA:!PSK:!SRP')
        except ssl.SSLError: 
            pass
            
        try: 
            context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError: 
            pass 
        
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_path = os.path.join(temp_dir, "cert.pem")
            key_path = os.path.join(temp_dir, "key.pem")
            
            with open(cert_path, "wb") as f: 
                f.write(cert.public_bytes(Encoding.PEM))
            with open(key_path, "wb") as f: 
                f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
            
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
        self.cert_cache[hostname] = context
        return context

    def generate_host_cert(self, hostname: str):
        # [Vector Optimization] Reuse the shared private key
        key = self.shared_leaf_key if self.shared_leaf_key else ec.generate_private_key(ec.SECP256R1())
        
        if isinstance(hostname, bytes):
            hostname = hostname.decode('utf-8', errors='ignore')

        san_list = [x509.DNSName(hostname)]
        try:
            if re.match(r'^[\d\.:]+$', hostname):
                san_list = [x509.IPAddress(ipaddress.ip_address(hostname))]
        except ValueError: 
            pass
            
        try: 
            now = datetime.datetime.now(datetime.timezone.utc)
        except AttributeError: 
            now = datetime.datetime.utcnow()
        
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        )
        cert = builder.sign(self.ca_key, hashes.SHA256())
        return cert, key

class CaptureApp:
    """
    Main application wrapper connecting the CLI with the ProxyManager.
    """
    def __init__(self, port, target_override, scope_regex):
        self.request_log: List[CapturedRequest] = []
        self.capture_count = 0
        self.ready_event = asyncio.Event()
        
        if not ProxyManager:
            logger.critical("ProxyManager module not found. Cannot start capture.")
            sys.exit(1)

        self.manager = ProxyManager(
            tcp_port=port, 
            ssl_context_factory=CA_MANAGER.get_ssl_context if CA_MANAGER else None,
            external_callback=self.on_capture
        )
        self.target_override = target_override
        self.scope_regex = scope_regex

    def on_capture(self, protocol, data):
        if protocol == "CAPTURE":
            # data is CapturedRequest
            data.id = len(self.request_log)
            self.request_log.append(data)
            self.capture_count += 1
            if self.capture_count % 50 == 0:
                print(f"[*] Captured {self.capture_count} requests...", end='\r', flush=True)

    async def run(self):
        if CA_MANAGER: 
            CA_MANAGER.initialize()
            
        self.ready_event.set()
        
        # Start the ProxyManager
        await self.manager.run(
            target_override=self.target_override, 
            scope_regex=self.scope_regex
        )

# -- RACE CONDITION LOGIC (Optimized) --

async def Last_Byte_Stream_Body(payload: bytes, barrier: asyncio.Barrier, warmup_ms: int) -> AsyncIterator[bytes]:
    """
    Streams request body, pausing before the last byte for synchronization.
    Vector Optimization: Uses memoryview to zero-copy slice the payload.
    """
    if len(payload) <= 1:
        if warmup_ms > 0:
            await asyncio.sleep(warmup_ms / 1000.0)
        try:
            if barrier: await barrier.wait()
        except asyncio.BrokenBarrierError:
            pass
        yield payload
        return

    # Zero-copy slicing
    mv = memoryview(payload)
    yield mv[:-1] 

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        if barrier: await barrier.wait() 
    except asyncio.BrokenBarrierError:
        pass

    yield mv[-1:]

async def Staged_Stream_Body(payload: bytes, barriers: List[asyncio.Barrier]) -> AsyncIterator[bytes]:
    """
    Splits payload by {{SYNC}} markers for multi-step synchronization.
    """
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

async def send_probe_advanced(client: httpx.AsyncClient, request: CapturedRequest, payload: bytes, barriers: List[asyncio.Barrier], warmup_ms: int, index: int, is_staged: bool, base_headers: httpx.Headers) -> ScanResult:
    """
    Sends a single probe request using httpx with the specified synchronization strategy.
    Recalculates Content-Length to ensure valid headers during edits/streaming.
    [VECTOR] Uses pre-calculated base_headers to reduce overhead.
    """
    start_time = time.perf_counter()
    body_hash = None
    body_snippet = None

    try:
        # [VECTOR] Efficient Header Construction
        # Reuse parsed headers to save CPU time per probe
        req_headers = base_headers.copy()
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        # Fix Content-Length
        actual_length = len(payload)
        req_headers["Content-Length"] = str(actual_length)

        if "content-type" not in req_headers and request.method in ["POST", "PUT", "PATCH"] and actual_length > 0:
             req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        content_stream = None
        if is_staged:
            content_stream = Staged_Stream_Body(payload, barriers)
        else:
            barrier = barriers[0] if barriers else None
            content_stream = Last_Byte_Stream_Body(payload, barrier, warmup_ms)
            
        content = content_stream if content_stream else payload

        async with client.stream(
            method=request.method,
            url=request.url,
            content=content,
            headers=req_headers
        ) as response:

            body = await response.aread()
            
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')

        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, response.status_code, duration, body_hash, body_snippet)
        
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, error=str(e))

async def run_scan(request: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str = "auto"):
    """
    Orchestrates the race condition attack.
    Combines the new CaptureApp structure with the original robust barrier logic.
    """
    attack_payload = request.get_attack_payload()
    sync_markers_count = attack_payload.count(SYNC_MARKER)

    # H2 Engine Delegation
    use_h2_engine = False
    if strategy in ["spa", "first-seq"]:
        use_h2_engine = True

    if use_h2_engine:
        if not H2_AVAILABLE:
            logger.error(f"Strategy '{strategy}' requires 'h2' library (low_level module).")
            return []

        logger.info(f"REPLAYING ATTACK (Advanced H2 Engine): {request.method} {request.url}")

        def synchronous_h2_attack():
            if HTTP2RaceEngine is None:
                return []
            engine = HTTP2RaceEngine(request, concurrency, strategy, warmup)
            try:
                return engine.run_attack()
            except Exception as e:
                return [ScanResult(0, 0, 0, error=str(e))]

        # Run synchronous H2 engine in a thread to avoid blocking asyncio loop
        return await asyncio.to_thread(synchronous_h2_attack)

    # Standard HTTPX (H1/H2) with Barriers
    barriers = []
    if sync_markers_count > 0:
        for _ in range(sync_markers_count):
            barriers.append(asyncio.Barrier(concurrency))
        strategy_label = f"Staged ({sync_markers_count} sync points)"
        # Staged attacks control their own timing via barriers
        warmup = 0 
    elif concurrency > 1:
        barriers.append(asyncio.Barrier(concurrency))
        strategy_label = "Last-Byte Sync (LBS)"
    else:
        strategy_label = "Single Request"

    logger.info(f"REPLAYING ATTACK (Standard httpx): {request.method} {request.url}")
    logger.info(f"Mode: {strategy_label} | Concurrency: {concurrency}")

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency*2)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)
    
    # [VECTOR] Pre-calculate base headers object to avoid repetitive parsing overhead
    base_headers = httpx.Headers(request.headers)
    base_headers["User-Agent"] = "Scalpel-CLI/5.4-Optimized"

    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=timeout, verify=False) as client:
        results = [None] * concurrency
        
        if hasattr(asyncio, 'TaskGroup'):
            async with asyncio.TaskGroup() as tg:
                for i in range(concurrency):
                    safe_spawn(
                        tg, 
                        send_probe_advanced(
                            client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0, base_headers
                        ), 
                        results, 
                        i
                    )
        else:
            # Fallback
            tasks = [
                send_probe_advanced(client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0, base_headers) 
                for i in range(concurrency)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r if isinstance(r, ScanResult) else ScanResult(i, 0, 0, error=str(r)) for i, r in enumerate(results)]

    return results

def analyze_results(results: List[ScanResult]):
    """
    Analyzes and prints statistical data from the scan results.
    """
    if not results:
        print("\n-- Analysis Summary --\n  (No results to analyze)")
        return
        
    successful = [r for r in results if r.error is None]
    
    print(Colors.style("\n-- Analysis Summary --", Colors.BOLD))

    signatures = defaultdict(list)
    for r in successful:
        key = (r.status_code, r.status_code//100, r.body_hash) 
        signatures[key].append(r)

    print(Colors.style("\n[Response Signatures]", Colors.CYAN))
    
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
            snippet = group[0].body_snippet if group and group[0].body_snippet else ""
            hash_short = body_hash[:16] if body_hash else "N/A (Empty)"
            
            # Colorize status code
            sc_color = Colors.GREEN # Default 2xx
            if 300 <= status_code < 400: sc_color = Colors.YELLOW
            elif status_code >= 400: sc_color = Colors.RED

            sc_str = Colors.style(f"{status_code:<6}", sc_color, bold=True)

            print(f"  {count:<6} {sc_str} {hash_short:<16} {snippet}")
        
        print("  " + "-" * 90)

        if len(signatures) > 1:
            logging.warning("Multiple response signatures detected! Indicates potential race condition.")
            print(Colors.style("\n  [!] WARNING: Multiple response signatures detected!", Colors.RED, bold=True))

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
            
            print(Colors.style("\n[Timing Metrics]", Colors.CYAN))
            print(f"  Average: {avg:.2f}ms")
            print(f"  Min/Max: {min_t:.2f}ms / {max_t:.2f}ms")
            print(f"  Jitter (StdDev): {std_dev:.2f}ms")
            
            if len(timings) > 1 and NUMPY_AVAILABLE:
                print(Colors.style("\n[Timing Distribution (Histogram)]", Colors.CYAN))
                try:
                    bins_count = min(int(len(timings) / 5) + 5, 20) 
                    counts, bins = np.histogram(timings, bins=bins_count)
                    max_count = max(counts) if len(counts) > 0 else 0
                    
                    if max_count > 0:
                        for i in range(len(counts)):
                            bar_len = int((counts[i] / max_count) * 40)
                            bar_char = '█'
                            # Colorize bar
                            bar_display = Colors.style((bar_char * bar_len), Colors.BLUE) if counts[i] > 0 else ''
                            print(f"  {bins[i]:>7.2f}ms -- {bins[i+1]:>7.2f}ms | {bar_display:<40} ({counts[i]})")
                except Exception:
                    pass

    errors = [r for r in results if r.error is not None]
    if errors:
        print(Colors.style("\n[Errors]", Colors.RED))
        for err in errors:
            print(f"  Probe {err.index}: {err.error} ({err.duration:.2f}ms)")

def edit_request_body(request: CapturedRequest):
    """
    Provides a CLI for editing the body of a captured request.
    """
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
             return

    try:
        new_body = new_body_str.encode('utf-8')
    except UnicodeEncodeError:
        logger.error("Could not encode input as UTF-8. Using 'replace' strategy.")
        new_body = new_body_str.encode('utf-8', errors='replace')

    request.edited_body = new_body
    print(f"\n[*] Body updated. New length: {len(new_body)} bytes. Sync points: {new_body.count(SYNC_MARKER)}")

def main():
    if platform.system() == "Windows":
        try:
            if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    elif UVLOOP_AVAILABLE:
        # [Vector Optimization] Use uvloop if available on non-Windows systems
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    parser = argparse.ArgumentParser(description="Scalpel Racer v6.0 (Optimized) -- ProxyManager Integrated")
    
    parser.add_argument("-l", "--listen", type=int, default=8080, help="Listening port (default: 8080)")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrency (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("-w", "--warmup", type=int, default=DEFAULT_WARMUP, help=f"Warm-up delay (ms) (default: {DEFAULT_WARMUP})")
    parser.add_argument("-t", "--target", type=str, help="Target Base URL for override.")
    parser.add_argument("-s", "--scope", type=str, help="Regex scope filter.")
    
    parser.add_argument("--strategy", choices=["auto", "spa", "first-seq"], default="auto",
                        help="Attack strategy: auto, spa, or first-seq")
    
    parser.add_argument("--http2", action="store_true", help="Force HTTP/2 for 'auto' strategy.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")

    args = parser.parse_args()

    # Initialize logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
        stream=sys.stderr 
    )

    if CRYPTOGRAPHY_AVAILABLE:
        globals()['CA_MANAGER'] = CAManager()

    # Create the App (Delegates to ProxyManager)
    app = CaptureApp(args.listen, args.target, args.scope)

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        print("\n[*] Capture stopped. Proceeding to selection menu.", file=sys.stderr)
    except SystemExit:
        return
    except Exception as e:
        logger.critical(f"App stopped: {e}")

    if not app.request_log:
        print("\n[*] No requests captured matching scope.")
        sys.exit(0)

    # Interactive Menu
    while True:
        print(Colors.style("\n\n-- Captured Requests --", Colors.BOLD))
        print(f"{'ID':<5} {'Method':<7} {'URL (Size) [Status]'} ")
        print("-" * 100)
        
        display_log = app.request_log[-50:]
        if len(app.request_log) > 50:
             print(f"  ... (Showing last 50 of {len(app.request_log)} requests) ...")

        for req in display_log:
            # Colorize Method
            m_color = Colors.GREEN
            if req.method == "POST": m_color = Colors.BLUE
            elif req.method in ["PUT", "PATCH"]: m_color = Colors.YELLOW
            elif req.method == "DELETE": m_color = Colors.RED

            method_str = Colors.style(f"{req.method:<7}", m_color)

            # Manually construct string to inject color (bypassing __str__)
            body_len = len(req.get_attack_payload())
            edited_flag = Colors.style("[E]", Colors.YELLOW) if req.edited_body is not None else ""

            display_url = req.url if len(req.url) < 70 else req.url[:67] + "..."
            trunc_flag = " [T]" if req.truncated else ""

            print(f"{req.id:<5} {req.protocol:<8} {method_str} {display_url} ({body_len} bytes){edited_flag}{trunc_flag}")
    
        print("-" * 100)
        print("Commands: [ID] to race | 'e [ID]' to edit body | 'q' to quit")
        
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
                 selected_req = next((r for r in app.request_log if r.id == req_id), None)
                 if selected_req:
                     edit_request_body(selected_req)
                 else:
                     print("Invalid ID.")
            except ValueError:
                 print("Invalid ID format.")
            continue

        try:
            req_id = int(command)
            selected_req = next((r for r in app.request_log if r.id == req_id), None)
            if selected_req:
                try:
                      # New run logic integration
                      results = asyncio.run(
                          run_scan(selected_req, args.concurrency, args.http2, args.warmup, args.strategy)
                      )
                      analyze_results(results)
                except Exception as e:
                       logger.error(f"Error during attack execution: {e}", exc_info=True)
                
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