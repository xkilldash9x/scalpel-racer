#Filename: proxy_common.py
"""
PROXY COMMON DEFINITIONS
Shared logic, constants, and base classes for the Scalpel Proxy Core.
Implements Single Source of Truth (SSOT) for proxy configuration.
Updated for RFC 9113 (HTTP/2) Compliance.
"""

import os
import asyncio
import ssl
import re
import socket
import time
from typing import Optional, Callable, Tuple, List, Union, Dict, cast, FrozenSet

# [APEX] Dependencies for Shared Logic
from structures import CapturedHeaders, SENSITIVE_HEADERS_BYTES
from compat import hpack

# -- Constants --
STRICT_HEADER_PATTERN = re.compile(rb'^([!#$%&\'*+\-.^_`|~0-9a-zA-Z]+):[ \t]*(.*)$')
UPSTREAM_CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
KEEPALIVE_INTERVAL = 10.0
FLOW_CONTROL_TIMEOUT = 30.0
MAX_HEADER_LIST_SIZE = 262144
STREAM_QUEUE_SIZE = 1024
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
GOAWAY_MAX_FRAME = b'\x00\x00\x08\x07\x00\x00\x00\x00\x00\x7f\xff\xff\xff\x00\x00\x00\x00'
READ_CHUNK_SIZE = 65536
COMPACTION_THRESHOLD = 65536

# RFC 9113 Section 8.2.2: Connection-specific fields MUST be omitted.
H2_FORBIDDEN_HEADERS: FrozenSet[bytes] = frozenset({
    b'connection', b'keep-alive', b'proxy-connection', b'transfer-encoding', b'upgrade'
})

# Type alias for Queue items: (Payload, EndStream, AckLength/FlowControlledLength)
QueueItem = Tuple[Union[List[Tuple[bytes, bytes]], bytes], bool, int]

class ProxyError(Exception):
    """Base exception for Proxy operations."""

class PayloadTooLargeError(ProxyError):
    """Raised when the payload exceeds safe capture limits."""

class H2StreamContext:
    """
    Maintains the state of a single HTTP/2 stream within the proxy.
    Tracks flow control events, data queues, and capture state.
    Moved to common to reduce complexity in the protocol handler.
    """
    __slots__ = (
        'stream_id', 'scheme', 'method', 'downstream_closed', 'upstream_closed',
        'upstream_flow_event', 'downstream_flow_event',
        'upstream_queue', 'downstream_queue', 'sender_tasks',
        'captured_headers', 'request_body_chunks', 'current_body_size',
        'capture_finalized', 'truncated', 'start_time', 'client_addr'
    )

    def __init__(self, stream_id: int, scheme: str, client_addr: Optional[Tuple[str, int]]):
        """Initializes the stream context."""
        self.stream_id = stream_id
        self.scheme = scheme
        self.method = "GET"
        self.downstream_closed = False
        self.upstream_closed = False
        self.upstream_flow_event = asyncio.Event()
        self.upstream_flow_event.set()
        self.downstream_flow_event = asyncio.Event()
        self.downstream_flow_event.set()
        # Strictly typed queues
        self.upstream_queue: asyncio.Queue[Optional[QueueItem]] = asyncio.Queue(
            maxsize=STREAM_QUEUE_SIZE
        )
        self.downstream_queue: asyncio.Queue[Optional[QueueItem]] = asyncio.Queue(
            maxsize=STREAM_QUEUE_SIZE
        )
        self.sender_tasks: List[asyncio.Task[None]] = []
        self.captured_headers: CapturedHeaders = {"pseudo": {}, "headers": []}
        self.request_body_chunks: List[bytes] = []
        self.current_body_size = 0
        self.capture_finalized = False
        self.truncated = False
        self.start_time = time.time()
        self.client_addr = client_addr

# -- Stateless Helper Functions --

def wrap_h2_security_headers(
    headers: List[Tuple[bytes, bytes]]
) -> List[Tuple[bytes, bytes]]:
    """Wraps sensitive headers to prevent HPACK indexing."""
    if not hpack:
        return headers
    return [
        hpack.NeverIndexedHeaderTuple(k, v)
        if k.lower() in SENSITIVE_HEADERS_BYTES
        else (k, v)
        for k, v in headers
    ]

def validate_h2_header_value(value: bytes) -> bool:
    """
    RFC 9113 Section 8.2.1: Field values MUST NOT contain CR, LF, or NUL.
    """
    return b'\r' not in value and b'\n' not in value and b'\x00' not in value

def prepare_forwarded_headers(
    headers: List[Tuple[bytes, bytes]],
    is_upstream: bool,
    upstream_host: str = ""
) -> Tuple[List[Tuple[bytes, bytes]], Optional[bytes]]:
    """
    Cleans and filters headers for forwarding.
    Enforces strict RFC 9113 compliance (validation, stripping, CONNECT rules).
    """
    decoded = []
    protocol = None
    host_val = None

    # RFC 9113 Section 8.5: Detect CONNECT to handle pseudo-headers
    is_connect = False
    for k, v in headers:
        k_b = k if isinstance(k, bytes) else k.encode('utf-8')
        v_b = v if isinstance(v, bytes) else v.encode('utf-8')

        # RFC 9113 Section 8.2.1: No leading/trailing whitespace
        v_b = v_b.strip()

        # Strict validation
        if not validate_h2_header_value(v_b):
            continue

        if k_b == b':method' and v_b == b'CONNECT':
            is_connect = True

        if k_b == b':protocol':
            protocol = v_b
        elif k_b.lower() == b'host':
            host_val = v_b
        decoded.append((k_b, v_b))

    out = []
    pseudo = {}
    for k_b, v_b in decoded:
        if k_b.startswith(b':'):
            # RFC 9113 Section 8.5: Omit :scheme and :path for CONNECT
            if is_connect and k_b in (b':scheme', b':path'):
                continue
            pseudo[k_b] = v_b
        else:
            k_lower = k_b.lower()
            if k_lower in H2_FORBIDDEN_HEADERS:
                continue
            # RFC 9113 Section 8.2.2: TE MUST be 'trailers' or absent
            if k_lower == b'te' and v_b.lower() != b'trailers':
                continue
            if k_lower == b'host':
                continue
            out.append((k_b, v_b))

    if is_upstream and b':authority' not in pseudo:
        if host_val:
            pseudo[b':authority'] = host_val
        elif upstream_host:
            pseudo[b':authority'] = upstream_host.encode('utf-8')

    final = list(pseudo.items())
    final.extend(out)
    return wrap_h2_security_headers(final), protocol

def convert_h2_to_h1(
    headers: List[Tuple[bytes, bytes]], default_auth: str
) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
    """
    Converts H2 pseudo-headers to H1 request line and headers.
    Handles RFC 9113 CONNECT target derivation.
    """
    method = b'GET'
    path = None
    authority = default_auth.encode()
    clean = []
    for k, v in headers:
        v = v.strip()
        if k == b':method':
            method = v
        elif k == b':path':
            path = v
        elif k == b':authority':
            authority = v
        elif k.lower() == b'host':
            continue
        elif not k.startswith(b':'):
            clean.append((k, v))

    clean.insert(0, (b'Host', authority))
    clean.append((b'Connection', b'close'))

    # RFC 9113: CONNECT target is the authority
    if method == b'CONNECT':
        target = authority
    else:
        target = path if path is not None else b'/'

    return b"%s %s HTTP/1.1\r\n" % (method, target), clean

def process_h2_headers_for_capture(
    headers: List[Tuple[object, object]]
) -> CapturedHeaders:
    """Converts raw headers into the CapturedHeaders structure."""
    pseudo: Dict[str, str] = {}
    normal: List[Tuple[str, str]] = []
    cookies: List[str] = []
    authority: Optional[str] = None

    for k, v in headers:
        k_s = k.decode('utf-8') if isinstance(k, bytes) else str(k)
        v_s = v.decode('utf-8') if isinstance(v, bytes) else str(v)
        v_s = v_s.strip()

        if k_s.lower() == 'host' and not authority:
            authority = v_s
        if k_s.lower() in {x.decode('ascii') for x in H2_FORBIDDEN_HEADERS}:
            continue

        if k_s.startswith(':'):
            pseudo[k_s] = v_s
            if k_s == ':authority':
                authority = v_s
            elif k_s.lower() == 'cookie':
                cookies.append(v_s)
        else:
            normal.append((k_s, v_s))

    if cookies:
        normal.append(('cookie', '; '.join(cookies)))
    if ':authority' not in pseudo and authority:
        pseudo[':authority'] = authority

    return cast(CapturedHeaders, {"pseudo": pseudo, "headers": normal})

class BaseProxyHandler:
    """
    Base class containing shared logic for HTTP/1.1 and HTTP/2 handlers.
    Manages upstream connections and logging.
    """
    __slots__ = (
        'explicit_host', 'upstream_verify_ssl', 'upstream_ca_bundle', 'callback',
        'ssl_context_factory', 'upstream_host', 'upstream_port', 'client_addr'
    )

    def __init__(
        self,
        explicit_host: str,
        upstream_verify_ssl: bool,
        upstream_ca_bundle: Optional[str],
        manager_callback: Callable[[str, object], None],
        ssl_context_factory: Optional[Callable[[str], ssl.SSLContext]] = None,
        client_addr: Optional[Tuple[str, int]] = None
    ):
        """Initializes the BaseProxyHandler with connection parameters."""
        self.explicit_host = explicit_host
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.callback = manager_callback
        self.ssl_context_factory = ssl_context_factory
        self.upstream_host: str = ""
        self.upstream_port: int = 443
        self.client_addr = client_addr

    def log(self, level: str, msg: object) -> None:
        """Emits a log message via the callback."""
        if self.callback:
            try:
                self.callback(level, msg)
            except Exception: # pylint: disable=broad-exception-caught
                pass

    def _parse_target(self, explicit_host: str, default_port: int = 443) -> Tuple[str, int]:
        """Parses a host string into (hostname, port)."""
        if not explicit_host:
            return "", 0
        if explicit_host.startswith('['):
            end = explicit_host.find(']')
            if end != -1:
                host = explicit_host[1:end]
                rem = explicit_host[end+1:]
                if rem.startswith(':'):
                    try:
                        return host, int(rem[1:])
                    except ValueError:
                        pass
                else:
                    return host, default_port
        if ':' in explicit_host:
            host, port_str = explicit_host.rsplit(':', 1)
            try:
                return host, int(port_str)
            except ValueError:
                pass
        return explicit_host, default_port

    async def _connect_upstream(
        self,
        host: str,
        port: int,
        alpn_protocols: Optional[List[str]] = None
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establishes a connection to the upstream server with strict SSL/TLS options.
        """
        ctx = ssl.create_default_context()
        # OpSec: Respect SSLKEYLOGFILE for debugging if set
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            ctx.keylog_filename = keylog

        if self.upstream_verify_ssl:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            if self.upstream_ca_bundle:
                ctx.load_verify_locations(cafile=self.upstream_ca_bundle)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if alpn_protocols:
            try:
                ctx.set_alpn_protocols(alpn_protocols)
            except NotImplementedError:
                pass

        try:
            server_hostname = host if (self.upstream_verify_ssl or alpn_protocols) else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname),
                timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            try:
                sock = writer.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            return reader, writer
        except ProxyError:
            raise
        except Exception as e:
            if not isinstance(e, asyncio.TimeoutError):
                raise ProxyError(f"Upstream connection failed: {e}") from e
            raise

    def _is_url_allowed(self, url: str, scope_pattern: Optional[re.Pattern[str]]) -> bool:
        """Checks if the URL matches the scope pattern."""
        if not scope_pattern:
            return True
        return bool(scope_pattern.search(url))
