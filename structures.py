#Filename: structures.py
"""
CORE DATA STRUCTURES
Single Source of Truth (SSOT).
Optimized for memory efficiency and rapid serialization.
Standardized for integration across the Proxy Manager, Core, and Race Engines.
Strict type enforcement at the runtime boundary.
"""

import time
from typing import Dict, List, Tuple, Optional, Any, TypedDict, Set

# -- Constants --

MAX_RESPONSE_BODY_READ: int = 1024 * 1024      # 1MB limit for response analysis
MAX_CAPTURE_BODY_SIZE: int = 10 * 1024 * 1024  # 10MB limit for proxy capture storage
SYNC_MARKER: bytes = b"{{SYNC}}"               # Marker for splitting payloads

# RFC 9113: Headers to strip during forwarding
# [VECTOR OPTIMIZATION] Use set for O(1) lookup speed in hot paths
HOP_BY_HOP_HEADERS: Set[str] = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade', 'host',
    'accept-encoding', 'upgrade-insecure-requests', 'proxy-connection',
    'content-length', 'http2-settings'
}

# OpSec: Headers to redact in UI logs
# Use set for O(1) lookup speed
SENSITIVE_HEADERS: Set[str] = {
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'x-auth-token', 'x-api-key', 'access_token', 'authentication', 'bearer'
}

# Pre-computed byte sets for low-level proxy operations (Zero-Copy)
SENSITIVE_HEADERS_BYTES: Set[bytes] = {h.encode('ascii') for h in SENSITIVE_HEADERS}
HOP_BY_HOP_HEADERS_BYTES: Set[bytes] = {h.encode('ascii') for h in HOP_BY_HOP_HEADERS}

# -- Types --

class CapturedHeaders(TypedDict):
    """
    Represents captured HTTP/2 headers, separating pseudo-headers from normal headers.
    """
    pseudo: Dict[str, str]
    headers: List[Tuple[str, str]]

class ScanResult:
    """
    Result of a single probe within a race batch.
    Optimized __slots__ - significantly reduces memory usage.
    """
    __slots__ = ('index', 'status_code', 'duration', 'body_hash', 'body_snippet', 'error')

    def __init__(
        self,
        index: int,
        status_code: int,
        duration: float,
        body_hash: Optional[str] = None,
        body_snippet: Optional[str] = None,
        error: Optional[str] = None
    ) -> None:
        self.index = index
        self.status_code = status_code
        self.duration = duration
        self.body_hash = body_hash
        self.body_snippet = body_snippet
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        """Converts the scan result to a dictionary for logging/storage."""
        return {
            'index': self.index,
            'status_code': self.status_code,
            'duration': self.duration,
            'body_hash': self.body_hash,
            'body_snippet': self.body_snippet,
            'error': self.error
        }

    def __repr__(self) -> str:
        return f"<ScanResult #{self.index} Status:{self.status_code}>"

class CapturedRequest:
    """
    Standardized request object.
    Used by Proxy to capture, and Race Engines to replay.
    Optimized: __slots__ lowers instantiation overhead.
    Aligned with PCAPNG Enhanced Packet Blocks for 5-tuple tracking.
    """
    # pylint: disable=redefined-builtin
    __slots__ = (
        'id', 'method', 'url', 'headers', 'body', 'truncated', 'protocol',
        'edited_body', 'timestamp_start', 'timestamp_end', 'client_addr', 'server_addr'
    )

    def __init__(
        self,
        request_id: int,
        method: str,
        url: str,
        headers: List[Tuple[str, str]],
        body: bytes,
        truncated: bool = False,
        protocol: str = "HTTP/1.1",
        edited_body: Optional[bytes] = None,
        timestamp_start: float = 0.0,
        timestamp_end: float = 0.0,
        client_addr: Optional[Tuple[str, int]] = None,
        server_addr: Optional[Tuple[str, int]] = None
    ) -> None:
        """
        Initializes a CapturedRequest object with full telemetry support.
        Strict typing enforced: headers must be a list of tuples, body must be bytes.
        """
        # Map request_id argument to self.id to resolve builtin shadowing while
        # maintaining backward compatibility with consumers (e.g., scalpel_racer.py).
        self.id: int = request_id
        self.method: str = method
        self.url: str = url

        # Strict type check for headers
        if not isinstance(headers, list):
            raise TypeError(f"Headers must be List[Tuple[str, str]], got {type(headers).__name__}")
        self.headers: List[Tuple[str, str]] = headers

        # Strict type check for body
        if not isinstance(body, bytes):
            raise TypeError(f"Request body must be bytes, got {type(body).__name__}")
        self.body: bytes = body

        self.truncated: bool = truncated
        self.protocol: str = protocol

        if edited_body is not None and not isinstance(edited_body, bytes):
            raise TypeError(f"edited_body must be bytes, got {type(edited_body).__name__}")
        self.edited_body: Optional[bytes] = edited_body

        # Telemetry Logic: If 0.0 is passed, we assume capture time is NOW.
        self.timestamp_start: float = timestamp_start if timestamp_start > 0 else time.time()
        self.timestamp_end: float = timestamp_end
        self.client_addr: Optional[Tuple[str, int]] = client_addr
        self.server_addr: Optional[Tuple[str, int]] = server_addr

    def get_attack_payload(self) -> bytes:
        """Returns the edited body if it exists, else the captured body."""
        return self.edited_body if self.edited_body is not None else self.body

    def headers_dict(self) -> Dict[str, str]:
        """Returns headers as a dictionary. Note: Lossy for duplicate keys."""
        return dict(self.headers)

    def display_str(self) -> str:
        """Sanitized string for CLI display."""
        payload = self.get_attack_payload()
        body_len = len(payload)
        edit_flag = "[E]" if self.edited_body is not None else ""
        trunc_flag = " [T]" if self.truncated else ""

        clean_url = self.url
        if len(clean_url) > 60:
            clean_url = clean_url[:57] + "..."

        return (f"[{self.protocol}] {self.method:<6} {clean_url} "
                f"({body_len}b){edit_flag}{trunc_flag}")

    def _get_redacted_headers(self) -> str:
        """Returns a string representation of headers with sensitive values masked."""
        lines: List[str] = []
        for k, v in self.headers:
            if k.lower() in SENSITIVE_HEADERS:
                lines.append(f"{k}: [REDACTED]")
            else:
                lines.append(f"{k}: {v}")
        return ", ".join(lines)

    def detailed_str(self) -> str:
        """Detailed string representation with full headers and body."""
        payload = self.get_attack_payload()
        return (
            f"{self.display_str()}\n\n"
            f"Headers: {self._get_redacted_headers()}\n"
            f"Body: {payload.decode('utf-8', 'ignore')}"
        )

    def __str__(self) -> str:
        return self.display_str()

    def to_dict(self) -> Dict[str, Any]:
        """Converts the request to a dictionary format for logging or storage."""
        payload = self.get_attack_payload()
        edited_str = self.edited_body.decode('utf-8', 'ignore') if self.edited_body else None

        return {
            'id': self.id,
            'method': self.method,
            'url': self.url,
            'headers': self.headers_dict(),
            'body': payload.decode('utf-8', 'ignore'),
            'truncated': self.truncated,
            'protocol': self.protocol,
            'edited_body': edited_str,
            'timestamp_start': self.timestamp_start,
            'timestamp_end': self.timestamp_end,
            'client_addr': self.client_addr,
            'server_addr': self.server_addr
        }

    def __repr__(self) -> str:
        return f"<CapturedRequest #{self.id} {self.method} {self.url}>"
