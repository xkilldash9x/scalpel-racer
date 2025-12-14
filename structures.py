# structures.py
"""
Data structures and constants for the Scalpel Racer application.
Standardized for integration across the Proxy Manager, Core, and Race Engines.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, TypedDict

class CapturedHeaders(TypedDict):
    """
    Represents captured HTTP/2 headers, separating pseudo-headers from normal headers.
    """
    pseudo: Dict[str, str]
    headers: List[Tuple[str, str]]

# --- Constants ---
MAX_RESPONSE_BODY_READ = 1024 * 1024  # 1MB max read for analysis
SYNC_MARKER = b"{{SYNC}}"

# RFC 9113 Section 8.2.2: Connection-Specific Header Fields
# These must be stripped during HTTP/2 forwarding to prevent smuggling/protocol errors.
HOP_BY_HOP_HEADERS = [
    'connection', 
    'keep-alive', 
    'proxy-authenticate', 
    'proxy-authorization',
    'te', 
    'trailers', 
    'transfer-encoding', 
    'upgrade',
    'host', 
    'accept-encoding', 
    'upgrade-insecure-requests',
    'proxy-connection', 
    'content-length', 
    'http2-settings'
]

# --- Data Structures ---
@dataclass
class ScanResult:
    """
    Represents the result of a single race attempt (probe).
    """
    index: int
    status_code: int
    duration: float
    body_hash: Optional[str] = None
    body_snippet: Optional[str] = None
    error: Optional[str] = None

@dataclass
class CapturedRequest:
    """
    Represents a captured HTTP request.
    Shared definition for proxy_core and scalpel_racer.
    """
    id: int
    method: str
    url: str
    headers: List[Tuple[str, str]] # Stored as list of tuples for H2/Order preservation
    body: bytes
    truncated: bool = False
    protocol: str = "HTTP/1.1"
    edited_body: Optional[bytes] = None

    def get_attack_payload(self) -> bytes:
        """Returns the edited body if available, otherwise the original captured body."""
        return self.edited_body if self.edited_body is not None else self.body

    @property
    def headers_dict(self) -> Dict[str, str]:
        """Returns headers as a dictionary (lossy for duplicate keys)."""
        return dict(self.headers)

    def __str__(self) -> str:
        """CLI-friendly string representation."""
        body_len = len(self.get_attack_payload())
        edited_flag = "[E]" if self.edited_body is not None else ""
        # Truncate URL for display
        display_url = self.url if len(self.url) < 70 else self.url[:67] + "..."
        trunc_flag = " [T]" if self.truncated else ""
        return f"{self.id:<5} {self.protocol:<8} {self.method:<7} {display_url} ({body_len} bytes){edited_flag}{trunc_flag}"
