# structures.py
"""
Data structures and constants for the Scalpel Racer application.
Standardized for integration across the Proxy Manager, Core, and Race Engines.
[Security] Includes sensitive header redaction for log sanitization.
[VECTOR OPTIMIZED] Uses __slots__ for memory efficiency in high-volume objects.
"""

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
# These must be stripped during HTTP/2 forwarding.
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

# Sensitive headers that should be redacted in logs
SENSITIVE_HEADERS = {
    'authorization', 
    'proxy-authorization', 
    'cookie', 
    'set-cookie', 
    'x-auth-token',
    'x-api-key',
    'access_token'
}

# --- Data Structures ---

class ScanResult:
    """
    Represents the result of a single race attempt (probe).
    [VECTOR] Optimized: __slots__ reduces memory usage by avoiding __dict__.
    """
    __slots__ = ('index', 'status_code', 'duration', 'body_hash', 'body_snippet', 'error')
    
    def __init__(self, index: int, status_code: int, duration: float, body_hash: Optional[str] = None, body_snippet: Optional[str] = None, error: Optional[str] = None):
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

class CapturedRequest:
    """
    Represents a captured HTTP request.
    Shared definition for proxy_core and scalpel_racer.
    [VECTOR] Optimized: __slots__ significantly lowers instantiation overhead.
    """
    __slots__ = ('id', 'method', 'url', 'headers', 'body', 'truncated', 'protocol', 'edited_body')
    
    def __init__(self, id: int, method: str, url: str, headers: List[Tuple[str, str]], body: bytes, truncated: bool = False, protocol: str = "HTTP/1.1", edited_body: Optional[bytes] = None):
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.truncated = truncated
        self.protocol = protocol
        self.edited_body = edited_body

    def get_attack_payload(self) -> bytes:
        """Returns the edited body if available, otherwise the original captured body."""
        return self.edited_body if self.edited_body is not None else self.body

    def headers_dict(self) -> Dict[str, str]:
        """Returns headers as a dictionary (lossy for duplicate keys).""" 
        return dict(self.headers)

    def _get_redacted_headers(self) -> str:
        """Returns a string representation of headers with sensitive values masked."""
        lines = [] 
        for k, v in self.headers: 
            if k.lower() in SENSITIVE_HEADERS: # [Security] Redact sensitive headers
                lines.append(f"{k}: [REDACTED]") 
            else:
                lines.append(f"{k}: {v}")
        return ", ".join(lines)

    def __str__(self) -> str:
        """CLI-friendly string representation with security redaction."""
        body_len = len(self.get_attack_payload())
        edited_flag = "[E]" if self.edited_body is not None else ""
        
        # Truncate URL for display
        display_url = self.url if len(self.url) < 70 else self.url[:67] + "..."
        trunc_flag = " [T]" if self.truncated else ""
        
        # We don't print full headers in the one-line summary
        return f"{self.id:<5} {self.protocol:<8} {self.method:<7} {display_url} ({body_len} bytes){edited_flag}{trunc_flag}"
    
    def detailed_str(self) -> str:
        """Detailed string representation with full headers and body."""
        return f"{self.__str__()}\n\nHeaders: {self._get_redacted_headers()}\nBody: {self.get_attack_payload().decode('utf-8', 'ignore')}"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the request to a dictionary format for logging or storage."""
        return {
            'id': self.id,
            'method': self.method,
            'url': self.url,
            'headers': self.headers_dict(),
            # Decode for JSON serialization
            'body': self.get_attack_payload().decode('utf-8', 'ignore'),
            'truncated': self.truncated,
            'protocol': self.protocol,
            'edited_body': self.edited_body.decode('utf-8', 'ignore') if self.edited_body else None
        }

class RaceResult:
    """
    Represents the result of a complete race (multiple probes).
    """
    __slots__ = ('id', 'scan_results', 'final_status_code', 'final_body_hash', 
                 'final_body_snippet', 'final_error', 'final_duration', 
                 'final_protocol', 'final_headers', 'final_body', 
                 'final_truncated', 'final_edited_body')
    
    def __init__(self, id: int, scan_results: List[ScanResult], final_status_code: int, final_body_hash: Optional[str] = None, final_body_snippet: Optional[str] = None, final_error: Optional[str] = None, final_duration: Optional[float] = None, final_protocol: Optional[str] = None, final_headers: Optional[Dict[str, str]] = None, final_body: Optional[bytes] = None, final_truncated: bool = False, final_edited_body: Optional[bytes] = None):
        self.id = id
        self.scan_results = scan_results
        self.final_status_code = final_status_code
        self.final_body_hash = final_body_hash
        self.final_body_snippet = final_body_snippet
        self.final_error = final_error
        self.final_duration = final_duration
        self.final_protocol = final_protocol
        self.final_headers = final_headers
        self.final_body = final_body
        self.final_truncated = final_truncated
        self.final_edited_body = final_edited_body

    def get_final_body(self) -> bytes:
        """Returns the final body if available, otherwise an empty byte string."""
        return self.final_body if self.final_body is not None else b""

    def get_final_headers(self) -> Dict[str, str]:
        """Returns the final headers if available, otherwise an empty dictionary."""
        return self.final_headers if self.final_headers is not None else {}
    
    def get_final_attack_payload(self) -> bytes:
        """Returns the edited body if available, otherwise the final body."""
        return self.final_edited_body if self.final_edited_body is not None else self.get_final_body()

    def to_dict(self) -> Dict[str, Any]:
        """Converts the race result to a dictionary format for logging or storage."""
        return {
            'id': self.id,
            'scan_results': [r.to_dict() for r in self.scan_results],
            'final_status_code': self.final_status_code,
            'final_body_hash': self.final_body_hash,
            'final_body_snippet': self.final_body_snippet,
            'final_error': self.final_error,
            'final_duration': self.final_duration,
            'final_protocol': self.final_protocol,
            'final_headers': self.final_headers,
            # We skip full body serialization for RaceResult in summaries as it can be large
            'final_truncated': self.final_truncated,
            'error': self.final_error
        }

class RaceConfiguration:
    """
    Represents the configuration for a race.
    """
    __slots__ = ('id', 'target_url', 'method', 'headers', 'body', 'num_probes', 
                 'timeout', 'protocol', 'edited_body')
    
    def __init__(self, id: int, target_url: str, method: str, headers: List[Tuple[str, str]], body: bytes, num_probes: int, timeout: float, protocol: str = "HTTP/1.1", edited_body: Optional[bytes] = None):
        self.id = id
        self.target_url = target_url
        self.method = method
        self.headers = headers
        self.body = body
        self.num_probes = num_probes
        self.timeout = timeout
        self.protocol = protocol
        self.edited_body = edited_body

    def to_dict(self) -> Dict[str, Any]:
        """Converts the race configuration to a dictionary format for logging or storage."""
        return {
            'id': self.id,
            'target_url': self.target_url,
            'method': self.method,
            'headers': dict(self.headers),
            'body': self.body.decode('utf-8', 'ignore'),
            'num_probes': self.num_probes,
            'timeout': self.timeout,
            'protocol': self.protocol,
            'edited_body': self.edited_body.decode('utf-8', 'ignore') if self.edited_body else None
        }

class ProxyManagerConfig:
    """
    Represents the configuration for the Proxy Manager.
    """
    __slots__ = ('listen_port', 'upstream_proxy', 'max_connections', 'log_level', 'sensitive_headers')
    
    def __init__(self, listen_port: int, upstream_proxy: Optional[str] = None, max_connections: int = 100, log_level: str = "INFO", sensitive_headers: List[str] = None):
        self.listen_port = listen_port
        self.upstream_proxy = upstream_proxy
        self.max_connections = max_connections
        self.log_level = log_level
        self.sensitive_headers = sensitive_headers if sensitive_headers else list(SENSITIVE_HEADERS)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the Proxy Manager configuration to a dictionary format for logging or storage."""
        return {
            'listen_port': self.listen_port,
            'upstream_proxy': self.upstream_proxy,
            'max_connections': self.max_connections,
            'log_level': self.log_level,
            'sensitive_headers': self.sensitive_headers
        }