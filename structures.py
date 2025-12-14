# structures.py
"""
Data structures and constants for the Scalpel Racer application.

Refactored to include strictly prohibited HTTP/2 connection headers as per RFC 9113.
"""

from typing import Dict, Optional

# --- Constants ---
MAX_RESPONSE_BODY_READ = 1024 * 1024  # 1MB max read for analysis
SYNC_MARKER = b"{{SYNC}}"

# RFC 9113 Section 8.2.2: Connection-Specific Header Fields
# These fields MUST be stripped by an intermediary before forwarding a request or response.
# This prevents HTTP Request Smuggling (H2.TE / H2.CL) and Protocol Errors.
HOP_BY_HOP_HEADERS = [
    'connection', 
    'keep-alive', 
    'proxy-authenticate', 
    'proxy-authorization',
    'te',  # Exception: 'trailers' allowed, checked in logic
    'trailers', 
    'transfer-encoding', 
    'upgrade',
    'host',  # HTTP/2 uses :authority
    'accept-encoding', 
    'upgrade-insecure-requests',
    'proxy-connection', # Non-standard but common
    'content-length', # Calculated per-frame
    'http2-settings'
]


# --- Data Structures ---
class ScanResult:
    """
    Represents the result of a single race attempt.

    Attributes:
        index (int): The index of the probe.
        status_code (int): The HTTP status code received.
        duration (float): The duration of the request in milliseconds.
        body_hash (str, optional): SHA-256 hash of the response body.
        body_snippet (str, optional): A snippet of the response body.
        error (str, optional): Error message if the request failed.
    """
    def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None,
                 body_snippet: str = None, error: str = None):
        self.index = index
        self.status_code = status_code
        self.duration = duration
        self.body_hash = body_hash
        self.body_snippet = body_snippet
        self.error = error


class CapturedRequest:
    """
    Represents a captured HTTP request.

    Attributes:
        id (int): The unique identifier of the captured request.
        method (str): The HTTP method (e.g., GET, POST).
        url (str): The full URL of the request.
        headers (Dict[str, str]): A dictionary of HTTP headers.
        body (bytes): The request body.
        edited_body (bytes, optional): The modified body for attack replay.
    """
    def __init__(self, id: int, method: str, url: str, headers: Dict[str, str], body: bytes):
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.edited_body: Optional[bytes] = None

    def __str__(self) -> str:
        body_len = len(self.get_attack_payload())
        edited_flag = "[E]" if self.edited_body is not None else ""
        display_url = self.url if len(self.url) < 80 else self.url[:77] + "..."
        return f"{self.id:<5} {self.method:<7} {display_url} ({body_len} bytes) {edited_flag}"

    def get_attack_payload(self) -> bytes:
        """
        Returns the payload to be used in an attack.
        Returns the edited body if present, otherwise the original body.
        """
        return self.edited_body if self.edited_body is not None else self.body