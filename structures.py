# structures.py
"""
Data structures and constants for the Scalpel Racer application.

This module defines the core data classes used to represent captured HTTP requests
and the results of race condition testing attempts. It also includes constants
for configuration limits and header management.
"""

from typing import Dict, Optional

# --- Constants ---
MAX_RESPONSE_BODY_READ = 1024 * 1024  # 1MB max read for analysis
SYNC_MARKER = b"{{SYNC}}"

# RFC 2616 Hop-by-Hop headers + others managed by httpx/proxies
HOP_BY_HOP_HEADERS = [
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    'host', 'accept-encoding', 'upgrade-insecure-requests',
    'proxy-connection'
]


# --- Data Structures ---
class ScanResult:
    """
    Represents the result of a single race attempt (one probe).

    This class encapsulates all relevant metrics and data obtained from sending
    a single request as part of a race condition attack, allowing for subsequent
    statistical analysis and anomaly detection.

    Attributes:
        index (int): The sequence index of the request in the batch.
        status_code (int): The HTTP status code returned by the server.
        duration (float): The time taken for the request to complete, in seconds.
        body_hash (str, optional): A hash (e.g., MD5/SHA) of the response body for uniqueness checks.
        body_snippet (str, optional): A short preview of the response body text.
        error (str, optional): A description of any error that occurred during the request.
    """

    def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None,
                 body_snippet: str = None, error: str = None):
        """
        Initializes a new instance of the ScanResult class.

        Args:
            index (int): The sequence index of the request.
            status_code (int): The HTTP status code received.
            duration (float): The round-trip time of the request in seconds.
            body_hash (str, optional): A hash of the response body. Defaults to None.
            body_snippet (str, optional): A snippet of the response body. Defaults to None.
            error (str, optional): Error message if the request failed. Defaults to None.
        """
        self.index = index
        self.status_code = status_code
        self.duration = duration
        self.body_hash = body_hash
        self.body_snippet = body_snippet
        self.error = error


class CapturedRequest:
    """
    Represents a captured HTTP request that can be replayed or raced.

    This class stores the essential components of an HTTP request (method, URL, headers, body)
    captured by the proxy. It allows for modification of the request body (editing)
    before being used in an attack.

    Attributes:
        id (int): A unique identifier for the captured request.
        method (str): The HTTP method (e.g., "GET", "POST").
        url (str): The full URL of the request.
        headers (Dict[str, str]): A dictionary of HTTP headers.
        body (bytes): The original raw body of the request.
        edited_body (Optional[bytes]): An optional modified version of the body to be used in attacks.
    """

    def __init__(self, id: int, method: str, url: str, headers: Dict[str, str], body: bytes):
        """
        Initializes a new instance of the CapturedRequest class.

        Args:
            id (int): The unique ID assigned to this request.
            method (str): The HTTP method.
            url (str): The target URL.
            headers (Dict[str, str]): The HTTP headers.
            body (bytes): The request body payload.
        """
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.edited_body: Optional[bytes] = None

    def __str__(self) -> str:
        """
        Returns a string representation of the captured request.

        The format includes the ID, method, truncated URL, body size, and an indicator
        if the body has been edited.

        Returns:
            str: A formatted string describing the request.
        """
        body_len = len(self.get_attack_payload())
        edited_flag = "[E]" if self.edited_body is not None else ""
        display_url = self.url if len(self.url) < 80 else self.url[:77] + "..."
        return f"{self.id:<5} {self.method:<7} {display_url} ({body_len} bytes) {edited_flag}"

    def get_attack_payload(self) -> bytes:
        """
        Retrieves the payload to be used for an attack.

        If the request body has been edited, the edited version is returned.
        Otherwise, the original captured body is returned.

        Returns:
            bytes: The payload data (body) for the attack.
        """
        return self.edited_body if self.edited_body is not None else self.body
