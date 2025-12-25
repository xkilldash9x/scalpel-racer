#Filename: compat.py
"""
[VECTOR] COMPATIBILITY LAYER
Centralizes optional dependencies (H2, NetfilterQueue) and provides
strictly typed Mocks/Sentinels.
Eliminates duplicate try/except blocks and ensures type safety across modules.
"""

import sys
from typing import Any, List, Tuple, Optional, Dict

# -- HTTP/2 (h2) Support --

H2_AVAILABLE = False
hpack: Any = None

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
        ConnectionTerminated, TrailersReceived, ResponseReceived, Event
    )
    from h2.errors import ErrorCodes
    from h2.settings import SettingCodes
    import hpack
    H2_AVAILABLE = True

except ImportError:
    # Mock Classes for Static Type Checking & Runtime Safety
    
    class SettingCodes:
        """Mock Setting Codes for H2."""
        HEADER_TABLE_SIZE = 0x1
        ENABLE_PUSH = 0x2
        MAX_CONCURRENT_STREAMS = 0x3
        INITIAL_WINDOW_SIZE = 0x4
        MAX_FRAME_SIZE = 0x5
        MAX_HEADER_LIST_SIZE = 0x6
        ENABLE_CONNECT_PROTOCOL = 0x8

    class ErrorCodes:
        """Mock Error Codes for H2."""
        NO_ERROR = 0x0
        PROTOCOL_ERROR = 0x1
        INTERNAL_ERROR = 0x2
        CONNECT_ERROR = 0xa

    class H2Configuration:  # type: ignore
        """Mock Configuration for H2."""
        def __init__(
            self, 
            client_side: bool = True, 
            header_encoding: Any = None, 
            validate_inbound_headers: bool = True, 
            validate_outbound_headers: bool = True, 
            normalize_inbound_headers: bool = True, 
            normalize_outbound_headers: bool = True
        ) -> None: 
            pass

    class H2Connection:  # type: ignore
        """Mock Connection for H2."""
        def __init__(self, config: Any = None) -> None: 
            self.config = config
            self.local_settings = {
                SettingCodes.ENABLE_PUSH: 0,
                SettingCodes.MAX_HEADER_LIST_SIZE: 65536,
                SettingCodes.ENABLE_CONNECT_PROTOCOL: 0,
            }
            self.outbound_flow_control_window = 65535
            self.remote_flow_control_window = lambda x: 65535
            self.remote_settings: Dict[int, int] = {}

        def initiate_connection(self) -> None:
            """Mock initiation."""
            pass

        def data_to_send(self) -> bytes:
            """Mock data retrieval."""
            return b""

        def send_headers(self, *args: Any, **kwargs: Any) -> None:
            """Mock sending headers."""
            pass

        def send_data(self, *args: Any, **kwargs: Any) -> None:
            """Mock sending data."""
            pass

        def receive_data(self, data: bytes) -> List[Any]:
            """Mock receiving data."""
            return []

        def acknowledge_received_data(self, *args: Any) -> None:
            """Mock acknowledgement."""
            pass

        def get_next_available_stream_id(self) -> int:
            """Mock stream ID generation."""
            return 1

        def reset_stream(self, *args: Any) -> None:
            """Mock stream reset."""
            pass

        def ping(self, *args: Any) -> None:
            """Mock ping."""
            pass

        def close_connection(self, *args: Any) -> None:
            """Mock close."""
            pass

    # -- Event Mocks --

    class Event:
        """Base Mock Event."""
        pass # type: ignore

    class RequestReceived(Event):
        """Mock RequestReceived Event."""
        stream_id: int
        headers: List[Tuple[bytes, bytes]]
        stream_ended: bool

    class DataReceived(Event):
        """Mock DataReceived Event."""
        stream_id: int
        data: bytes
        flow_controlled_length: int
        stream_ended: bool

    class StreamEnded(Event):
        """Mock StreamEnded Event."""
        stream_id: int

    class StreamReset(Event):
        """Mock StreamReset Event."""
        stream_id: int
        error_code: int

    class WindowUpdated(Event):
        """Mock WindowUpdated Event."""
        stream_id: int
        delta: int

    class ConnectionTerminated(Event):
        """Mock ConnectionTerminated Event."""
        error_code: int
        last_stream_id: int
        additional_data: Optional[bytes]

    class TrailersReceived(Event):
        """Mock TrailersReceived Event."""
        stream_id: int
        headers: List[Tuple[bytes, bytes]]
        stream_ended: bool

    class ResponseReceived(Event):
        """Mock ResponseReceived Event."""
        stream_id: int
        headers: List[Tuple[bytes, bytes]]
        stream_ended: bool


# -- NetfilterQueue Support (Linux) --

NFQUEUE_AVAILABLE = False
NetfilterQueue: Any = None

try:
    if sys.platform.startswith("linux"):
        from netfilterqueue import NetfilterQueue
        NFQUEUE_AVAILABLE = True
    else:
        NetfilterQueue = None
except ImportError:
    pass

# -- Safe Fallback for Consumers --

class MockPacketController:
    """
    Stub used if PacketController logic is missing or fails to import.
    Prevents ImportError in consuming modules.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int = 0) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.active = False

    def start(self) -> None:
        """Mock start."""
        pass

    def stop(self) -> None:
        """Mock stop."""
        pass