#Filename: compat.py
"""
[VECTOR] COMPATIBILITY LAYER
Centralizes optional dependencies (H2, NetfilterQueue) and provides
strictly typed Mocks/Sentinels.
Eliminates duplicate try/except blocks and ensures type safety across modules.
"""

import sys
from typing import List, Tuple, Optional, Dict, Any, Callable, TYPE_CHECKING, Literal

# -- Export definitions for Facade Pattern --
__all__ = [
    'H2_AVAILABLE', 'hpack', 'H2Connection', 'H2Configuration',
    'SettingCodes', 'ErrorCodes', 'Event', 'RequestReceived',
    'DataReceived', 'StreamEnded', 'StreamReset', 'WindowUpdated',
    'ConnectionTerminated', 'TrailersReceived', 'ResponseReceived',
    'NFQUEUE_AVAILABLE', 'NetfilterQueue', 'MockPacketController'
]

# -- HTTP/2 (h2) Support --

if TYPE_CHECKING:
    import hpack as _hpack_lib
    from h2.connection import H2Connection as _H2Connection
    from h2.config import H2Configuration as _H2Configuration
    from h2.events import (
        RequestReceived as _RequestReceived,
        DataReceived as _DataReceived,
        StreamEnded as _StreamEnded,
        StreamReset as _StreamReset,
        WindowUpdated as _WindowUpdated,
        ConnectionTerminated as _ConnectionTerminated,
        TrailersReceived as _TrailersReceived,
        ResponseReceived as _ResponseReceived,
        Event as _Event
    )
    from h2.errors import ErrorCodes as _ErrorCodes
    from h2.settings import SettingCodes as _SettingCodes

    # Type Aliases for static analysis
    hpack = _hpack_lib
    H2Connection = _H2Connection
    H2Configuration = _H2Configuration
    RequestReceived = _RequestReceived
    DataReceived = _DataReceived
    StreamEnded = _StreamEnded
    StreamReset = _StreamReset
    WindowUpdated = _WindowUpdated
    ConnectionTerminated = _ConnectionTerminated
    TrailersReceived = _TrailersReceived
    ResponseReceived = _ResponseReceived
    Event = _Event
    ErrorCodes = _ErrorCodes
    SettingCodes = _SettingCodes

    H2_AVAILABLE: bool = True

else:
    try:
        # Attempt to import real dependencies
        import hpack
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import (
            RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
            ConnectionTerminated, TrailersReceived, ResponseReceived, Event
        )
        from h2.errors import ErrorCodes
        from h2.settings import SettingCodes

        H2_AVAILABLE = True

    except ImportError:
        H2_AVAILABLE = False
        hpack = None

        # Mock Classes for Runtime Safety (when H2 is missing)

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

        class H2Configuration:
            """Mock Configuration for H2."""
            def __init__(
                self,
                client_side: bool = True,
                header_encoding: Optional[str] = None,
                validate_inbound_headers: bool = True,
                validate_outbound_headers: bool = True,
                normalize_inbound_headers: bool = True,
                normalize_outbound_headers: bool = True
            ) -> None:
                pass

        class H2Connection:
            """Mock Connection for H2."""
            def __init__(self, config: Optional['H2Configuration'] = None) -> None:
                self.config = config
                self.local_settings = {
                    SettingCodes.ENABLE_PUSH: 0,
                    SettingCodes.MAX_HEADER_LIST_SIZE: 65536,
                    SettingCodes.ENABLE_CONNECT_PROTOCOL: 0,
                }
                self.outbound_flow_control_window = 65535
                # Explicitly typed lambda
                self.remote_flow_control_window: Callable[[int], int] = lambda stream_id: 65535
                self.remote_settings: Dict[int, int] = {}

            def initiate_connection(self) -> None:
                pass

            def data_to_send(self) -> bytes:
                return b""

            def send_headers(
                self, stream_id: int, headers: List[Tuple[bytes, bytes]], **kwargs: Any
            ) -> None:
                pass

            def send_data(self, stream_id: int, data: bytes, **kwargs: Any) -> None:
                pass

            def receive_data(self, data: bytes) -> List[Any]:
                return []

            def acknowledge_received_data(self, acknowledged_size: int, stream_id: int) -> None:
                pass

            def get_next_available_stream_id(self) -> int:
                return 1

            def reset_stream(self, stream_id: int, error_code: int = 0) -> None:
                pass

            def ping(self, opaque_data: bytes) -> None:
                pass

            def close_connection(self, error_code: int = 0, **kwargs: Any) -> None:
                pass

        # -- Event Mocks --

        class Event:
            """Base Mock Event."""

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

if TYPE_CHECKING:
    NFQUEUE_AVAILABLE: bool = True
    NetfilterQueue: Any = None
    try:
        from netfilterqueue import NetfilterQueue as _NetfilterQueue
        NetfilterQueue = _NetfilterQueue
    except ImportError:
        pass
else:
    NFQUEUE_AVAILABLE = False
    NetfilterQueue = None

    try:
        if sys.platform.startswith("linux"):
            from netfilterqueue import NetfilterQueue
            NFQUEUE_AVAILABLE = True
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
        self.source_port = source_port
        self.active = False

    def start(self) -> None:
        """Mock start."""

    def stop(self) -> None:
        """Mock stop."""
