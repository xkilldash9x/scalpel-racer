
import pytest
from proxy_core import H2_AVAILABLE, ErrorCodes

def test_h2_imports_correctly():
    """
    Verifies that the H2 library imports correctly and key components
    are available, confirming the fix for the renamed PingAcknowledged event.
    """
    assert H2_AVAILABLE is True, "H2_AVAILABLE should be True if h2 is installed"

    # Ensure ErrorCodes is the actual Enum, not object
    assert ErrorCodes is not object, "ErrorCodes should be the actual class, not a placeholder object"
    assert hasattr(ErrorCodes, "PROTOCOL_ERROR"), "ErrorCodes should have PROTOCOL_ERROR"

def test_ping_ack_received_available():
    """
    Verifies that PingAckReceived is available in proxy_core.
    """
    from proxy_core import PingAckReceived
    assert PingAckReceived is not object, "PingAckReceived should be imported from h2.events"
    assert PingAckReceived.__name__ == "PingAckReceived"
