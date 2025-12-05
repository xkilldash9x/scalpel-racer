import pytest
import importlib
import sys

def test_h2_availability():
    """
    Verifies that proxy_core initializes h2 dependencies correctly
    without falling back to degraded mode.
    """
    # Attempt to import the core module
    try:
        import proxy_core
        # Force a reload ensures we aren't testing a cached state if run in a suite
        importlib.reload(proxy_core)
    except ImportError as e:
        pytest.fail(f"CRITICAL: Could not import proxy_core module. Error: {e}")

    # Primary check for the availability flag
    if not proxy_core.H2_AVAILABLE:
        _run_diagnostic_failure()

    # If we get here, H2_AVAILABLE is True. 
    # Now we verify we aren't being lied to (checking for dummy classes).
    try:
        import h2
        import h2.events
        
        # Capture version for stdout in case of debugging later
        print(f"Verified h2 library version: {h2.__version__}")

        # Verify the critical attributes that caused previous issues
        # Note: 'SettingsAcknowledged' is the correct name for h2 < 4.0 (which seems to be installed)
        has_ping_ack = hasattr(h2.events, 'PingAckReceived')
        has_settings_ack = hasattr(h2.events, 'SettingsAcknowledged')

        assert has_ping_ack, "H2_AVAILABLE is True, but 'PingAckReceived' is missing from h2.events."
        assert has_settings_ack, "H2_AVAILABLE is True, but 'SettingsAcknowledged' is missing from h2.events."

    except ImportError:
        pytest.fail("H2_AVAILABLE is True, but direct import of 'h2' failed during verification.")


def _run_diagnostic_failure():
    """
    Helper to identify exactly why H2_AVAILABLE is False and fail the test with details.
    """
    diagnostic_msg = "The proxy is running in degraded mode (H2_AVAILABLE = False)."
    
    # Attempt to run the exact import block from proxy_core to expose the specific error
    try:
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import (
            RequestReceived, DataReceived, StreamEnded, StreamReset, WindowUpdated,
            SettingsAcknowledged, ConnectionTerminated, TrailersReceived, PingAckReceived,
            ResponseReceived
        )
        # If this succeeds, the logic in proxy_core is likely flawed
        diagnostic_msg += "\n    [?] Manual import succeeded. Check proxy_core.py detection logic."
    except ImportError as e:
        # This captures the actual missing dependency or mismatched name
        diagnostic_msg += f"\n    [!] DIAGNOSIS: Specific import failure:\n        {e}"

    pytest.fail(diagnostic_msg)