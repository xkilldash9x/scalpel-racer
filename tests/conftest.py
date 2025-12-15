# conftest.py
import sys
import os
import pytest
from unittest.mock import MagicMock

# 1. Add project root to path to ensure imports work correctly
sys.path.append(os.getcwd())

# 2. Mock system dependencies CONDITIONALLY.
# Best Practice: Only mock globally if the environment is missing the dependency.
# This allows Integration tests to use the real libraries if installed,
# while Unit tests can still use @patch for isolation.

def conditional_mock(module_name):
    """
    Attempts to import a module. If it fails, mocks it in sys.modules.
    Returns True if mocked, False if real.
    """
    try:
        __import__(module_name)
    except ImportError:
        sys.modules[module_name] = MagicMock()
        return True
    return False

# -- Mock 'h2' library --
if conditional_mock("h2"):
    sys.modules["h2.connection"] = MagicMock()
    sys.modules["h2.config"] = MagicMock()
    sys.modules["h2.events"] = MagicMock()
    sys.modules["h2.errors"] = MagicMock()
    sys.modules["h2.exceptions"] = MagicMock()
    sys.modules["h2.settings"] = MagicMock()

# -- Mock hpack --
conditional_mock("hpack")

# -- Mock 'netfilterqueue' (Linux only) --
conditional_mock("netfilterqueue")

# -- Mock 'scapy' --
if conditional_mock("scapy"):
    sys.modules["scapy.all"] = MagicMock()

# -- Mock 'cryptography' --
# Critical for test_generate_host_cert_integration: 
# We must allow the REAL cryptography module to load if present.
if conditional_mock("cryptography"):
    sys.modules["cryptography.x509"] = MagicMock()
    sys.modules["cryptography.hazmat"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives.asymmetric"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives.serialization"] = MagicMock()
    sys.modules["cryptography.x509.oid"] = MagicMock()

# -- Mock 'httpx' --
# If installed, let it load so integration tests can use real clients.
# Unit tests should use @patch("scalpel_racer.httpx") explicitly.
conditional_mock("httpx")

# -- Mock 'numpy' --
# We keep the explicit mock configuration for numpy to ensure 
# predictable histogram data during analysis tests, unless you want
# real numpy math in integration tests.
try:
    import numpy
except ImportError:
    mock_numpy = MagicMock()
    # Configure histogram to return usable dummy data (counts, bins)
    mock_numpy.histogram.return_value = ([10, 5], [0, 50, 100])
    sys.modules["numpy"] = mock_numpy

@pytest.fixture
def mock_socket():
    """Returns a magic mock behaving like a socket."""
    return MagicMock()

@pytest.fixture
def mock_ssl_context():
    """Returns a magic mock behaving like an SSL context."""
    return MagicMock()