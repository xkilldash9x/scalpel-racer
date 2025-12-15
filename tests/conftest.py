# conftest.py
import sys
import os
import pytest
from unittest.mock import MagicMock

# 1. Add project root to path to ensure imports work correctly
sys.path.append(os.getcwd())

# 2. Mock system dependencies GLOBALLY.
# This must happen before tests import production modules to prevent ImportErrors
# and to ensure that tests run in isolation without side effects.

# -- Mock 'h2' library --
mock_h2 = MagicMock()
sys.modules["h2"] = mock_h2
sys.modules["h2.connection"] = MagicMock()
sys.modules["h2.config"] = MagicMock()
sys.modules["h2.events"] = MagicMock()
sys.modules["h2.errors"] = MagicMock()
sys.modules["h2.exceptions"] = MagicMock()
sys.modules["h2.settings"] = MagicMock()

# -- Mock hpack for proxy_core --
sys.modules["hpack"] = MagicMock()

# -- Mock 'netfilterqueue' (Linux only) --
sys.modules["netfilterqueue"] = MagicMock()

# -- Mock 'scapy' --
mock_scapy = MagicMock()
sys.modules["scapy"] = mock_scapy
sys.modules["scapy.all"] = mock_scapy

# -- Mock 'cryptography' --
mock_crypto = MagicMock()
sys.modules["cryptography"] = mock_crypto
sys.modules["cryptography.x509"] = MagicMock()
sys.modules["cryptography.hazmat"] = MagicMock()
sys.modules["cryptography.hazmat.primitives"] = MagicMock()
sys.modules["cryptography.hazmat.primitives.asymmetric"] = MagicMock()
sys.modules["cryptography.hazmat.primitives.serialization"] = MagicMock()
sys.modules["cryptography.x509.oid"] = MagicMock()

# -- Mock 'httpx' --
# Critical: Mocked to prevent import errors if the library is missing in the test env
mock_httpx = MagicMock()
sys.modules["httpx"] = mock_httpx

# -- Mock 'numpy' --
mock_numpy = MagicMock()

# Configure histogram to return usable dummy data (counts, bins) for analyze_results tests
mock_numpy.histogram.return_value = ([10, 5], [0, 50, 100])
sys.modules["numpy"] = mock_numpy

# -- Mock 'proxy_manager' --
# REMOVED: We are testing this module, so we must not mock it.
# If CaptureApp checks for it, we rely on the real import now.

@pytest.fixture
def mock_socket():
    """Returns a magic mock behaving like a socket."""
    return MagicMock()

@pytest.fixture
def mock_ssl_context():
    """Returns a magic mock behaving like an SSL context."""
    return MagicMock()