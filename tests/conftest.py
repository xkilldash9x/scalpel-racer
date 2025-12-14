import sys
import os
import pytest
from unittest.mock import MagicMock

# 1. Add project root to path
sys.path.append(os.getcwd())

# 2. Mock system dependencies GLOBALLY.
#    This must happen before tests import production modules.

# -- Mock 'h2' library --
mock_h2 = MagicMock()
sys.modules["h2"] = mock_h2
sys.modules["h2.connection"] = MagicMock()
sys.modules["h2.config"] = MagicMock()
sys.modules["h2.events"] = MagicMock()
sys.modules["h2.errors"] = MagicMock()
sys.modules["h2.exceptions"] = MagicMock()
sys.modules["h2.settings"] = MagicMock()
# Mock hpack for proxy_core
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

@pytest.fixture
def mock_socket():
    return MagicMock()

@pytest.fixture
def mock_ssl_context():
    return MagicMock()

