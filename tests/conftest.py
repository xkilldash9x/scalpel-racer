# conftest.py
import sys
import os
import pytest
from unittest.mock import MagicMock

sys.path.append(os.getcwd())

def conditional_mock(module_name):
    try: __import__(module_name)
    except ImportError: sys.modules[module_name] = MagicMock(); return True
    return False

if conditional_mock("h2"):
    sys.modules["h2.connection"] = MagicMock()
    sys.modules["h2.config"] = MagicMock()
    sys.modules["h2.events"] = MagicMock()
    sys.modules["h2.errors"] = MagicMock()
    sys.modules["h2.exceptions"] = MagicMock()
    sys.modules["h2.settings"] = MagicMock()

conditional_mock("hpack")
conditional_mock("netfilterqueue")

if conditional_mock("scapy"): sys.modules["scapy.all"] = MagicMock()
if conditional_mock("cryptography"):
    sys.modules["cryptography.x509"] = MagicMock()
    sys.modules["cryptography.hazmat"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives.asymmetric"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives.serialization"] = MagicMock()
    sys.modules["cryptography.x509.oid"] = MagicMock()

conditional_mock("httpx")

try: import numpy
except ImportError:
    mock_numpy = MagicMock()
    mock_numpy.histogram.return_value = ([10, 5], [0, 50, 100])
    sys.modules["numpy"] = mock_numpy

@pytest.fixture
def mock_socket(): return MagicMock()

@pytest.fixture
def mock_ssl_context(): return MagicMock()
