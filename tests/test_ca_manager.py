import pytest
from unittest.mock import MagicMock, patch, ANY
import os
import tempfile
import ssl
import scalpel_racer

# Mock the cryptography library if not available
try:
    import cryptography
except ImportError:
    import sys
    sys.modules['cryptography'] = MagicMock()
    sys.modules['cryptography.x509'] = MagicMock()
    sys.modules['cryptography.x509.oid'] = MagicMock()
    sys.modules['cryptography.hazmat.primitives'] = MagicMock()
    sys.modules['cryptography.hazmat.primitives.asymmetric'] = MagicMock()
    sys.modules['cryptography.hazmat.primitives.serialization'] = MagicMock()

# Import CAManager after importing scalpel_racer to patch appropriately
from scalpel_racer import CAManager

@pytest.fixture
def ca_manager():
    # Use a temporary directory for CA files during tests
    with tempfile.TemporaryDirectory() as tmpdir:
        # Patch the module-level constants in scalpel_racer
        with patch("scalpel_racer.CA_CERT_FILE", os.path.join(tmpdir, "test_ca.pem")), \
             patch("scalpel_racer.CA_KEY_FILE", os.path.join(tmpdir, "test_ca.key")):

            manager = CAManager()
            yield manager

# Ensure the SUT thinks cryptography is available for these tests
@patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True)
def test_ca_manager_generate_and_load(ca_manager):
    # Test Generation
    ca_manager.initialize()

    assert ca_manager.ca_key is not None
    assert ca_manager.ca_cert is not None

    # Verify files exist (using the patched paths)
    assert os.path.exists(scalpel_racer.CA_CERT_FILE)
    assert os.path.exists(scalpel_racer.CA_KEY_FILE)

    # Test Loading (re-initialize)
    # Clear memory
    ca_manager.ca_key = None
    ca_manager.ca_cert = None

    ca_manager.initialize()
    assert ca_manager.ca_key is not None
    assert ca_manager.ca_cert is not None

@patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True)
def test_ca_manager_get_ssl_context(ca_manager):
    ca_manager.initialize()

    # Mock ssl.SSLContext class to verify interactions
    with patch("ssl.SSLContext") as MockContext:
        context_instance = MockContext.return_value

        ctx = ca_manager.get_ssl_context("example.com")

        assert ctx == context_instance
        # Verify that the certificate chain was loaded into the context
        context_instance.load_cert_chain.assert_called_once()

        # Check cache
        assert "example.com" in ca_manager.cert_cache
        assert ca_manager.cert_cache["example.com"] == ctx

        # Subsequent call should return cached context
        ctx2 = ca_manager.get_ssl_context("example.com")
        assert ctx2 == ctx
        # Ensure load_cert_chain was not called again
        assert context_instance.load_cert_chain.call_count == 1

@patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", False)
def test_ca_manager_no_crypto(ca_manager):
    # Test initialization when cryptography is unavailable
    ca_manager.initialize()
    assert ca_manager.ca_key is None
    assert ca_manager.ca_cert is None