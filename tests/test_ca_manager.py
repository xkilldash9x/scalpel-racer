import pytest
from unittest.mock import MagicMock, patch, ANY
import os
import tempfile
import ssl
import scalpel_racer

# Import CAManager after importing scalpel_racer to patch appropriately
from scalpel_racer import CAManager

@pytest.fixture
def ca_manager():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Patch the module-level constants
        with patch("scalpel_racer.CA_CERT_FILE", os.path.join(tmpdir, "test_ca.pem")), \
             patch("scalpel_racer.CA_KEY_FILE", os.path.join(tmpdir, "test_ca.key")):

            manager = CAManager()
            yield manager

@patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True)
def test_ca_manager_generate_and_load(ca_manager):
    # Test Generation
    ca_manager.initialize()

    assert ca_manager.ca_key is not None
    assert ca_manager.ca_cert is not None

    # Verify files exist
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

    # Mock ssl.SSLContext to verify interactions
    with patch("ssl.SSLContext") as MockContext:
        context_instance = MockContext.return_value

        ctx = ca_manager.get_ssl_context("example.com")

        assert ctx == context_instance
        context_instance.load_cert_chain.assert_called_once()

        # Check cache
        assert "example.com" in ca_manager.cert_cache
        assert ca_manager.cert_cache["example.com"] == ctx

        # Subsequent call should return cached
        ctx2 = ca_manager.get_ssl_context("example.com")
        assert ctx2 == ctx
        assert context_instance.load_cert_chain.call_count == 1 # No new load

@patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", False)
def test_ca_manager_no_crypto(ca_manager):
    ca_manager.initialize()
    assert ca_manager.ca_key is None
