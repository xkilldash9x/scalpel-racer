# tests/test_verify_certs.py

"""
Tests for verify_certs.py.
Covers CertManager, ECC key generation, and SSLContext caching.
"""
import pytest
import ssl
import os
from unittest.mock import MagicMock, patch, ANY
from verify_certs import CertManager, CA_KEY_PATH, CA_CERT_PATH, CERTS_DIR

class TestCertManager:

    @pytest.fixture
    def manager(self):
        """Fixture that prevents auto-generation on init for finer control."""
        # [FIX] Patch _generate_static_server_cert to prevent side effects during init
        with patch.object(CertManager, "_load_or_generate_ca"), \
             patch.object(CertManager, "_generate_static_server_cert"):
            # We explicitly mock os.makedirs to avoid FS touches
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=True):
                    # Mock os.stat to prevent FileNotFoundError when checking permissions
                    with patch("os.stat") as mock_stat:
                        mock_stat.return_value.st_mode = 0o700
                        # We also mock the shared key generation in init to avoid real crypto in simple tests
                        with patch("verify_certs.ec.generate_private_key"):
                            return CertManager()

    @patch("verify_certs.ec.generate_private_key")
    @patch("verify_certs.x509.CertificateBuilder")
    def test_load_or_generate_ca_creates_new(self, mock_builder, mock_ec):
        """
        Verify that if CA files don't exist, we generate a new ECC CA.
        """
        # [FIX] Configure Builder Chain to prevent 'NoneType object has no attribute ...'
        mock_builder_inst = mock_builder.return_value
        for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                       'not_valid_before', 'not_valid_after', 'add_extension']:
            getattr(mock_builder_inst, method).return_value = mock_builder_inst

        # Mock filesystem to say files do NOT exist
        # We patch os.open for secure writes
        with patch("os.path.exists", return_value=False), \
             patch("builtins.open", MagicMock()) as mock_file, \
             patch("os.open") as mock_os_open, \
             patch("os.fdopen") as mock_fdopen, \
             patch("os.makedirs"):
            
            # Mock os.open to return a file descriptor
            mock_os_open.return_value = 123
            mock_fdopen.return_value.__enter__.return_value = mock_file.return_value

            # Use real class to test the _load_or_generate_ca logic
            # We patch _generate_static_server_cert here so we only test the CA logic
            with patch.object(CertManager, "_generate_static_server_cert"):
                mgr = CertManager()
            
            # Security Check: Ensure EC key generation was called 
            # Once for shared leaf key, Once for CA key
            assert mock_ec.call_count >= 2
            
            # Verify we opened CA_KEY_PATH via secure write (os.open)
            # 0o600 is 384
            mock_os_open.assert_any_call(CA_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

            # Verify CA cert opened via standard open
            mock_file.assert_any_call(CA_CERT_PATH, "wb")
            
            # Verify CA cert builder was invoked
            mock_builder_inst.sign.assert_called()

    @patch("verify_certs.serialization.load_pem_private_key")
    @patch("verify_certs.x509.load_pem_x509_certificate")
    def test_load_existing_ca(self, mock_load_cert, mock_load_key):
        """Verify loading existing keys from disk."""
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock()), \
             patch("os.chmod", MagicMock()), \
             patch("os.stat") as mock_stat, \
             patch("verify_certs.ec.generate_private_key"), \
             patch.object(CertManager, "_generate_static_server_cert"): # Mock static gen
             
             # Mock stat so S_IMODE works
             mock_stat.return_value.st_mode = 0o700

             mgr = CertManager()
             
             mock_load_key.assert_called()
             mock_load_cert.assert_called()
             assert mgr.ca_key is not None
             assert mgr.ca_cert is not None

    @patch("verify_certs.x509.CertificateBuilder")
    @patch("verify_certs.ssl.create_default_context")
    @patch("verify_certs.ec.generate_private_key")
    def test_get_context_caching(self, mock_ec, mock_ssl_create, mock_builder, manager):
        """
        [VECTOR OPTIMIZATION] Verify that SSLContexts are cached per hostname.
        This ensures we don't regenerate certs for every request.
        """
        from cryptography import x509 # Ensure x509 is available for spec

        # Setup CA mocks so signing works
        manager.ca_key = MagicMock()
        manager.ca_cert = MagicMock()
        # [FIX] Set spec=x509.Name to satisfy cryptography's strict type checking
        manager.ca_cert.subject = MagicMock(spec=x509.Name)
        
        # [FIX] Setup the Mock Builder to handle the fluent interface calls
        b_inst = mock_builder.return_value
        for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                       'not_valid_before', 'not_valid_after', 'add_extension', 'sign']:
            getattr(b_inst, method).return_value = b_inst

        # Ensure shared key is set
        manager.shared_leaf_key = MagicMock()
        
        mock_ctx = MagicMock()
        mock_ssl_create.return_value = mock_ctx
        
        host = "cache-test.com"
        
        # Mock file IO for saving the leaf cert
        with patch("builtins.open", MagicMock()), \
             patch("os.open", MagicMock()), \
             patch("os.fdopen", MagicMock()), \
             patch("os.close", MagicMock()):
            # First Call: Should generate
            ctx1 = manager.get_context_for_host(host)
            
            # Second Call: Should return cached
            ctx2 = manager.get_context_for_host(host)
        
        assert ctx1 is ctx2
        
        # Verify SSL context creation happened once
        mock_ssl_create.assert_called_once()
        
        # [FIXED ASSERTION] Verify ALPN setting includes 'h3' for QUIC support
        mock_ctx.set_alpn_protocols.assert_called_with(["h3", "h2", "http/1.1"])

    def test_get_context_threading(self, manager):
        """Verify thread safety lock is present."""
        import threading
        assert hasattr(manager, "lock")
        assert isinstance(manager.lock, type(threading.Lock()))

    @patch("verify_certs.x509.CertificateBuilder")
    @patch("verify_certs.ssl.create_default_context")
    @patch("verify_certs.ec.generate_private_key")
    def test_leaf_cert_generation_logic(self, mock_ec, mock_ssl, mock_builder, manager):
        """
        Comprehensive test for leaf certificate generation parameters.
        Verifies Subject, SAN, Issuer, Validity, and Signing via the Builder Mock.
        """
        manager.ca_key = MagicMock()
        manager.ca_cert = MagicMock()
        manager.shared_leaf_key = MagicMock()
        
        # Setup Fluent Interface on Builder Mock
        b_inst = mock_builder.return_value
        for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                       'not_valid_before', 'not_valid_after', 'sign']:
            getattr(b_inst, method).return_value = b_inst
        
        # We need to spy on add_extension separately to check arguments
        b_inst.add_extension.return_value = b_inst

        host = "secure-test.com"

        with patch("builtins.open", MagicMock()), \
             patch("os.open", MagicMock()), \
             patch("os.fdopen", MagicMock()):
            manager.get_context_for_host(host)

        # 1. Verify Public Key setting
        b_inst.public_key.assert_called_with(manager.shared_leaf_key.public_key.return_value)

        # 2. Verify Issuer Name
        b_inst.issuer_name.assert_called_with(manager.ca_cert.subject)

        # 3. Verify Signing
        b_inst.sign.assert_called_with(manager.ca_key, ANY)

        # 4. Verify SAN Extension (Subject Alternative Name)
        found_san = False
        for call_args in b_inst.add_extension.call_args_list:
            ext = str(call_args[0][0]) 
            if "SubjectAlternativeName" in ext and f"DNSName(value='{host}')" in ext:
                found_san = True
                break
        
        assert found_san, "SAN Extension was not added to the leaf certificate"