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
        with patch.object(CertManager, "_load_or_generate_ca"):
            # We explicitly mock os.makedirs to avoid FS touches
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=True):
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
        with patch("os.path.exists", return_value=False), \
             patch("builtins.open", MagicMock()) as mock_file, \
             patch("os.makedirs"):
            
            # Use real class to test the _load_or_generate_ca logic
            mgr = CertManager()
            
            # Security Check: Ensure EC key generation was called 
            # Once for shared leaf key, Once for CA key
            assert mock_ec.call_count >= 2
            
            # Should open key file and cert file for writing
            assert mock_file.call_count >= 2
            mock_file.assert_any_call(CA_KEY_PATH, "wb")
            mock_file.assert_any_call(CA_CERT_PATH, "wb")
            
            # Verify CA cert builder was invoked
            mock_builder_inst.sign.assert_called()

    @patch("verify_certs.serialization.load_pem_private_key")
    @patch("verify_certs.x509.load_pem_x509_certificate")
    def test_load_existing_ca(self, mock_load_cert, mock_load_key):
        """Verify loading existing keys from disk."""
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock()), \
             patch("verify_certs.ec.generate_private_key"): # Mock shared key gen
             
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
        # This prevents the real CertificateBuilder from rejecting our MagicMock key
        b_inst = mock_builder.return_value
        for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                       'not_valid_before', 'not_valid_after', 'add_extension', 'sign']:
            getattr(b_inst, method).return_value = b_inst

        # Ensure shared key is set (fixture mocks init, so we set it manually)
        manager.shared_leaf_key = MagicMock()
        
        mock_ctx = MagicMock()
        mock_ssl_create.return_value = mock_ctx
        
        host = "cache-test.com"
        
        # Mock file IO for saving the leaf cert
        with patch("builtins.open", MagicMock()):
            # First Call: Should generate
            ctx1 = manager.get_context_for_host(host)
            
            # Second Call: Should return cached
            ctx2 = manager.get_context_for_host(host)
        
        assert ctx1 is ctx2
        
        # Verify generation only happened once (during init for shared key, NOT during get_context)
        # mock_ec is the one from the test arguments, used for asserting.
        # Since we set shared_leaf_key manually, mock_ec shouldn't be called here.
        mock_ec.assert_not_called()
        
        # Verify SSL context creation happened once
        mock_ssl_create.assert_called_once()
        
        # Verify ALPN setting (Required for H2)
        mock_ctx.set_alpn_protocols.assert_called_with(["h2", "http/1.1"])

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

        with patch("builtins.open", MagicMock()):
            manager.get_context_for_host(host)

        # 1. Verify Public Key setting
        # It should pass the public key derived from the Shared Key
        b_inst.public_key.assert_called_with(manager.shared_leaf_key.public_key.return_value)

        # 2. Verify Issuer Name
        # It should use the subject name from the CA cert
        b_inst.issuer_name.assert_called_with(manager.ca_cert.subject)

        # 3. Verify Signing
        # It should be signed with the CA's private key
        b_inst.sign.assert_called_with(manager.ca_key, ANY)

        # 4. Verify SAN Extension (Subject Alternative Name)
        # We look through call args to find the extension
        found_san = False
        for call_args in b_inst.add_extension.call_args_list:
            # call_args[0][0] is the extension object
            ext = str(call_args[0][0]) 
            if "SubjectAlternativeName" in ext and f"DNSName(value='{host}')" in ext:
                found_san = True
                break
        
        assert found_san, "SAN Extension was not added to the leaf certificate"

        # 5. Verify Validity
        assert b_inst.not_valid_before.called
        assert b_inst.not_valid_after.called