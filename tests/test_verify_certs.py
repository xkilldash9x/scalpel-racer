# tests/test_verify_certs.py

import pytest
from unittest.mock import MagicMock, patch
from verify_certs import generate_ca, check_pair
from structures import CapturedRequest

class TestVerifyCerts:

    @patch("verify_certs.ec.generate_private_key")  # UPGRADE: Mocking EC instead of RSA
    @patch("verify_certs.x509.CertificateBuilder")
    @patch("verify_certs.socket.gethostname", return_value="testbox")
    def test_generate_ca_logic(self, mock_host, mock_builder, mock_ec):
        """Test CA generation logic (ECC NIST P-256) without writing files."""
        mock_file = MagicMock()
        
        # Mock Builder
        b = mock_builder.return_value
        for m in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                  'not_valid_before', 'not_valid_after', 'add_extension', 'sign']:
            getattr(b, m).return_value = b
            
        with patch("builtins.open", mock_file):
            generate_ca()
            
        # Security Check: Ensure EC key generation was called, not RSA
        mock_ec.assert_called_once()
        
        # Should open key file and cert file for writing
        assert mock_file.call_count == 2
        mock_file.assert_any_call("scalpel_ca.key", "wb")
        mock_file.assert_any_call("scalpel_ca.pem", "wb")

    @patch("verify_certs.install_certs")
    def test_check_pair_success(self, mock_install):
        """Test successful key/cert pair verification."""
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock()), \
             patch("verify_certs.serialization.load_pem_private_key") as mock_load_key, \
             patch("verify_certs.x509.load_pem_x509_certificate") as mock_load_cert:
            
            # Setup public numbers match
            mock_load_key.return_value.public_key.return_value.public_numbers.return_value = 12345
            mock_load_cert.return_value.public_key.return_value.public_numbers.return_value = 12345
            
            check_pair()
            
            mock_install.assert_called_once()

    def test_check_pair_mismatch(self):
        """Test failed verification."""
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock()), \
             patch("verify_certs.serialization.load_pem_private_key") as mock_load_key, \
             patch("verify_certs.x509.load_pem_x509_certificate") as mock_load_cert, \
             patch("verify_certs.install_certs") as mock_install:
             
            # Mismatch
            mock_load_key.return_value.public_key.return_value.public_numbers.return_value = 111
            mock_load_cert.return_value.public_key.return_value.public_numbers.return_value = 999
            
            check_pair()
            
            mock_install.assert_not_called()

class TestSecurityRedaction:
    """Tests for the new log redaction features."""
    
    def test_header_redaction(self):
        headers = [
            ("Host", "example.com"),
            ("Authorization", "Bearer sensitive_token_123"),
            ("Cookie", "session_id=secret"),
            ("User-Agent", "SafeAgent")
        ]
        req = CapturedRequest(1, "GET", "http://example.com", headers, b"")
        
        redacted = req._get_redacted_headers()
        
        assert "Host: example.com" in redacted
        assert "User-Agent: SafeAgent" in redacted
        
        # Verify Sensitive Data is GONE
        assert "sensitive_token_123" not in redacted
        assert "session_id=secret" not in redacted
        
        # Verify Mask is PRESENT
        assert "Authorization: [REDACTED]" in redacted
        assert "Cookie: [REDACTED]" in redacted