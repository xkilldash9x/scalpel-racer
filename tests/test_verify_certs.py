# tests/test_verify_certs.py

import pytest
from unittest.mock import MagicMock, patch
from verify_certs import generate_ca, check_pair

class TestVerifyCerts:

    @patch("verify_certs.rsa.generate_private_key")
    @patch("verify_certs.x509.CertificateBuilder")
    @patch("verify_certs.socket.gethostname", return_value="testbox")
    def test_generate_ca_logic(self, mock_host, mock_builder, mock_rsa):
        """Test CA generation logic without writing files."""
        mock_file = MagicMock()
        
        # Mock Builder
        b = mock_builder.return_value
        for m in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                  'not_valid_before', 'not_valid_after', 'add_extension', 'sign']:
            getattr(b, m).return_value = b
            
        with patch("builtins.open", mock_file):
            generate_ca()
            
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
            key_pub = MagicMock()
            cert_pub = MagicMock()
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