import pytest
from unittest.mock import MagicMock, patch
from verify_certs import CertManager

class TestCertManager:
    @patch("verify_certs.ec.generate_private_key")
    @patch("verify_certs.x509.CertificateBuilder")
    def test_shared_key_optimization(self, mock_builder, mock_ec):
        # Mock initialization to prevent FS writes
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock()):
            mgr = CertManager()
            # Init calls generate_private_key once for shared_leaf_key
            
            mgr.ca_cert = MagicMock()
            mgr.ca_key = MagicMock()
            
            # [FIX] Mock ssl.create_default_context to avoid real FS access in load_cert_chain
            with patch("ssl.create_default_context") as mock_ssl_ctx_factory:
                mock_ctx = MagicMock()
                mock_ssl_ctx_factory.return_value = mock_ctx

                # get_context should NOT generate new keys
                current_count = mock_ec.call_count
                mgr.get_context_for_host("a.com")
                assert mock_ec.call_count == current_count

                # Verify load_cert_chain was called on the mock context
                mock_ctx.load_cert_chain.assert_called()
