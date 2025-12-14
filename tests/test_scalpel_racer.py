# tests/test_scalpel_racer.py
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from scalpel_racer import run_scan, CAManager
from structures import ScanResult, CapturedRequest

class TestScalpelIntegration:
    
    @patch("scalpel_racer.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_run_scan_standard(self, mock_client):
        # Setup AsyncClient mock
        client_inst = AsyncMock()
        mock_client.return_value.__aenter__.return_value = client_inst
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.aread = AsyncMock(return_value=b"body")
        
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        
        # FIX: client.stream should not be an AsyncMock itself (which creates a coroutine when called), 
        # but a method returning an async context manager (the stream_ctx).
        client_inst.stream = MagicMock(return_value=stream_ctx)
        
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        # Run standard attack
        results = await run_scan(req, concurrency=2, http2=False, warmup=0, strategy="auto")
        
        assert len(results) == 2
        assert results[0].status_code == 200

    @patch("scalpel_racer.HTTP2RaceEngine")
    @patch("scalpel_racer.H2_AVAILABLE", True)
    @pytest.mark.asyncio
    async def test_run_scan_h2_delegation(self, mock_h2_cls):
        """Verify 'spa' strategy triggers HTTP2RaceEngine."""
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        mock_engine = mock_h2_cls.return_value
        mock_engine.run_attack.return_value = [ScanResult(0, 200, 10)]
        
        await run_scan(req, concurrency=1, http2=True, warmup=0, strategy="spa")
        
        mock_h2_cls.assert_called_once()
        assert mock_h2_cls.call_args[0][2] == "spa"

    @patch("scalpel_racer.ec.generate_private_key")
    @patch("scalpel_racer.x509.CertificateBuilder")
    def test_ca_generation(self, mock_builder, mock_key):
        """Test CA Manager crypto calls."""
        with patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
             patch("builtins.open", MagicMock()), \
             patch("os.chown"):
            
            # Setup fluent interface for Builder
            builder_instance = mock_builder.return_value
            builder_instance.subject_name.return_value = builder_instance
            builder_instance.issuer_name.return_value = builder_instance
            builder_instance.public_key.return_value = builder_instance
            builder_instance.serial_number.return_value = builder_instance
            builder_instance.not_valid_before.return_value = builder_instance
            builder_instance.not_valid_after.return_value = builder_instance
            builder_instance.add_extension.return_value = builder_instance
            
            mgr = CAManager()
            mgr.generate_ca()
            
            mock_key.assert_called()
            builder_instance.sign.assert_called()