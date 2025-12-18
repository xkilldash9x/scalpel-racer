import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from scalpel_racer import run_scan, CapturedRequest, ScanResult

class TestScalpelIntegration:
    @patch("scalpel_racer.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_run_scan_standard(self, mock_client):
        client_inst = AsyncMock()
        mock_client.return_value.__aenter__.return_value = client_inst
        mock_resp = MagicMock(); mock_resp.status_code = 200; mock_resp.aread = AsyncMock(return_value=b"body")
        client_inst.stream.return_value.__aenter__.return_value = mock_resp
        
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        results = await run_scan(req, concurrency=2, http2=False, warmup=0)
        assert len(results) == 2
