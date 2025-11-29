import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from scalpel_racer import send_probe, run_scan, analyze_results, ScanResult, CapturedRequest, XY_stream_body

@pytest.mark.asyncio
async def test_send_probe_success():
    # Mock dependencies
    client = MagicMock()
    client.request = AsyncMock()
    client.request.return_value.status_code = 200

    req = CapturedRequest(1, "GET", "http://example.com", {}, b"data")
    barrier = asyncio.Barrier(1)

    result = await send_probe(client, req, barrier, warmup_ms=0, index=0)

    assert result.index == 0
    assert result.status_code == 200
    assert result.error is None
    assert result.duration >= 0

    # Verify client call
    client.request.assert_called_once()
    args, kwargs = client.request.call_args
    assert kwargs['method'] == "GET"
    assert kwargs['url'] == "http://example.com"
    # Headers are modified
    assert "User-Agent" in kwargs['headers']
    assert "X-Scalpel-Probe" in kwargs['headers']
    # GET requests should not have Content-Type set if not present
    assert "Content-Type" not in kwargs['headers']

@pytest.mark.asyncio
async def test_send_probe_exception():
    client = MagicMock()
    client.request = AsyncMock(side_effect=Exception("Connection Error"))

    req = CapturedRequest(1, "GET", "http://example.com", {}, b"")
    barrier = asyncio.Barrier(1)

    result = await send_probe(client, req, barrier, warmup_ms=0, index=1)

    assert result.index == 1
    assert result.status_code == 0
    assert result.error == "Connection Error"

@pytest.mark.asyncio
async def test_run_scan():
    # We need to mock httpx.AsyncClient and send_probe
    # But run_scan calls send_probe which uses the client.
    # Easiest is to mock httpx.AsyncClient context manager.

    req = CapturedRequest(1, "POST", "http://example.com", {}, b"data")

    with patch("scalpel_racer.httpx.AsyncClient") as MockClient, \
         patch("scalpel_racer.analyze_results") as mock_analyze:

        # Setup async context manager mock
        mock_client_instance = AsyncMock()
        MockClient.return_value.__aenter__.return_value = mock_client_instance

        # Setup send_probe behavior via client.request mock
        # Since run_scan calls send_probe, and send_probe calls client.request
        mock_client_instance.request.return_value.status_code = 202

        await run_scan(req, concurrency=5, http2=False, warmup=0)

        # Verify
        assert mock_client_instance.request.call_count == 5
        mock_analyze.assert_called_once()
        results = mock_analyze.call_args[0][0]
        assert len(results) == 5
        assert results[0].status_code == 202

def test_analyze_results(capsys):
    results = [
        ScanResult(0, 200, 100.0),
        ScanResult(1, 200, 110.0),
        ScanResult(2, 500, 50.0),
        ScanResult(3, 0, 0.0, "Error")
    ]

    analyze_results(results)

    captured = capsys.readouterr()
    assert "[200]: 2 responses" in captured.out
    assert "[500]: 1 responses" in captured.out
    # Timing calculation: (100+110+50)/3 = 260/3 = 86.67
    assert "Timing: Avg 86.67ms" in captured.out

@pytest.mark.asyncio
async def test_xy_stream_body_warmup():
    payload = b"AB"
    barrier = asyncio.Barrier(1)

    start = asyncio.get_event_loop().time()
    parts = []
    async for part in XY_stream_body(payload, barrier, warmup_ms=100):
        parts.append(part)
    end = asyncio.get_event_loop().time()

    assert parts == [b"A", b"B"]
    # Should take at least 0.1s
    assert (end - start) >= 0.1
