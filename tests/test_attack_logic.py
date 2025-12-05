import pytest
import asyncio
import hashlib
from unittest.mock import MagicMock, AsyncMock, patch
import httpx
import numpy as np
# Updated imports to match the structure in scalpel_racer.py
from scalpel_racer import send_probe_advanced, run_scan, analyze_results, ScanResult, CapturedRequest, Staged_Stream_Body, Last_Byte_Stream_Body, SYNC_MARKER

# Helper for async iteration compatibility
async def a_next(gen):
    try:
        return await gen.__anext__()
    except StopAsyncIteration:
        raise

# Helper to create a mock HTTPX response for streaming
class MockResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    async def aread(self, n=None):
        return self._body

    # Mock async context manager behavior
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

# --- Tests for Staged_Stream_Body (Capability Improvement) ---

@pytest.mark.asyncio
async def test_staged_stream_synchronization():
    payload = b"A{{SYNC}}B{{SYNC}}C"
    # Two barriers, requiring 2 parties each
    b1, b2 = asyncio.Barrier(2), asyncio.Barrier(2)
    barriers = [b1, b2]

    # Two concurrent streamers
    s1 = Staged_Stream_Body(payload, barriers)
    s2 = Staged_Stream_Body(payload, barriers)

    # Get first parts (Stage 1)
    assert await a_next(s1) == b"A"
    assert await a_next(s2) == b"A"
    
    # Both should now be waiting at b1.
    results_s2 = await asyncio.gather(a_next(s1), a_next(s2))
    assert results_s2 == [b"B", b"B"]
    
    # Both should now be waiting at b2.
    results_s3 = await asyncio.gather(a_next(s1), a_next(s2))
    assert results_s3 == [b"C", b"C"]

    # [FIX] Explicitly close the generators to prevent RuntimeWarning
    await s1.aclose()
    await s2.aclose()
# --- Tests for send_probe_advanced (Integration) ---

@pytest.mark.asyncio
async def test_send_probe_advanced_differential_analysis():
    # Verify body reading and hashing (Capability Improvement)
    client = MagicMock()
    
    response_body = b"response data"
    expected_hash = hashlib.sha256(response_body).hexdigest()
    mock_response = MockResponse(status_code=200, body=response_body)
    # client.stream returns an async context manager (MockResponse implements it)
    client.stream.return_value = mock_response

    # Added default Content-Type check
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"request data")
    barrier = asyncio.Barrier(1)

    # Use Last-Byte Sync mode
    result = await send_probe_advanced(client, req, req.body, [barrier], 0, 0, is_staged=False)

    assert result.status_code == 200
    assert result.body_hash == expected_hash
    assert result.body_snippet == "response data"

    # Verify the content passed to the client was the LBS generator
    args, kwargs = client.stream.call_args
    # Check if the content is an async generator
    assert hasattr(kwargs['content'], '__aiter__')
    
    # Verify default Content-Type was added
    assert kwargs['headers']['Content-Type'] == "application/x-www-form-urlencoded"

@pytest.mark.asyncio
async def test_send_probe_advanced_case_insensitive_content_type():
    # Verify Content-Type check is case-insensitive
    client = MagicMock()
    mock_response = MockResponse(status_code=200, body=b"")
    client.stream.return_value = mock_response

    # Request has mixed-case Content-Type
    req = CapturedRequest(1, "POST", "http://example.com", {"Content-tYpE": "application/json"}, b"data")
    barrier = asyncio.Barrier(1)

    await send_probe_advanced(client, req, req.body, [barrier], 0, 0, is_staged=False)

    args, kwargs = client.stream.call_args
    # Verify the existing Content-Type was used, and the default was NOT added.
    assert kwargs['headers']['Content-tYpE'] == "application/json"
    assert 'Content-Type' not in kwargs['headers']


@pytest.mark.asyncio
async def test_send_probe_advanced_staged_mode():
    # Verify Staged mode uses the correct generator
    client = MagicMock()
    mock_response = MockResponse(status_code=200, body=b"")
    client.stream.return_value = mock_response

    req = CapturedRequest(1, "POST", "http://example.com", {}, b"")
    payload = b"A{{SYNC}}B"
    barrier = asyncio.Barrier(1)

    # Use Staged mode
    result = await send_probe_advanced(client, req, payload, [barrier], 0, 0, is_staged=True)

    assert result.status_code == 200
    
    # Verify the content passed to the client was the Staged generator
    args, kwargs = client.stream.call_args
    assert hasattr(kwargs['content'], '__aiter__')

# --- Tests for analyze_results (Unit) ---

# Helper for hashing
def h(data):
    return hashlib.sha256(data.encode()).hexdigest()

def test_analyze_results_identical(capsys):
    # Test Differential Analysis (Identical responses)
    hash1 = h("body1")
    results = [
        ScanResult(0, 200, 100.0, hash1, "body1"),
        ScanResult(1, 200, 110.0, hash1, "body1"),
    ]

    analyze_results(results)

    captured = capsys.readouterr()
    assert f"2      200    {hash1[:16]} body1" in captured.out
    assert "[+] Consistency: All responses are identical" in captured.out
    assert "Average: 105.00ms" in captured.out

def test_analyze_results_different_bodies(capsys):
    # Test Differential Analysis (Different bodies, same status)
    hash1 = h("body1")
    hash2 = h("body2")
    results = [
        ScanResult(0, 200, 100.0, hash1, "body1"),
        ScanResult(1, 200, 110.0, hash2, "body2"),
    ]

    analyze_results(results)

    captured = capsys.readouterr()
    assert f"1      200    {hash1[:16]} body1" in captured.out
    assert f"1      200    {hash2[:16]} body2" in captured.out
    assert "[!] WARNING: Multiple response signatures detected!" in captured.out

def test_analyze_results_mixed_status(capsys):
    # Test Differential Analysis (Different status and bodies)
    hash1 = h("success")
    hash2 = h("error")
    results = [
        ScanResult(0, 200, 100.0, hash1, "success"),
        ScanResult(1, 500, 50.0, hash2, "error"),
    ]

    analyze_results(results)

    captured = capsys.readouterr()
    # Sorted by status
    assert f"1      200    {hash1[:16]} success" in captured.out
    assert f"1      500    {hash2[:16]} error" in captured.out
    assert "[!] WARNING: Multiple response signatures detected!" in captured.out
    assert "Observed different status code families" in captured.out

def test_analyze_results_histogram(capsys):
    # Test visualization component
    hash1 = h("body1")
    # Generate 20 results with slightly varied timings
    results = [ScanResult(i, 200, 100.0 + (i%5)*5, hash1, "body1") for i in range(20)]

    analyze_results(results)
    captured = capsys.readouterr()
    
    assert "[Timing Distribution (Histogram)]" in captured.out
    assert "|" in captured.out
    assert "#" in captured.out

# --- Tests for run_scan (Integration) ---

@pytest.mark.asyncio
async def test_run_scan_staged_strategy_setup():
    # Test that run_scan correctly identifies the staged strategy and sets up barriers
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"")
    req.edited_body = b"P1{{SYNC}}P2{{SYNC}}P3" # 2 sync points

    # Mock dependencies
    # Patching httpx.AsyncClient (used as a context manager)
    with patch("scalpel_racer.httpx.AsyncClient") as MockClient, \
         patch("scalpel_racer.analyze_results"), \
         patch("scalpel_racer.send_probe_advanced", new_callable=AsyncMock) as mock_send_probe:
        
        # Configure the mock client context manager behavior
        client_instance = MockClient.return_value
        client_instance.__aenter__.return_value = client_instance
        
        # Warmup should be ignored in staged mode
        await run_scan(req, concurrency=5, http2=False, warmup=100)

        # Verify send_probe_advanced calls
        assert mock_send_probe.call_count == 5
        args, kwargs = mock_send_probe.call_args_list[0]
        
        # Check arguments: client, request, payload, barriers, warmup_ms, index, is_staged
        assert args[2] == b"P1{{SYNC}}P2{{SYNC}}P3"
        assert len(args[3]) == 2 # 2 barriers created
        assert args[4] == 0 # warmup_ms should be 0
        assert args[6] == True # is_staged

@pytest.mark.asyncio
async def test_run_scan_lbs_strategy_setup():
    # Test standard LBS setup
    req = CapturedRequest(1, "POST", "http://example.com", {}, b"P1P2")

    # Mock dependencies
    with patch("scalpel_racer.httpx.AsyncClient") as MockClient, \
         patch("scalpel_racer.analyze_results"), \
         patch("scalpel_racer.send_probe_advanced", new_callable=AsyncMock) as mock_send_probe:

        client_instance = MockClient.return_value
        client_instance.__aenter__.return_value = client_instance

        await run_scan(req, concurrency=5, http2=False, warmup=100)

        # Verify send_probe_advanced calls
        args, kwargs = mock_send_probe.call_args_list[0]
        
        assert args[2] == b"P1P2"
        assert len(args[3]) == 1 # 1 barrier created
        assert args[4] == 100 # warmup_ms
        assert args[6] == False # is_staged
