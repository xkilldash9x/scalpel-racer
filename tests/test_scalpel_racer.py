# File: tests/test_scalpel_racer.py
import pytest
import asyncio
import ssl
import sys
import os
from unittest.mock import MagicMock, patch, AsyncMock, mock_open

# Import the module under test
from scalpel_racer import (
    run_scan, CAManager, Last_Byte_Stream_Body, Staged_Stream_Body,
    analyze_results, CaptureApp, edit_request_body, fix_sudo_ownership, 
    safe_spawn, CA_CERT_FILE, CA_KEY_FILE
)
from structures import ScanResult, CapturedRequest, SYNC_MARKER

class TestScalpelIntegration:

    @patch("scalpel_racer.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_run_scan_standard(self, mock_client):
        """Test standard async attack flow via httpx."""
        client_inst = AsyncMock()
        mock_client.return_value.__aenter__.return_value = client_inst
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.aread = AsyncMock(return_value=b"body")
        
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        client_inst.stream = MagicMock(return_value=stream_ctx)
        
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        results = await run_scan(req, concurrency=2, http2=False, warmup=0, strategy="auto")
        
        assert len(results) == 2
        assert results[0].status_code == 200
        assert results[0].error is None

    @patch("scalpel_racer.HTTP2RaceEngine")
    @patch("scalpel_racer.H2_AVAILABLE", True)
    @pytest.mark.asyncio
    async def test_run_scan_h2_delegation(self, mock_h2_cls):
        """Verify 'spa' strategy triggers HTTP2RaceEngine delegation."""
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        mock_engine = mock_h2_cls.return_value
        mock_engine.run_attack.return_value = [ScanResult(0, 200, 10)]
        
        results = await run_scan(req, concurrency=1, http2=True, warmup=0, strategy="spa")
        
        mock_h2_cls.assert_called_once()
        assert len(results) == 1
        assert results[0].status_code == 200

    @patch("scalpel_racer.H2_AVAILABLE", False)
    @pytest.mark.asyncio
    async def test_run_scan_h2_missing(self):
        """Verify fallback or error when H2 library is missing."""
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        results = await run_scan(req, concurrency=1, http2=True, warmup=0, strategy="spa")
        assert results == []

    @pytest.mark.asyncio
    async def test_last_byte_stream_logic(self):
        """
        Critical Test: Ensure the generator yields payload in two parts
        and waits on the barrier.
        """
        payload = b"Payload" # 7 bytes
        barrier = asyncio.Barrier(1)
        
        gen = Last_Byte_Stream_Body(payload, barrier, warmup_ms=0)
        
        parts = []
        async for part in gen:
            parts.append(part)
            
        # Should be split into "Payloa" and "d"
        assert len(parts) == 2
        assert parts[0] == b"Payloa"
        assert parts[1] == b"d"

    @pytest.mark.asyncio
    async def test_last_byte_stream_short_payload(self):
        """Verify handling of 1-byte payloads (no split)."""
        payload = b"X"
        gen = Last_Byte_Stream_Body(payload, None, 0)
        parts = [p async for p in gen]
        assert parts == [b"X"]

    @pytest.mark.asyncio
    async def test_staged_stream_logic(self):
        """Verify splitting by {{SYNC}} marker."""
        payload = b"Step1" + SYNC_MARKER + b"Step2"
        barriers = [asyncio.Barrier(1)]
        
        gen = Staged_Stream_Body(payload, barriers)
        parts = [p async for p in gen]
        
        assert parts == [b"Step1", b"Step2"]

    def test_ca_manager_crypto(self):
        """Test CA Manager certificate generation calls (Security)."""
        # Using context managers to keep the mock scope tight and prevent leaks
        with patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
             patch("builtins.open", mock_open()), \
             patch("os.chown"), patch("os.chmod"), \
             patch("scalpel_racer.ec.generate_private_key") as mock_key, \
             patch("scalpel_racer.x509.CertificateBuilder") as mock_builder:
            
            # Setup fluent interface for Builder
            builder_instance = mock_builder.return_value
            for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                           'not_valid_before', 'not_valid_after', 'add_extension']:
                getattr(builder_instance, method).return_value = builder_instance
            
            mgr = CAManager()
            mgr.generate_ca()
            
            # Verify that we actually called the key generation
            mock_key.assert_called()
            builder_instance.sign.assert_called()

    def test_ca_manager_caching(self):
        """Test that SSL contexts are cached by hostname."""
        with patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
             patch("builtins.open", mock_open()):
            
            mgr = CAManager()
            mgr.ca_key = MagicMock()
            mgr.ca_cert = MagicMock()
            
            with patch.object(mgr, 'generate_host_cert') as mock_gen, \
                 patch("ssl.SSLContext") as mock_ssl_ctx, \
                 patch("tempfile.TemporaryDirectory"):
                
                mock_gen.return_value = (MagicMock(), MagicMock())
                
                # First call
                ctx1 = mgr.get_ssl_context("example.com")
                # Second call
                ctx2 = mgr.get_ssl_context("example.com")
                
                assert ctx1 == ctx2
                # generate_host_cert should only be called once
                assert mock_gen.call_count == 1

    def test_analyze_results_logic(self, capsys):
        """Verify statistical analysis and grouping logic via stdout."""
        results = [
            ScanResult(0, 200, 100, "hash1", "snippet1"),
            ScanResult(1, 200, 110, "hash1", "snippet1"),
            ScanResult(2, 500, 50, "hash2", "error_page"),
        ]
        
        analyze_results(results)
        captured = capsys.readouterr()
        
        assert "[Response Signatures]" in captured.out
        # Should see two groups
        assert "200" in captured.out
        assert "500" in captured.out
        # Should verify timing average (100+110+50)/3 = 86.67
        assert "Average: 86.67ms" in captured.out

    @patch("scalpel_racer.os.chown")
    @patch("scalpel_racer.os.chmod")
    def test_fix_sudo_ownership(self, mock_chmod, mock_chown):
        """Test that file ownership is reverted if running as sudo."""
        with patch("os.geteuid", return_value=0), \
             patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"}):
            
            fix_sudo_ownership("test.pem")
            mock_chown.assert_called_with("test.pem", 1000, 1000)

    @patch("builtins.input")
    @patch("sys.stdin")
    def test_edit_request_body(self, mock_stdin, mock_input):
        """Test interactive body editor."""
        req = CapturedRequest(0, "POST", "url", [], b"old")
        
        # Simulate user input
        mock_stdin.readline.side_effect = ["new_body\n", ""]
        
        with patch("builtins.print"):
            edit_request_body(req)
        
        assert req.edited_body == b"new_body\n"

    def test_capture_app_callback(self):
        """Test CaptureApp logging callback."""
        # Mock ProxyManager import if not present
        with patch("scalpel_racer.ProxyManager", MagicMock()):
            app = CaptureApp(8080, None, None)
            req = CapturedRequest(0, "GET", "url", [], b"")
            app.on_capture("CAPTURE", req)
            
            assert len(app.request_log) == 1
            assert app.request_log[0].id == 0
            assert app.request_log[0].method == "GET"
            assert app.request_log[0].url == "url"
            assert app.request_log[0].headers == []
            assert app.request_log[0].body == b""
            assert app.request_log[0].truncated == False

    def test_generate_host_cert_integration(self, tmp_path, monkeypatch):
        """
        Integration test for CAManager.generate_host_cert.
        Runs actual crypto logic to verify file generation and SSL context creation.
        """
        # Move into the temp dir for this test to avoid file clutter
        monkeypatch.chdir(tmp_path)

        # 1. Initialize CA in temp dir
        manager = CAManager()
        manager.initialize()
        assert os.path.exists(CA_CERT_FILE), "CA Cert not created" 
        assert os.path.exists(CA_KEY_FILE), "CA Key not created"

        # 2. Trigger Host Cert Generation
        hostname = "test-target.local"
        context = manager.get_ssl_context(hostname)
        
        # Verify SSLContext returned
        assert isinstance(context, ssl.SSLContext)
        # Verify cache populated
        assert hostname in manager.cert_cache
        # Verify the cached object is indeed an SSLContext
        assert isinstance(manager.cert_cache[hostname], ssl.SSLContext)
        
        # 3. Verify IP Address logic (Regex path)
        ip_host = "127.0.0.1"
        context_ip = manager.get_ssl_context(ip_host)
        
        assert isinstance(context_ip, ssl.SSLContext)
        assert ip_host in manager.cert_cache

    @pytest.mark.asyncio
    async def test_safe_spawn_logic(self): 
        """
        Test safe_spawn ensuring the supervisor wrapper handles 
        both success and exception cases without crashing.
        """
        # Mock the TaskGroup
        tg_mock = MagicMock()
        results = [None]

        # -- Case 1: Success --
        async def success_coro():
            return "Success"
        
        # Call safe_spawn (synchronous setup)
        safe_spawn(tg_mock, success_coro(), results, 0)
        
        # Retrieve the wrapper coroutine that was passed to tg.create_task()
        assert tg_mock.create_task.called
        wrapper_coro_success = tg_mock.create_task.call_args[0][0]
        
        # Manually await it to trigger the logic
        await wrapper_coro_success
        assert results[0] == "Success"

        # -- Case 2: Failure --
        async def fail_coro():
            raise ValueError("Crash")
        
        safe_spawn(tg_mock, fail_coro(), results, 0)
        
        # Retrieve the new wrapper
        wrapper_coro_fail = tg_mock.create_task.call_args[0][0]
        
        # Await it; it should NOT raise, but should update results with an error
        await wrapper_coro_fail
        
        assert isinstance(results[0], ScanResult)
        assert results[0].error == "Crash"