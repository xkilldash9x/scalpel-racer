# tests/test_scalpel_racer.py
import pytest
import asyncio
import ssl
import sys
import os
import re
from unittest.mock import MagicMock, patch, AsyncMock, mock_open

# Import the module under test
from scalpel_racer import (
    run_scan, CAManager, Last_Byte_Stream_Body, Staged_Stream_Body,
    analyze_results, CaptureApp, 
    edit_request_body,
    safe_spawn, send_probe_advanced, CA_CERT_FILE, CA_KEY_FILE, IP_REGEX
)

# Import the new location for permission handling
import permissions

try:
    from structures import ScanResult, CapturedRequest, SYNC_MARKER
except ImportError:
    # Use fallback definitions if structures.py is missing during test
    from scalpel_racer import ScanResult, CapturedRequest, SYNC_MARKER

class TestScalpelIntegration:

    @patch("scalpel_racer.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_run_scan_standard(self, mock_client):
        """Test standard async attack flow via httpx."""
        client_inst = AsyncMock()
        mock_client.return_value.__aenter__.return_value = client_inst
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        
        # Mocking aiter_bytes for the new optimized incremental read loop
        async def async_iter_chunks():
            yield b"body"
        mock_resp.aiter_bytes = MagicMock(return_value=async_iter_chunks())
        mock_resp.aread = AsyncMock(return_value=b"body")
        
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        client_inst.stream = MagicMock(return_value=stream_ctx)
        
        # [FIX] Setup .request() to return the response because run_scan uses it directly
        # when strategy="auto" and no synchronization barriers needed.
        client_inst.request.return_value = mock_resp
        
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        # We patch GC since run_scan disables it
        with patch("gc.disable"), patch("gc.enable"):
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
        
        with patch("gc.disable"), patch("gc.enable"):
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
        
        # Verify memoryview usage
        assert isinstance(parts[0], memoryview)

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

    @pytest.mark.asyncio
    async def test_send_probe_optimization_bypass(self):
        """
        Verify that send_probe_advanced bypasses stream generation for simple requests
        (Vector Optimization).
        """
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.aread = AsyncMock(return_value=b"")
        
        # Mock incremental loop
        async def empty_aiter():
            if False: yield b"" # Empty generator
        mock_resp.aiter_bytes.return_value = empty_aiter()

        # Setup standard request return
        mock_client.request.return_value = mock_resp
        
        # Setup streaming context (not used in bypass, but good for safety)
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        mock_client.stream = MagicMock(return_value=stream_ctx)

        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        payload = b"SimplePayload"
        base_headers = MagicMock()
        base_headers.copy.return_value = {}

        # Case 1: No barriers, no warmup, not staged -> Should be raw bytes
        # This triggers the optimization path which calls client.request() directly
        await send_probe_advanced(
            mock_client, req, payload, barriers=[], warmup_ms=0, index=0, is_staged=False, base_headers=base_headers
        )
        
        # [FIX] Check client.request calls
        call_kwargs = mock_client.request.call_args[1]
        assert call_kwargs['content'] == payload, "Optimization failed: Stream used instead of raw bytes"

        # Reset mocks
        mock_client.request.reset_mock()
        mock_client.stream.reset_mock()

        # Case 2: Warmup -> Should be stream/generator
        # This triggers the complex path which calls client.request() but with generator
        await send_probe_advanced(
            mock_client, req, payload, barriers=[], warmup_ms=100, index=0, is_staged=False, base_headers=base_headers
        )
        
        # Check that client.stream was called (not .request, since it handles context manager)
        assert mock_client.stream.called
        call_kwargs_warmup = mock_client.stream.call_args[1]
        assert call_kwargs_warmup['content'] != payload, "Optimization check failed: Should use stream for warmup"

    def test_ca_manager_crypto(self):
        """Test CA Manager certificate generation calls (Security)."""
        # Using context managers to keep the mock scope tight and prevent leaks
        with patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
             patch("builtins.open", mock_open()), \
             patch("scalpel_racer.os.path.exists", return_value=False), \
             patch("scalpel_racer.os.makedirs"), \
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

    def test_ca_manager_shared_key_optimization(self):
        """Test that Host Certs reuse the shared ephemeral key (Vector Optimization)."""
        # Patch dependencies.
        # Note: We must patch CertificateBuilder here because
        # initialize() calls generate_ca() which uses it.
        # [FIX] We also patch verify_certs.ssl.create_default_context to prevent
        # ctx.load_cert_chain from trying to read non-existent mocked files.
        with patch("scalpel_racer.CRYPTOGRAPHY_AVAILABLE", True), \
             patch("builtins.open", mock_open()), \
             patch("scalpel_racer.os.path.exists", return_value=False), \
             patch("scalpel_racer.os.makedirs"), \
             patch("scalpel_racer.ec.generate_private_key") as mock_gen_key, \
             patch("scalpel_racer.x509.CertificateBuilder") as mock_builder, \
             patch("verify_certs.ssl.create_default_context"):
        
            
            # Setup fluent interface for mock builder
            builder_instance = mock_builder.return_value
            for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                           'not_valid_before', 'not_valid_after', 'add_extension']:
                getattr(builder_instance, method).return_value = builder_instance
            
            mgr = CAManager()
            mgr.initialize()
            
            # Expect 2 calls:
            # 1. Shared Ephemeral Key (initialize optimization)
            # 2. CA Private Key (generate_ca)
            assert mock_gen_key.call_count == 2
            
            # Mock the CA cert so generation doesn't crash
            mgr.ca_cert = MagicMock()
            mgr.ca_key = MagicMock()
            
            # Generate two host certs
            mgr.generate_host_cert("test1.com")
            mgr.generate_host_cert("test2.com")
            
            # Critical Check: Count should REMAIN 2.
            # If the optimization failed, generate_host_cert would call generate_private_key, 
            # increasing this count.
            assert mock_gen_key.call_count == 2

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

    # [REFACTORED TEST]
    # We patch 'permissions' module dependencies because the functionality moved there.
    @patch("permissions.os.chown")
    @patch("permissions.os.walk")
    def test_fix_sudo_ownership(self, mock_walk, mock_chown):
        """Test that file ownership is reverted if running as sudo."""
        # Mock os.walk to return a fake file structure
        # Yields: (root, dirs, files)
        mock_walk.return_value = [("/fake/dir", [], ["test.pem"])]
        
        with patch("os.geteuid", return_value=0), \
             patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"}):
            
            # Call the updated function
            permissions.restore_ownership()
            
            # Verify chown was called on the file found by walk
            expected_path = os.path.join("/fake/dir", "test.pem")
            mock_chown.assert_any_call(expected_path, 1000, 1000)

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

class TestAppIntegration:
    @patch("scalpel_racer.CertManager")
    @patch("scalpel_racer.ProxyManager")
    @patch("scalpel_racer.PromptSession")
    @patch("scalpel_racer.patch_stdout")
    @pytest.mark.asyncio
    async def test_app_startup_wiring(self, mock_patch_stdout, mock_session, mock_pm, mock_cm):
        """
        Verify that CertManager is initialized and its factory method
        is passed to the ProxyManager during app startup.
        """
        from scalpel_racer import ScalpelApp

        # Setup Mocks
        cm_instance = mock_cm.return_value
        # Mock the bound method that serves as the factory
        cm_instance.get_context_for_host = MagicMock()
        
        # [FIX] Mock ProxyManager.run to be an async mock because app.run() awaits it
        # And ensure it returns cleanly so await proxy_task doesn't deadlock.
        pm_instance = mock_pm.return_value
        pm_instance.run = AsyncMock(return_value=None)
        
        app = ScalpelApp(port=8081, strategy="spa")
        
        # Break the infinite loop for testing
        # [FIX] use EOFError to cleanly break loop
        mock_session.return_value.prompt_async.side_effect = EOFError
        
        # Run
        await app.run()
        
        # Verify CertManager init
        mock_cm.assert_called_once()
        
        # Verify ProxyManager init received the factory
        mock_pm.assert_called_once()
        call_args = mock_pm.call_args
        # Check args passed to ProxyManager constructor
        # Args: port, quic_port, ssl_factory, callback
        assert call_args[0][0] == 8081
        assert call_args[0][2] == cm_instance.get_context_for_host
        assert call_args[0][3] == app._handler