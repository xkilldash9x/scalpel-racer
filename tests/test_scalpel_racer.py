# tests/test_scalpel_racer.py
import pytest
import asyncio
import sys
import os
from unittest.mock import MagicMock, patch, AsyncMock, mock_open

# Import the module under test
from scalpel_racer import (
    run_scan, CertManager, Last_Byte_Stream_Body, Staged_Stream_Body,
    analyze_results, ScalpelApp, 
    safe_spawn, send_probe_advanced
)

# [FIX] Import verify_certs to ensure the patcher can find the module
import verify_certs
# Import permissions to patch ownership logic
import permissions

try:
    from structures import ScanResult, CapturedRequest, SYNC_MARKER
except ImportError:
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
        
        async def async_iter_chunks():
            yield b"body"
        mock_resp.aiter_bytes = MagicMock(return_value=async_iter_chunks())
        mock_resp.aread = AsyncMock(return_value=b"body")
        
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        client_inst.stream = MagicMock(return_value=stream_ctx)
        
        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        
        with patch("gc.disable"), patch("gc.enable"):
            results = await run_scan(req, concurrency=2, http2=False, warmup=0, strategy="auto")
        
        assert len(results) == 2
        assert results[0].status_code == 200
        assert results[0].error is None

    @patch("scalpel_racer.HTTP2RaceEngine")
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

    @pytest.mark.asyncio
    async def test_last_byte_stream_logic(self):
        """Critical Test: Ensure generator yields payload in two parts."""
        payload = b"Payload" 
        barrier = asyncio.Barrier(1)
        
        gen = Last_Byte_Stream_Body(payload, barrier, warmup_ms=0)
        
        parts = []
        async for part in gen:
            parts.append(part)
            
        assert len(parts) == 2
        assert parts[0] == b"Payloa"
        assert parts[1] == b"d"
        assert isinstance(parts[0], bytes)

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
    async def test_send_probe_advanced_usage(self):
        """
        Verify that send_probe_advanced uses client.stream correctly.
        """
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.aread = AsyncMock(return_value=b"")
        
        async def empty_aiter():
            if False: yield b""
        mock_resp.aiter_bytes.return_value = empty_aiter()

        stream_ctx = AsyncMock()
        stream_ctx.__aenter__.return_value = mock_resp
        mock_client.stream = MagicMock(return_value=stream_ctx)

        req = CapturedRequest(0, "GET", "http://a.com", [], b"")
        payload = b"SimplePayload"
        
        # Case 1: Standard send (No barriers)
        await send_probe_advanced(
            mock_client, req, payload, barriers=[], warmup_ms=0, index=0, is_staged=False
        )
        
        # Verify call arguments
        assert mock_client.stream.called
        call_kwargs = mock_client.stream.call_args[1]
        
        # Verify content is a generator/iterator, not raw bytes
        content_arg = call_kwargs['content']
        assert hasattr(content_arg, '__aiter__') or hasattr(content_arg, '__anext__')
        
        # Consume the generator to ensure it yields the correct data
        parts = [p async for p in content_arg]
        assert b"".join(parts) == payload

        # Reset
        mock_client.stream.reset_mock()

        # Case 2: Warmup/Complex -> Should also use generator
        await send_probe_advanced(
            mock_client, req, payload, barriers=[], warmup_ms=100, index=0, is_staged=False
        )
        
        assert mock_client.stream.called
        call_kwargs_warmup = mock_client.stream.call_args[1]
        assert call_kwargs_warmup['content'] != payload

    def test_ca_manager_crypto(self):
        """Test CA Manager certificate generation calls (Security)."""
        # [FIX] Patch 'verify_certs' namespaces instead of 'scalpel_racer'
        # The CertManager code resides in verify_certs.py
        with patch("builtins.open", mock_open()), \
             patch("verify_certs.os.path.exists", return_value=False), \
             patch("verify_certs.os.makedirs"), \
             patch("os.chown"), patch("os.chmod"), \
             patch("verify_certs.ec.generate_private_key") as mock_key, \
             patch("verify_certs.x509.CertificateBuilder") as mock_builder:
            
            # Setup fluent interface for Builder
            builder_instance = mock_builder.return_value
            for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                           'not_valid_before', 'not_valid_after', 'add_extension']:
                getattr(builder_instance, method).return_value = builder_instance
            
            # [FIXED] CertManager generates CA in __init__ automatically via _load_or_generate_ca
            # We do NOT call generate_ca() manually anymore as the method was removed.
            mgr = CertManager()
            
            # Verify that we actually called the key generation
            mock_key.assert_called()
            builder_instance.sign.assert_called()

    def test_ca_manager_shared_key_optimization(self):
        """Test that Host Certs reuse the shared ephemeral key (Vector Optimization)."""
        # [FIX] Patch 'verify_certs' namespaces
        with patch("builtins.open", mock_open()), \
             patch("verify_certs.os.path.exists", return_value=False), \
             patch("verify_certs.os.makedirs"), \
             patch("verify_certs.ec.generate_private_key") as mock_gen_key, \
             patch("verify_certs.x509.CertificateBuilder") as mock_builder, \
             patch("verify_certs.ssl.create_default_context"):
            
            builder_instance = mock_builder.return_value
            for method in ['subject_name', 'issuer_name', 'public_key', 'serial_number', 
                           'not_valid_before', 'not_valid_after', 'add_extension']:
                getattr(builder_instance, method).return_value = builder_instance
            
            mgr = CertManager()
            # This triggers _load_or_generate_ca (1 key gen) + shared key init (1 key gen)
            # Re-initialize to ensure we capture the constructor calls
            mgr.__init__()
            
            # Expect 2 calls: 1. Shared Ephemeral Key, 2. CA Private Key
            assert mock_gen_key.call_count >= 2
            
            mgr.ca_cert = MagicMock()
            mgr.ca_key = MagicMock()
            
            current_call_count = mock_gen_key.call_count
            
            # [FIXED] Use get_context_for_host instead of generate_host_cert
            mgr.get_context_for_host("test1.com")
            mgr.get_context_for_host("test2.com")
            
            # Critical Check: Count should NOT increase if optimization works
            assert mock_gen_key.call_count == current_call_count

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
        assert "200" in captured.out
        assert "500" in captured.out
        assert "Average: 86.67ms" in captured.out

    @patch("permissions.os.chown")
    @patch("permissions.os.walk")
    def test_fix_sudo_ownership(self, mock_walk, mock_chown):
        """Test that file ownership is reverted if running as sudo."""
        mock_walk.return_value = [("/fake/dir", [], ["test.pem"])]
        
        with patch("os.geteuid", return_value=0), \
             patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"}):
            
            permissions.restore_ownership()
            
            expected_path = os.path.join("/fake/dir", "test.pem")
            mock_chown.assert_any_call(expected_path, 1000, 1000)

    @patch("scalpel_racer.print_formatted_text")
    @patch("scalpel_racer.PromptSession")
    def test_scalpel_app_handler(self, mock_session, mock_print):
        """Test ScalpelApp logging callback."""
        with patch("scalpel_racer.ProxyManager", MagicMock()):
            app = ScalpelApp(8080, "auto")
            req = CapturedRequest(0, "GET", "url", [], b"")
            app._handler("CAPTURE", req)
            
            assert len(app.storage) == 1
            assert app.storage[0].id == 0
            assert app.storage[0].method == "GET"

    @pytest.mark.asyncio
    async def test_safe_spawn_logic(self): 
        """Test safe_spawn supervisor wrapper."""
        tg_mock = MagicMock()
        results = [None]

        # Success Case
        async def success_coro(): return "Success"
        safe_spawn(tg_mock, success_coro(), results, 0)
        wrapper_coro_success = tg_mock.create_task.call_args[0][0]
        await wrapper_coro_success
        assert results[0] == "Success"

        # Failure Case
        async def fail_coro(): raise ValueError("Crash")
        safe_spawn(tg_mock, fail_coro(), results, 0)
        wrapper_coro_fail = tg_mock.create_task.call_args[0][0]
        await wrapper_coro_fail
        assert isinstance(results[0], ScanResult)
        assert results[0].error == "Crash"

class TestAppIntegration:
    @patch("scalpel_racer.print_formatted_text")
    @patch("scalpel_racer.CertManager")
    @patch("scalpel_racer.ProxyManager")
    @patch("scalpel_racer.PromptSession")
    @patch("scalpel_racer.patch_stdout")
    @pytest.mark.asyncio
    async def test_app_startup_wiring(self, mock_patch_stdout, mock_session, mock_pm, mock_cm, mock_print):
        """Verify initialization wiring."""
        from scalpel_racer import ScalpelApp

        cm_instance = mock_cm.return_value
        cm_instance.get_context_for_host = MagicMock()
        
        pm_instance = mock_pm.return_value
        pm_instance.run = AsyncMock(return_value=None)
        
        app = ScalpelApp(port=8081, strategy="spa")
        mock_session.return_value.prompt_async.side_effect = EOFError
        
        await app.run()
        
        mock_cm.assert_called_once()
        mock_pm.assert_called_once()
        
        # [FIX] Access kwargs since ProxyManager uses keyword arguments in production code
        # ScalpelApp initializes ProxyManager(tcp_port=..., ...)
        # Using .call_args.kwargs retrieves the dictionary of keyword arguments passed
        call_kwargs = mock_pm.call_args.kwargs
        assert call_kwargs['tcp_port'] == 8081
        assert call_kwargs['ssl_context_factory'] == cm_instance.get_context_for_host
        assert call_kwargs['external_callback'] == app._handler