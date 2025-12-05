# FILE: tests/test_proxy_core_capture.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from proxy_core import NativeProxyHandler, StreamContext
import re

@pytest.fixture
def capture_handler():
    # Setup a handler with a mock capture callback
    capture_cb = MagicMock()
    
    # We patch H2 dependencies to avoid init errors
    with patch("proxy_core.H2_AVAILABLE", True), \
         patch("proxy_core.H2Connection"), \
         patch("proxy_core.H2Configuration"), \
         patch("proxy_core.SettingCodes"):
        
        handler = NativeProxyHandler(
            AsyncMock(), MagicMock(), 
            "original.com:443", capture_cb, 
            target_override=None, scope_pattern=None
        )
        handler.upstream_scheme = "https"
        return handler

def test_finalize_capture_standard(capture_handler):
    # Setup context with request data
    ctx = StreamContext(1, "https")
    # [FIX] Use captured_headers structure
    ctx.captured_headers = {
        "pseudo": {
            ':method': 'POST', 
            ':path': '/api/login', 
            ':authority': 'original.com'
        },
        "headers": {
            'content-type': 'application/json',
            'user-agent': 'test-agent'
        }
    }
    ctx.request_body = b'{"user": "admin"}'
    ctx.downstream_closed = True # Required to finalize

    capture_handler.finalize_capture(ctx)

    # Verify callback called with correct data
    capture_handler.capture_callback.assert_called_once()
    captured = capture_handler.capture_callback.call_args[0][0]
    
    assert captured.method == "POST"
    assert captured.url == "https://original.com/api/login"
    assert captured.body == b'{"user": "admin"}'
    assert captured.headers['content-type'] == 'application/json'

def test_finalize_capture_with_override(capture_handler):
    # Enable override
    capture_handler.target_override = "http://localhost:8080/v1/"
    
    ctx = StreamContext(1, "https")
    ctx.captured_headers = {
        "pseudo": {
            ':method': 'GET', 
            ':path': '/users?id=1', 
            ':authority': 'original.com'
        },
        "headers": {}
    }
    
    capture_handler.finalize_capture(ctx)
    
    captured = capture_handler.capture_callback.call_args[0][0]
    # Verify override is applied (base replaced, path appended)
    assert captured.url == "http://localhost:8080/v1/users?id=1"

def test_finalize_capture_scope_filtering(capture_handler):
    # Set scope to only allow specific domain
    capture_handler.scope_pattern = re.compile(r"allowed\.com")
    
    # 1. Blocked Request
    ctx_blocked = StreamContext(1, "https")
    ctx_blocked.captured_headers = {
        "pseudo": {':method': 'GET', ':path': '/', ':authority': 'blocked.com'},
        "headers": {}
    }
    
    capture_handler.finalize_capture(ctx_blocked)
    capture_handler.capture_callback.assert_not_called()
    
    # 2. Allowed Request
    ctx_allowed = StreamContext(3, "https")
    ctx_allowed.captured_headers = {
        "pseudo": {':method': 'GET', ':path': '/', ':authority': 'allowed.com'},
        "headers": {}
    }
    
    capture_handler.finalize_capture(ctx_allowed)
    capture_handler.capture_callback.assert_called_once()

def test_finalize_capture_header_filtering(capture_handler):
    # HOP_BY_HOP headers should be removed
    ctx = StreamContext(1, "https")
    ctx.captured_headers = {
        "pseudo": {':method': 'GET', ':path': '/', ':authority': 'test.com'},
        "headers": {
            'connection': 'keep-alive', # Should be removed
            'upgrade': 'h2c',           # Should be removed
            'x-custom': 'keep-me'       # Should be kept
        }
    }
    
    capture_handler.finalize_capture(ctx)
    
    captured = capture_handler.capture_callback.call_args[0][0]
    assert 'x-custom' in captured.headers
    assert 'connection' not in captured.headers
    assert 'upgrade' not in captured.headers

def test_finalize_capture_fallback_authority(capture_handler):
    # Test fallback to Host header if :authority is missing
    # [FIX] Clear explicit_host so it doesn't take precedence over the 'host' header in the fallback logic.
    capture_handler.explicit_host = None
    
    ctx = StreamContext(1, "https")
    ctx.captured_headers = {
        "pseudo": {':method': 'GET', ':path': '/'}, # No :authority
        "headers": {'host': 'fallback.com'}
    }
    
    capture_handler.finalize_capture(ctx)
    
    captured = capture_handler.capture_callback.call_args[0][0]
    assert captured.url == "https://fallback.com/"

def test_finalize_capture_fallback_explicit_host(capture_handler):
    # Test fallback to explicit_host (CONNECT target) if :authority and Host are missing
    capture_handler.explicit_host = "connect-target.com"
    
    ctx = StreamContext(1, "https")
    ctx.captured_headers = {
        "pseudo": {':method': 'GET', ':path': '/'}, 
        "headers": {} # No Host header
    }
    
    capture_handler.finalize_capture(ctx)
    
    captured = capture_handler.capture_callback.call_args[0][0]
    assert captured.url == "https://connect-target.com/"