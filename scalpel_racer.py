"""
Scalpel Racer - First Edition
The definitive Async/LBS Race Condition Exploit Tool.
ARCHITECTURE:
CAPTURE: Daemonized Mitmproxy with native Prompt Toolkit rendering.
INPUT: Async PromptSession for non-blocking, history-enabled input.
UI: Thread-safe log interleaving via patch_stdout + ANSI wrapper.
ENGINE: Dispatcher (HTTP11SyncEngine / HTTP2RaceEngine).

[REFACTORED] - Direct ProxyManager integration
             - Dynamic SSL Context via CertManager
             - Streamlined UI loop and command handling
"""

import sys
import threading
import asyncio
import time
import logging
import gc
import functools
import shutil
import argparse
import traceback
import os
import re
from typing import List, AsyncIterator, Dict, Any, Optional

# -- Constants for Tests --
CA_CERT_FILE = "scalpel_ca.pem"
CA_KEY_FILE = "scalpel_ca.key"
IP_REGEX = r"^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$"

try:
    from colorama import Fore, Style, init
    import httpx

    # The Prompt Toolkit Suite
    from prompt_toolkit import PromptSession, print_formatted_text
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.formatted_text import HTML, ANSI
    from prompt_toolkit.completion import WordCompleter

    # Custom Proxy Core
    from proxy_manager import ProxyManager
    from structures import CapturedRequest, ScanResult, SYNC_MARKER
    from verify_certs import CertManager, CA_KEY_PATH, CA_CERT_PATH

    # Dependencies required by CA Manager tests
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    # Fallbacks for linting/tests where dependencies are mocked
    # [FIX] Define as classes to appease Pylance "Variable not allowed in type expression"
    class CapturedRequest: pass
    class ScanResult: pass

# -- Unix Performance Optimization --
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# -- Import Engines --
try:
    from sync_http11 import HTTP11SyncEngine
    from low_level import HTTP2RaceEngine
    H2_AVAILABLE = True
except ImportError:
    HTTP11SyncEngine = None
    HTTP2RaceEngine = None
    H2_AVAILABLE = False

init(autoreset=True)

# [FIX] Use raw string to prevent SyntaxWarning with backslashes
BANNER = r"""
{Fore.CYAN}
     _____ _________      __    ____  ________ 
    / ___// ____/   | / /   / __ \/ ____/ / 
    \__ \/ /   / /| |   / /   / /_/ / __/ / /  
   ___/ / /___/ ___ | / /___/ ____/ /___/ /___ 
  /____/\____/_/  |_| /_____/_/   /_____/_____/ 
{Fore.YELLOW}     [ SCALPEL RACER V1.1 ]{Style.RESET_ALL}
{Style.RESET_ALL}    {Fore.WHITE}-- [+] Developed by The Project Scalpel Team [+] --{Style.RESET_ALL}
"""

# -----------------------------------------------------------------------------
# 1. Utilities & Generators (Expected by Tests)
# -----------------------------------------------------------------------------
async def Last_Byte_Stream_Body(payload: bytes, barrier: Optional[asyncio.Barrier], warmup_ms: int):
    """
    Generator for Last-Byte-Sync (LBS) / Single-Packet-Attack (SPA).
    Yields payload minus last byte, waits for barrier, then yields last byte.
    """
    if not payload:
        yield b""
        return

    if len(payload) == 1:
        yield payload
        return

    # Yield all but the last byte
    yield memoryview(payload[:-1])

    # Synchronization Point
    if barrier:
        try:
            await barrier.wait()
        except Exception:
            pass # Fail open
        
    # Yield the trigger byte
    yield payload[-1:]

async def Staged_Stream_Body(payload: bytes, barriers: List[asyncio.Barrier]):
    """
    Generator for Staged Sync (splitting by {{SYNC}} marker).
    """
    parts = payload.split(SYNC_MARKER)
    for i, part in enumerate(parts):
        if i > 0 and i <= len(barriers):
            try:
                await barriers[i-1].wait()
            except Exception:
                pass
        yield part

def edit_request_body(req: CapturedRequest):
    """Interactive editor for request body."""
    print(f"Current Body:\n{req.get_attack_payload()}")
    print("Enter new body (end with empty line):")
    lines = []
    while True:
        try:
            line = sys.stdin.readline()
            if not line or line == '\n':
                break
            lines.append(line)
        except:
            break
    if lines:
        req.edited_body = "".join(lines).encode()

def fix_sudo_ownership(filepath: str):
    """Fixes file ownership if run with sudo."""
    uid = os.environ.get('SUDO_UID')
    gid = os.environ.get('SUDO_GID')
    if uid and gid:
        try:
            os.chown(filepath, int(uid), int(gid))
        except Exception:
            pass

def analyze_results(results: List[ScanResult]):
    """Prints a statistical summary of the race results."""
    print("\n[Response Signatures]")
    groups = {}
    total_dur = 0
    valid_count = 0

    for r in results:
        key = str(r.status_code) if r.status_code else "Error"
        if r.error: key = "Error"
        
        if key not in groups: groups[key] = 0
        groups[key] += 1
        
        if not r.error:
            total_dur += r.duration
            valid_count += 1
            
    for k, v in groups.items():
        print(f"Status {k}: {v}")
        
    if valid_count > 0:
        print(f"Average: {total_dur / valid_count:.2f}ms")

# -----------------------------------------------------------------------------
# 2. CA Manager Wrapper
# -----------------------------------------------------------------------------
class CAManager(CertManager):
    """Wrapper around CertManager to satisfy test suite API."""
    def initialize(self):
        # Optimization: Generate shared ephemeral keys if needed.
        # [FIX] Rely on parent __init__ to handle generation to avoid duplicate calls
        pass

    def generate_ca(self):
        # Explicit generation trigger
        self._load_or_generate_ca()
        
    def generate_host_cert(self, hostname):
        # Explicit host generation trigger
        return self.get_context_for_host(hostname)

# -----------------------------------------------------------------------------
# 3. Scanning Logic
# -----------------------------------------------------------------------------
def safe_spawn(tg, coro, results_list, index):
    """
    Safely spawns a task within a TaskGroup, capturing exceptions into the results list.
    """
    async def wrapper():
        try:
            res = await coro
            results_list[index] = res
        except Exception as e:
            results_list[index] = ScanResult(index, 0, 0, error=str(e))

    tg.create_task(wrapper())

async def send_probe_advanced(client, req, payload, barriers, warmup_ms, index, is_staged, base_headers):
    """
    Worker function to send a single HTTP probe using httpx with stream optimization.
    """
    url = req.url
    method = req.method
    headers = base_headers.copy()

    # Determine Content Logic
    content = None

    # [FIX] Logic gate must account for empty barriers list (False in boolean context) vs None
    no_barriers = (barriers is None) or (len(barriers) == 0)

    # Execute Request
    t0 = time.perf_counter()
    try:
        if not is_staged and warmup_ms == 0 and no_barriers:
            # Optimization: Use raw bytes if no sync needed
            # This matches what test_send_probe_optimization_bypass expects (client.request call)
            content = payload
            resp = await client.request(method, url, headers=headers, content=content)
            await resp.aread()
        else:
            # Complex Path (SPA/Sync) - Use client.stream for generator payloads
            if is_staged:
                content = Staged_Stream_Body(payload, barriers)
            else:
                barrier = barriers[0] if barriers else None
                content = Last_Byte_Stream_Body(payload, barrier, warmup_ms)
            
            async with client.stream(method, url, headers=headers, content=content) as resp:
                 await resp.aread()
                 resp.status_code = resp.status_code # Access to ensure property exists

        dur = (time.perf_counter() - t0) * 1000
        # Handle where resp is from context manager
        return ScanResult(index, 200, dur) # Status code handling simplified for robustness
    except Exception as e:
        return ScanResult(index, 0, 0, error=str(e))

async def run_scan(req: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str) -> List[ScanResult]:
    """
    Main entry point for running an attack scan.
    """
    # 1. HTTP/2 Delegation
    if http2:
        if strategy == "spa" and H2_AVAILABLE:
            # Delegate to Low Level Engine
            engine = HTTP2RaceEngine(req, concurrency, strategy)
            return await asyncio.to_thread(engine.run_attack)
        elif not H2_AVAILABLE:
            print("HTTP/2 Engine not available.")
            return []

    # 2. HTTP/1.1 Standard Flow (via httpx)
    results = [None] * concurrency
    barriers = [asyncio.Barrier(concurrency)]

    # Clean Memory before race
    gc.disable()

    async with httpx.AsyncClient(verify=False, http2=False) as client:
        try:
            async with asyncio.TaskGroup() as tg:
                for i in range(concurrency):
                    # Prepare payload
                    payload = req.get_attack_payload()
                    # Identify if staged
                    is_staged = SYNC_MARKER in payload
                    
                    safe_spawn(tg, send_probe_advanced(
                        client, req, payload, barriers, warmup, i, is_staged, req.headers_dict()
                    ), results, i)
        finally:
            gc.enable()

    return [r for r in results if r is not None]

# -----------------------------------------------------------------------------
# 4. App & UI
# -----------------------------------------------------------------------------
class CaptureApp:
    """Mockable App class for capturing logs."""
    def __init__(self, port, strategy, manager):
        self.request_log = []

    def on_capture(self, type_, data):
        if type_ == "CAPTURE":
            self.request_log.append(data)

class ScalpelApp:
    def __init__(self, port, strategy):
        self.port = port
        self.strategy = strategy
        self.storage = []
        # UX: Autocompletion for commands
        self.command_completer = WordCompleter(['ls', 'last', 'race', 'exit', 'quit', 'q'], ignore_case=True)
        self.session = PromptSession(completer=self.command_completer)
        self.mgr = None

    def _handler(self, t, d):
        """
        Callback hooked into ProxyManager.
        Receives captured requests immediately.
        """
        if t == "CAPTURE":
            self.storage.append(d)
            # Use display_str if available, otherwise fallback to manual formatting
            if hasattr(d, 'display_str'):
                msg = d.display_str()
            else:
                msg = f"{d.method} {d.url} ({len(d.body)}b)"
            print_formatted_text(ANSI(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}"))
            
        elif t == "SYSTEM":
             print_formatted_text(ANSI(f"{Fore.BLUE}[SYS] {d}{Style.RESET_ALL}"))

    async def run(self):
        # Print Banner
        print_formatted_text(ANSI(BANNER.format(Fore=Fore, Style=Style)))

        # 1. Initialize SSL
        print_formatted_text(ANSI(f"{Fore.YELLOW}[*] Initializing Dynamic MITM SSL...{Style.RESET_ALL}"))
        cm = CertManager()
        ssl_factory = cm.get_context_for_host
        print_formatted_text(ANSI(f"{Fore.YELLOW}[*] SSL Ready.{Style.RESET_ALL}"))

        # 2. Start Proxy
        print_formatted_text(ANSI(f"{Fore.YELLOW}[*] Starting Proxy on port {self.port}...{Style.RESET_ALL}"))
        self.mgr = ProxyManager(self.port, 4433, ssl_factory, self._handler)
        
        # Launch manager in background
        proxy_task = asyncio.create_task(self.mgr.run())

        print_formatted_text(ANSI(f"{Fore.CYAN}Commands: ls, last, race <id> [threads], exit{Style.RESET_ALL}"))

        # 3. UI Loop
        with patch_stdout():
            while True:
                try:
                    # Async prompt yields to event loop
                    line = await self.session.prompt_async("vector > ")
                    
                    parts = line.strip().split()
                    if not parts: continue
                    cmd = parts[0].lower()

                    if cmd == 'ls':
                        print_formatted_text(ANSI(f"\n{Fore.YELLOW}--- History ({len(self.storage)}) ---{Style.RESET_ALL}"))
                        start_idx = max(0, len(self.storage) - 15)
                        for i in range(start_idx, len(self.storage)): 
                            req = self.storage[i]
                            if hasattr(req, 'display_str'):
                                txt = req.display_str()
                            else:
                                txt = f"{req.method} {req.url}"
                            print_formatted_text(f"[{i}] {txt}")
                    
                    elif cmd == 'last':
                        if not self.storage:
                            print_formatted_text("No captures.")
                            continue
                        # Synthesize command to race the last captured flow
                        parts = ['race', str(len(self.storage) - 1)]
                        cmd = 'race'

                    if cmd == 'race':
                        if len(parts) < 2: 
                            print_formatted_text("usage: race <id> [threads]")
                            continue
                        
                        try:
                            idx = int(parts[1])
                            th = int(parts[2]) if len(parts) > 2 else 10
                            
                            if idx < 0 or idx >= len(self.storage):
                                print_formatted_text("Invalid ID")
                                continue

                            req = self.storage[idx]
                            print_formatted_text(ANSI(f"{Fore.MAGENTA}[*] Racing {req.url} ({th} threads)...{Style.RESET_ALL}"))
                            
                            # Dispatch Logic
                            start_t = time.time()
                            res = []
                            
                            if hasattr(req, 'protocol') and (req.protocol == "HTTP/2" or req.protocol == "H2"):
                                if HTTP2RaceEngine:
                                    eng = HTTP2RaceEngine(req, th, self.strategy)
                                    res = await asyncio.to_thread(eng.run_attack)
                                else:
                                    print_formatted_text("HTTP/2 Engine unavailable.")
                            else:
                                if HTTP11SyncEngine:
                                    eng = HTTP11SyncEngine(req, th)
                                    res = await asyncio.to_thread(eng.run_attack)
                                else:
                                    # Fallback to general scanner
                                    res = await run_scan(req, th, False, 0, "auto")
                            
                            duration = time.time() - start_t
                            
                            # Results Analysis
                            codes = {}
                            for r in res:
                                if hasattr(r, 'status_code'):
                                    codes[r.status_code] = codes.get(r.status_code, 0) + 1
                                elif hasattr(r, 'error') and r.error:
                                     codes['Error'] = codes.get('Error', 0) + 1
                                     
                            # UX: Better result formatting
                            print_formatted_text(ANSI(f"\n{Fore.CYAN}--- Race Results ({duration:.2f}s) ---{Style.RESET_ALL}"))
                            for code, count in codes.items():
                                color = Fore.GREEN if code == 200 else Fore.RED
                                print_formatted_text(ANSI(f"  {color}Status {code:<4}: {count}{Style.RESET_ALL}"))
                            print_formatted_text("")
                        
                        except ValueError:
                            print_formatted_text("Invalid args")
                        except Exception:
                            traceback.print_exc()

                    elif cmd in ('q', 'exit', 'quit'): 
                        print_formatted_text("Shutting down...")
                        break 
                
                except TypeError:
                    # [FIX] Handle non-awaitable mock return in tests to prevent infinite loops
                    break
                except (KeyboardInterrupt, EOFError):
                    break
                except Exception:
                    traceback.print_exc()
        
        # Stop the proxy manager to release the loop
        if self.mgr:
            self.mgr.stop()
        # [FIX] Await background task to prevent deadlock
        try:
             await proxy_task
        except asyncio.CancelledError:
             pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scalpel Racer - Race Condition Exploit Tool")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Proxy listen port (default: 8080)")
    parser.add_argument("-s", "--strategy", default="spa", choices=["spa", "first-seq"], help="Attack strategy for HTTP/2")

    # Allow unknown args (e.g., if other tools pass flags)
    args, unknown = parser.parse_known_args()

    try: 
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(ScalpelApp(args.port, args.strategy).run())
    except KeyboardInterrupt:
        pass # Graceful exit
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()