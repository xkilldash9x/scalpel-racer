# scalpel_racer.py
"""
Scalpel Racer -- Advanced Race Condition Testing Tool.
[Merged Edition: Interactive UI + Refactored Secure Backend + Histogram Analytics]

ARCHITECTURE:
- UI: PromptToolkit Interactive Shell.
- PROXY: Delegates to 'proxy_manager.py' (QUIC/TCP) and 'proxy_core.py'.
- CERTS: Delegates to 'verify_certs.py' (CertManager).
- ATTACK: Internal 'low_level' (H2) and 'httpx' (H1) engines.
"""

import sys
import asyncio
import time
import argparse
import traceback
import logging
import hashlib
import gc
from typing import List, AsyncIterator, Optional, Dict, Union, Tuple
from collections import defaultdict

# -- Third Party Dependencies --

# 1. Formatting & UI
try:
    from colorama import Fore, Style, init as colorama_init
    from prompt_toolkit import PromptSession, print_formatted_text
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.formatted_text import HTML, ANSI
    from prompt_toolkit.completion import WordCompleter
    UI_AVAILABLE = True
except ImportError:
    UI_AVAILABLE = False

    # Fallback for missing UI libraries
    def print_formatted_text(*args, **kwargs):
        for arg in args:
            print(arg)

    def ANSI(text): return text
    def HTML(text): return text

    class PromptSession:
        def __init__(self, completer=None, **kwargs): pass
        async def prompt_async(self, text): return await asyncio.to_thread(input, text)

    class WordCompleter:
        def __init__(self, words, ignore_case=True): pass

    class patch_stdout:
        def __enter__(self): pass
        def __exit__(self, *args): pass

    # Mock Colorama
    class MockColor:
        def __getattr__(self, name): return ""

    Fore = MockColor()
    Style = MockColor()

    print("Warning: 'prompt_toolkit' or 'colorama' not found. UI will be limited.")

# 2. Network & Performance
try:
    import httpx
    import uvloop
    if sys.platform != "win32":
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# 3. Data Science (Histogram)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

# -- Internal Modules --

# [STRICT REQUIREMENT] Proxy Manager must be present
try:
    from proxy_manager import ProxyManager
except ImportError:
    print(f"{Fore.RED}[CRITICAL] 'proxy_manager.py' not found. Cannot start interception engine.{Style.RESET_ALL}")
    sys.exit(1)

# [STRICT REQUIREMENT] Certificate Manager must be present
try:
    from verify_certs import CertManager
except ImportError:
    print(f"{Fore.RED}[CRITICAL] 'verify_certs.py' not found. Cannot manage SSL/TLS.{Style.RESET_ALL}")
    sys.exit(1)

# [STRICT REQUIREMENT] HTTP/2 Engine must be present
from low_level import HTTP2RaceEngine

# -- Structures & Constants --
from structures import (
    ScanResult, 
    CapturedRequest, 
    SYNC_MARKER
)

# Initialize Colorama
if UI_AVAILABLE:
    colorama_init(autoreset=True)

# Global Configuration
DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100 

# Global Logger
logger = logging.getLogger(__name__)

# Banner
BANNER = r"""
{Fore.CYAN}
   _____ _________    __    ____  ________ 
  / ___// ____/   |  / /   / __ \/ ____/ / 
  \__ \/ /   / /| | / /   / /_/ / __/ / /  
 ___/ / /___/ ___ |/ /___/ ____/ /___/ /___
/____/\____/_/  |_/_____/_/   /_____/_____/
{Fore.YELLOW}     [ SCALPEL RACER V2.2 ]{Style.RESET_ALL}
{Style.RESET_ALL}    {Fore.WHITE}-- [+] Integrated Proxy & Cert Manager [+] --{Style.RESET_ALL}
"""

# -----------------------------------------------------------------------------
# 1. Race Condition Logic
# -----------------------------------------------------------------------------

def safe_spawn(tg: asyncio.TaskGroup, coro, result_list, index):
    """Supervisor wrapper for tasks to prevent fail-fast cascades."""
    async def wrapper():
        try:
            res = await coro
            result_list[index] = res
        except Exception as e:
            # logger.debug(f"Probe {index} failed: {e}")
            result_list[index] = ScanResult(index, 0, 0, error=str(e))
    tg.create_task(wrapper())

async def Last_Byte_Stream_Body(payload: bytes, barrier: asyncio.Barrier, warmup_ms: int) -> AsyncIterator[bytes]:
    """Streams request body, pausing before the last byte for synchronization."""
    if len(payload) <= 1:
        if warmup_ms > 0:
            await asyncio.sleep(warmup_ms / 1000.0)
        try:
            if barrier: await barrier.wait()
        except asyncio.BrokenBarrierError:
            pass
        yield payload
        return

    yield payload[:-1] 

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        if barrier: await barrier.wait() 
    except asyncio.BrokenBarrierError:
        pass

    yield payload[-1:]

async def Staged_Stream_Body(payload: bytes, barriers: List[asyncio.Barrier]) -> AsyncIterator[bytes]:
    """Splits payload by {{SYNC}} markers for multi-step synchronization."""
    parts = payload.split(SYNC_MARKER)
    barrier_idx = 0
    
    for i, part in enumerate(parts):
        if i > 0:
            if barrier_idx < len(barriers):
                try:
                    await barriers[barrier_idx].wait()
                    barrier_idx += 1
                except asyncio.BrokenBarrierError:
                    pass
        if part:
            yield part

async def send_probe_advanced(client: httpx.AsyncClient, request: CapturedRequest, payload: bytes, barriers: List[asyncio.Barrier], warmup_ms: int, index: int, is_staged: bool) -> ScanResult:
    """
    Sends a single probe request using httpx with the specified synchronization strategy.
    """
    start_time = time.perf_counter()
    body_hash = None
    body_snippet = None

    try:
        # Convert Headers to dict if they are list of tuples (common in H2)
        if isinstance(request.headers, list):
             req_headers = httpx.Headers(request.headers)
        else:
             req_headers = httpx.Headers(request.headers)

        req_headers["User-Agent"] = "Scalpel-CLI/5.4-Optimized"
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        # Fix Content-Length
        actual_length = len(payload)
        req_headers["Content-Length"] = str(actual_length)

        if "content-type" not in req_headers and request.method in ["POST", "PUT", "PATCH"] and actual_length > 0:
             req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        content_stream = None
        if is_staged:
            content_stream = Staged_Stream_Body(payload, barriers)
        else:
            barrier = barriers[0] if barriers else None
            content_stream = Last_Byte_Stream_Body(payload, barrier, warmup_ms)
            
        content = content_stream if content_stream else payload

        async with client.stream(
            method=request.method,
            url=request.url,
            content=content,
            headers=req_headers
        ) as response:
            body = await response.aread()
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')

        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, response.status_code, duration, body_hash, body_snippet)
        
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, error=str(e))

async def run_scan(request: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str = "auto"):
    """
    Orchestrates the race condition attack.
    """
    # Ensure request has helper methods. 
    # If it came from ProxyManager's internal class, it might lack 'get_attack_payload'.
    # We monkey-patch or use direct body access.
    if hasattr(request, 'get_attack_payload'):
        attack_payload = request.get_attack_payload()
    else:
        attack_payload = request.body

    sync_markers_count = attack_payload.count(SYNC_MARKER)

    # H2 Engine Delegation - STRICT (Always Available)
    use_h2_engine = False
    if strategy in ["spa", "first-seq"]:
        use_h2_engine = True

    if use_h2_engine:
        # Direct call to HTTP2RaceEngine
        engine = HTTP2RaceEngine(request, concurrency, strategy, warmup)
        return await asyncio.to_thread(engine.run_attack)

    # Standard HTTPX (H1/H2) with Barriers
    barriers = []
    if sync_markers_count > 0:
        for _ in range(sync_markers_count):
            barriers.append(asyncio.Barrier(concurrency))
        warmup = 0 
    elif concurrency > 1:
        barriers.append(asyncio.Barrier(concurrency))

    # Memory Cleanup
    gc.collect()
    gc.disable()

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency*2)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)

    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=timeout, verify=False) as client:
        results = [None] * concurrency
        
        if hasattr(asyncio, 'TaskGroup'):
            async with asyncio.TaskGroup() as tg:
                for i in range(concurrency):
                    safe_spawn(
                        tg, 
                        send_probe_advanced(
                            client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0
                        ), 
                        results, 
                        i
                    )
        else:
            # Fallback
            tasks = [
                send_probe_advanced(client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0) 
                for i in range(concurrency)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r if isinstance(r, ScanResult) else ScanResult(i, 0, 0, error=str(r)) for i, r in enumerate(results)]

    gc.enable()
    return results

# -----------------------------------------------------------------------------
# 2. Analytics & Histogram
# -----------------------------------------------------------------------------

def analyze_results(results: List[ScanResult]):
    """
    Analyzes and prints statistical data from the scan results.
    Includes Numpy Histogram Logic.
    """
    if not results:
        print_formatted_text(ANSI(f"\n{Fore.RED}-- Analysis Summary --\n  (No results to analyze){Style.RESET_ALL}"))
        return
        
    successful = [r for r in results if r.error is None]
    
    print_formatted_text(ANSI(f"\n{Fore.CYAN}-- Analysis Summary --{Style.RESET_ALL}"))

    signatures = defaultdict(list)
    for r in successful:
        key = (r.status_code, r.status_code//100, r.body_hash) 
        signatures[key].append(r)

    print_formatted_text(ANSI(f"\n{Fore.YELLOW}[Response Signatures]{Style.RESET_ALL}"))
    
    if not signatures:
        print("  (No successful responses)")
    else:
        sorted_keys = sorted(signatures.keys(), key=lambda k: k[0])

        print(f"  {'Count':<6} {'Status':<6} {'Hash (SHA256)':<16} {'Snippet (First 100 chars)'}")
        print("  " + "-" * 90)
        for key in sorted_keys:
            status_code, _, body_hash = key
            group = signatures[key]
            count = len(group)
            snippet = group[0].body_snippet if group and group[0].body_snippet else ""
            hash_short = body_hash[:16] if body_hash else "N/A (Empty)"
            
            # Colorize status
            sc_color = Fore.GREEN if 200 <= status_code < 300 else (Fore.RED if status_code >= 500 else Fore.YELLOW)
            
            print_formatted_text(ANSI(f"  {count:<6} {sc_color}{status_code:<6}{Style.RESET_ALL} {hash_short:<16} {snippet}"))
        
        print("  " + "-" * 90)

        if len(signatures) > 1:
            print_formatted_text(ANSI(f"\n  {Fore.RED}[!] WARNING: Multiple response signatures detected! Indicates potential race condition.{Style.RESET_ALL}"))

    if successful:
        timings = [r.duration for r in successful]
        if len(timings) > 0:
            avg = sum(timings) / len(timings)
            min_t = min(timings)
            max_t = max(timings)
            
            if len(timings) > 1:
                std_dev = (sum((t - avg) ** 2 for t in timings) / (len(timings)-1)) ** 0.5
            else:
                std_dev = 0.0
            
            print_formatted_text(ANSI(f"\n{Fore.YELLOW}[Timing Metrics]{Style.RESET_ALL}"))
            print(f"  Average: {avg:.2f}ms")
            print(f"  Min/Max: {min_t:.2f}ms / {max_t:.2f}ms")
            print(f"  Jitter (StdDev): {std_dev:.2f}ms")
            
            # -- HISTOGRAM LOGIC --
            if len(timings) > 1 and NUMPY_AVAILABLE:
                print_formatted_text(ANSI(f"\n{Fore.YELLOW}[Timing Distribution (Histogram)]{Style.RESET_ALL}"))
                try:
                    bins_count = min(int(len(timings) / 5) + 5, 20) 
                    counts, bins = np.histogram(timings, bins=bins_count)
                    max_count = max(counts) if len(counts) > 0 else 0
                    
                    if max_count > 0:
                        for i in range(len(counts)):
                            bar_len = int((counts[i] / max_count) * 40)
                            bar_char = '█'
                            bar_display = (bar_char * bar_len) if counts[i] > 0 else ''
                            # Gradient coloring for histogram bars
                            bar_color = Fore.GREEN
                            if i > len(counts) * 0.7: bar_color = Fore.YELLOW
                            if i > len(counts) * 0.9: bar_color = Fore.RED

                            print_formatted_text(ANSI(f"  {bins[i]:>7.2f}ms -- {bins[i+1]:>7.2f}ms | {bar_color}{bar_display:<40}{Style.RESET_ALL} ({counts[i]})"))
                except Exception as e:
                    print(f"Histogram error: {e}")

# -----------------------------------------------------------------------------
# 3. Interactive UI Application
# -----------------------------------------------------------------------------

class ScalpelApp:
    """Main application class handling the UI and orchestration."""
    def __init__(self, port, strategy):
        self.port = port
        self.strategy = strategy
        self.storage: List[CapturedRequest] = []
        self.command_completer = WordCompleter(['ls', 'last', 'race', 'help', 'exit', 'quit', 'q'], ignore_case=True)
        self.session = PromptSession(completer=self.command_completer)
        self.mgr = None
        self.cert_mgr = None
        self.capture_count = 0

    def _handler(self, protocol, data):
        """
        Callback hooked into ProxyManager.
        Receives captured requests immediately.
        """
        if protocol == "CAPTURE":
            # Normalization: Incoming 'data' might be proxy_manager.CapturedRequest
            # or structures.CapturedRequest.
            data.id = len(self.storage)
            self.storage.append(data)
            self.capture_count += 1
            
            # Visual feedback
            if hasattr(data, 'display_str'):
                msg = data.display_str()
            else:
                msg = f"{data.method} {data.url} ({len(data.body)}b)"
            
            print_formatted_text(ANSI(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}"))
            
        elif protocol == "SYSTEM":
             print_formatted_text(ANSI(f"{Fore.BLUE}[SYS] {data}{Style.RESET_ALL}"))
        
        elif protocol == "ERROR":
             print_formatted_text(ANSI(f"{Fore.RED}[ERR] {data}{Style.RESET_ALL}"))

    async def run(self):
        # 1. Initialize CA (External Module)
        print_formatted_text(ANSI(f"{Fore.YELLOW}[*] Loading Certificate Manager...{Style.RESET_ALL}"))
        self.cert_mgr = CertManager() # Initialize verify_certs.CertManager
        
        # 2. Start Proxy (Pass Context Factory)
        print_formatted_text(ANSI(BANNER.format(Fore=Fore, Style=Style)))
        print_formatted_text(ANSI(f"{Fore.YELLOW}[*] Starting Proxy on port {self.port}...{Style.RESET_ALL}"))
        
        # Instantiate ProxyManager
        self.mgr = ProxyManager(
            tcp_port=self.port, 
            ssl_context_factory=self.cert_mgr.get_context_for_host, 
            external_callback=self._handler
        )
        proxy_task = asyncio.create_task(self.mgr.run())

        print_formatted_text(ANSI(f"{Fore.CYAN}Commands: ls, last, race <id> [threads], exit{Style.RESET_ALL}"))

        # 3. UI Loop
        with patch_stdout():
            while True:
                try:
                    line = await self.session.prompt_async("vector > ")
                    parts = line.strip().split()
                    if not parts: continue
                    cmd = parts[0].lower()

                    if cmd == 'ls':
                        print_formatted_text(ANSI(f"\n{Fore.YELLOW}--- History ({len(self.storage)}) ---{Style.RESET_ALL}"))
                        start_idx = max(0, len(self.storage) - 15)
                        for i in range(start_idx, len(self.storage)): 
                            req = self.storage[i]
                            txt = req.display_str() if hasattr(req, 'display_str') else f"{req.method} {req.url}"
                            print_formatted_text(f"[{i}] {txt}")
                    
                    elif cmd == 'last':
                        if not self.storage:
                            print_formatted_text("No captures.")
                            continue
                        parts = ['race', str(len(self.storage) - 1)]
                        cmd = 'race'

                    elif cmd in ('help', '?'):
                        print_formatted_text(ANSI(f"\n{Fore.YELLOW}--- Scalpel Racer Commands ---{Style.RESET_ALL}"))
                        print_formatted_text(ANSI(f"  {Fore.CYAN}ls{Style.RESET_ALL}                     : List captured requests (shows last 15)"))
                        print_formatted_text(ANSI(f"  {Fore.CYAN}last{Style.RESET_ALL}                   : Race the most recently captured request"))
                        print_formatted_text(ANSI(f"  {Fore.CYAN}race <id> [threads]{Style.RESET_ALL}    : Race specific request (default threads: 10)"))
                        print_formatted_text(ANSI(f"  {Fore.CYAN}help / ?{Style.RESET_ALL}               : Show this help message"))
                        print_formatted_text(ANSI(f"  {Fore.CYAN}exit / quit / q{Style.RESET_ALL}        : Exit the application"))
                        print_formatted_text("")

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
                            
                            # Execute Scan
                            results = await run_scan(req, th, False, 100, self.strategy)
                            
                            # Analyze Results (Using Histogram Logic)
                            analyze_results(results)

                        except ValueError:
                            print_formatted_text("Invalid args")
                        except Exception:
                            traceback.print_exc()

                    elif cmd in ('q', 'exit', 'quit'): 
                        print_formatted_text("Shutting down...")
                        break 
                
                except (KeyboardInterrupt, EOFError):
                    break
                except Exception:
                    traceback.print_exc()
        
        if self.mgr:
            self.mgr.stop()
        try:
             await proxy_task
        except asyncio.CancelledError:
             pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scalpel Racer - Race Condition Exploit Tool")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Proxy listen port (default: 8080)")
    parser.add_argument("-s", "--strategy", default="auto", choices=["auto", "spa", "first-seq"], help="Attack strategy")

    args, unknown = parser.parse_known_args()

    try: 
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(ScalpelApp(args.port, args.strategy).run())
    except KeyboardInterrupt:
        pass 
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()