# scalpel_racer.py
"""
Scalpel Racer -- Advanced Race Condition Testing Tool.
[VECTOR] Optimized: Pre-calculated headers, GC control, Strategy Routing, and Rich Analytics.
"""

import sys
import asyncio
import time
import argparse
import traceback
import logging
import hashlib
import gc
from typing import List, AsyncIterator
from collections import defaultdict

# -- Third Party Dependencies --

try:
    from colorama import Fore, Style, init as colorama_init
    from prompt_toolkit import PromptSession, print_formatted_text
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.formatted_text import HTML, ANSI
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.key_binding import KeyBindings
    UI_AVAILABLE = True
except ImportError:
    UI_AVAILABLE = False
    print("Warning: 'prompt_toolkit' or 'colorama' not found. UI will be limited.")

try:
    import httpx
    import uvloop
    # Windows doesn't support uvloop, so we skip it there
    if sys.platform != "win32":
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

# -- Internal Modules --

try:
    from proxy_manager import ProxyManager
except ImportError:
    print(f"{Fore.RED}[CRITICAL] 'proxy_manager.py' not found."
          f" Cannot start interception engine.{Style.RESET_ALL}")
    sys.exit(1)

try:
    from verify_certs import CertManager
except ImportError:
    print(f"{Fore.RED}[CRITICAL] 'verify_certs.py' not found."
          f" Cannot manage SSL/TLS.{Style.RESET_ALL}")
    sys.exit(1)

from low_level import HTTP2RaceEngine
from sync_http11 import HTTP11SyncEngine # [VECTOR] Import H1 Engine
from structures import ScanResult, CapturedRequest, SYNC_MARKER

if UI_AVAILABLE:
    colorama_init(autoreset=True)

# -- Configuration --

DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100
logger = logging.getLogger(__name__)

BANNER = r"""
{Fore.CYAN}
   _____ _________    __    ____  ________
  / ___// ____/   |  / /   / __ \/ ____/ /
  \__ \/ /   / /| | / /   / /_/ / __/ / /
 ___/ / /___/ ___ |/ /___/ ____/ /___/ /___
/____/\____/_/  |_/_____/_/   /_____/_____/
{Fore.YELLOW}     [ SCALPEL RACER V0.1.3 ]{Style.RESET_ALL}
{Style.RESET_ALL}    {Fore.WHITE}-- [+] Optimized by Vector [+] --{Style.RESET_ALL}
"""

# -- Helper Functions --

def format_request_display(req) -> str:
    """
    Format request for display with colored method if UI is available.
    """
    if not UI_AVAILABLE or not hasattr(req, 'method'):
        return req.display_str() if hasattr(req, 'display_str') else f"{req.method} {req.url}"

    # Reconstruct the display string with colors
    # Use getattr/safety checks even if __slots__ enforces existence, to be safe against mocks
    payload = req.get_attack_payload() if hasattr(req, 'get_attack_payload') else (
        req.body if hasattr(req, 'body') else b""
    )
    body_len = len(payload)

    edited = getattr(req, 'edited_body', None)
    truncated = getattr(req, 'truncated', False)
    protocol = getattr(req, 'protocol', 'HTTP/1.1')

    edit_flag = f"{Fore.MAGENTA}[E]{Style.RESET_ALL}" if edited is not None else ""
    trunc_flag = f"{Fore.RED} [T]{Style.RESET_ALL}" if truncated else ""

    clean_url = req.url
    if len(clean_url) > 60:
        clean_url = clean_url[:57] + "..."

    m = req.method.upper()
    if m == 'GET':
        method_color = Fore.GREEN
    elif m == 'POST':
        method_color = Fore.CYAN
    elif m == 'DELETE':
        method_color = Fore.RED
    elif m in ('PUT', 'PATCH'):
        method_color = Fore.YELLOW
    else:
        method_color = Fore.WHITE

    method_str = f"{method_color}{req.method:<6}{Style.RESET_ALL}"
    proto_str = f"{Style.DIM}[{protocol}]{Style.RESET_ALL}"

    return f"{proto_str} {method_str} {clean_url} ({body_len}b){edit_flag}{trunc_flag}"

def safe_spawn(tg: asyncio.TaskGroup, coro, result_list, index):
    """
    Supervisor wrapper to prevent fail-fast cascades in the TaskGroup.
    Catches exceptions per-request so one failure doesn't kill the batch.
    """
    async def wrapper():
        try:
            res = await coro
            result_list[index] = res
        except Exception as e: # pylint: disable=broad-exception-caught
            result_list[index] = ScanResult(index, 0, 0, error=str(e))
    tg.create_task(wrapper())

async def last_byte_stream_body(
    payload: bytes, barrier: asyncio.Barrier, warmup_ms: int
) -> AsyncIterator[bytes]:
    """
    Standard Packet Bunching strategy (Last-Byte Sync).
    Streams the payload but holds the final byte at the barrier.
    """
    if len(payload) <= 1:
        if warmup_ms > 0:
            await asyncio.sleep(warmup_ms / 1000.0)
        try:
            if barrier:
                await barrier.wait()
        except asyncio.BrokenBarrierError:
            pass
        yield payload
        return

    yield payload[:-1]

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        if barrier:
            await barrier.wait()
    except asyncio.BrokenBarrierError:
        pass

    yield payload[-1:]

async def staged_stream_body(
    payload: bytes, barriers: List[asyncio.Barrier]
) -> AsyncIterator[bytes]:
    """
    Multi-stage sync using {{SYNC}} markers in the payload.
    Useful for complex state machine race conditions.
    """
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

async def send_probe_advanced(
    client: httpx.AsyncClient,
    request: CapturedRequest,
    payload: bytes,
    barriers: List[asyncio.Barrier],
    warmup_ms: int,
    index: int,
    is_staged: bool,
    base_headers: httpx.Headers
) -> ScanResult:
    """
    Sends a single probe. Optimized to accept pre-calculated headers to reduce overhead.
    """
    start_time = time.perf_counter()
    body_hash = None
    body_snippet = None

    try:
        # [VECTOR] Optimization: Copy pre-validated headers instead of re-parsing every time
        req_headers = base_headers.copy()
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        content_stream = None
        if is_staged:
            content_stream = staged_stream_body(payload, barriers)
        else:
            barrier = barriers[0] if barriers else None
            content_stream = last_byte_stream_body(payload, barrier, warmup_ms)

        # We prefer the stream generator if we are syncing, otherwise raw payload
        final_content = content_stream if content_stream else payload

        async with client.stream(
            method=request.method,
            url=request.url,
            content=final_content,
            headers=req_headers
        ) as response:
            body = await response.aread()
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ')

        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, response.status_code, duration, body_hash, body_snippet)
    except Exception as e: # pylint: disable=broad-exception-caught
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, error=str(e))

async def run_scan(
    request: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str = "auto"
):
    """
    Orchestrates the race condition attack.
    Routes to the correct engine (H2, H1 Sync, or Standard H1) based on strategy.
    """
    if hasattr(request, 'get_attack_payload'):
        attack_payload = request.get_attack_payload()
    else:
        attack_payload = request.body

    # [VECTOR] Logic Correction: Correctly route to H1 or H2 engine
    use_h2_engine = False
    if strategy == "spa":
        use_h2_engine = True
    elif strategy == "first-seq":
        # If user explicitly requested H2, or protocol implies it, use H2.
        # Otherwise allow H1 First-Seq (Packet Bunching)
        if http2 or request.protocol == "HTTP/2":
            use_h2_engine = True

    if use_h2_engine:
        engine = HTTP2RaceEngine(request, concurrency, strategy, warmup)
        return await asyncio.to_thread(engine.run_attack)

    # Check if we should use specialized H1 Sync Engine (for first-seq on H1)
    if strategy == "first-seq" and not use_h2_engine:
        engine = HTTP11SyncEngine(request, concurrency, strategy)
        return await asyncio.to_thread(engine.run_attack)

    # -- Standard HTTPX (H1/H2) with Barriers --
    sync_markers_count = attack_payload.count(SYNC_MARKER)
    barriers = []

    if sync_markers_count > 0:
        for _ in range(sync_markers_count):
            barriers.append(asyncio.Barrier(concurrency))
        warmup = 0
    elif concurrency > 1:
        barriers.append(asyncio.Barrier(concurrency))

    # Clean up memory before the race starts to minimize local jitter
    gc.collect()
    gc.disable()

    # [VECTOR] Optimization: Pre-calculate static headers once
    actual_length = len(attack_payload)
    base_headers = httpx.Headers(request.headers)
    base_headers["User-Agent"] = "Scalpel-CLI/5.4-Optimized"
    base_headers["Content-Length"] = str(actual_length)

    is_post_put = request.method in ["POST", "PUT", "PATCH"]
    if "content-type" not in base_headers and is_post_put and actual_length > 0:
        base_headers["Content-Type"] = "application/x-www-form-urlencoded"

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency*2)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)

    async with httpx.AsyncClient(
        http2=http2, limits=limits, timeout=timeout, verify=False
    ) as client:
        results = [None] * concurrency

        # Use TaskGroup for modern asyncio safety if available
        if hasattr(asyncio, 'TaskGroup'):
            async with asyncio.TaskGroup() as tg:
                for i in range(concurrency):
                    safe_spawn(tg, send_probe_advanced(
                        client, request, attack_payload, barriers, warmup, i,
                        sync_markers_count > 0, base_headers
                    ), results, i)
        else:
            # Legacy fallback
            tasks = [
                send_probe_advanced(
                    client, request, attack_payload, barriers, warmup, i,
                    sync_markers_count > 0, base_headers
                )
                for i in range(concurrency)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [
                r if isinstance(r, ScanResult) else ScanResult(i, 0, 0, error=str(r))
                for i, r in enumerate(results)
            ]

    gc.enable()
    return results

# -- Analytics & Histogram --

def analyze_results(results: List[ScanResult]):
    """
    Analyzes and prints statistical data from the scan results.
    Merged logic: Refactored Structure + Production Metrics (Min/Max/Gradient).
    """
    if not results:
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
        print(f"  {'Count':<6} {'Status':<6} {'Hash (SHA256)':<16} {'Snippet'}")
        print("  " + "-" * 90)
        for key in sorted_keys:
            status_code, _, body_hash = key
            group = signatures[key]
            snippet = group[0].body_snippet if group and group[0].body_snippet else ""
            hash_short = body_hash[:16] if body_hash else "N/A"
            if 200 <= status_code < 300:
                sc_color = Fore.GREEN
            elif status_code >= 500:
                sc_color = Fore.RED
            else:
                sc_color = Fore.YELLOW
            print_formatted_text(
                ANSI(f"  {len(group):<6} {sc_color}{status_code:<6}{Style.RESET_ALL} "
                     f"{hash_short:<16} {snippet}")
            )
        print("  " + "-" * 90)

    if successful:
        timings = [r.duration for r in successful]
        if len(timings) > 0:
            avg = sum(timings) / len(timings)
            min_t = min(timings)
            max_t = max(timings)
            # Calculate Standard Deviation
            if len(timings) > 1:
                variance = sum((t - avg) ** 2 for t in timings) / (len(timings)-1)
                std_dev = variance ** 0.5
            else:
                std_dev = 0.0

            print_formatted_text(ANSI(f"\n{Fore.YELLOW}[Timing Metrics]{Style.RESET_ALL}"))
            print(f"  Avg: {avg:.2f}ms | Min: {min_t:.2f}ms | "
                  f"Max: {max_t:.2f}ms | Jitter: {std_dev:.2f}ms")

            # Histogram Logic
            if len(timings) > 1 and NUMPY_AVAILABLE:
                print_formatted_text(ANSI(f"\n{Fore.YELLOW}[Timing Distribution]{Style.RESET_ALL}"))
                try:
                    bins_count = min(int(len(timings)/5)+5, 20)
                    counts, bins = np.histogram(timings, bins=bins_count)
                    max_count = max(counts) if len(counts) > 0 else 0

                    if max_count > 0:
                        for i, count in enumerate(counts):
                            bar_len = int((count / max_count) * 40)
                            bar_char = '█'
                            # Gradient coloring from Production Logic
                            bar_color = Fore.GREEN
                            if i > len(counts) * 0.7:
                                bar_color = Fore.YELLOW
                            if i > len(counts) * 0.9:
                                bar_color = Fore.RED

                            bar_display = (bar_char * bar_len) if count > 0 else ''
                            print_formatted_text(
                                ANSI(f"  {bins[i]:>6.2f}ms | {bar_color}{bar_display:<40}"
                                     f"{Style.RESET_ALL} ({count})")
                            )
                except Exception as e: # pylint: disable=broad-exception-caught
                    print(f"Histogram error: {e}")

# -- Application Logic --

class ScalpelApp:
    """
    Main Application Class for Scalpel Racer.
    Handles the TUI loop, command parsing, and proxy orchestration.
    """
    def __init__(self, port, strategy, bind_ip="127.0.0.1"):
        self.port = port
        self.strategy = strategy
        self.bind_ip = bind_ip
        self.storage: List[CapturedRequest] = []
        self.command_completer = WordCompleter(
            ['ls', 'last', 'race', 'exit', 'quit', 'q', 'help', '?'], ignore_case=True
        )

        self.kb = None
        if UI_AVAILABLE:
            self.kb = KeyBindings()

            @self.kb.add('f1')
            def _(event):
                event.current_buffer.text = 'help'
                event.current_buffer.validate_and_handle()

            @self.kb.add('f5')
            def _(event):
                event.current_buffer.text = 'ls'
                event.current_buffer.validate_and_handle()

            @self.kb.add('escape', 'r')
            def _(event):
                event.current_buffer.text = 'last'
                event.current_buffer.validate_and_handle()

        self.session = PromptSession(
            completer=self.command_completer,
            bottom_toolbar=self._get_toolbar_info,
            key_bindings=self.kb
        )
        self.mgr = None
        self.cert_mgr = None
        self.capture_count = 0

    def _get_toolbar_info(self):
        """Generates the bottom status toolbar."""
        if not UI_AVAILABLE:
            return None
        return HTML(
            f' <b><style bg="ansiblue"> Proxy: {self.bind_ip}:{self.port} </style></b>  '
            f'<b><style bg="ansimagenta"> Mode: {self.strategy} </style></b>  '
            f'<b><style bg="ansigreen"> Captures: {self.capture_count} </style></b> '
            f'<style fg="gray"> [F1] Help [F5] List [Alt-r] Race Last</style>'
        )

    def _handler(self, protocol, data):
        """
        Callback handler for the ProxyManager.
        Receives captured requests, system messages, or errors.
        """
        if protocol == "CAPTURE":
            data.id = len(self.storage)
            self.storage.append(data)
            self.capture_count += 1
            msg = format_request_display(data)
            # Avoid double coloring the prefix since format_request_display handles colors
            print_formatted_text(ANSI(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}"))
        elif protocol == "SYSTEM":
            print_formatted_text(ANSI(f"{Fore.BLUE}[SYS] {data}{Style.RESET_ALL}"))
        elif protocol == "ERROR":
            print_formatted_text(ANSI(f"{Fore.RED}[ERR] {data}{Style.RESET_ALL}"))

    async def run(self):
        """Main async loop for the application."""
        print_formatted_text(
            ANSI(f"{Fore.YELLOW}[*] Loading Certificate Manager...{Style.RESET_ALL}")
        )
        self.cert_mgr = CertManager()

        print_formatted_text(ANSI(BANNER.format(Fore=Fore, Style=Style)))
        print_formatted_text(
            ANSI(f"{Fore.YELLOW}[*] Starting Proxy on {self.bind_ip}:{self.port}...{Style.RESET_ALL}")
        )

        self.mgr = ProxyManager(
            tcp_port=self.port,
            ssl_context_factory=self.cert_mgr.get_context_for_host,
            external_callback=self._handler,
            bind_ip=self.bind_ip
        )
        proxy_task = asyncio.create_task(self.mgr.run())

        print_formatted_text(
            ANSI(f"{Fore.CYAN}Commands: ls, last, race <id> [threads], exit{Style.RESET_ALL}")
        )

        with patch_stdout():
            while True:
                try:
                    line = await self.session.prompt_async("vector > ")
                    parts = line.strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].lower()

                    if cmd == 'ls':
                        print_formatted_text(
                            ANSI(f"\n{Fore.YELLOW}--- History ({len(self.storage)}) "
                                 f"---{Style.RESET_ALL}")
                        )
                        if not self.storage:
                            print_formatted_text(
                                ANSI(f"{Fore.CYAN}ℹ No requests captured yet.{Style.RESET_ALL}")
                            )
                            print_formatted_text(
                                ANSI(f"{Fore.CYAN}  Configure your browser/client to proxy "
                                     f"through {Fore.WHITE}localhost:{self.port}{Style.RESET_ALL}")
                            )
                        else:
                            start_idx = max(0, len(self.storage) - 15)
                            for i in range(start_idx, len(self.storage)):
                                req = self.storage[i]
                                txt = format_request_display(req)
                                print_formatted_text(ANSI(f"[{i}] {txt}"))

                    elif cmd in ('help', '?'):
                        print_formatted_text(
                            ANSI(f"\n{Fore.YELLOW}--- Available Commands ---{Style.RESET_ALL}")
                        )
                        print_formatted_text(
                            ANSI(f"  {Fore.GREEN}ls{Style.RESET_ALL}          "
                                 "List recent captured requests")
                        )
                        print_formatted_text(
                            ANSI(f"  {Fore.GREEN}last{Style.RESET_ALL}        "
                                 "Race the most recently captured request")
                        )
                        print_formatted_text(
                            ANSI(f"  {Fore.GREEN}race <id>{Style.RESET_ALL}   "
                                 "Race a specific request ID (from ls)")
                        )
                        print_formatted_text(
                            ANSI(f"  {Fore.GREEN}exit{Style.RESET_ALL}        "
                                 "Stop proxy and exit")
                        )
                        print_formatted_text(
                            ANSI(f"\n{Fore.YELLOW}--- Tips ---{Style.RESET_ALL}")
                        )
                        print_formatted_text(
                            ANSI(f"  • Configure your browser to proxy HTTP traffic to "
                                 f"{Fore.WHITE}{self.bind_ip}:{self.port}{Style.RESET_ALL}")
                        )
                        print_formatted_text(
                            ANSI(f"  • Race commands accept optional thread count: "
                                 f"{Fore.CYAN}race <id> 20{Style.RESET_ALL}")
                        )

                    elif cmd == 'last':
                        if not self.storage:
                            print_formatted_text("No captures.")
                            continue
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
                            print_formatted_text(
                                ANSI(f"{Fore.MAGENTA}[*] Racing {req.url} "
                                     f"({th} threads)...{Style.RESET_ALL}")
                            )

                            # Execute the race with the selected strategy
                            results = await run_scan(
                                req, th, False, DEFAULT_WARMUP, self.strategy
                            )
                            analyze_results(results)
                        except Exception: # pylint: disable=broad-exception-caught
                            traceback.print_exc()

                    elif cmd in ('q', 'exit', 'quit'):
                        print_formatted_text("Shutting down...")
                        break
                except (KeyboardInterrupt, EOFError):
                    break

        if self.mgr:
            self.mgr.stop()
        try:
            await proxy_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scalpel Racer - Race Condition Exploit Tool"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8080, help="Proxy listen port (default: 8080)"
    )
    parser.add_argument(
        "-b", "--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-s", "--strategy", default="auto", choices=["auto", "spa", "first-seq"],
        help="Attack strategy"
    )

    args, unknown = parser.parse_known_args()

    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(ScalpelApp(args.port, args.strategy, args.bind).run())
    except KeyboardInterrupt:
        pass
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"Error: {e}")
        traceback.print_exc()
