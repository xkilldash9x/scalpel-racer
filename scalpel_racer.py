import asyncio
import httpx
import time
import argparse
import sys
import re
from typing import List, AsyncIterator, Optional, Dict
from urllib.parse import urljoin

# -- Configuration --
DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100  # ms

class ScanResult:
    def __init__(self, index: int, status_code: int, duration: float, error: str = None):
        self.index = index
        self.status_code = status_code
        self.duration = duration
        self.error = error

class CapturedRequest:
    def __init__(self, id: int, method: str, url: str, headers: Dict[str, str], body: bytes):
        self.id = id
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body

    def __str__(self):
        return f"[{self.id}] {self.method} {self.url} ({len(self.body)} bytes)"

class CaptureServer:
    def __init__(self, port: int, target_override: str = None, scope_regex: str = None):
        self.port = port
        self.target_override = target_override
        self.scope_pattern = re.compile(scope_regex) if scope_regex else None
        self.request_log: List[CapturedRequest] = []
        self.server = None
        self.stop_event = asyncio.Event()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, '127.0.0.1', self.port)
        print(f"[*] Listening on http://127.0.0.1:{self.port}")
        if self.target_override:
            print(f"[*] Target Override: {self.target_override}")
        if self.scope_pattern:
            print(f"[*] Scope Filter: {self.scope_pattern.pattern}")
        print("[*] Press Ctrl+C to stop capturing and select a request to race.\n")

        # Keep server running until stopped
        async with self.server:
            await self.stop_event.wait()
            self.server.close()
            await self.server.wait_closed()

    async def handle_client(self, reader, writer):
        try:
            # 1. Parse Request Line
            line = await reader.readline()
            if not line: return
            method, path, _ = line.decode().strip().split(' ')

            # 2. Parse Headers
            headers = {}
            content_length = 0
            while True:
                line = await reader.readline()
                if line == b'\r\n': break
                key, value = line.decode().strip().split(':', 1)
                headers[key.strip()] = value.strip()
                if key.lower() == 'content-length':
                    content_length = int(value.strip())

            # 3. Parse Body
            body = await reader.read(content_length)

            # 4. Construct Target URL
            final_url = path
            if self.target_override:
                # Handle path joining carefully
                rel_path = path if not path.startswith("http") else path.split(headers.get("Host", ""), 1)[-1]
                final_url = urljoin(self.target_override, rel_path)
            elif path.startswith("http"):
                final_url = path
            elif "Host" in headers:
                scheme = "https" if self.port == 443 else "http"
                final_url = f"{scheme}://{headers['Host']}{path}"

            # 5. Scope Check
            if self.scope_pattern:
                if not self.scope_pattern.search(final_url):
                    # Out of scope, ignore silently or verbose
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return

            # 6. Capture
            req_id = len(self.request_log)
            # Filter hop-by-hop headers
            safe_headers = {k: v for k, v in headers.items()
                           if k.lower() not in ['content-length', 'host', 'connection', 'accept-encoding', 'upgrade-insecure-requests']}

            captured = CapturedRequest(req_id, method, final_url, safe_headers, body)
            self.request_log.append(captured)

            print(f"[+] Captured {captured}")

            # Respond to client
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nCaptured.")
            await writer.drain()

        except Exception as e:
            print(f"[!] Error handling request: {e}")
        finally:
            writer.close()

# --- Attack Logic ---

async def XY_stream_body(payload: bytes, barrier: asyncio.Barrier, warmup_ms: int) -> AsyncIterator[bytes]:
    if len(payload) == 0:
        yield b""
        return

    yield payload[:-1]  # Send all but last byte

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        await barrier.wait() # Sync
    except asyncio.BrokenBarrierError:
        pass

    yield payload[-1:] # Send last byte

async def send_probe(client: httpx.AsyncClient, request: CapturedRequest, barrier: asyncio.Barrier, warmup_ms: int, index: int) -> ScanResult:
    start_time = time.perf_counter()
    try:
        req_headers = request.headers.copy()
        req_headers["User-Agent"] = "Scalpel-CLI/2.0"
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        if "Content-Type" not in req_headers and request.method != "GET":
             req_headers["Content-Type"] = "application/octet-stream"

        response = await client.request(
            method=request.method,
            url=request.url,
            content=XY_stream_body(request.body, barrier, warmup_ms),
            headers=req_headers
        )
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, response.status_code, duration)
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, str(e))

async def run_scan(request: CapturedRequest, concurrency: int, http2: bool, warmup: int):
    print(f"\n[!] REPLAYING ATTACK: {request.method} {request.url}")
    print(f"[*] Payload: {len(request.body)} bytes | Concurrency: {concurrency} | Warmup: {warmup}ms | Mode: {'HTTP/2' if http2 else 'HTTP/1.1'}")

    barrier = asyncio.Barrier(concurrency)
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)

    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=timeout, verify=False) as client:
        tasks = [asyncio.create_task(send_probe(client, request, barrier, warmup, i)) for i in range(concurrency)]
        results = await asyncio.gather(*tasks)

    analyze_results(results)

def analyze_results(results: List[ScanResult]):
    successful = [r for r in results if r.error is None]
    status_codes = {}
    for r in successful:
        status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1

    print("\n-- Results --")
    for code, count in status_codes.items():
        print(f"[{code}]: {count} responses")

    if successful:
        timings = [r.duration for r in successful]
        avg = sum(timings) / len(timings)
        std_dev = (sum((t - avg) ** 2 for t in timings) / len(timings)) ** 0.5
        print(f"Timing: Avg {avg:.2f}ms | Jitter (StdDev) {std_dev:.2f}ms")

# --- Main CLI Flow ---

def main():
    parser = argparse.ArgumentParser(description="Scalpel Racer v2 - Scoped Capture & Replay")

    # Capture Mode
    parser.add_argument("-l", "--listen", type=int, default=8080, help="Listening port (default: 8080)")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target Base URL (e.g. https://api.example.com)")
    parser.add_argument("-s", "--scope", type=str, help="Regex scope filter (e.g. '/api/v1/transfer')")

    # Attack Config
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrency")
    parser.add_argument("-w", "--warmup", type=int, default=DEFAULT_WARMUP, help="Warm-up delay (ms)")
    parser.add_argument("--http2", action="store_true", help="Force HTTP/2")

    args = parser.parse_args()

    # 1. Start Capture Server
    capture_server = CaptureServer(args.listen, args.target, args.scope)

    try:
        asyncio.run(capture_server.start())
    except KeyboardInterrupt:
        pass # Expected exit to menu

    # 2. Selection Menu
    log = capture_server.request_log
    if not log:
        print("\n[!] No requests captured matching scope.")
        sys.exit(0)

    print("\n\n--- Captured Requests ---")
    print(f"{'ID':<4} {'Method':<6} {'URL'}")
    print("-" * 60)

    # Show last 10 requests by default to avoid spam, or all
    display_log = log # log[-20:] if len(log) > 20 else log
    for req in display_log:
        print(f"{req.id:<4} {req.method:<6} {req.url}")

    print("-" * 60)

    while True:
        choice = input("\nEnter Request ID to Race (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            sys.exit(0)

        try:
            req_id = int(choice)
            selected_req = next((r for r in log if r.id == req_id), None)
            if selected_req:
                # 3. Launch Attack
                asyncio.run(run_scan(selected_req, args.concurrency, args.http2, args.warmup))
                break
            else:
                print("Invalid ID.")
        except ValueError:
            print("Invalid input.")

if __name__ == "__main__":
    main()
