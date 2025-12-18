import asyncio
import time
import sys
import traceback
from collections import deque

# Tunables
HOST = '127.0.0.1'
PORT = 8000
RESET_THRESHOLD = 0.5  # Seconds of silence before resetting stats

class RaceTarget:
    def __init__(self):
        self.hits = []
        self.last_hit = 0

    async def handle_client(self, reader, writer):
        # 1. Record exact arrival time (Packet received by Kernel -> App)
        arrival = time.perf_counter()
        
        # Check if this is a new "burst" (reset if > 0.5s silence)
        if arrival - self.last_hit > RESET_THRESHOLD and self.hits:
            self.print_stats()
            self.hits = []
            print("\n[!] --- NEW BURST DETECTED ---")

        self.last_hit = arrival
        self.hits.append(arrival)

        # 2. Read Request (Drain buffer so we can reply)
        try:
            # Read until EOF or HTTP end (simple implementation)
            request = await reader.read(4096)
        except Exception:
            pass

        # 3. Fast Reply
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        writer.write(response)
        await writer.drain()
        writer.close()

    def print_stats(self):
        if not self.hits: return
        count = len(self.hits)
        if count < 2: return

        # Sort just in case async scheduling jumbled them slightly
        self.hits.sort()
        
        start = self.hits[0]
        end = self.hits[-1]
        delta_seconds = end - start
        delta_ms = delta_seconds * 1000

        print(f"[*] Burst Summary:")
        print(f"    Requests: {count}")
        print(f"    First:    {start:.6f}")
        print(f"    Last:     {end:.6f}")
        print(f"    Total Window: {Fore.GREEN}{delta_ms:.4f} ms{Style.RESET_ALL}")
        
        if delta_ms < 5.0:
            print(f"    {Fore.CYAN}>> COMPRESSION: EXTREME (Packet Bunching Active){Style.RESET_ALL}")
        elif delta_ms < 20.0:
            print(f"    {Fore.YELLOW}>> COMPRESSION: GOOD (Likely standard Async){Style.RESET_ALL}")
        else:
            print(f"    {Fore.RED}>> COMPRESSION: POOR (Network Jitter Detected){Style.RESET_ALL}")

async def main():
    server = await asyncio.start_server(RaceTarget().handle_client, HOST, PORT)
    print(f"[*] Dummy Target listening on {HOST}:{PORT}")
    print("[*] Ready for fire testing...")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    # Optional coloring
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
    except ImportError:
        class Fore: GREEN = ""; CYAN = ""; YELLOW = ""; RED = ""
        class Style: RESET_ALL = ""
    
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass # Graceful exit
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()