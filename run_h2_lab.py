# FILE: run_h2_lab.py
from hypercorn.config import Config
from hypercorn.asyncio import serve
import asyncio
from tests.lab.vulnerable_lab import app 

config = Config()
config.bind = ["127.0.0.1:5000"]
config.certfile = "scalpel_ca.pem"
config.keyfile = "scalpel_ca.key"
config.alpn_protocols = ["h2"]

# [FIX] Allow 1000+ concurrent streams for stress testing
config.h2_max_concurrent_streams = 2000 

print("[*] Running HTTP/2 Lab on https://127.0.0.1:5000")
if __name__ == "__main__":
    asyncio.run(serve(app, config))