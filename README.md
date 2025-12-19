
```text
   _____ _________    __    ____  ________
  / ___// ____/   |  / /   / __ \/ ____/ /
  \__ \/ /   / /| | / /   / /_/ / __/ / /
 ___/ / /___/ ___ |/ /___/ ____/ /___/ /___
/____/\____/_/  |_/_____/_/   /_____/_____/
```

# Scalpel Racer

> **A high-precision race condition exploitation framework.**

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![Strategies](https://img.shields.io/badge/strategies-SPA%20%7C%20First--Seq%20%7C%20Sync-orange)
![Status](https://img.shields.io/badge/status-active-green)

Scalpel Racer is an advanced testing tool designed to identify and exploit race conditions in web applications with **microsecond precision**. Unlike standard tools, it bypasses network jitter using low-level packet manipulation strategies.

---

## Why Scalpel Racer?

*   **Single Packet Attack (SPA):** Squeezes 20+ requests into a single TCP packet for maximum simultaneity.
*   **First-Sequence Sync:** (Linux only) Kernel-level packet bunching using `NetfilterQueue` for the ultimate race window.
*   **Built-in Interception:** Includes a full HTTP/1.1 & HTTP/2 proxy to capture requests directly from your browser.
*   **Rich Analytics:** Visualize response distribution, timing jitter, and body hashes in real-time.

## Key Features

| Feature | Description |
| :--- | :--- |
| **Concurrency** | Send massive bursts of requests simultaneously. |
| **Strategies** | **Auto** (httpx), **SPA** (H2 Frames), **First-Seq** (Kernel Sync). |
| **Traffic Capture** | Built-in proxy (TCP & HTTP/3 aware) for easy workflow integration. |
| **Request Editing** | Modify bodies and inject `{{SYNC}}` markers for Staged attacks. |
| **HTTPS Support** | Dynamic CA generation for seamless HTTPS interception. |
| **Analysis** | Automatic grouping of responses by status and content hash. |

## Installation

### 1. Clone & Environment
Scalpel Racer requires **Python 3.11+**.

```bash
git clone https://github.com/xkilldash9x/scalpel-racer.git
cd scalpel-racer

# Linux / MacOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

> **Note for Linux Users:** To use the **First-Seq** strategy, you must install system headers:
> ```bash
> sudo apt-get install libnetfilter-queue-dev
> pip install NetfilterQueue scapy
> ```

## Usage Guide

### 1. Start the Engine
Launch the tool. It acts as an interactive CLI and Proxy.

```bash
# Listen on port 8080 (default)
python3 scalpel_racer.py
```

### 2. Capture Traffic
Configure your browser (or Burp Suite) to proxy through `127.0.0.1:8080`.
*   Trigger the request you want to test in your browser.
*   It will appear in the Scalpel CLI.

### 3. Race!
Inside the CLI:

*   **`ls`**: List captured requests.
*   **`race <ID>`**: Launch an attack on request #ID.
*   **`race <ID> 20`**: Launch with 20 concurrent threads.

```text
vector > ls
[0] POST https://api.example.com/transfer

vector > race 0 20
[*] Racing https://api.example.com/transfer (20 threads)...
```

## Attack Strategies

### Auto (Default)
Uses `httpx` with synchronization barriers. Good for general testing.
*   Supports **Staged Attacks**: Insert `{{SYNC}}` in the body (e.g., `param=val&{{SYNC}}final=true`) to pause requests before the final byte.

### SPA (Single Packet Attack)
```bash
python3 scalpel_racer.py --strategy spa
```
Uses **HTTP/2** features to pre-send headers and hold the final DATA frame. All requests complete when the final packet arrives, eliminating most network jitter.

### First-Seq (Kernel Sync)
```bash
sudo python3 scalpel_racer.py --strategy first-seq
```
**The Nuclear Option.** Uses `iptables` to hold packets at the network interface level until the entire batch is ready. Requires `sudo`.

## Architecture

*   **`scalpel_racer.py`**: Command Center & UI.
*   **`proxy_manager.py`**: Unified Proxy (TCP/QUIC) Orchestrator.
*   **`proxy_core.py`**: Native H1/H2 Proxy Engine.
*   **`low_level.py`**: Raw Socket Engine for SPA/First-Seq.
*   **`packet_controller.py`**: Linux Netfilter Controller.

## Troubleshooting

### Common Issues

*   **`AttributeError: module 'asyncio' has no attribute 'TaskGroup'`**:
    *   **Cause**: You are running Python older than 3.11.
    *   **Fix**: Upgrade to Python 3.11 or higher.

*   **`ImportError: No module named 'aioquic'`**:
    *   **Cause**: The optional HTTP/3 dependency is missing.
    *   **Fix**: Install it via `pip install aioquic` or ignore the warning if you don't need HTTP/3 support.

*   **`NetfilterQueue` not found / `fatal error: libnetfilter_queue/libnetfilter_queue.h: No such file`**:
    *   **Cause**: Missing system headers for compiling the Python package.
    *   **Fix**: Run `sudo apt-get install libnetfilter-queue-dev` (Ubuntu/Debian) before pip installing.

*   **`Permission Denied` (when using `first-seq`)**:
    *   **Cause**: Modifying firewall rules requires root privileges.
    *   **Fix**: Run the script with `sudo`.

*   **`Address already in use`**:
    *   **Cause**: Another process (or a previous instance of Scalpel Racer) is using port 8080 or 4433.
    *   **Fix**: Kill the process using `lsof -i :8080` / `kill <PID>` or use the `-l <port>` argument to listen on a different port.

*   **Browser Warnings / SSL Errors**:
    *   **Cause**: The browser does not trust the generated CA.
    *   **Fix**: Import `scalpel_ca.pem` into your browser's Trusted Root Certification Authorities store. Firefox has its own store separate from the OS.

*   **No Requests Captured**:
    *   **Cause**: The proxy is not configured correctly in your browser/tool, or the `scope` regex is too restrictive.
    *   **Fix**: Ensure your browser proxy is set to `127.0.0.1:8080` (or your custom port) for both HTTP and HTTPS. Check your `--scope` argument.

---
_Crafted with precision by Scalpel Team._
