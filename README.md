
```text
   _____ _________    __    ____  ________
  / ___// ____/   |  / /   / __ \/ ____/ /
  \__ \/ /   / /| | / /   / /_/ / __/ / /
 ___/ / /___/ ___ |/ /___/ ____/ /___/ /___
/____/\____/_/  |_/_____/_/   /_____/_____/
```

# Scalpel Racer

> **A high-precision race condition exploitation framework.**

![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)
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

### 1. Clone & Build
Scalpel Racer requires **Go 1.18+**.

```bash
git clone https://github.com/xkilldash9x/scalpel-racer.git
cd scalpel-racer
go build -o scalpel-racer ./cmd/scalpel-racer
```

## Usage Guide

### 1. Start the Engine
Launch the tool. It acts as an interactive CLI and Proxy.

```bash
# Listen on port 8080 (default)
./scalpel-racer
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
Uses `net/http` with synchronization barriers. Good for general testing.
*   Supports **Staged Attacks**: Insert `{{SYNC}}` in the body (e.g., `param=val&{{SYNC}}final=true`) to pause requests before the final byte.

### SPA (Single Packet Attack)
Uses **HTTP/2** features to pre-send headers and hold the final DATA frame. All requests complete when the final packet arrives, eliminating most network jitter.

## Architecture

*   **`cmd/scalpel-racer`**: Command Center & UI.
*   **`internal/proxy`**: Unified Proxy (TCP/QUIC) Orchestrator.
*   **`internal/engine`**: Native H1/H2 Proxy Engine.
*   **`internal/packet`**: Low-level packet manipulation.

## Troubleshooting

### Common Issues

*   **`permission denied` (when running `./scalpel-racer`)**:
    *   **Cause**: The binary does not have execute permissions.
    *   **Fix**: Run `chmod +x ./scalpel-racer`.

*   **`address already in use`**:
    *   **Cause**: Another process (or a previous instance of Scalpel Racer) is using the specified port.
    *   **Fix**: Kill the process using `lsof -i :<port>` / `kill <PID>` or use the `-l <port>` argument to listen on a different port.

*   **Browser Warnings / SSL Errors**:
    *   **Cause**: The browser does not trust the generated CA.
    *   **Fix**: Import `~/.scalpel-racer/certs/ca.pem` into your browser's Trusted Root Certification Authorities store. Firefox has its own store separate from the OS.

*   **No Requests Captured**:
    *   **Cause**: The proxy is not configured correctly in your browser/tool, or the `scope` regex is too restrictive.
    *   **Fix**: Ensure your browser proxy is set to `127.0.0.1:8080` (or your custom port) for both HTTP and HTTPS. Check your `--scope` argument.

---
_Crafted with precision by Project Scalpel Team._
