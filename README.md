# Scalpel Racer

Scalpel Racer is an advanced race condition testing tool designed to identify and exploit race conditions in web applications. It supports multiple attack strategies, including HTTP/2 Single Packet Attacks (SPA), Synchronous HTTP/1.1 Staged Attacks, and low-level TCP packet manipulation (First-Sequence Sync).

## Features

*   **Concurrency**: Sends multiple requests simultaneously to trigger race conditions.
*   **Attack Strategies**:
    *   **Auto (httpx)**: Uses asynchronous HTTP requests (via `httpx`) with synchronization barriers. Supports both Last-Byte Sync and Staged attacks (using `{{SYNC}}` markers).
    *   **SPA (Single Packet Attack)**: Uses low-level HTTP/2 frames to send request headers early and trigger all requests with a single TCP packet containing the last byte of data. This minimizes network jitter.
    *   **First-Seq (First Sequence Sync)**: A highly advanced strategy that uses Linux `NetfilterQueue` and `iptables` to intercept and synchronize the very first TCP packet of the request burst, ensuring maximum parallelism at the network layer.
*   **Traffic Capture**: Includes a built-in proxy server (TCP & QUIC/HTTP3 awareness) to capture requests directly from your browser, Burp Suite, or other tools.
*   **Request Editing**: Modify captured requests (body, headers) before launching an attack. Supports inserting `{{SYNC}}` markers for staged attacks.
*   **HTTPS Interception**: Supports HTTPS traffic capture via a dynamically generated Certificate Authority (CA).
*   **Response Analysis**: Automatically groups responses by status code and body hash, calculates timing statistics (average, jitter), and generates histograms.
*   **HTTP/3 Support**: Includes experimental support for HTTP/3 (QUIC) interception and logging via `proxy_manager.py` (requires `aioquic`).

## Requirements

*   **Python 3.11+** (Required for `asyncio.TaskGroup` and modern TLS features)
*   **Core Dependencies**:
    *   `httpx`: For standard HTTP requests and the 'auto' strategy.
    *   `numpy`: For statistical analysis of timing data.
    *   `cryptography`: For HTTPS interception (CA generation).
*   **Advanced Dependencies** (Required for SPA and First-Seq):
    *   `h2` (>= 4.1.0): Required for HTTP/2 Single Packet Attacks and First-Seq.
    *   `NetfilterQueue` & `scapy`: Required for the First-Seq strategy (Linux only, requires root).
*   **Optional Dependencies**:
    *   `aioquic`: Required for HTTP/3 (QUIC) proxying and interception.

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/scalpel-racer.git
    cd scalpel-racer
    ```

2.  **Create and Activate Virtual Environment (Required):**
    You must run Scalpel Racer within a virtual environment to ensure dependency isolation.

    *Linux / MacOS:*
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

    *Windows:*
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

    *Note: If `requirements.txt` is missing, install the packages manually:*
    ```bash
    pip install httpx numpy cryptography h2 prompt_toolkit colorama
    ```
    *For HTTP/3 support:*
    ```bash
    pip install aioquic
    ```
    *For Linux users wanting to use `first-seq`:*
    ```bash
    sudo apt-get install libnetfilter-queue-dev  # Debian/Ubuntu
    pip install NetfilterQueue scapy
    ```

## Usage

### 1. Basic Capture & Race

Start the tool to capture traffic. By default, it listens on port 8080.

```bash
python3 scalpel_racer.py -l 8080
```

Configure your browser or tool (e.g., Burp Suite, Postman) to use `localhost:8080` as an HTTP/HTTPS proxy.

1.  **Trigger the Request**: Perform the action you want to test in your web application.
2.  **Select Request**: Scalpel Racer will display the captured request in the terminal.
3.  **Stop Capture**: Press `Ctrl+C` to stop capturing and enter the selection menu.
4.  **Launch Attack**: Enter the **ID** of the request you want to race.
5.  **Analysis**: The tool will replay the request concurrently according to the configured strategy and display a statistical analysis of the results.

### 2. Request Editing (Staged Attacks)

You can modify the request body before attacking, which is useful for Staged Attacks.

1.  In the selection menu, type `e <ID>` (e.g., `e 0`) to edit the request body.
2.  Insert `{{SYNC}}` markers where you want the request to pause.
    *   *Example*: `param1=value1&{{SYNC}}param2=race_condition`
3.  Save the changes.
4.  Run the attack by entering the ID. The 'auto' strategy will detect the markers and use them for synchronization.

### 3. HTTPS Setup

To capture HTTPS traffic without browser warnings or connection errors, you must trust the generated CA certificate:

1.  Run Scalpel Racer once. It will generate `scalpel_ca.pem` and `scalpel_ca.key` in the current directory.
2.  Import `scalpel_ca.pem` into your browser's "Trusted Root Certification Authorities" store (or your OS system store).

### 4. Command Line Arguments

```text
usage: scalpel_racer.py [-h] [-l LISTEN] [-t TARGET] [-s SCOPE] [-c CONCURRENCY]
                        [-w WARMUP] [--strategy {auto,spa,first-seq}] [--http2]

Scalpel Racer - Advanced Race Condition Tester

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        Listening port (default: 8080)
  -t TARGET, --target TARGET
                        Target Base URL for override (e.g. https://api.example.com/v1).
  -s SCOPE, --scope SCOPE
                        Regex scope filter for capturing requests.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent requests (default: 15)
  -w WARMUP, --warmup WARMUP
                        Warm-up delay (ms) before the final trigger (default: 100)
  --strategy {auto,spa,first-seq}
                        Attack strategy:
                        auto: Use httpx LBS/Staged Attack (Default). Detects {{SYNC}} markers.
                        spa: Use HTTP/2 Single Packet Attack (H2 engine).
                        first-seq: Use HTTP/2 First Sequence Sync (H2 engine, Linux root only).
  --http2               Force HTTP/2 for 'auto' strategy.
  -v, --verbose         Enable verbose logging (DEBUG level).
```

## Advanced Strategies

### SPA (Single Packet Attack)
```bash
python3 scalpel_racer.py --strategy spa
```
This strategy uses the `h2` library to manage the HTTP/2 connection manually. It sends the `HEADERS` frame and all but the last byte of the `DATA` frame for every concurrent request. After a warmup period, it sends the final byte for all requests in a tight loop. This often results in the server processing requests closer together than standard HTTP/1.1 or naive async approaches.

### First-Seq (Linux Only)
```bash
sudo python3 scalpel_racer.py --strategy first-seq
```
This is the most potent strategy. It leverages `iptables` to route specific outgoing TCP packets to a `NetfilterQueue`. The `PacketController` intercepts the first packet of the trigger burst (the final DATA frames) and holds it. Once the application attempts to send the subsequent packets, the controller releases the hold. This effectively "bunches" the packets at the kernel network interface level, minimizing the time difference between the first and last packet hitting the wire.

**Note**: This requires running Scalpel Racer as root (`sudo`).

## Architecture & Code Structure

The repository is organized into several key components that work together to capture, process, and replay requests:

*   **`scalpel_racer.py`**: The **Command Center**. It handles the interactive CLI (via `prompt_toolkit`), argument parsing, and high-level orchestration of the attack. It delegates capturing to `ProxyManager` and attacks to the specific engines.
*   **`proxy_manager.py`**: The **Unified Proxy Orchestrator**. It manages both the TCP proxy (for HTTP/1.1 & HTTP/2) and the QUIC server (for HTTP/3). It acts as the central logging facility, feeding captured requests back to `scalpel_racer.py`.
*   **`proxy_core.py`**: The **TCP Proxy Engine**. Implements `NativeProxyHandler` using `h2` and `asyncio`. It handles the complex logic of intercepting and parsing HTTP/1.1 and HTTP/2 traffic, including TLS termination.
*   **`low_level.py`**: The **HTTP/2 Race Engine**. Contains `HTTP2RaceEngine`, which implements the raw socket and protocol logic required for the high-precision **SPA** and **First-Seq** strategies.
*   **`sync_http11.py`**: The **HTTP/1.1 Sync Engine**. Implements `HTTP11SyncEngine` using Python threads and barriers to execute synchronous **Staged Attacks** (Staged LBS) for legacy HTTP/1.1 targets.
*   **`packet_controller.py`**: The **Network Interceptor**. Manages Linux `NetfilterQueue` and `iptables` rules. It is responsible for holding and releasing packets at the kernel level for the **First-Seq** strategy.
*   **`structures.py`**: **Data Models**. Defines shared data structures like `CapturedRequest` and `ScanResult` to ensure consistency across the application.
*   **`verify_certs.py`**: **Certificate Utility**. Handles the generation and verification of the dynamic CA certificates used for HTTPS interception.

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
