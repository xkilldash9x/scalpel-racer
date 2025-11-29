# Scalpel Racer

Scalpel Racer is an advanced race condition testing tool designed to identify and exploit race conditions in web applications. It supports multiple attack strategies, including HTTP/2 Single Packet Attacks (SPA) and low-level TCP packet manipulation.

## Features

*   **Concurrency**: Sends multiple requests simultaneously to trigger race conditions.
*   **Attack Strategies**:
    *   **Auto (httpx)**: Uses asynchronous HTTP requests with synchronization barriers (Last-Byte Sync or Staged).
    *   **SPA (Single Packet Attack)**: Uses HTTP/2 to send request headers early and trigger all requests with a single TCP packet (Last-Byte).
    *   **First-Seq (First Sequence Sync)**: A highly advanced strategy that uses Linux NetfilterQueue to intercept and synchronize the very first TCP packet of the request burst, ensuring maximum parallelism.
*   **Traffic Capture**: Includes a built-in proxy server to capture requests directly from your browser or other tools.
*   **Request Editing**: Modify captured requests (body, headers) before launching an attack.
*   **HTTPS Interception**: Supports HTTPS traffic capture via a dynamically generated Certificate Authority (CA).

## Requirements

*   Python 3.7+
*   **Core Dependencies**:
    *   `httpx`: For standard HTTP requests.
    *   `numpy`: For statistical analysis of timing data.
    *   `cryptography`: For HTTPS interception (CA generation).
*   **Advanced Dependencies** (Optional but recommended):
    *   `h2`: Required for SPA and First-Seq strategies.
    *   `NetfilterQueue` & `scapy`: Required for the First-Seq strategy (Linux only).

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/scalpel-racer.git
    cd scalpel-racer
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

    *Note: If `requirements.txt` is missing, install the core packages:*
    ```bash
    pip install httpx numpy cryptography h2
    ```
    *For Linux users wanting to use `first-seq`:*
    ```bash
    sudo apt-get install libnetfilter-queue-dev  # Debian/Ubuntu
    pip install NetfilterQueue scapy
    ```

## Usage

### 1. Basic Capture & Race

Start the tool to capture traffic on port 8080:

```bash
python3 scalpel_racer.py -l 8080
```

Configure your browser or tool (e.g., Burp Suite, Postman) to use `localhost:8080` as an HTTP/HTTPS proxy.

1.  Trigger the request you want to test in your application.
2.  Scalpel Racer will display the captured request.
3.  Press `Ctrl+C` to stop capturing and enter the selection menu.
4.  Enter the **ID** of the request you want to race.
5.  The tool will replay the request concurrently and analyze the results.

### 2. HTTPS Setup

To capture HTTPS traffic, you need to trust the generated CA certificate:

1.  Run Scalpel Racer once. It will generate `scalpel_ca.pem` and `scalpel_ca.key`.
2.  Import `scalpel_ca.pem` into your browser's "Trusted Root Certification Authorities" store.

### 3. Command Line Arguments

```text
usage: scalpel_racer.py [-h] [-l LISTEN] [-t TARGET] [-s SCOPE] [-c CONCURRENCY]
                        [-w WARMUP] [--strategy {auto,spa,first-seq}] [--http2]

Scalpel Racer v5.0 - Advanced Race Condition Tester

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        Listening port (default: 8080)
  -t TARGET, --target TARGET
                        Target Base URL for override (e.g. https://api.example.com/v1).
  -s SCOPE, --scope SCOPE
                        Regex scope filter.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Concurrency (default: 15)
  -w WARMUP, --warmup WARMUP
                        Warm-up delay (ms) (default: 100)
  --strategy {auto,spa,first-seq}
                        Attack strategy:
                        auto: Use httpx LBS/Staged Attack (Default).
                        spa: Use HTTP/2 Single Packet Attack (H2 engine).
                        first-seq: Use HTTP/2 First Sequence Sync (H2 engine, Linux root only).
  --http2               Force HTTP/2 for 'auto' strategy.
```

### 4. Advanced Strategies

*   **SPA (Single Packet Attack)**:
    ```bash
    python3 scalpel_racer.py --strategy spa
    ```
    This prepares all requests on the server (sending headers) and triggers them by sending the last byte of the body for all requests simultaneously.

*   **First-Seq (Linux Only)**:
    ```bash
    sudo python3 scalpel_racer.py --strategy first-seq
    ```
    This uses `iptables` and `NetfilterQueue` to hold the very first packet of the trigger burst. It ensures that the operating system sends all trigger packets as close together as possible before releasing the hold.

## Architecture

*   `scalpel_racer.py`: The main entry point. Handles the UI, proxy server, and high-level attack orchestration.
*   `low_level.py`: Contains the `HTTP2RaceEngine`, which implements the raw socket and HTTP/2 logic for advanced attacks.
*   `packet_controller.py`: Manages the Linux packet interception logic (`PacketController`) for the First-Seq strategy.
