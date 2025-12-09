# Scalpel Racer: Copilot Instructions

## Project Overview

Scalpel Racer is an advanced race condition testing tool that identifies and exploits concurrency vulnerabilities in web applications. It operates as a transparent HTTP/HTTPS proxy with multiple attack strategies (Auto, SPA, First-Seq) that send synchronized concurrent requests to trigger timing-dependent bugs.

**Key Insight**: The entire architecture centers on **request capture → modification → concurrent replay** with different synchronization mechanisms for maximum timing precision.

## Architecture & Data Flow

### Core Components

1. **`scalpel_racer.py`** (Main Orchestrator)
   - Proxy server startup and lifecycle management
   - CA certificate generation (RSA-3072 per NIST SP 800-57)
   - Interactive CLI for request capture, editing, and attack execution
   - Routes attacks to strategy-specific engines (Auto, SPA, First-Seq)

2. **`proxy_core.py`** (HTTP/2 Native Proxy - Sans-IO)
   - Full-duplex HTTP/2 connection handling using hyper-h2 library
   - RFC 9113 strict compliance (validates headers, enforces flow control)
   - HPACK bomb mitigation and connection state machine management
   - Intercepts and captures client/server traffic
   - Uses asyncio.TaskGroup for robust concurrency (Python 3.11+)

3. **`low_level.py`** (HTTP/2 Race Engine)
   - Synchronous socket-based HTTP/2 implementation for **Single Packet Attacks (SPA)**
   - Sends request headers early, triggers all requests with single TCP packet containing final byte
   - Minimizes network jitter for precise timing
   - Direct H2Connection control via hyper-h2

4. **`sync_http11.py`** (HTTP/1.1 Staged Attack Engine)
   - Thread-based synchronization with `threading.Barrier`
   - Synchronizes threads immediately before `socket.send()` call
   - Supports `{{SYNC}}` markers in request bodies for staged attacks
   - Higher precision than asyncio for CPU-bound synchronization

5. **`packet_controller.py`** (First Sequence Sync)
   - Linux-only: Uses iptables + NetfilterQueue to intercept TCP packets
   - Deliberately reorders first packet of burst to occur **after** subsequent packets
   - Maximizes server-side parallelism by exploiting kernel packet ordering
   - Requires root privileges and libnetfilter-queue-dev system dependency

6. **`structures.py`** (Shared Data Model)
   - `CapturedRequest`: Encapsulates HTTP method, URL, headers, body, and optional edited payload
   - `ScanResult`: Records individual race attempt (status, duration, body hash, error)
   - Constants: `SYNC_MARKER = b"{{SYNC}}"`, `HOP_BY_HOP_HEADERS` (RFC 9113 Section 8.2.2)

## Attack Strategies

| Strategy | Transport | Synchronization | When to Use | Trade-offs |
|----------|-----------|-----------------|------------|-----------|
| **Auto (Last-Byte Sync)** | HTTP/1.1 or HTTP/2 | Async barriers + `{{SYNC}}` markers | Default, staged attacks, maximum control | Lower timing precision |
| **Auto (Single Request)** | HTTP/1.1 or HTTP/2 | Simple async concurrency | Quick testing, no markers needed | Basic parallelism only |
| **SPA** | HTTP/2 | Single TCP packet trigger | HTTP/2-only targets, minimal jitter | No request body editing post-capture |
| **First-Seq** | HTTP/2 | Linux kernel packet reordering | Maximum parallelism, advanced tests | Linux/root only, complex setup |

**Example**: For a login form race condition, capture the POST request, insert `{{SYNC}}` before the critical parameter, then use "auto" strategy to synchronize at that exact point.

## Critical Patterns & Conventions

### Request Editing with Sync Markers
- Edit captured requests via interactive CLI (`e <ID>`)
- Insert `{{SYNC}}` to mark synchronization points: `user_id=123&{{SYNC}}&transfer=1000`
- Only the "auto" strategy recognizes markers; SPA/First-Seq ignore them
- Marker automatically triggers strategy switch to "auto" with warning

### Header Stripping (RFC 9113 Compliance)
- `HOP_BY_HOP_HEADERS` stripped from all requests to prevent smuggling (H2.TE, H2.CL)
- Includes: `connection`, `transfer-encoding`, `content-length`, `te`, `upgrade`, `host` (→ `:authority`)
- Enforced in both proxy and attack engines; violation causes protocol errors

### Response Analysis
- Groups responses by status code + body MD5 hash
- Computes timing stats: mean, std dev, jitter percentage
- Max body read: 1MB (`MAX_RESPONSE_BODY_READ`)
- Generates histograms of response times for visual jitter analysis

### Concurrency Models
- **Async (scalpel_racer.py)**: Uses asyncio.TaskGroup; ideal for I/O-bound operations
- **Threads (sync_http11.py)**: Barrier-based; better for CPU-bound pre-send synchronization
- **Synchronous (low_level.py)**: Direct socket control; required for SPA packet-level precision

## Testing & Development Workflow

### Running Tests
```bash
# Install test dependencies (in venv)
pip install -r requirements.txt

# Run all tests with coverage
pytest tests/ -v --cov=. --cov-report=term-missing

# Run specific test file
pytest tests/test_h2_engine.py -v

# Run test matching pattern
pytest tests/ -k "test_spa" -v
```

### Test Architecture Patterns
- **Mocking strategy**: Mock h2 library imports before SUT import (see `test_h2_engine.py`)
- **Fixtures**: Use autouse fixtures for sys.modules patching and import isolation
- **PacketController**: Always mocked in unit tests (requires root + Linux)
- **Baseline testing**: `tests/update_baselines.py` regenerates expected attack results

### Key Test Files
- `test_h2_engine.py`: HTTP/2 race engine, SPA/First-Seq strategies
- `test_proxy_core.py`: Proxy request/response handling, flow control
- `test_sync_http11.py`: Staged attacks with barriers
- `test_proxy_core_advanced.py`: Flow control, graceful shutdown, RFC 9113 strictness
- `test_combined_fixes.py`: Regression tests for known issues (E1-E3, N2, B05, PC1-PC2)

## Development Guidelines

### When Adding Features
1. **Attack Engines**: Sync operations must complete before socket/send operations (see `sync_http11.py` barrier placement)
2. **Proxy Logic**: Always validate headers against `HOP_BY_HOP_HEADERS` before forwarding
3. **Concurrency**: Use asyncio.TaskGroup for new async code; prefer explicit TimeoutErrors over silent failures
4. **Logging**: Replace print/traceback with logging module (all modules use logger = logging.getLogger(__name__))

### Common Debugging Tasks
- **Race condition not triggering?** Check concurrency >= 15, warmup >= 100ms, network jitter is low
- **SPA failing silently?** Verify h2 library installed (`pip install h2`), target supports HTTP/2
- **First-Seq errors?** Check root privileges, iptables/NetfilterQueue installed, NFQUEUE_AVAILABLE=True
- **Header validation errors?** Inspect `HOP_BY_HOP_HEADERS` stripping; verify `:authority` pseudo-header present for HTTP/2

### Dependencies & Versions
- **Core**: httpx>=0.28.0, numpy>=1.26.4, cryptography>=42.0.0
- **Advanced**: h2>=4.1.0 (SPA/First-Seq), NetfilterQueue>=1.0.0 (First-Seq Linux only)
- **Testing**: pytest>=8.0.0, pytest-asyncio>=0.23.5, hypercorn>=0.16.0
- **Python**: 3.7+ (uses asyncio.TaskGroup which requires 3.11+)

## Integration Points

- **Proxy Server**: Binds to localhost:8080 (configurable), intercepts HTTP/HTTPS via standard proxy settings
- **CA Certificate**: Auto-generated on first run, must be trusted in browser to avoid connection errors
- **External Tool Integration**: Captures from Burp Suite, Postman, curl via HTTP proxy environment variables
- **Attack Engines**: Select via `-s/--strategy` flag during attack launch; auto-selected based on request markers

## File Organization
```
scalpel_racer.py          # Main entry point, orchestration
proxy_core.py             # HTTP/2 proxy implementation
low_level.py              # HTTP/2 SPA engine
sync_http11.py            # HTTP/1.1 staged attack engine
packet_controller.py      # First-Seq packet reordering (Linux)
structures.py             # Shared data structures & constants
tests/                    # Comprehensive test suite
  test_h2_engine.py       # SPA/First-Seq attack tests
  test_proxy_core*.py     # Proxy behavior & RFC compliance tests
  test_sync_http11.py     # Staged attack synchronization tests
  test_combined_fixes.py  # Regression & integration tests
```
