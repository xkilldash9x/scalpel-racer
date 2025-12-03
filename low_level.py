# FILE: ./low_level.py
import socket
import ssl
import time
import threading
import select
import hashlib
import sys
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

# Define placeholders for data structures to allow parsing and type hinting.
# We attempt to import the actual definitions from the main script (scalpel_racer.py).
class ScanResult:
     """
     Placeholder class for ScanResult to allow type hinting.
     Actual definition is imported from scalpel_racer.py.
     """
     def __init__(self, index: int, status_code: int, duration: float, body_hash: str = None, body_snippet: str = None, error: str = None):
        self.index = index; self.status_code = status_code; self.duration = duration
        self.body_hash = body_hash; self.body_snippet = body_snippet; self.error = error

class CapturedRequest:
    """
    Placeholder class for CapturedRequest to allow type hinting.
    Actual definition is imported from scalpel_racer.py.
    """
    def get_attack_payload(self) -> bytes:
        """
        Placeholder method for get_attack_payload.

        Returns:
            bytes: The attack payload.
        """
        pass
    pass 

MAX_RESPONSE_BODY_READ = 1024 * 1024

try:
    # Attempt to import the actual definitions when running via scalpel_racer.py
    from structures import ScanResult, CapturedRequest, MAX_RESPONSE_BODY_READ
except ImportError:
    # This is expected if running low_level_h2.py independently
    pass


# Import H2 library
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        ResponseReceived, DataReceived, StreamEnded, StreamReset
    )
except ImportError:
    # This exception is critical and will be caught by scalpel_racer.py
    raise ImportError("The 'h2' library is required for low-level HTTP/2 attacks. Install with: pip install h2")

# Import PacketController (Optional dependency for 'first-seq')
try:
    # We only import the class definition and the availability flag.
    from packet_controller import PacketController, NFQUEUE_AVAILABLE
except ImportError:
    PacketController = None
    NFQUEUE_AVAILABLE = False


class HTTP2RaceEngine:
    """
    Implements low-level HTTP/2 attacks (SPA and First-Sequence Sync) using raw sockets and the h2 library.
    This engine operates synchronously (blocking I/O managed via threads) as required for precise packet control.
    """
    def __init__(self, request: CapturedRequest, concurrency: int, strategy="spa", warmup_ms=100):
        """
        Initialize the HTTP2RaceEngine.

        Args:
            request (CapturedRequest): The request to race.
            concurrency (int): The number of concurrent requests to send.
            strategy (str, optional): The attack strategy ('spa' or 'first-seq'). Defaults to "spa".
            warmup_ms (int, optional): The warm-up delay in milliseconds before the trigger phase. Defaults to 100.
        """
        self.request = request
        self.concurrency = concurrency
        self.strategy = strategy
        self.warmup_ms = warmup_ms
        
        self.target_host = None
        self.target_port = 443
        self.target_ip = None
        self.conn: Optional[H2Connection] = None
        self.sock = None
        
        # Results and State tracking
        self.streams: Dict[int, Dict] = {} # stream_id -> {index, start_time, headers, body, finished, error}
        self.lock = threading.Lock()
        # Event to signal when the attack is complete
        self.all_streams_finished = threading.Event()

        self._parse_target()

    # (_parse_target, connect, run_attack, _prepare_requests, _trigger_requests, _handle_connection_closed, _finalize_results remain the same)

    def _parse_target(self):
        """
        Extracts target host and port from the request URL.

        Parses the URL stored in the request object to determine the target hostname
        and port. Defaults to port 443 for HTTPS.

        Raises:
            ValueError: If the URL scheme is not supported.
        """
        parsed_url = urlparse(self.request.url)
        self.target_host = parsed_url.hostname
        
        if parsed_url.scheme == 'https':
            self.target_port = parsed_url.port or 443
        elif parsed_url.scheme == 'http':
            # We do not implement HTTP/2 over cleartext (h2c). 
            print("[!] Warning: Target scheme is HTTP. Low-level H2 strategies require HTTPS. Attempting connection on port 443.")
            self.target_port = 443
        else:
            raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}")

    def connect(self):
        """
        Establishes the TCP connection, performs SSL handshake, and initiates H2 connection.

        This method resolves the target IP, creates a raw TCP socket (with TCP_NODELAY),
        wraps it in SSL with ALPN set to 'h2', and initializes the HTTP/2 state machine.

        Raises:
            ConnectionError: If connection fails, SSL handshake fails, or HTTP/2 is not negotiated.
        """
        print(f"[*] Connecting to {self.target_host}:{self.target_port}...")
        
        # 1. Resolve IP (Crucial for PacketController targeting)
        try:
            self.target_ip = socket.gethostbyname(self.target_host)
            print(f"[*] Resolved IP: {self.target_ip}")
        except socket.gaierror as e:
            raise ConnectionError(f"DNS resolution failed for {self.target_host}: {e}")

        # 2. Create Raw Socket
        try:
            # Connect using the IP address
            sock = socket.create_connection((self.target_ip, self.target_port), timeout=10)
        except socket.error as e:
            raise ConnectionError(f"Could not connect to {self.target_ip}:{self.target_port}: {e}")

        # Optimization: Disable Nagle's algorithm (TCP_NODELAY)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # 3. Wrap with SSL
        context = ssl.create_default_context()
        # Mimic 'verify=False'
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Set ALPN protocols to force negotiation of HTTP/2
        try:
            context.set_alpn_protocols(["h2"])
        except NotImplementedError:
            raise ConnectionError("Python SSL library does not support ALPN (required for HTTP/2).")

        try:
            # We must pass the original hostname for SNI.
            self.sock = context.wrap_socket(sock, server_hostname=self.target_host)
            
            # Verify H2 negotiation success
            negotiated_protocol = self.sock.selected_alpn_protocol()
            if negotiated_protocol != "h2":
                self.sock.close()
                raise ConnectionError(f"Server did not negotiate HTTP/2 (ALPN returned: {negotiated_protocol}). Cannot proceed.")
        
        except ssl.SSLError as e:
            sock.close()
            raise ConnectionError(f"SSL Handshake failed: {e}")
        except ConnectionError as e:
             sock.close()
             raise e

        # 4. Initialize H2 Connection State Machine
        config = H2Configuration(client_side=True, header_encoding='utf-8')
        self.conn = H2Connection(config=config)
        self.conn.initiate_connection()
        # Send the initial H2 preface and SETTINGS frame
        self.sock.sendall(self.conn.data_to_send())
        print("[*] Connection established and H2 handshake initiated.")

    def run_attack(self) -> List[ScanResult]:
        """
        Executes the attack sequence: Connect, Prepare, Trigger, Receive.

        This method coordinates the entire attack lifecycle, including setting up
        the PacketController (if using 'first-seq' strategy), sending requests,
        and collecting results.

        Returns:
            List[ScanResult]: A list of ScanResult objects containing the outcome of each request.
        """
        
        # --- Pre-flight checks ---
        if self.strategy == "first-seq":
            if not NFQUEUE_AVAILABLE:
                print("[!] Error: First Sequence Sync requested but NetfilterQueue/Scapy is unavailable or unsupported.")
                return []

        # 1. Connect
        try:
            self.connect()
        except ConnectionError as e:
            print(f"[!] Connection failed: {e}")
            # Return error results for all concurrent requests if connection fails
            return [ScanResult(i, 0, 0.0, error=str(e)) for i in range(self.concurrency)]

        packet_controller = None
        # 2. Initialize PacketController (if required)
        if self.strategy == "first-seq":
            # Get the local source port of the established connection
            try:
                source_port = self.sock.getsockname()[1]
            except OSError as e:
                print(f"[!] Could not determine source port: {e}")
                return [ScanResult(i, 0, 0.0, error=f"Source port error: {e}") for i in range(self.concurrency)]

            packet_controller = PacketController(self.target_ip, self.target_port, source_port)
            try:
                # Start interception (sets iptables rules and binds NFQueue)
                packet_controller.start()
            except Exception as e:
                # This catches PermissionError (if not root) or other initialization failures
                self.sock.close()
                # We re-raise the exception to be handled by the caller (run_scan)
                raise e

        # Start the background receiver thread to handle responses
        receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
        receiver_thread.start()

        try:
            # 3. Preparation Phase (Send HEADERS + Partial DATA)
            self._prepare_requests()
            
            # 4. Warmup Period (Delay before trigger)
            if self.warmup_ms > 0:
                print(f"[*] Waiting for warmup ({self.warmup_ms}ms)...")
                time.sleep(self.warmup_ms / 1000.0)

            # 5. Trigger Phase (Send Final DATA)
            self._trigger_requests()

            # 6. Wait for responses
            print("[*] Waiting for responses (Timeout: 10s)...")
            # Wait for the receiver thread to signal completion or timeout
            self.all_streams_finished.wait(timeout=10)
            
            if not self.all_streams_finished.is_set():
                 print("[!] Warning: Timeout waiting for all responses.")

        except Exception as e:
            # Handle exceptions during the attack phases (e.g., socket errors during send)
            print(f"[!] Error during attack execution: {type(e).__name__}: {e}")
            # Mark any pending streams with the error
            with self.lock:
                for stream_data in self.streams.values():
                    if not stream_data["finished"]:
                        stream_data["finished"] = True
                        stream_data["error"] = f"Attack interrupted: {e}"
        finally:
            # --- Cleanup ---
            # Stop the PacketController (removes iptables rules)
            if packet_controller:
                packet_controller.stop()

            # Ensure the receiver thread knows to stop
            self.all_streams_finished.set()
            
            # Close the connection gracefully
            if self.sock:
                try:
                    # Send GOAWAY frame if the connection is still open
                    if self.conn.state_machine.state != 'CLOSED':
                        self.conn.close_connection()
                        data_to_send = self.conn.data_to_send()
                        if data_to_send:
                             self.sock.sendall(data_to_send)
                    self.sock.close()
                except Exception:
                    pass

        # Process the collected stream data into ScanResult objects
        return self._finalize_results()

    def _prepare_requests(self):
        """
        Sends HEADERS and partial DATA frames for all requests.

        This initializes the HTTP/2 streams and sends the initial part of the
        payload, up to the last byte. This prepares the server to receive the
        trigger (last byte) later.
        """
        print("[*] Preparing requests (Sending HEADERS and partial DATA)...")
        
        payload = self.request.get_attack_payload()
        
        # Determine partial body (all but last byte)
        if len(payload) > 1:
            partial_body = payload[:-1]
        else:
            partial_body = b""

        for i in range(self.concurrency):
            # Client stream IDs must be odd (1, 3, 5, ...)
            stream_id = (i * 2) + 1 
            
            # 1. Construct Headers
            headers = self._construct_h2_headers(len(payload))
            
            # 2. Generate HEADERS frame (end_stream=False)
            self.conn.send_headers(stream_id, headers, end_stream=False)
            
            # Initialize stream tracking structure
            with self.lock:
                self.streams[stream_id] = {
                    "index": i,
                    "start_time": None, # Set just before trigger
                    "headers": {},
                    "body": bytearray(),
                    "finished": False,
                    "error": None
                }

            # 3. Generate partial DATA frame (if any)
            if partial_body:
                self.conn.send_data(stream_id, partial_body, end_stream=False)
        
        # Send all prepared frames in one batch
        data_to_send = self.conn.data_to_send()
        if data_to_send:
            self.sock.sendall(data_to_send)
            
        print(f"[*] Prepared {self.concurrency} requests. Preparation payload size: {len(data_to_send)} bytes.")

    def _trigger_requests(self):
        """
        Generates and sends the final DATA frames (the trigger) in a single sendall() call.

        This sends the last byte of data for all streams, triggering the backend
        processing. If 'first-seq' strategy is active, the first packet of this
        burst is intercepted by the PacketController.
        """
        print("[*] Sending trigger frames (Final DATA)...")
        
        payload = self.request.get_attack_payload()
        
        # Determine the final byte of the payload
        if len(payload) >= 1:
            final_byte = payload[-1:]
        else:
            # If payload was empty, the trigger is an empty DATA frame with END_STREAM
            final_byte = b""

        # Record start time just before generating the trigger frames
        start_time = time.perf_counter()

        # Generate all trigger frames
        for i in range(self.concurrency):
            stream_id = (i * 2) + 1
            
            # Update stream start time
            with self.lock:
                if stream_id in self.streams:
                    self.streams[stream_id]["start_time"] = start_time

            # Generate final DATA frame with END_STREAM=True
            self.conn.send_data(stream_id, final_byte, end_stream=True)
        
        # Get the raw bytes of all concatenated trigger frames
        data_to_send = self.conn.data_to_send()
        
        print(f"[*] Trigger payload size: {len(data_to_send)} bytes.")
        
        if self.strategy == "first-seq":
             print("[*] Sending via First Sequence Sync (Packet interception active)...")
        
        # Send the entire trigger payload in one syscall.
        # If strategy="first-seq", the OS will split this, and PacketController will intercept.
        self.sock.sendall(data_to_send)
        print("[*] Trigger frames sent.")

    def _construct_h2_headers(self, content_length: int) -> List[Tuple[str, str]]:
        """
        Creates the list of HTTP/2 headers, including pseudo-headers.
		...
        """
        parsed_url = urlparse(self.request.url)
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query

        # :authority (Host header equivalent)
        authority = self.target_host
        if self.target_port != 443:
             authority += f":{self.target_port}"

        headers = [
            (':method', self.request.method),
            (':authority', authority),
            (':scheme', 'https'), # We force HTTPS in this engine
            (':path', path),
        ]
        
        # Add user-provided headers
        header_keys = set()
        for k, v in self.request.headers.items():
            k_lower = k.lower()
            header_keys.add(k_lower)
            # Skip headers managed by H2 pseudo-headers or connection protocols
            if k_lower not in ['host', 'connection', 'transfer-encoding', 'content-length', 'keep-alive', 'upgrade']:
                headers.append((k_lower, v))

        # Ensure Content-Type if missing
        if 'content-type' not in header_keys and self.request.method in ["POST", "PUT", "PATCH"] and content_length > 0:
             headers.append(('content-type', 'application/x-www-form-urlencoded'))

        # Add Content-Length
        if content_length > 0:
            headers.append(('content-length', str(content_length)))
        
        # Add default User-Agent if not present
        if 'user-agent' not in header_keys:
            headers.append(('user-agent', 'Scalpel-CLI/5.3-LowLevelH2')) # C03 Version Bump
        
        return headers

    def _receive_loop(self):
        """
        Background thread to read data from the socket and process H2 events.
		...
        """
        while not self.all_streams_finished.is_set():
            try:
                # Use select for non-blocking read with a short timeout
                ready, _, _ = select.select([self.sock], [], [], 0.1)
                
                if ready:
                    data = self.sock.recv(65536)
                    if not data:
                        # Connection closed by the server (EOF)
                        self._handle_connection_closed("Connection closed by server.")
                        break

                    # Pass the received data to the H2 state machine
                    try:
                        events = self.conn.receive_data(data)
                    except Exception as e:
                        # Handle H2 protocol errors
                        self._handle_connection_closed(f"HTTP/2 Protocol Error: {e}")
                        break
                        
                    # Process the events
                    self._process_events(events)
                    
                    # [E3 FIX] Move sendall inside the try block
                    # Send any data generated (e.g., ACKs, WINDOW_UPDATEs)
                    data_to_send = self.conn.data_to_send()
                    if data_to_send:
                        self.sock.sendall(data_to_send)

            # [E2 FIX] Broaden exception handling to include OSError
            except (ssl.SSLError, socket.error, OSError) as e:
                # Handle socket level errors
                self._handle_connection_closed(f"Connection error: {e}")
                break
        
        # Ensure the event is set when the loop finishes
        self.all_streams_finished.set()

    def _process_events(self, events):
        """
        Handles H2 events (headers received, data received, stream end/reset).
		...
        """
        with self.lock:
            for event in events:
                stream_id = getattr(event, 'stream_id', None)
                
                if stream_id not in self.streams:
                    continue
                
                stream_data = self.streams[stream_id]
                
                if stream_data["finished"]:
                    continue

                if isinstance(event, ResponseReceived):
                    # Parse headers (H2 headers are typically bytes tuples)
                    for header, value in event.headers:
                        try:
                            # Decode headers, assuming UTF-8
                            header_str = header.decode('utf-8')
                            value_str = value.decode('utf-8')
                            stream_data["headers"][header_str] = value_str
                        except UnicodeDecodeError:
                            pass
                
                elif isinstance(event, DataReceived):
                    # Append body data
                    stream_data["body"].extend(event.data)
                    
                    # Acknowledge received data for flow control.
                    self.conn.acknowledge_received_data(event.flow_controlled_length, stream_id)

                elif isinstance(event, StreamEnded):
                    # Stream successfully completed
                    stream_data["finished"] = True

                elif isinstance(event, StreamReset):
                    # Stream was aborted
                    stream_data["finished"] = True
                    stream_data["error"] = f"Stream reset by server (Error code: {event.error_code})"

            # Check if all initiated streams have finished.
            # B05 FIX: Ensure we check against the expected concurrency count.
            # This prevents premature termination if _process_events is called before all streams are initialized in _prepare_requests.
            finished_count = sum(1 for s in self.streams.values() if s.get("finished"))

            if finished_count >= self.concurrency:
                self.all_streams_finished.set()

    def _handle_connection_closed(self, reason: str):
        """
        Marks all pending streams as finished with an error.
		...
        """
        with self.lock:
            for stream_data in self.streams.values():
                if not stream_data["finished"]:
                    stream_data["finished"] = True
                    stream_data["error"] = reason
        self.all_streams_finished.set()

    def _finalize_results(self) -> List[ScanResult]:
        """
        Converts internal stream data into ScanResult objects.
		...
        """
        final_results = []
        
        with self.lock:
            for stream_id, data in self.streams.items():
                index = data["index"]
                
                # Calculate duration
                if data["start_time"]:
                    # Use current time as end time approximation
                    duration = (time.perf_counter() - data["start_time"]) * 1000
                else:
                    duration = 0

                if data["error"]:
                    result = ScanResult(index, 0, duration, error=data["error"])
                else:
                    # Extract status code from ':status'
                    try:
                        status_code = int(data["headers"].get(':status', 0))
                    except ValueError:
                        status_code = 0
                    
                    # Process body
                    body = bytes(data["body"])
                    body_hash = None
                    body_snippet = None

                    if body:
                        body_hash = hashlib.sha256(body).hexdigest()
                        # [P6 FIX] Remove unnecessary try/except block.
                        body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')
                    
                    # Handle timeouts (unfinished streams)
                    if not data["finished"] and status_code == 0 and not data["error"]:
                         result = ScanResult(index, 0, duration, error="Response timeout")
                    else:
                        result = ScanResult(index, status_code, duration, body_hash, body_snippet)
                
                final_results.append(result)

        # Return results sorted by the original request index
        return sorted(final_results, key=lambda r: r.index)