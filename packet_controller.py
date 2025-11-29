import os
import sys
import threading
import time
import subprocess
import socket
from typing import Optional

# Conditional imports and availability check for Linux-specific libraries
NFQUEUE_AVAILABLE = False
# Check if the platform is Linux
if sys.platform.startswith("linux"):
    try:
        # These libraries require system dependencies (libnetfilter-queue-dev) and root privileges
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP, TCP
        NFQUEUE_AVAILABLE = True
    except ImportError:
        print("[!] 'NetfilterQueue' or 'scapy' not found. First Sequence Sync will be disabled.")
        print("[!] Install them via: pip install NetfilterQueue scapy")
        print("[!] Ensure system dependencies (e.g. libnetfilter-queue-dev) are installed.")
    except Exception as e:
        # Catch other potential initialization errors
        print(f"[!] Error initializing NFQueue/Scapy: {e}. First Sequence Sync disabled.")
# If not Linux, NFQUEUE_AVAILABLE remains False.

# Configuration Constants
REORDER_DELAY = 0.010 # 10ms - The delay before releasing the first packet.
QUEUE_NUM = 99 # The specific iptables NFQUEUE number.

class PacketController:
    """
    Manages the interception and reordering of TCP packets using Linux iptables and NetfilterQueue.
    Implements the core mechanism for the First Sequence Sync attack.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int):
        """
        Initialize the PacketController.

        Args:
            target_ip (str): The IP address of the target server.
            target_port (int): The port number of the target server.
            source_port (int): The local source port used for the connection.

        Raises:
            ImportError: If NetfilterQueue is not available or supported on the system.
        """
        if not NFQUEUE_AVAILABLE:
            # Safety guard against attempting to use the class when dependencies are missing
            raise ImportError("NetfilterQueue is not available or supported on this system.")
            
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port
        self.queue_num = QUEUE_NUM
        self.nfqueue = None
        
        # State tracking for the reordering logic
        self.first_packet_info = None # Stores (seq, pkt_object) of the intercepted first packet
        self.expected_next_seq = None # Tracks the sequence number continuity
        self.lock = threading.Lock()
        self.active = False
        
        # Thread management
        self.listener_thread = None
        self.release_thread = None
        
        # Synchronization events
        self.first_packet_held = threading.Event()
        self.subsequent_packets_released = threading.Event()

    def start(self):
        """
        Sets up iptables rules and starts the NFQueue listener thread.

        This method configures iptables to redirect specific outbound TCP packets to the
        NetfilterQueue and starts background threads to process intercepted packets.

        Raises:
             PermissionError: If the process lacks root privileges required for iptables/NFQueue.
             RuntimeError: If binding to the NetfilterQueue fails.
        """
        print(f"[*] PacketController: Starting interception for {self.target_ip}:{self.target_port} (Source Port: {self.source_port})")
        
        # 1. Set up the iptables rule
        self._manage_iptables(action='A')

        # 2. Initialize and bind NetfilterQueue
        self.nfqueue = NetfilterQueue()
        try:
            # Bind the specific queue number to our callback function
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError as e:
            # Handle binding errors (e.g., permission denied)
            self._manage_iptables(action='D') # Clean up the rule
            if "Permission denied" in str(e):
                 raise PermissionError("Failed to bind NetfilterQueue. Root privileges required.")
            raise RuntimeError(f"Failed to bind NetfilterQueue (Queue Num {self.queue_num}): {e}")

        # 3. Start the processing threads
        self.active = True
        # The listener thread runs the blocking nfqueue.run() loop
        self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self.listener_thread.start()
        
        # The release thread handles the timing and release of the held first packet
        self.release_thread = threading.Thread(target=self._delayed_release_first_packet, daemon=True)
        self.release_thread.start()

        print("[*] PacketController: Active and listening on NFQueue.")

    def stop(self):
        """
        Stops the NFQueue listener and cleans up iptables rules.

        This method signals the background threads to stop, unbinds the NetfilterQueue,
        and removes the added iptables rules.
        """
        if not self.active:
            return
            
        print("[*] PacketController: Stopping...")
        self.active = False
        
        # 1. Unbind the queue (causes nfqueue.run() to return)
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except Exception:
                pass
        
        # 2. Clean up iptables rule
        self._manage_iptables(action='D')
        
        # 3. Ensure threads are finished
        # Set events to unblock the release thread if it was waiting.
        self.first_packet_held.set()
        self.subsequent_packets_released.set()

        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=1)
        if self.release_thread and self.release_thread.is_alive():
             self.release_thread.join(timeout=1)

        print("[*] PacketController: Stopped.")

    def _manage_iptables(self, action: str):
        """
        Helper to add ('A') or delete ('D') the required iptables rule.

        The rule targets outgoing TCP packets with the PSH flag set, destined for
        the target IP and port, and originating from the specified source port.

        Args:
            action (str): The iptables action flag, either 'A' (Append) or 'D' (Delete).

        Raises:
            PermissionError: If the iptables command fails due to permission issues.
            RuntimeError: If the iptables command fails for other reasons.
        """
        
        # The rule specifically targets the exact connection parameters.
        # Optimization: We specifically target packets with the PSH flag set, 
        # which the OS typically sets when sending the application data burst from sendall().
        rule = [
            'iptables',
            f'-{action}', 'OUTPUT',
            '-p', 'tcp',
            '--dport', str(self.target_port),
            '--sport', str(self.source_port),
            '-d', self.target_ip,
            '-m', 'tcp', '--tcp-flags', 'ALL', 'PSH', 
            '-j', 'NFQUEUE',
            '--queue-num', str(self.queue_num)
        ]
        
        try:
            # Execute the iptables command, hiding output unless an error occurs
            subprocess.check_call(rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            # Handle errors during iptables configuration
            if action == 'A':
                self._manage_iptables(action='D') # Attempt cleanup
                # Check common error codes related to permissions
                if e.returncode in [1, 4]: 
                     raise PermissionError("Failed to configure iptables. Ensure running as root and iptables is installed/functional.")
                raise RuntimeError(f"Failed to configure iptables (Return code {e.returncode}).")
            # If deletion fails (e.g., rule didn't exist), we ignore it.

    def _listener_loop(self):
        """
        The main loop for the NFQueue listener thread.

        This method calls `nfqueue.run()` which blocks and processes packets via
        the registered callback function. It runs until the queue is unbound.
        """
        try:
            # This call blocks and processes packets via the callback
            self.nfqueue.run()
        except Exception as e:
            if self.active:
                # Log errors only if the controller is supposed to be active
                print(f"[!] NFQueue listener loop error: {e}")

    def _queue_callback(self, pkt):
        """
        The core logic executed for every intercepted packet.

        This callback inspects the packet sequence number to determine if it is
        the first packet of the burst or a subsequent one. It holds the first
        packet and releases subsequent ones to achieve reordering.

        Args:
            pkt: The NetfilterQueue packet object.
        """
        if not self.active:
            pkt.accept()
            return

        try:
            # Parse the packet payload using Scapy
            ip_packet = IP(pkt.get_payload())
            
            if TCP not in ip_packet:
                 pkt.accept()
                 return

            tcp_segment = ip_packet[TCP]
            seq = tcp_segment.seq
            payload_len = len(tcp_segment.payload)

            # We only care about packets carrying application data
            if payload_len == 0:
                 pkt.accept()
                 return

            # --- Reordering Logic ---
            with self.lock:
                if self.first_packet_info is None:
                    # This is the very first data packet of the burst. Hold it.
                    print(f"[*] Intercepted and holding First Packet (Seq: {seq}, Len: {payload_len})")
                    self.first_packet_info = (seq, pkt)
                    # Calculate the sequence number expected for the next packet
                    self.expected_next_seq = seq + payload_len
                    self.first_packet_held.set()
                    # Return without verdicting. It remains queued.
                    return

                elif seq == self.expected_next_seq:
                    # This is the expected subsequent packet. Release immediately.
                    # print(f"[*] Releasing subsequent packet (Seq: {seq})") # Optional: verbose logging
                    pkt.accept()
                    self.expected_next_seq = seq + payload_len
                    
                    # Signal the release thread that subsequent packets have started flowing
                    if not self.subsequent_packets_released.is_set():
                         self.subsequent_packets_released.set()
                    return
                
                else:
                     # Handle unexpected sequence numbers (e.g., retransmissions)
                     # print(f"[*] Accepting unexpected sequence packet (Seq: {seq}, Expected: {self.expected_next_seq})") # Optional: verbose logging
                     pkt.accept()
                     return

        except Exception as e:
            # Safety catch: Accept the packet if processing fails
            print(f"[!] Error processing packet: {e}")
            pkt.accept()

    def _delayed_release_first_packet(self):
        """
        Thread responsible for releasing the first packet after synchronization.

        This method waits for the first packet to be held, then waits for subsequent
        packets to be released (or a timeout), applies a delay, and finally releases
        the held first packet.
        """
        
        # 1. Wait until the first packet is intercepted and held
        if not self.first_packet_held.wait(timeout=5):
            if self.active:
                 print("[!] Timeout waiting for the first packet to be intercepted.")
            return

        # 2. Synchronization: Wait until subsequent packets are released first.
        if not self.subsequent_packets_released.wait(timeout=0.5): # 500ms timeout
             # If timeout occurs, the entire payload likely fit in the first packet (smaller than MTU).
             if self.active:
                print("[*] Note: No subsequent packets detected. Payload likely smaller than MTU. Releasing immediately.")
        else:
             # 3. If subsequent packets were released, add the fixed delay.
             time.sleep(REORDER_DELAY)

        # 4. Release the first packet
        with self.lock:
            if self.first_packet_info:
                seq, pkt = self.first_packet_info
                try:
                    print(f"[*] Releasing First Packet (Seq: {seq})")
                    # Verdict the packet (Accept) so the OS sends it out (now out of order).
                    pkt.accept()
                except Exception as e:
                    # Handle potential errors if the packet already expired from the queue
                    print(f"[!] Error releasing first packet: {e}")
                self.first_packet_info = None
