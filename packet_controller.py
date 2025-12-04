# FILE: ./packet_controller.py
"""
Implements the PacketController for the 'First Sequence Sync' strategy.

This module provides the `PacketController` class, which uses Linux `iptables` and
`NetfilterQueue` to intercept and manipulate outgoing TCP packets. The core purpose
is to deliberately reorder the first packet of a data burst to occur *after* subsequent
packets, maximizing parallelism on the receiving server side.

Dependencies:
    - libnetfilter-queue-dev (System)
    - NetfilterQueue (Python)
    - scapy (Python)
    - root privileges (for iptables and NFQueue binding)
"""

import os
import sys
import threading
import time
import subprocess
import socket
from typing import Optional, Tuple, List

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
REORDER_DELAY = 0.010  # 10ms - The delay before releasing the first packet.
QUEUE_NUM = 99  # The specific iptables NFQUEUE number.


class PacketController:
    """
    Manages the interception and reordering of TCP packets using Linux iptables and NetfilterQueue.
    Implements the core mechanism for the First Sequence Sync attack.

    Attributes:
        target_ip (str): The IP address of the target server.
        target_port (int): The destination port on the target server.
        source_port (int): The local source port used for the connection.
        queue_num (int): The NetfilterQueue number to bind to.
        nfqueue (NetfilterQueue): The NetfilterQueue instance.
        first_packet_info (Tuple[int, object]): Stores the sequence number and packet object of the held first packet.
        expected_next_seq (int): Tracks the expected next sequence number for continuity checks.
        lock (threading.Lock): Thread lock for synchronizing access to state variables.
        active (bool): Flag indicating if the controller is currently active.
        listener_thread (threading.Thread): Thread running the NFQueue listener loop.
        release_thread (threading.Thread): Thread managing the delayed release of the first packet.
        first_packet_held (threading.Event): Event set when the first packet is intercepted.
        subsequent_packets_released (threading.Event): Event set when subsequent packets are observed and released.
    """

    def __init__(self, target_ip: str, target_port: int, source_port: int):
        """
        Initialize the PacketController.

        Args:
            target_ip (str): The destination IP address to filter for.
            target_port (int): The destination port to filter for.
            source_port (int): The local source port to filter for.

        Raises:
            ImportError: If NetfilterQueue is not available (e.g., non-Linux OS or missing libs).
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
        self.first_packet_info: Optional[Tuple[int, object]] = None  # Stores (seq, pkt_object) of the intercepted first packet
        self.expected_next_seq: Optional[int] = None  # Tracks the sequence number continuity
        self.lock = threading.Lock()
        self.active = False

        # Thread management
        self.listener_thread: Optional[threading.Thread] = None
        self.release_thread: Optional[threading.Thread] = None

        # Synchronization events
        self.first_packet_held = threading.Event()
        self.subsequent_packets_released = threading.Event()

    def start(self):
        """
        Sets up iptables rules and starts the NFQueue listener thread.

        This method configures the system to intercept specific TCP PSH packets matching
        the target/source criteria and sends them to the NetfilterQueue. It then
        starts the listener loop and the release management thread.

        Raises:
            PermissionError: If root privileges are missing.
            RuntimeError: If binding to the queue fails.
        """
        print(f"[*] PacketController: Starting interception for {self.target_ip}:{self.target_port} (Source Port: {self.source_port})")

        # 1. Set up the iptables rule (PC1: Now idempotent)
        self._manage_iptables(action='A')

        # 2. Initialize and bind NetfilterQueue
        self.nfqueue = NetfilterQueue()
        try:
            # Bind the specific queue number to our callback function
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError as e:
            # Handle binding errors (e.g., permission denied)
            self._manage_iptables(action='D')  # Clean up the rule
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

        This method signals the threads to stop, unbinds the NetfilterQueue,
        removes the iptables rules, and waits for threads to join.
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

        # 2. Clean up iptables rule (PC1: Now idempotent)
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
        Helper to add ('A') or delete ('D') the required iptables rule idempotently.

        This method checks if the rule already exists before attempting to add or
        delete it, preventing duplicate rules or errors when deleting non-existent rules.

        Args:
            action (str): The iptables action flag, 'A' (Append) or 'D' (Delete).

        Raises:
            RuntimeError: If the iptables command fails or is not found.
            PermissionError: If the operation is denied (usually lack of root).
        """

        # Base rule definition (excluding the action flag)
        # Optimization: We specifically target packets with the PSH flag set,
        # which the OS typically sets when sending the application data burst from sendall().
        base_rule = [
            'iptables',
            # Action flag will be inserted here later
            'OUTPUT',
            '-p', 'tcp',
            '--dport', str(self.target_port),
            '--sport', str(self.source_port),
            '-d', self.target_ip,
            '-m', 'tcp', '--tcp-flags', 'ALL', 'PSH',
            '-j', 'NFQUEUE',
            '--queue-num', str(self.queue_num)
        ]

        # [PC1 FIX] Idempotency Check using -C
        check_rule = base_rule.copy()
        check_rule.insert(1, '-C')  # Insert Check command

        try:
            # Check the rule status. Returns 0 if exists, non-zero otherwise.
            subprocess.check_call(check_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            rule_exists = True
        except subprocess.CalledProcessError:
            rule_exists = False
        # [PC2 FIX] Handle missing iptables binary
        except FileNotFoundError:
            raise RuntimeError("iptables command not found. Ensure it is installed and in PATH.")

        if action == 'A' and rule_exists:
            # Rule already present, no action needed.
            return
        elif action == 'D' and not rule_exists:
            # Rule already absent, no action needed.
            return

        # Define the actual action rule
        action_rule = base_rule.copy()
        action_rule.insert(1, f'-{action}')

        try:
            # Execute the iptables command
            subprocess.check_call(action_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # [PC2 FIX] Handle missing iptables binary
        except FileNotFoundError:
            raise RuntimeError("iptables command not found during execution. Ensure it is installed and in PATH.")
        except subprocess.CalledProcessError as e:
            # Handle errors during iptables configuration
            if action == 'A':
                # B06: Removed recursive cleanup attempt. stop() handles final cleanup.

                # Check common error codes related to permissions
                if e.returncode in [1, 4]:
                    raise PermissionError("Failed to configure iptables. Ensure running as root and iptables is installed/functional.")
                raise RuntimeError(f"Failed to configure iptables (Return code {e.returncode}).")
            # If deletion fails (rare due to the check), log a warning.
            elif action == 'D':
                print(f"[!] Warning: Failed to remove iptables rule (Return code {e.returncode}). Rule might need manual removal.")

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

        This method waits for the first packet to be intercepted, then waits for
        subsequent packets to be released (or a timeout), sleeps for `REORDER_DELAY`,
        and finally releases the held first packet.
        """

        # 1. Wait until the first packet is intercepted and held
        if not self.first_packet_held.wait(timeout=5):
            if self.active:
                print("[!] Timeout waiting for the first packet to be intercepted.")
            return

        # 2. Synchronization: Wait until subsequent packets are released first.
        if not self.subsequent_packets_released.wait(timeout=0.5):  # 500ms timeout
            # If timeout occurs, the entire payload likely fit in the first packet (smaller than MTU).
            if self.active:
                print("[*] Note: No subsequent packets detected. Payload likely smaller than MTU. Releasing immediately.")
        else:
            # 3. If subsequent packets were released, add the fixed delay.
            time.sleep(REORDER_DELAY)

        # 4. Release the first packet
        with self.lock:
            # B03 FIX: Check if active and info exists before releasing, ensuring queue is likely still bound.
            if self.first_packet_info and self.active:
                seq, pkt = self.first_packet_info
                try:
                    print(f"[*] Releasing First Packet (Seq: {seq})")
                    # Verdict the packet (Accept) so the OS sends it out (now out of order).
                    pkt.accept()
                except Exception as e:
                    # Handle potential errors if the packet already expired from the queue
                    print(f"[!] Error releasing first packet: {e}")
                self.first_packet_info = None