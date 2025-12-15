# packet_controller.py
"""
Implements the PacketController for the 'First Sequence Sync' strategy.
Uses Linux NetfilterQueue to hold the first packet of a burst.
Refined: High-performance raw packet parsing (no Scapy) and improved accuracy (no PSH flag reliance).
[OPTIMIZED] - Pre-compiled structs
            - unpack_from
"""

import os
import sys
import threading
import time
import subprocess
import logging
import struct
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Check for Linux-specific dependencies
NFQUEUE_AVAILABLE = False
if sys.platform.startswith("linux"):
    try:
        from netfilterqueue import NetfilterQueue
        NFQUEUE_AVAILABLE = True
    except ImportError:
        pass

# Constants
REORDER_DELAY = 0.010  # 10ms
QUEUE_NUM = 99

# Pre-compile struct formats
_STRUCT_H = struct.Struct("!H")
_STRUCT_I = struct.Struct("!I")

class PacketController:
    """
    Manages interception and reordering of TCP packets using NetfilterQueue.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int):
        # Validate dependencies unless we are in a test environment
        if not NFQUEUE_AVAILABLE and 'unittest' not in sys.modules and 'pytest' not in sys.modules:
             raise ImportError("NetfilterQueue is not available or supported on this system.")

        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port
        self.queue_num = QUEUE_NUM
        
        self.nfqueue = None
        self.active = False
        self.lock = threading.Lock()
        
        # State tracking
        self.first_packet_info: Optional[Tuple[int, object]] = None
        self.expected_next_seq: Optional[int] = None
        
        # Threads
        self.listener_thread: Optional[threading.Thread] = None
        self.release_thread: Optional[threading.Thread] = None
        
        # Events
        self.first_packet_held = threading.Event()
        self.subsequent_packets_released = threading.Event()

    def start(self):
        """
        Sets up iptables rules and starts the NFQueue listener.
        """
        logger.info(f"PacketController: Starting interception for {self.target_ip}:{self.target_port}")
        
        # 1. Insert iptables rule
        # Security: Use 'I' (Insert) to ensure this rule is at the top of the chain
        self._manage_iptables(action='I')
        
        # 2. Bind NetfilterQueue
        self.nfqueue = NetfilterQueue()
        try:
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError as e:
            # Cleanup if bind fails to prevent stuck rules
            self._manage_iptables(action='D')
            raise RuntimeError(f"Failed to bind NFQueue: {e}")

        # 3. Start Threads
        self.active = True
        
        self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self.listener_thread.start()
        
        self.release_thread = threading.Thread(target=self._delayed_release_first_packet, daemon=True)
        self.release_thread.start()

    def stop(self):
        """
        Stops the listener and cleans up.
        Robustness: Explicitly releases held packets (fail-open) to avoid blackholing traffic.
        """
        if not self.active:
            return
            
        self.active = False
        
        # Release any held packet
        with self.lock:
            if self.first_packet_info:
                try:
                    _, pkt = self.first_packet_info
                    pkt.accept()
                except Exception:
                    pass
                self.first_packet_info = None

        # Unbind queue
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except Exception:
                pass
        
        # Remove iptables rule
        self._manage_iptables(action='D')
        
        # Unblock any waiting threads
        self.first_packet_held.set()
        self.subsequent_packets_released.set()
        
        # Join threads
        if self.listener_thread:
            self.listener_thread.join(timeout=1)
        if self.release_thread:
            self.release_thread.join(timeout=1)

    def _manage_iptables(self, action: str):
        """
        Idempotent wrapper for iptables management.
        Refined: Removes strict PSH flag filtering to ensure we catch all data segments.
        Args:
            action: 'I' for Insert, 'D' for Delete.
        """
        base_rule = [
            'iptables', 'OUTPUT',
            '-p', 'tcp',
            '--dport', str(self.target_port),
            '--sport', str(self.source_port),
            '-d', self.target_ip,
            # RISK FIX: Removed '-m tcp --tcp-flags ALL PSH'
            # This ensures we catch the first packet even if TSO/GSO delayed the PSH flag.
            '-j', 'NFQUEUE', '--queue-num', str(self.queue_num)
        ]
        
        # Check if rule exists
        check_rule = base_rule.copy()
        check_rule.insert(1, '-C')
        
        try:
            subprocess.check_call(check_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            rule_exists = True
        except subprocess.CalledProcessError:
            rule_exists = False
        except FileNotFoundError:
            # Handle systems without iptables gracefully
            return 

        if (action == 'I' or action == 'A') and rule_exists:
            return
        if action == 'D' and not rule_exists:
            return

        # Execute action
        action_rule = base_rule.copy()
        action_rule.insert(1, f'-{action}')
        
        try:
            subprocess.check_call(action_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to modify iptables rule ({action}): {e}")

    def _listener_loop(self):
        """
        Main blocking loop for packet processing.
        """
        try:
            self.nfqueue.run()
        except Exception as e:
            if self.active:
                logger.error(f"NFQueue listener error: {e}")

    def _queue_callback(self, pkt):
        """
        Process intercepted packets.
        LATENCY FIX: Uses direct struct unpacking instead of Scapy.
        """
        if not self.active:
            pkt.accept()
            return
            
        try:
            # Optimization: Parse raw bytes directly
            raw_data = pkt.get_payload()
            
            # --- 1. Parse IPv4 Header ---
            if len(raw_data) < 20:
                pkt.accept()
                return

            # Byte 0: Version (4 bits) + IHL (4 bits)
            ver_ihl = raw_data[0]
            version = ver_ihl >> 4
            
            if version != 4:
                # We only handle IPv4 for this specific attack logic
                pkt.accept()
                return

            # IHL is in 32-bit words, so * 4 for bytes
            ihl = (ver_ihl & 0x0F) * 4
            
            # Protocol is at Byte 9
            protocol = raw_data[9]
            if protocol != 6: # 6 = TCP
                pkt.accept()
                return

            # Total Length is at Bytes 2-3
            # Use pre-compiled struct with unpack_from
            total_len = _STRUCT_H.unpack_from(raw_data, 2)[0]

            # --- 2. Parse TCP Header ---
            tcp_header_start = ihl
            if len(raw_data) < tcp_header_start + 20:
                pkt.accept()
                return

            # Sequence Number: Bytes 4-7 relative to TCP start
            # Use pre-compiled struct with unpack_from
            seq = _STRUCT_I.unpack_from(raw_data, tcp_header_start + 4)[0]
            
            # Data Offset: Byte 12, high 4 bits (in 32-bit words)
            data_offset_byte = raw_data[tcp_header_start + 12]
            tcp_header_len = (data_offset_byte >> 4) * 4
            
            # --- 3. Calculate Payload Length ---
            payload_len = total_len - ihl - tcp_header_len

            # Filter empty ACKs/SYN/FINs (No Data)
            if payload_len <= 0:
                pkt.accept()
                return

            # --- 4. Packet Bunching Logic ---
            with self.lock:
                if self.first_packet_info is None:
                    # Case 1: First Packet -> Hold it
                    self.first_packet_info = (seq, pkt)
                    self.expected_next_seq = seq + payload_len
                    self.first_packet_held.set()
                    return # Do not verdict (holds in queue)

                elif seq == self.expected_next_seq:
                    # Case 2: Subsequent Packet (Expected) -> Release immediately
                    pkt.accept()
                    self.expected_next_seq = seq + payload_len
                    
                    if not self.subsequent_packets_released.is_set():
                        self.subsequent_packets_released.set()
                    return

                else:
                    # Case 3: Retransmission or Out-of-order -> Let it pass
                    pkt.accept()
                    return

        except Exception as e:
            logger.error(f"Error in queue callback: {e}")
            pkt.accept()

    def _delayed_release_first_packet(self):
        """
        Waits for the sync condition, then releases the held packet.
        """
        # Wait for first packet to be caught
        if not self.first_packet_held.wait(timeout=5):
            return

        # Wait for subsequent packets (sync signal)
        if not self.subsequent_packets_released.wait(timeout=0.5):
            # Timeout implies single-packet payload; just proceed
            pass
        else:
            # Sync achieved: Wait specific delay to force reordering
            time.sleep(REORDER_DELAY)

        with self.lock:
            if self.first_packet_info and self.active:
                _, pkt = self.first_packet_info
                try:
                    pkt.accept()
                except Exception as e:
                    logger.error(f"Error releasing held packet: {e}")
                
                # Cleanup state
                self.first_packet_info = None
                self.first_packet_held.clear()
                self.subsequent_packets_released.clear()
                self.expected_next_seq = None
