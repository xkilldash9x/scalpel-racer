# packet_controller.py
"""
Implements the PacketController for the 'First Sequence Sync' strategy.
Uses Linux NetfilterQueue to hold the first packet of a burst.
"""

import os
import sys
import threading
import time
import subprocess
import socket
import logging
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)

# Check for Linux-specific dependencies
NFQUEUE_AVAILABLE = False
if sys.platform.startswith("linux"):
    try:
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP, TCP
        NFQUEUE_AVAILABLE = True
    except ImportError:
        pass

# Constants
REORDER_DELAY = 0.010  # 10ms
QUEUE_NUM = 99

class PacketController:
    """
    Manages interception and reordering of TCP packets using NetfilterQueue.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int):
        # Validate dependencies unless we are in a test environment
        if not NFQUEUE_AVAILABLE and 'unittest' not in sys.modules:
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
        self._manage_iptables(action='A')
        
        # 2. Bind NetfilterQueue
        self.nfqueue = NetfilterQueue()
        try:
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError as e:
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
        """
        if not self.active:
            return
            
        self.active = False
        
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
        Targets TCP packets with the PSH flag set.
        """
        base_rule = [
            'iptables', 'OUTPUT',
            '-p', 'tcp',
            '--dport', str(self.target_port),
            '--sport', str(self.source_port),
            '-d', self.target_ip,
            '-m', 'tcp', '--tcp-flags', 'ALL', 'PSH',
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
            # Handle systems without iptables gracefully-ish
            return 

        if action == 'A' and rule_exists:
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
        """
        if not self.active:
            pkt.accept()
            return
            
        try:
            # Parse Packet
            ip_packet = IP(pkt.get_payload())
            
            # Filter non-TCP
            if TCP not in ip_packet:
                pkt.accept()
                return
                
            tcp_segment = ip_packet[TCP]
            seq = tcp_segment.seq
            payload_len = len(tcp_segment.payload)

            # Filter empty ACKs/SYN/FINs
            if payload_len == 0:
                pkt.accept()
                return

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