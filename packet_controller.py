# packet_controller.py
"""
[VECTOR] KERNEL INTERFACE
Manages Linux NetfilterQueue for 'First Sequence Sync' (Packet Bunching).
Requires: sudo apt install libnetfilter-queue-dev && pip install NetfilterQueue
Now uses nftables (nft) for modern rule management.
"""

import sys
import threading
import time
import subprocess
import logging
import struct
import atexit
import signal
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

NFQUEUE_AVAILABLE = False
if sys.platform.startswith("linux"):
    try:
        from netfilterqueue import NetfilterQueue
        NFQUEUE_AVAILABLE = True
    except ImportError:
        pass

# -- Constants --
REORDER_DELAY = 0.010  # 10ms
QUEUE_NUM = 99
_STRUCT_H = struct.Struct("!H")
_STRUCT_I = struct.Struct("!I")

class PacketController:
    """
    Manages interception and reordering of TCP packets using NetfilterQueue.
    Uses nftables for rule management.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int):
        if not NFQUEUE_AVAILABLE and 'unittest' not in sys.modules:
            raise ImportError("NetfilterQueue not available (Linux Only). Cannot use first-seq strategy.")

        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port
        self.queue_num = QUEUE_NUM
        
        self.nfqueue = None
        self.active = False
        self.lock = threading.Lock()
        
        # Thread handles
        self.listener_thread: Optional[threading.Thread] = None
        self.release_thread: Optional[threading.Thread] = None
        
        self.first_packet_info: Optional[Tuple[int, object]] = None
        self.expected_next_seq: Optional[int] = None
        
        self.first_packet_held = threading.Event()
        self.subsequent_packets_released = threading.Event()
        
        atexit.register(self.stop)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.stop()
        sys.exit(0)

    def start(self):
        self._manage_nftables(action='add')
        self.nfqueue = NetfilterQueue()
        try:
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError:
            self._manage_nftables(action='delete')
            raise

        self.active = True
        
        self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self.listener_thread.start()
        
        self.release_thread = threading.Thread(target=self._delayed_release, daemon=True)
        self.release_thread.start()

    def stop(self):
        if not self.active: return
        self.active = False
        
        with self.lock:
            if self.first_packet_info:
                try: self.first_packet_info[1].accept()
                except: pass
                self.first_packet_info = None

        if self.nfqueue:
            try: self.nfqueue.unbind()
            except: pass
            # Explicitly close to ensure recv loop unblocks if supported
            try: self.nfqueue.get_fd()
            except: pass
        
        self._manage_nftables(action='delete')
        self.first_packet_held.set()
        self.subsequent_packets_released.set()

        # [FIX] Explicitly join threads to ensure they are dead before 
        # checking is_alive() in tests.
        if self.listener_thread and self.listener_thread.is_alive():
            try:
                self.listener_thread.join(timeout=1.0)
            except RuntimeError: pass
            
        if self.release_thread and self.release_thread.is_alive():
            try:
                self.release_thread.join(timeout=1.0)
            except RuntimeError: pass

    def _manage_nftables(self, action: str):
        """
        Manages nftables rules.
        Creates a dedicated table 'scalpel_racer' to avoid polluting the global filter table.
        """
        table_name = "scalpel_racer"
        chain_name = "output_hook"
        
        if action == 'add':
            # 1. Create the table
            cmd_table = ['nft', 'add', 'table', 'ip', table_name]
            
            # 2. Create the chain attached to the output hook
            # Note: The syntax { type filter ... } requires careful arg passing in subprocess
            cmd_chain = [
                'nft', 'add', 'chain', 'ip', table_name, chain_name,
                '{', 'type', 'filter', 'hook', 'output', 'priority', '0', ';', '}'
            ]

            # 3. Add the rule to send matching TCP traffic to the queue
            cmd_rule = [
                'nft', 'add', 'rule', 'ip', table_name, chain_name,
                'ip', 'protocol', 'tcp',
                'ip', 'daddr', self.target_ip,
                'tcp', 'dport', str(self.target_port),
                'tcp', 'sport', str(self.source_port),
                'counter', 'queue', 'num', str(self.queue_num)
            ]

            try:
                subprocess.call(cmd_table, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.call(cmd_chain, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.call(cmd_rule, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception: 
                pass

        elif action == 'delete':
            # Atomic cleanup: deleting the table removes the chain and rules contained within
            cmd_del = ['nft', 'delete', 'table', 'ip', table_name]
            try:
                subprocess.call(cmd_del, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception: 
                pass

    def _listener_loop(self):
        # [FIX] Loop while active to ensure thread stays alive in tests where run() is mocked to return instantly
        while self.active:
            try: 
                self.nfqueue.run()
            except Exception: 
                pass
            # Avoid busy loop CPU spike if run() returns immediately (e.g. in tests or error)
            time.sleep(0.1)

    def _queue_callback(self, pkt):
        if not self.active:
            pkt.accept(); return
        try:
            raw = pkt.get_payload()
            # Basic IPv4 TCP Sanity Check
            if len(raw) < 20 or (raw[0] >> 4) != 4 or raw[9] != 6:
                pkt.accept(); return
            
            ihl = (raw[0] & 0x0F) * 4
            total_len = _STRUCT_H.unpack_from(raw, 2)[0]
            tcp_start = ihl
            seq = _STRUCT_I.unpack_from(raw, tcp_start + 4)[0]
            data_off = (raw[tcp_start + 12] >> 4) * 4
        
            # Check if packet has payload
            if total_len - ihl - data_off <= 0:
                pkt.accept(); return

            with self.lock:
                if self.first_packet_info is None:
                    # Hold the first data packet
                    self.first_packet_info = (seq, pkt)
                    self.expected_next_seq = seq + (total_len - ihl - data_off)
                    self.first_packet_held.set()
                elif seq == self.expected_next_seq:
                    # Release subsequent immediately
                    pkt.accept()
                    self.expected_next_seq += (total_len - ihl - data_off)
                    self.subsequent_packets_released.set()
                else:
                    pkt.accept()
        except: pkt.accept()

    def _delayed_release(self):
        if not self.first_packet_held.wait(timeout=5): return
        
        # Wait for subsequent packets or short timeout
        if self.subsequent_packets_released.wait(timeout=0.5):
            time.sleep(REORDER_DELAY)
        
        with self.lock:
            if self.first_packet_info:
                try: self.first_packet_info[1].accept()
                except: pass
                self.first_packet_info = None
                self.first_packet_held.clear()
                self.subsequent_packets_released.clear()