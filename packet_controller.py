#Filename: packet_controller.py
"""
[VECTOR] KERNEL INTERFACE
Manages Linux NetfilterQueue for 'First Sequence Sync' (Packet Bunching).
Strictly typed and refactored to use compat.py for robust imports.
"""

import sys
import threading
import time
import subprocess
import logging
import struct
import atexit
from typing import Optional, Tuple, Protocol, cast, Any

# [APEX] Use Compat Layer for safety
from compat import NFQUEUE_AVAILABLE, NetfilterQueue

logger = logging.getLogger(__name__)

# -- TCP/IP Constants --
REORDER_DELAY: float = 0.010  # 10ms
QUEUE_NUM: int = 99
IP_HEADER_MIN_LEN: int = 20
IP_VERSION_4: int = 4
PROTOCOL_TCP: int = 6

# Structs for binary parsing (Big Endian Network Order)
_STRUCT_H = struct.Struct("!H")  # Unsigned short (2 bytes)
_STRUCT_I = struct.Struct("!I")  # Unsigned int (4 bytes)

# -- Protocols --

class NFPacket(Protocol):
    """Protocol defining the interface of a NetfilterQueue packet."""
    def get_payload(self) -> bytes: ...
    def accept(self) -> None: ...
    def drop(self) -> None: ...
    def get_fd(self) -> int: ...


class PacketController:
    """
    Manages interception and reordering of TCP packets using NetfilterQueue.
    Uses nftables for modern rule management.
    """
    def __init__(self, target_ip: str, target_port: int, source_port: int):
        """
        Initializes the PacketController.
        """
        # Runtime safety check - warns but allows instantiation for testing
        if not NFQUEUE_AVAILABLE and 'unittest' not in sys.modules:
            logger.warning("Initializing PacketController without NetfilterQueue support.")

        self.target_ip: str = target_ip
        self.target_port: int = target_port
        self.source_port: int = source_port
        self.queue_num: int = QUEUE_NUM

        self.nfqueue: Optional[Any] = None 
        self.active: bool = False
        self.lock: threading.Lock = threading.Lock()

        self.listener_thread: Optional[threading.Thread] = None
        self.release_thread: Optional[threading.Thread] = None

        # State Tracking
        self.first_packet_info: Optional[Tuple[int, NFPacket]] = None
        self.expected_next_seq: Optional[int] = None

        self.first_packet_held: threading.Event = threading.Event()
        self.subsequent_packets_released: threading.Event = threading.Event()
        
        atexit.register(self.stop)

    def start(self) -> None:
        """
        Starts the packet interception.
        """
        if not NFQUEUE_AVAILABLE or NetfilterQueue is None:
            logger.error("NetfilterQueue unavailable. Cannot start interception.")
            return

        self._manage_nftables(action='add')
        
        try:
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self._queue_callback)
        except OSError as e:
            logger.error("Failed to bind NFQueue %s: %s", self.queue_num, e)            
            self._manage_nftables(action='delete')
             # Do not raise here to prevent crashing the main app, just log failure
            return
        
        self.active = True

        self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self.listener_thread.start()

        self.release_thread = threading.Thread(target=self._delayed_release, daemon=True)
        self.release_thread.start()

    def stop(self) -> None:
        """Stops interception and cleans up rules."""
        if not self.active:
            return
            
        self.active = False
        logger.info("Stopping PacketController...")

        with self.lock:
            if self.first_packet_info:
                try: 
                    self.first_packet_info[1].accept()
                except Exception: 
                    pass
                self.first_packet_info = None

        if self.nfqueue:
            try: 
                self.nfqueue.unbind()
            except Exception: 
                pass
            try:
                if hasattr(self.nfqueue, 'get_fd'): 
                    self.nfqueue.get_fd() 
            except Exception: 
                pass

        self._manage_nftables(action='delete')
        self.first_packet_held.set()
        self.subsequent_packets_released.set()

        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=1.0)
        if self.release_thread and self.release_thread.is_alive():
            self.release_thread.join(timeout=1.0)
        logger.info("PacketController stopped.")

    def _manage_nftables(self, action: str) -> None:
        table_name = "scalpel_racer_ctx"
        chain_name = "output_hook"
        
        if action == 'add':
            cmd_table = ['nft', 'add', 'table', 'ip', table_name]
            cmd_chain = [
                'nft', 'add', 'chain', 'ip', table_name, chain_name, 
                '{', 'type', 'filter', 'hook', 'output', 'priority', '0', ';', '}'
            ]
            
            rule_args = [
                'nft', 'add', 'rule', 'ip', table_name, chain_name,
                'ip', 'protocol', 'tcp', 'ip', 'daddr', self.target_ip,
                'tcp', 'dport', str(self.target_port)
            ]
            if self.source_port != 0:
                rule_args.extend(['tcp', 'sport', str(self.source_port)])
            
            rule_args.extend(['counter', 'queue', 'num', str(self.queue_num)])

            try:
                subprocess.run(
                    cmd_table, check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
                subprocess.run(
                    cmd_chain, check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
                subprocess.run(
                    rule_args, check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError: 
                logger.error("Failed to add nftables rule")
        elif action == 'delete':
            try: 
                subprocess.run(
                    ['nft', 'delete', 'table', 'ip', table_name], 
                    check=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except Exception: 
                pass

    def _listener_loop(self) -> None:
        while self.active and self.nfqueue:
            try: 
                self.nfqueue.run()
            except Exception: 
                pass
            time.sleep(0.1)

    def _queue_callback(self, pkt: Any) -> None:
        # Cast to protocol for type safety
        packet = cast(NFPacket, pkt)
        if not self.active: 
            packet.accept()
            return
        
        try:
            raw = packet.get_payload()
            if len(raw) < 40: 
                packet.accept()
                return
            
            ihl = (raw[0] & 0x0F) * 4
            total_len = _STRUCT_H.unpack_from(raw, 2)[0]
            tcp_start = ihl
            seq = _STRUCT_I.unpack_from(raw, tcp_start + 4)[0]
            data_off = (raw[tcp_start + 12] >> 4) * 4
            payload_len = total_len - ihl - data_off

            if payload_len <= 0: 
                packet.accept()
                return

            with self.lock:
                if self.first_packet_info is None:
                    self.first_packet_info = (seq, packet)
                    self.expected_next_seq = seq + payload_len
                    self.first_packet_held.set()
                elif self.expected_next_seq is not None and seq == self.expected_next_seq:
                    packet.accept()
                    self.expected_next_seq += payload_len
                    self.subsequent_packets_released.set()
                else:
                    packet.accept()
        except Exception as e:
            logger.error("Error in queue callback: %s", e)
            packet.accept()

    def _delayed_release(self) -> None:
        while self.active:
            if not self.first_packet_held.wait(timeout=0.1): 
                continue
            
            if self.subsequent_packets_released.wait(timeout=5.0): 
                time.sleep(REORDER_DELAY)
            
            with self.lock:
                if self.first_packet_info:
                    try: 
                        self.first_packet_info[1].accept()
                    except Exception: 
                        pass
                    self.first_packet_info = None
                self.first_packet_held.clear()
                self.subsequent_packets_released.clear()
                self.expected_next_seq = None
