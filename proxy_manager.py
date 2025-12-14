# proxy_manager.py

"""
Proxy Manager with Full RFC 9000 QUIC (HTTP/3) Implementation.

Acts as the unified logging source and orchestrator for:
1. TCP H1/H2 Proxy (via proxy_core.py)
2. UDP H3/QUIC Proxy (Native Implementation)

Features:
- RFC 9000 Packet Parsing (Long/Short, Version Negotiation)
- VarInt Decoding
- Frame Inspection (STREAM, ACK, CRYPTO, HTTP/3 Frames)
- Robust Error Handling for Malformed Frames
"""

import asyncio
import logging
import socket
import struct
import binascii
import sys
import proxy_core

# -- Configuration --
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ProxyManager")

# -----------------------------------------------------------------------------
# 1. QUIC RFC 9000 Constants & Utilities
# -----------------------------------------------------------------------------

# Packet Types (Long Header) - RFC 9000 Section 17.2
QUIC_TYPE_INITIAL = 0x0
QUIC_TYPE_0RTT = 0x1
QUIC_TYPE_HANDSHAKE = 0x2
QUIC_TYPE_RETRY = 0x3

# Frame Types - RFC 9000 Section 12.4
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02 # Range 0x02-0x03
FRAME_RESET_STREAM = 0x04
FRAME_STOP_SENDING = 0x05
FRAME_CRYPTO = 0x06
FRAME_NEW_TOKEN = 0x07
FRAME_STREAM = 0x08 # Range 0x08-0x0f (bits indicate OFF, LEN, FIN)
FRAME_MAX_DATA = 0x10
FRAME_MAX_STREAM_DATA = 0x11
FRAME_MAX_STREAMS = 0x12 # 0x12-0x13
FRAME_DATA_BLOCKED = 0x14
FRAME_STREAM_DATA_BLOCKED = 0x15
FRAME_STREAMS_BLOCKED = 0x16 # 0x16-0x17
FRAME_NEW_CONNECTION_ID = 0x18
FRAME_RETIRE_CONNECTION_ID = 0x19
FRAME_PATH_CHALLENGE = 0x1a
FRAME_PATH_RESPONSE = 0x1b
FRAME_CONNECTION_CLOSE = 0x1c # 0x1c-0x1d
FRAME_HANDSHAKE_DONE = 0x1e

# HTTP/3 Frame Types - RFC 9114 Section 7.2
H3_FRAME_DATA = 0x00
H3_FRAME_HEADERS = 0x01
H3_FRAME_CANCEL_PUSH = 0x03
H3_FRAME_SETTINGS = 0x04
H3_FRAME_PUSH_PROMISE = 0x05
H3_FRAME_GOAWAY = 0x07
H3_FRAME_MAX_PUSH_ID = 0x0D

# RFC 9114 & QPACK Defined Settings
H3_SETTINGS_MAP = {
    0x01: "QPACK_MAX_TABLE_CAPACITY",
    0x06: "MAX_FIELD_SECTION_SIZE",
    0x07: "QPACK_BLOCKED_STREAMS",
    0x08: "ENABLE_CONNECT_PROTOCOL",
    0x09: "H3_DATAGRAM",
    # 0x2, 0x3, 0x4, 0x5 are reserved/forbidden
}

# Variable-Length Integer Decoding (RFC 9000 Section 16)
def decode_varint(data, offset):
    if offset >= len(data): return None, offset
    first = data[offset]
    prefix = first >> 6
    length = 1 << prefix
    
    if offset + length > len(data): return None, offset
    
    val = first & 0x3f
    for i in range(1, length):
        val = (val << 8) + data[offset + i]
    
    return val, offset + length

def get_varint_len(first_byte):
    return 1 << (first_byte >> 6)

# -----------------------------------------------------------------------------
# 2. RFC 9000 & 9114 Parsers
# -----------------------------------------------------------------------------

class QuicFrameParser:
    """Parses QUIC Transport Frames from a decrypted payload."""
    
    @staticmethod
    def parse_frames(payload):
        frames = []
        offset = 0
        limit = len(payload)
        
        while offset < limit:
            try:
                ftype = payload[offset]
                
                # PADDING (0x00)
                if ftype == FRAME_PADDING:
                    frames.append({"type": "PADDING"})
                    offset += 1
                    while offset < limit and payload[offset] == 0x00:
                        offset += 1 # Skip coalesced padding
                    continue
                
                # PING (0x01)
                if ftype == FRAME_PING:
                    frames.append({"type": "PING"})
                    offset += 1
                    continue
                
                # ACK (0x02, 0x03)
                if 0x02 <= ftype <= 0x03:
                    offset += 1
                    largest_acked, offset = decode_varint(payload, offset)
                    ack_delay, offset = decode_varint(payload, offset)
                    ack_range_count, offset = decode_varint(payload, offset)
                    
                    if largest_acked is None or ack_range_count is None:
                        raise ValueError("Truncated ACK Frame")

                    # Skip ranges (simplified)
                    first_ack_range, offset = decode_varint(payload, offset)
                    for _ in range(ack_range_count):
                        gap, offset = decode_varint(payload, offset)
                        ack_len, offset = decode_varint(payload, offset)
                    frames.append({"type": "ACK", "largest": largest_acked})
                    continue

                # CRYPTO (0x06)
                if ftype == FRAME_CRYPTO:
                    offset += 1
                    c_offset, offset = decode_varint(payload, offset)
                    c_len, offset = decode_varint(payload, offset)
                    
                    if c_len is None or offset + c_len > limit:
                        raise ValueError("Truncated CRYPTO Frame")
                    
                    offset += c_len # Skip data
                    frames.append({"type": "CRYPTO", "len": c_len, "offset": c_offset})
                    continue
                
                # STREAM (0x08 - 0x0f)
                if 0x08 <= ftype <= 0x0f:
                    off_bit = ftype & 0x04
                    len_bit = ftype & 0x02
                    fin_bit = ftype & 0x01
                    
                    offset += 1
                    stream_id, offset = decode_varint(payload, offset)
                    if stream_id is None:
                         raise ValueError("Truncated STREAM ID")
                    
                    data_offset = 0
                    if off_bit:
                        data_offset, offset = decode_varint(payload, offset)
                        if data_offset is None:
                            raise ValueError("Truncated STREAM Offset")
                    
                    length = 0
                    if len_bit:
                        length, offset = decode_varint(payload, offset)
                        if length is None: raise ValueError("Truncated STREAM Length")
                    else:
                        length = limit - offset # Consumes rest of packet
                    
                    if offset + length > limit:
                        raise ValueError("Truncated STREAM Data")

                    stream_data = payload[offset : offset + length]
                    offset += length
                    
                    frames.append({
                        "type": "STREAM", "id": stream_id, 
                        "fin": bool(fin_bit), "len": length, "data": stream_data
                    })
                    continue
                
                # NEW_CONNECTION_ID (0x18)
                if ftype == FRAME_NEW_CONNECTION_ID:
                    offset += 1
                    seq_num, offset = decode_varint(payload, offset)
                    retire_prior, offset = decode_varint(payload, offset)
                    
                    if seq_num is None or retire_prior is None:
                         raise ValueError("Truncated NEW_CONNECTION_ID Frame")

                    if offset >= limit:
                        raise ValueError("Truncated NEW_CONNECTION_ID Length")
                        
                    cid_len = payload[offset]
                    offset += 1
                    
                    if offset + cid_len + 16 > limit:
                        raise ValueError("Truncated NEW_CONNECTION_ID Payload")

                    cid = payload[offset : offset + cid_len]
                    offset += cid_len
                    # Stateless Reset Token is always 16 bytes
                    token = payload[offset : offset + 16]
                    offset += 16
                    
                    frames.append({
                        "type": "NEW_CONNECTION_ID",
                        "seq": seq_num,
                        "retire_prior": retire_prior,
                        "cid": binascii.hexlify(cid).decode()
                    })
                    continue

                # CONNECTION_CLOSE (0x1c, 0x1d)
                if ftype == 0x1c or ftype == 0x1d:
                    offset += 1
                    error_code, offset = decode_varint(payload, offset)
                    reason_len, offset = decode_varint(payload, offset)
                    
                    if error_code is None or reason_len is None or offset + reason_len > limit:
                         raise ValueError("Truncated CONNECTION_CLOSE Frame")
                         
                    reason = payload[offset : offset + reason_len]
                    offset += reason_len
                    frames.append({"type": "CONNECTION_CLOSE", "code": error_code, "reason": reason})
                    continue

                frames.append({"type": f"UNKNOWN_FRAME_0x{ftype:02x}"})
                break 
            
            except (IndexError, ValueError, struct.error) as e:
                # Catch malformed frames to prevent crash
                frames.append({
                    "type": "MALFORMED_FRAME", 
                    "error": str(e),
                    "offset_at_failure": offset
                })
                break
            
        return frames

class H3FrameParser:
    """Parses HTTP/3 Frames from a STREAM frame's data."""
    @staticmethod
    def parse(stream_data):
        h3_frames = []
        offset = 0
        limit = len(stream_data)
        
        while offset < limit:
            # 1. Decode Frame Type 
            ftype, next_off = decode_varint(stream_data, offset)
            if ftype is None: break 
            offset = next_off 

            # 2. Decode Frame Length
            length, next_off = decode_varint(stream_data, offset) 
            if length is None: break 
            offset = next_off

            # 3. Boundary Check (Prevents reading partial frames)
            if offset + length > limit: 
                needed = (offset + length) - limit
                h3_frames.append({"type": "INCOMPLETE", "needed": needed}) 
                break

            # 4. Extract Payload & Advance Main Offset
            payload = stream_data[offset : offset + length]
            offset += length

            info = {"raw_type": ftype, "len": length}

            # 5. Decode Frame-Specific Fields from 'payload'
            if ftype == H3_FRAME_GOAWAY:
                info["type"] = "GOAWAY"
                p_off = 0
                last_stream_id, p_off = decode_varint(payload, p_off)
                if last_stream_id is not None:
                    info["last_stream_id"] = last_stream_id
                    error_code, p_off = decode_varint(payload, p_off)
                    if error_code is not None:
                        info["error_code"] = error_code
                        # Rest of payload is the reason string
                        info["reason"] = payload[p_off:].decode('utf-8', errors='replace')

            elif ftype == H3_FRAME_MAX_PUSH_ID:
                info["type"] = "MAX_PUSH_ID"
                max_push_id, _ = decode_varint(payload, 0)
                if max_push_id is not None:
                    info["max_push_id"] = max_push_id

            elif ftype == H3_FRAME_HEADERS:
                info["type"] = "HEADERS"
                info["qpack_blob_len"] = len(payload)

            elif ftype == H3_FRAME_DATA:
                info["type"] = "DATA"
                info["snippet"] = payload[:20]

            elif ftype == H3_FRAME_SETTINGS:
                info["type"] = "SETTINGS"
                s_off = 0
                settings = {}
                
                while s_off < len(payload):
                    # Decode Key
                    s_id, s_off = decode_varint(payload, s_off)
                    if s_id is None: break
                    
                    # Decode Value
                    s_val, s_off = decode_varint(payload, s_off)
                    if s_val is None: break
                    
                    # 1. Check for Duplicates (Strict Mode)
                    # [FIX] Check against the key we are about to insert, not just the ID
                    readable_key = H3_SETTINGS_MAP.get(s_id, f"UNKNOWN_0x{s_id:x}")
                    if readable_key in settings:
                        info["error"] = f"Duplicate Setting ID: {s_id}"
                    
                    # 2. Store with readable name if possible
                    settings[readable_key] = s_val

                info["values"] = settings

            else:
                info["type"] = f"H3_FRAME_0x{ftype:x}"

            h3_frames.append(info)

        return h3_frames

class QuicPacketParser:
    """
    Parses RFC 9000 Packets (Unencrypted Headers).
    """
    
    def parse_packet(self, data):
        if len(data) < 1: return {"error": "Empty"}
        
        first = data[0]
        is_long = (first & 0x80) != 0
        fixed_bit = (first & 0x40) != 0
        
        info = {
            "header_form": "Long" if is_long else "Short",
            "fixed_bit": fixed_bit,
            "raw_len": len(data)
        }
        
        offset = 0
        if is_long:
            # -- Long Header --
            p_type = (first & 0x30) >> 4
            type_map = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
            info["type"] = type_map.get(p_type, "Unknown")
            
            offset += 1
            version = struct.unpack("!I", data[offset:offset+4])[0]
            info["version"] = hex(version)
            offset += 4

            if version == 0:
                info["type"] = "VersionNegotiation"
                return info
            
            dcid_len = data[offset]; offset += 1
            info["dcid"] = binascii.hexlify(data[offset : offset+dcid_len]).decode()
            offset += dcid_len
            
            scid_len = data[offset]; offset += 1
            info["scid"] = binascii.hexlify(data[offset : offset+scid_len]).decode()
            offset += scid_len
            
            if info["type"] == "Initial":
                token_len, offset = decode_varint(data, offset)
                offset += token_len
                
            payload_len, offset = decode_varint(data, offset)
            info["payload_len"] = payload_len
            info["payload_offset"] = offset

            # Note: Payload is encrypted in real traffic.
            # We skip parsing frames here unless keys are available.
            
        else:
            # -- Short Header (1-RTT) --
            info["type"] = "1-RTT"
            info["spin_bit"] = (first & 0x20) != 0
            info["key_phase"] = (first & 0x04) != 0
            
        return info

# -----------------------------------------------------------------------------
# 3. QUIC Server (UDP)
# -----------------------------------------------------------------------------

class QuicServer:
    def __init__(self, host, port, callback):
        self.host = host
        self.port = port
        self.callback = callback
        self.transport = None
        self.parser = QuicPacketParser()

    class UdpProtocol(asyncio.DatagramProtocol):
        def __init__(self, server_instance):
            self.server = server_instance
        
        def connection_made(self, transport):
            self.server.transport = transport
            
        def datagram_received(self, data, addr):
            # Parse RFC 9000 Packet
            parsed = self.server.parser.parse_packet(data)
            self.server.callback("QUIC", addr, parsed)

    async def start(self):
        loop = asyncio.get_running_loop()
        log.info(f"QUIC (H3) UDP Listener starting on {self.host}:{self.port}")
        await loop.create_datagram_endpoint(
            lambda: self.UdpProtocol(self),
            local_addr=(self.host, self.port)
        )

# -----------------------------------------------------------------------------
# 4. Main Manager Class
# -----------------------------------------------------------------------------

class ProxyManager:
    def __init__(self, tcp_port=8080, quic_port=4433, ssl_context_factory=None, external_callback=None):
        self.tcp_port = tcp_port
        self.quic_port = quic_port
        self.ssl_context_factory = ssl_context_factory
        self.external_callback = external_callback
        # Internal capture/logging callback
        self.quic_server = QuicServer("0.0.0.0", self.quic_port, self.unified_capture_callback)

    def unified_capture_callback(self, protocol, source, data=None):
        """
        The Unified Log Source.
        Received structured data from both H1/H2 (TCP) and H3 (QUIC) handlers.
        """
        # Forward data to external listeners (e.g. Racer UI)
        if self.external_callback:
            # For CAPTURE, 'data' is the object. For others, it might be None, so send source.
            payload = data if data else source
            self.external_callback(protocol, payload)

        # Handle cases where source is tuple (addr, port) or string (e.g., "SYSTEM")
        if isinstance(source, tuple):
            src_str = f"{source[0]}:{source[1]}"
        else:
            src_str = str(source)

        if protocol == "QUIC":
            # Formatted RFC 9000 Log
            # [FIXED] Resilience against non-dict data and missing keys
            if isinstance(data, dict):
                msg = f"Type: {data.get('type', 'UNK'):<10} | Ver: {data.get('version','N/A')} | DCID: {data.get('dcid','N/A')}"
                if 'payload_len' in data:
                    msg += f" | Len: {data['payload_len']}"
            else:
                msg = str(data)
            log.info(f"[QUIC] {src_str} -> {msg}")
            
        elif protocol == "CAPTURE":
            # data contains the CapturedRequest object
            req = data 
            if req:
                log.info(f"[{req.protocol}] {req.method} {req.url} (Body: {len(req.body)} bytes)")

        elif protocol == "SYSTEM":
            log.info(f"[SYSTEM] {src_str}")
        
        elif protocol == "ERROR":
            log.error(f"[ERROR] {src_str}: {data}")

    async def run(self, target_override=None, scope_regex=None):
        log.info("=== Starting Proxy Manager ===")
        
        scope_pattern = None
        if scope_regex:
            import re
            scope_pattern = re.compile(scope_regex)

        # 1. Start TCP (H1/H2) Proxy via proxy_core
        # We wrap the unified callback to adapt it to proxy_core's signature
        def core_adapter(level, msg):
            if level == "CAPTURE":
                # msg is CapturedRequest
                self.unified_capture_callback("CAPTURE", "TCP_CLIENT", msg)
            else:
                self.unified_capture_callback(level, "SYSTEM", msg)

        tcp_task = asyncio.create_task(
            proxy_core.start_proxy_server(
                "0.0.0.0", self.tcp_port, 
                core_adapter,
                target_override=target_override,
                scope_pattern=scope_pattern,
                ssl_context_factory=self.ssl_context_factory
            )
        )
        
        # 2. Start UDP (H3) Proxy
        await self.quic_server.start()
        
        # Keep running
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    manager = ProxyManager(tcp_port=8080, quic_port=4433)
    try:
        asyncio.run(manager.run())
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)