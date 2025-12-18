# proxy_manager.py

"""
Proxy Manager with Full RFC 9000 QUIC (HTTP/3) Implementation.
[VECTOR] Optimized with bytearray buffers for efficient stream reassembly.
"""

import asyncio
import logging
import socket
import struct
import binascii
import sys
import os
import proxy_core
from typing import Optional, Dict, List, Any, Union, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ProxyManager")

H3_FRAME_DATA = 0x00
H3_FRAME_HEADERS = 0x01
H3_FRAME_SETTINGS = 0x04

HAS_AIOQUIC = False
try:
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived, HandshakeCompleted, ConnectionTerminated
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    HAS_AIOQUIC = True
except ImportError: pass

def decode_varint(buf: bytes, offset: int) -> Tuple[Optional[int], int]:
    if offset >= len(buf): return None, 1
    first = buf[offset]; prefix = first >> 6; length = 1 << prefix
    if offset + length > len(buf): return None, length
    val = first & 0x3F
    for i in range(1, length): val = (val << 8) + buf[offset + i]
    return val, length

class CapturedRequest:
    def __init__(self, protocol: str, method: str, url: str, headers: Any, body: bytes = b""):
        self.id = 0; self.protocol = protocol; self.method = method; self.url = url; self.headers = headers; self.body = body
    def __repr__(self) -> str: return f"<{self.protocol} {self.method} {self.url} ({len(self.body)} bytes)>"

class QuicPacketParser:
    def parse_packet(self, data: Union[bytes, memoryview]) -> Dict[str, Any]:
        if not isinstance(data, (bytes, memoryview)): return {"error": "Invalid Input Type"}
        if not isinstance(data, memoryview): data = memoryview(data)
        if len(data) < 1: return {"error": "Empty"}
        try:
            first = data[0]; is_long = (first & 0x80) != 0
            info = {"header_form": "Long" if is_long else "Short", "raw_len": len(data), "fixed_bit": (first & 0x40) != 0}
            if is_long:
                if len(data) < 5: return {"error": "Truncated Long Header"}
                version = struct.unpack_from("!I", data, 1)[0]
                info["version"] = hex(version)
                type_bits = (first >> 4) & 0x03
                type_map = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
                info["type"] = type_map.get(type_bits, "Unknown")
                if version == 0: info["type"] = "VersionNegotiation"
            else: info["type"] = "1-RTT"
            return info
        except Exception as e: return {"error": str(e)}

class QuicFrameParser:
    @staticmethod
    def parse_frames(payload: bytes) -> List[Dict[str, Any]]:
        frames = []; offset = 0
        while offset < len(payload):
            try:
                frame_type, len_bytes = decode_varint(payload, offset)
                if frame_type is None: frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Frame Type"}); break
                offset += len_bytes; frame = {"type_code": frame_type}
                if frame_type == 0x00:
                    if not (frames and frames[-1].get("type") == "PADDING"): frame["type"] = "PADDING"; frames.append(frame)
                elif frame_type == 0x01: frame["type"] = "PING"; frames.append(frame)
                elif frame_type == 0x02:
                    frame["type"] = "ACK"; largest, l_len = decode_varint(payload, offset)
                    if largest is None: frames.append({"type": "MALFORMED_FRAME", "error": "Truncated ACK Largest"}); break
                    offset += l_len; frame["largest"] = largest
                    _, d_len = decode_varint(payload, offset); offset += d_len
                    _, c_len = decode_varint(payload, offset); offset += c_len
                    _, g_len = decode_varint(payload, offset); offset += g_len
                    frames.append(frame)
                elif 0x08 <= frame_type <= 0x0f:
                    frame["type"] = "STREAM"; sid, sid_len = decode_varint(payload, offset)
                    if sid is None: frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Stream ID"}); break
                    offset += sid_len; frame["id"] = sid
                    has_off = (frame_type & 0x04) != 0; has_len = (frame_type & 0x02) != 0
                    if has_off: _, off_len = decode_varint(payload, offset); offset += off_len
                    if has_len: dl, dl_len = decode_varint(payload, offset); offset += dl_len; data_len = dl
                    else: data_len = len(payload) - offset
                    if offset + data_len > len(payload): frames.append({"type": "MALFORMED_FRAME", "error": "Truncated Data"}); break
                    frame["len"] = data_len; frame["data"] = payload[offset:offset+data_len]; offset += data_len; frames.append(frame)
                elif frame_type == 0x18:
                    frame["type"] = "NEW_CONNECTION_ID";
                    seq, s_len = decode_varint(payload, offset)
                    if seq is None: break
                    offset += s_len;
                    frame["seq"] = seq
                    frame["retire_prior"], r_len = decode_varint(payload, offset);
                    offset += r_len
                    if offset >= len(payload): break
                    cid_len = payload[offset];
                    offset += 1
                    if offset + cid_len > len(payload): break
                    frame["cid"] = binascii.hexlify(payload[offset:offset+cid_len]).decode();
                    offset += cid_len + 16
                    frames.append(frame)
                else: frame["type"] = f"UNKNOWN_0x{frame_type:02x}"; frames.append(frame); break
            except Exception as e: frames.append({"type": "MALFORMED_FRAME", "error": str(e)}); break
        return frames

class H3FrameParser:
    @staticmethod
    def parse(data: bytes) -> List[Dict[str, Any]]:
        frames = []; offset = 0
        while offset < len(data):
            try:
                f_type, t_len = decode_varint(data, offset)
                if f_type is None: frames.append({"type": "INCOMPLETE", "needed": 1}); break
                offset += t_len
                f_len, l_len = decode_varint(data, offset)
                if f_len is None: frames.append({"type": "INCOMPLETE", "needed": 1}); break
                offset += l_len
                if offset + f_len > len(data): frames.append({"type": "INCOMPLETE", "needed": (offset + f_len) - len(data)}); break
                payload = data[offset:offset+f_len]; offset += f_len; frame = {"len": f_len}
                if f_type == H3_FRAME_DATA: frame["type"] = "DATA"; frame["payload"] = payload
                elif f_type == H3_FRAME_HEADERS: frame["type"] = "HEADERS"; frame["qpack_blob_len"] = len(payload)
                elif f_type == H3_FRAME_SETTINGS:
                    frame["type"] = "SETTINGS"; values = {}; p_off = 0; seen_ids = set()
                    while p_off < len(payload):
                        sid, s_len = decode_varint(payload, p_off); p_off += s_len
                        sval, v_len = decode_varint(payload, p_off); p_off += v_len
                        if sid in seen_ids: frame["error"] = f"Duplicate Setting ID: {sid}"
                        seen_ids.add(sid)
                        key_map = {0x01: "QPACK_MAX_TABLE_CAPACITY", 0x06: "MAX_FIELD_SECTION_SIZE"}
                        values[key_map.get(sid, f"UNK_{sid}")] = sval
                    frame["values"] = values
                else: frame["type"] = f"H3_FRAME_0x{f_type:02x}"
                frames.append(frame)
            except Exception as e: frames.append({"type": "MALFORMED", "error": str(e)}); break
        return frames

if HAS_AIOQUIC:
    class QuicInterceptor(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3_conn = H3Connection(self._quic)
            self.callback: Optional[callable] = None
            self._stream_buffers: Dict[int, Dict[str, Any]] = {}

        def connection_made(self, transport: asyncio.BaseTransport):
            super().connection_made(transport)
            sock = transport.get_extra_info('socket')
            if sock:
                try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except Exception as e: log.debug(f"Could not set socket options: {e}")

        def quic_event_received(self, event: Any):
            if isinstance(event, StreamDataReceived): self._h3_conn.handle_event(event)
            for h3_event in self._h3_conn.handle_event(event): self._handle_h3_event(h3_event)

        def _handle_h3_event(self, event: Any):
            if isinstance(event, HeadersReceived): self._process_headers(event)
            elif isinstance(event, DataReceived): self._process_data(event)

        def _process_headers(self, event: HeadersReceived):
            stream_id = event.stream_id; headers = {}; method = ""; path = ""; authority = ""; scheme = "https"
            for name, value in event.headers:
                name_str = name.decode('utf-8'); val_str = value.decode('utf-8')
                if name_str == ":method": method = val_str
                elif name_str == ":path": path = val_str
                elif name_str == ":authority": authority = val_str
                elif name_str == ":scheme": scheme = val_str
                else: headers[name_str] = val_str
            self._stream_buffers[stream_id] = {
                "method": method, "url": f"{scheme}://{authority}{path}",
                "headers": headers, "body": bytearray(), "finished": event.stream_ended
            }
            if event.stream_ended: self._finalize_request(stream_id)

        def _process_data(self, event: DataReceived):
            if event.stream_id in self._stream_buffers:
                self._stream_buffers[event.stream_id]["body"].extend(event.data)
                if event.stream_ended: self._finalize_request(event.stream_id)

        def _finalize_request(self, stream_id: int):
            req_data = self._stream_buffers.pop(stream_id, None)
            if not req_data: return
            req_body = bytes(req_data['body'])
            req = CapturedRequest(protocol="HTTP/3", method=req_data['method'], url=req_data['url'], headers=req_data['headers'], body=req_body)
            if self.callback: self.callback("CAPTURE", req)
            response_headers = [(b":status", b"200"), (b"server", b"ProxyManager-H3-Interceptor"), (b"content-type", b"text/plain"), (b"content-length", str(len(req_body) + 50).encode('utf-8'))]
            self._h3_conn.send_headers(stream_id=stream_id, headers=response_headers)
            self._h3_conn.send_data(stream_id=stream_id, data=b"Proxy Intercepted HTTP/3 Request.\n\nOriginal Body:\n" + req_body, end_stream=True)
            self.transmit()

class QuicServer:
    def __init__(self, host: str, port: int, callback: callable, ssl_context_factory=None):
        self.host = host; self.port = port; self.callback = callback; self.ssl_context_factory = ssl_context_factory; self.parser = QuicPacketParser()

    class UdpFallbackProtocol(asyncio.DatagramProtocol):
        def __init__(self, server: 'QuicServer'): self.server = server
        def connection_made(self, transport):
            sock = transport.get_extra_info('socket')
            if sock:
                try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except: pass
        def datagram_received(self, data, addr):
            parsed = self.server.parser.parse_packet(data)
            self.server.callback("QUIC_RAW", addr, parsed)

    async def start(self):
        loop = asyncio.get_running_loop()
        log.info(f"QUIC (H3) UDP Listener starting on {self.host}:{self.port}")
        
        if HAS_AIOQUIC:
            log.info("AioQuic detected. Enabling full HTTP/3 Proxying.")
            configuration = QuicConfiguration(is_client=False)
            
            # [FIX] Load certs from the 'certs/' directory
            cert_path = os.path.join("certs", "server.crt")
            key_path = os.path.join("certs", "server.key")
            
            try: 
                configuration.load_cert_chain(cert_path, key_path)
            except Exception as e: 
                log.warning(f"Could not load QUIC certificates from '{cert_path}'/'{key_path}'. Error: {e}")
                log.warning("Please ensure you have run 'verify_certs.py' to generate the static listener certificates.")
                
            def create_protocol(*args, **kwargs):
                p = QuicInterceptor(*args, **kwargs); p.callback = self.callback; return p
            await serve(self.host, self.port, configuration=configuration, create_protocol=create_protocol)
        else:
            log.warning("CRITICAL: 'aioquic' not found. Falling back to packet sniffing.")
            await loop.create_datagram_endpoint(lambda: self.UdpFallbackProtocol(self), local_addr=(self.host, self.port))

class ProxyManager:
    def __init__(self, tcp_port=8080, quic_port=4433, ssl_context_factory=None, external_callback=None):
        self.tcp_port = tcp_port; self.quic_port = quic_port
        self.ssl_context_factory = ssl_context_factory; self.external_callback = external_callback
        self.count = 0; self.quic_server = QuicServer("0.0.0.0", self.quic_port, self.unified_capture_callback, ssl_context_factory)
        self.stop_event = asyncio.Event(); self.proxy_task = None

    def unified_capture_callback(self, protocol: str, source: Any, data: Any = None):
        type_ = protocol; payload = data if data is not None else source
        source_str = f"{source[0]}:{source[1]}" if isinstance(source, tuple) and len(source) == 2 else (str(source) if source else "<?>")
        
        if type_ == "CAPTURE" and hasattr(payload, 'id'):
            payload.id = self.count; self.count += 1
            log.info(f"[CAPTURE] #{payload.id} [{payload.protocol}] {payload.method} {payload.url}")
        elif type_ == "QUIC" or type_ == "QUIC_RAW": log.info(f"[{protocol}] {source_str} {str(data)}")
        elif type_ == "SYSTEM": log.info(f"[SYSTEM] {source_str if source != 'SYSTEM' else ''} {payload}")
        elif type_ == "ERROR": log.error(f"[ERROR] {source_str}: {payload}")
        if self.external_callback:
            try: self.external_callback(type_, payload)
            except Exception: pass

    async def run(self, target_override=None, scope_regex=None, strict_mode=True):
        log.info("=== Starting Proxy Manager ===")
        scope_pattern = None
        if scope_regex: import re; scope_pattern = re.compile(scope_regex)
        def core_adapter(level, msg):
            if level == "CAPTURE": self.unified_capture_callback("CAPTURE", "TCP_CLIENT", msg)
            else: self.unified_capture_callback(level, "SYSTEM", msg)
        self.proxy_task = asyncio.create_task(proxy_core.start_proxy_server(
                "0.0.0.0", self.tcp_port, core_adapter, target_override=target_override,
                scope_pattern=scope_pattern, ssl_context_factory=self.ssl_context_factory, strict_mode=strict_mode))
        await self.quic_server.start()
        try: await self.stop_event.wait()
        except asyncio.CancelledError: pass
        finally:
            if self.proxy_task: self.proxy_task.cancel(); await self.proxy_task

    def stop(self): self.stop_event.set()

if __name__ == "__main__":
    manager = ProxyManager(tcp_port=8080, quic_port=4433)
    try: asyncio.run(manager.run())
    except KeyboardInterrupt: log.info("Shutting down..."); sys.exit(0)