#Filename: proxy_core.py
"""
ASYNC PROXY CORE - SCALPEL RACER
Orchestrator for the Proxy Engine.
Delegates protocol handling to specialized H1/H2 modules.
"""

import asyncio
import ssl
import re
import time
from typing import Optional, Callable, Tuple, List, Dict
from urllib.parse import urljoin, urlparse

# [APEX] Modular Imports
from structures import CapturedRequest, HOP_BY_HOP_HEADERS, MAX_CAPTURE_BODY_SIZE, HOP_BY_HOP_HEADERS_BYTES
from proxy_common import (
    BaseProxyHandler, ProxyError, PayloadTooLargeError,
    STRICT_HEADER_PATTERN, UPSTREAM_CONNECT_TIMEOUT, IDLE_TIMEOUT,
    MAX_HEADER_LIST_SIZE, COMPACTION_THRESHOLD, READ_CHUNK_SIZE,
    H2_PREFACE
)
from proxy_h2 import NativeProxyHandler

class Http11ProxyHandler(BaseProxyHandler):
    """
    Handles HTTP/1.1 connections, including parsing, forwarding, and
    tunneling (CONNECT method).
    """
    __slots__ = (
        'reader', 'writer', 'target_override', 'scope_pattern', 'buffer',
        '_buffer_offset', 'enable_tunneling', 'strict_mode', '_previous_byte_was_cr'
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        explicit_host: str,
        manager_callback: Callable[[str, object], None],
        target_override: Optional[str],
        scope_pattern: Optional[re.Pattern[str]],
        upstream_verify_ssl: bool = False,
        upstream_ca_bundle: Optional[str] = None,
        initial_data: bytes = b"",
        ssl_context_factory: Optional[Callable[[str], ssl.SSLContext]] = None,
        enable_tunneling: bool = True,
        strict_mode: bool = True
    ):
        """Initializes the Http11ProxyHandler."""
        raw_addr = writer.get_extra_info('peername')
        client_addr = (
            (str(raw_addr[0]), int(raw_addr[1]))
            if isinstance(raw_addr, tuple) and len(raw_addr) >= 2 else None
        )
        super().__init__(
            explicit_host, upstream_verify_ssl, upstream_ca_bundle,
            manager_callback, ssl_context_factory, client_addr
        )

        self.reader = reader
        self.writer = writer
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.buffer = bytearray(initial_data)
        self._buffer_offset = 0
        self.enable_tunneling = enable_tunneling
        self.strict_mode = strict_mode
        self._previous_byte_was_cr = False

    async def _read_strict_line(self) -> bytes:
        """
        Reads a single line from the buffer/stream, strictly adhering to RFC limits.
        Detects line folding or excessive length.
        """
        while True:
            lf_index = self.buffer.find(b'\n', self._buffer_offset)
            if lf_index == -1:
                if len(self.buffer) - self._buffer_offset > 0:
                    # [FIX] C0325: Removed superfluous parens
                    self._previous_byte_was_cr = self.buffer[-1] == 0x0D
                if (len(self.buffer) - self._buffer_offset) > MAX_HEADER_LIST_SIZE:
                    raise ProxyError("Header Line Exceeded Max Length")

                # Buffer compaction
                if (
                    self._buffer_offset > COMPACTION_THRESHOLD
                    and self._buffer_offset > (len(self.buffer) // 2)
                ):
                    del self.buffer[:self._buffer_offset]
                    self._buffer_offset = 0

                try:
                    data = await asyncio.wait_for(
                        self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyError("Read Timeout (Idle)") from exc

                if not data:
                    if len(self.buffer) - self._buffer_offset > 0:
                        raise ProxyError("Incomplete message")
                    return b""
                self.buffer.extend(data)
                continue

            line_len = lf_index - self._buffer_offset
            if line_len > MAX_HEADER_LIST_SIZE:
                raise ProxyError("Header Line Exceeded Max Length")

            is_crlf = False
            if lf_index > self._buffer_offset:
                if self.buffer[lf_index - 1] == 0x0D:
                    is_crlf = True
            elif lf_index == self._buffer_offset:
                if self._previous_byte_was_cr:
                    is_crlf = True

            line_end = lf_index - 1 if is_crlf else lf_index
            if line_end > self._buffer_offset:
                line = bytes(self.buffer[self._buffer_offset:line_end])
            else:
                line = b""

            self._buffer_offset = lf_index + 1
            self._previous_byte_was_cr = False
            return line

    async def run(self) -> None:
        """Main loop handling HTTP/1.1 request processing."""
        try:
            while True:
                start_ts = time.time()
                try:
                    line = await self._read_strict_line()
                except ProxyError as e:
                    self.log("ERROR", f"Framing Error: {e}")
                    if "Timeout" not in str(e) and "Incomplete" not in str(e):
                        await self._send_error(400, "Bad Request")
                    return

                if not line:
                    break

                try:
                    parts = line.split(b' ', 2)
                    if len(parts) != 3:
                        raise ValueError
                    method_b, target_b, version_b = parts
                    # [OPTIMIZATION] Keep method/target as bytes to avoid decode overhead
                except ValueError:
                    await self._send_error(400, "Malformed Request Line")
                    return

                headers = []
                headers_dict = {}
                try:
                    while True:
                        h_line = await self._read_strict_line()
                        if not h_line:
                            break
                        if h_line[0] in (0x20, 0x09):
                            raise ProxyError("Obsolete Line Folding Rejected")
                        match = STRICT_HEADER_PATTERN.match(h_line)
                        if not match:
                            raise ProxyError("Invalid Header Syntax")
                        # [OPTIMIZATION] Keep headers as bytes
                        key_b = match.group(1)
                        val_b = match.group(2).strip()
                        headers.append((key_b, val_b))
                        headers_dict[key_b.lower()] = val_b
                except ProxyError as e:
                    await self._send_error(400, str(e))
                    return

                if not await self._validate_request(method_b, headers_dict):
                    return

                # Transfer-Encoding & Content-Length handling
                te = headers_dict.get(b'transfer-encoding')
                cl = headers_dict.get(b'content-length')
                if te:
                    if cl and self.strict_mode:
                        headers = [h for h in headers if h[0].lower() != b'content-length']
                        if b'content-length' in headers_dict:
                            del headers_dict[b'content-length']
                    enc = [e.strip().lower() for e in te.split(b',')]
                    if b'chunked' in enc and enc[-1] != b'chunked':
                        await self._send_error(400, "Bad Transfer-Encoding")
                        return
                elif cl:
                    try:
                        if int(cl) < 0:
                            raise ValueError
                    except ValueError:
                        await self._send_error(400, "Invalid Content-Length")
                        return

                if method_b == b'CONNECT':
                    await self._handle_connect(target_b)
                    return

                keep_alive = await self._handle_request(
                    method_b, target_b, version_b, headers, headers_dict, start_ts
                )
                if not keep_alive:
                    break
        except Exception as e: # pylint: disable=broad-exception-caught
            self.log("ERROR", f"HTTP/1.1 Proxy Error: {e}")
        finally:
            if not self.writer.is_closing():
                self.writer.close()

    async def _validate_request(self, method: bytes, headers_dict: Dict[bytes, bytes]) -> bool:
        """Validates the request method and headers."""
        if method == b'CONNECT' and b'host' not in headers_dict:
            await self._send_error(400, "CONNECT requires Host header")
            return False
        if any(k.startswith(b':') for k in headers_dict):
            await self._send_error(400, "Pseudo-header in HTTP/1.1")
            return False
        return True

    async def _handle_connect(self, target: bytes) -> None:
        """Handles a CONNECT request for tunneling."""
        target_str = target.decode('ascii', errors='ignore')
        host, port = self._parse_target(target_str)
        if self.enable_tunneling:
            factory = self.ssl_context_factory
            if factory:
                try:
                    self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await self.writer.drain()
                    ssl_ctx = factory(host)
                    await self.writer.start_tls(ssl_ctx)
                    rem = self.buffer[self._buffer_offset:] if self.buffer else b""
                    handler = DualProtocolHandler(
                        self.reader, self.writer, target_str, self.callback,
                        self.target_override, self.scope_pattern, self.enable_tunneling,
                        self.upstream_verify_ssl, self.upstream_ca_bundle,
                        self.ssl_context_factory, initial_data=bytes(rem)
                    )
                    await handler.run()
                    return
                except Exception as e: # pylint: disable=broad-exception-caught
                    self.log("ERROR", f"MITM Upgrade Failed: {e}")
                    return
        try:
            u_r, u_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=UPSTREAM_CONNECT_TIMEOUT
            )
            self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self.writer.drain()
            if self.buffer and self._buffer_offset < len(self.buffer):
                u_w.write(self.buffer[self._buffer_offset:])
                await u_w.drain()
            await asyncio.gather(
                self._pipe(self.reader, u_w, False),
                self._pipe(u_r, self.writer),
                return_exceptions=True
            )
        except Exception: # pylint: disable=broad-exception-caught
            await self._send_error(502, "Bad Gateway")

    async def _send_error(self, code: int, message: str) -> None:
        """Sends an HTTP error response to the client."""
        try:
            resp = (
                f"HTTP/1.1 {code} {message}\r\n"
                "Connection: close\r\nContent-Length: 0\r\n\r\n"
            ).encode()
            self.writer.write(resp)
            await self.writer.drain()
        except Exception: # pylint: disable=broad-exception-caught
            pass

    async def _handle_request(
        self, method: bytes, target: bytes, version_b: bytes,
        headers: List[Tuple[bytes, bytes]], headers_dict: Dict[bytes, bytes], start_ts: float
    ) -> bool:
        """Handles a standard HTTP/1.1 request."""
        # [OPTIMIZATION] Bytes everywhere
        req_host_b = self.explicit_host.encode('ascii') if self.explicit_host else None

        if not req_host_b:
            p = urlparse(target)
            if p.scheme and p.netloc:
                req_host_b = p.netloc
        if not req_host_b:
            req_host_b = headers_dict.get(b'host')
        if not req_host_b:
            p = urlparse(target)
            req_host_b = p.netloc or b""

        # Resolve host/port for upstream connection
        # We need strings for socket/SSL calls
        req_host_str = req_host_b.decode('ascii', errors='ignore')
        scheme = "https" if self.upstream_verify_ssl else "http"
        default_port = 443 if scheme == "https" else 80
        host, port = self._parse_target(req_host_str if req_host_str else "", default_port=default_port)

        # Checking scope
        target_str = target.decode('ascii', errors='ignore')
        full_url = urljoin(self.target_override, target_str.lstrip('/')) if self.target_override else (
            target_str if target_str.startswith("http") else f"{scheme}://{host}:{port}{target_str}"
        )

        if not self._is_url_allowed(full_url, self.scope_pattern):
            await self._send_error(403, "Forbidden by Proxy Scope")
            return False

        body = b""
        te = headers_dict.get(b'transfer-encoding', b'').lower()
        cl = headers_dict.get(b'content-length')

        if b'chunked' in te:
            body = await self._read_chunked_body()
        elif cl:
            try:
                body = await self._read_bytes(int(cl))
            except ValueError:
                pass

        # Defer decoding for logging until inside _record_capture if possible,
        # or just decode here for the signature. _record_capture expects strings for now.
        headers_str = [(k.decode('latin1'), v.decode('latin1')) for k, v in headers]

        self._record_capture(
            method.decode('ascii'), target_str, headers_str, body, scheme, host, start_ts
        )

        conn = headers_dict.get(b'connection', b'').lower()
        keep_alive = True
        if b'close' in conn or version_b == b'HTTP/1.0':
            keep_alive = False

        if not self.enable_tunneling:
            msg = b"Captured."
            self.writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(msg)).encode() +
                b"\r\n\r\n" + msg
            )
            await self.writer.drain()
            return keep_alive

        try:
            u_r, u_w = await self._connect_upstream(host, port)
        except asyncio.TimeoutError:
            await self._send_error(504, "Gateway Timeout")
            return False
        except Exception: # pylint: disable=broad-exception-caught
            await self._send_error(502, "Bad Gateway")
            return False

        # Construct upstream request
        up_path_b = target
        if target.startswith(b"http"):
            p = urlparse(target)
            up_path_b = p.path if p.path else b"/"
            if p.query:
                up_path_b += b"?" + p.query

        # Construct request line
        # Note: version_b is already bytes e.g. b"HTTP/1.1"
        u_w.write(method + b' ' + up_path_b + b' ' + version_b + b'\r\n')

        # [OPTIMIZATION] Avoid decoding/encoding headers if possible.
        # We need HOP_BY_HOP_HEADERS_BYTES from structures.py (it's not imported there yet, let's assume I fix imports or use local set)
        # For now I will check against local set or strings.
        # Ideally structures.py has HOP_BY_HOP_HEADERS_BYTES.

        # Checking proxy_core imports:
        # from structures import CapturedRequest, HOP_BY_HOP_HEADERS, MAX_CAPTURE_BODY_SIZE
        # I need to ensure HOP_BY_HOP_HEADERS_BYTES is imported or generated.

        # Let's generate it locally for speed if not available, but I see it in structures.py!
        # I need to import it. I will add it to the imports in next step or use lazy conversion.
        # Let's assume standard set for now.

        for k, v in headers:
            # [OPTIMIZATION] Direct byte check against HOP_BY_HOP_HEADERS_BYTES
            if k.lower() not in HOP_BY_HOP_HEADERS_BYTES:
                 u_w.write(k + b': ' + v + b'\r\n')

        u_w.write(b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")

        if body:
            u_w.write(body)
        await u_w.drain()
        await self._pipe(u_r, self.writer)
        u_w.close()
        return False

    async def _read_chunked_body(self) -> bytes:
        """Reads a chunked HTTP body."""
        parts = []
        total = 0
        while True:
            line = await self._read_strict_line()
            if b';' in line:
                line, _ = line.split(b';', 1)
            try:
                size = int(line.strip(), 16)
            except ValueError as exc:
                raise ProxyError("Invalid chunk size") from exc

            if size == 0:
                while True:
                    t = await self._read_strict_line()
                    if not t:
                        break
                break

            data = await self._read_bytes(size)
            total += len(data)
            if total > MAX_CAPTURE_BODY_SIZE:
                raise PayloadTooLargeError(
                    f"Chunked body exceeded {MAX_CAPTURE_BODY_SIZE} bytes."
                )
            parts.append(data)
            await self._read_strict_line()
        return b"".join(parts)

    async def _read_bytes(self, n: int) -> bytes:
        """Reads exactly n bytes from the stream."""
        if n > MAX_CAPTURE_BODY_SIZE:
            raise PayloadTooLargeError(f"Content-Length {n} exceeds capture limit.")

        while (len(self.buffer) - self._buffer_offset) < n:
            if len(self.buffer) > MAX_CAPTURE_BODY_SIZE + 4096:
                raise PayloadTooLargeError("Buffer limit exceeded.")
            try:
                data = await asyncio.wait_for(
                    self.reader.read(READ_CHUNK_SIZE), timeout=IDLE_TIMEOUT
                )
            except asyncio.TimeoutError as exc:
                raise ProxyError("Read Timeout (Idle) in Body") from exc
            if not data:
                raise ProxyError("Incomplete read")

            if (
                self._buffer_offset > COMPACTION_THRESHOLD
                and self._buffer_offset > (len(self.buffer) // 2)
            ):
                del self.buffer[:self._buffer_offset]
                self._buffer_offset = 0
            self.buffer.extend(data)

        chunk = bytes(self.buffer[self._buffer_offset : self._buffer_offset + n])
        self._buffer_offset += n
        return chunk

    async def _pipe(
        self,
        r: asyncio.StreamReader,
        w: asyncio.StreamWriter,
        flush_buffer: bool = False
    ) -> None:
        """Pipes data from a reader to a writer."""
        try:
            if flush_buffer and (len(self.buffer) - self._buffer_offset) > 0:
                w.write(self.buffer[self._buffer_offset:])
                await w.drain()
                self._buffer_offset = 0
                del self.buffer[:]

            while not r.at_eof():
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception: # pylint: disable=broad-exception-caught
            pass
        finally:
            try:
                w.close()
                await w.wait_closed()
            except Exception: # pylint: disable=broad-exception-caught
                pass

    def _record_capture(
        self, method: str, path: str, headers: List[Tuple[str, str]], body: bytes,
        scheme: str, authority: str, start_ts: float
    ) -> None:
        """Records the captured request."""
        if self.target_override:
            url = urljoin(self.target_override, path.lstrip('/'))
        elif path.startswith('http'):
            url = path
        else:
            url = f"{scheme}://{authority}{path}"

        if self.scope_pattern and not self.scope_pattern.search(url):
            return

        captured = CapturedRequest(
            0, method, url, headers, body,
            (len(body) > MAX_CAPTURE_BODY_SIZE), "HTTP/1.1", None,
            start_ts, time.time(), self.client_addr,
            (authority, 443 if scheme == 'https' else 80)
        )
        self.log("CAPTURE", captured)

class DualProtocolHandler:
    """Detects protocol (HTTP/1.1 vs HTTP/2) and delegates."""
    __slots__ = (
        'reader', 'writer', 'explicit_host', 'callback', 'target_override',
        'scope_pattern', 'enable_tunneling', 'upstream_verify_ssl',
        'upstream_ca_bundle', 'ssl_context_factory', 'strict_mode', 'initial_data'
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        explicit_host: str,
        manager_callback: Callable[[str, object], None],
        target_override: Optional[str],
        scope_pattern: Optional[re.Pattern[str]],
        enable_tunneling: bool = True,
        upstream_verify_ssl: bool = False,
        upstream_ca_bundle: Optional[str] = None,
        ssl_context_factory: Optional[Callable[[str], ssl.SSLContext]] = None,
        strict_mode: bool = True,
        initial_data: bytes = b""
    ) -> None:
        """Initializes the DualProtocolHandler."""
        self.reader = reader
        self.writer = writer
        self.explicit_host = explicit_host
        self.callback = manager_callback
        self.target_override = target_override
        self.scope_pattern = scope_pattern
        self.enable_tunneling = enable_tunneling
        self.upstream_verify_ssl = upstream_verify_ssl
        self.upstream_ca_bundle = upstream_ca_bundle
        self.ssl_context_factory = ssl_context_factory
        self.strict_mode = strict_mode
        self.initial_data = initial_data

    async def run(self) -> None:
        """Determines protocol and delegates control to the appropriate handler."""
        protocol, initial_data = await self._detect_protocol()
        if protocol == "h2":
            # [FIX] E1123: Corrected parameter names (id_bytes -> initial_data)
            await NativeProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback,
                self.target_override, self.scope_pattern, self.enable_tunneling,
                self.upstream_verify_ssl, self.upstream_ca_bundle,
                initial_data=initial_data, ssl_context_factory=self.ssl_context_factory
            ).run()
        else:
            await Http11ProxyHandler(
                self.reader, self.writer, self.explicit_host, self.callback,
                self.target_override, self.scope_pattern, self.upstream_verify_ssl,
                self.upstream_ca_bundle, initial_data=initial_data,
                ssl_context_factory=self.ssl_context_factory,
                enable_tunneling=self.enable_tunneling, strict_mode=self.strict_mode
            ).run()

    async def _detect_protocol(self) -> Tuple[str, bytes]:
        """Peeks at the socket data to detect HTTP/2 preface."""
        try:
            ssl_obj = self.writer.get_extra_info('ssl_object')
            if ssl_obj:
                alpn = ssl_obj.selected_alpn_protocol()
                if alpn == "h2":
                    return "h2", b""
                if alpn == "http/1.1":
                    return "http/1.1", b""

            buffer = bytearray(self.initial_data)
            required = len(H2_PREFACE)
            for _ in range(5):
                if len(buffer) >= required:
                    break
                try:
                    chunk = await asyncio.wait_for(
                        self.reader.read(required - len(buffer)), timeout=0.5
                    )
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) >= 4 and not buffer.startswith(b'PRI '):
                        return "http/1.1", bytes(buffer)
                except asyncio.TimeoutError:
                    break

            data = bytes(buffer)
            if data.startswith(H2_PREFACE[:4]):
                if len(data) == required and data == H2_PREFACE:
                    return "h2", data
                if b'HTTP/2.0' in data:
                    return "h2", data
            return "http/1.1", data
        except Exception: # pylint: disable=broad-exception-caught
            return "http/1.1", self.initial_data

async def start_proxy_server(
    host: str,
    port: int,
    manager_callback: Callable[[str, object], None],
    target_override: Optional[str] = None,
    scope_pattern: Optional[re.Pattern[str]] = None,
    ssl_context_factory: Optional[Callable[[str], ssl.SSLContext]] = None,
    strict_mode: bool = True
) -> asyncio.AbstractServer:
    """
    Starts the TCP server on the given host/port and handles incoming connections.
    """
    async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await DualProtocolHandler(
            r, w, "", manager_callback, target_override, scope_pattern,
            ssl_context_factory=ssl_context_factory, strict_mode=strict_mode
        ).run()

    server = await asyncio.start_server(_handle, host, port)
    manager_callback("SYSTEM", f"Transparent Proxy (H1/H2) listening on {host}:{port}")

    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            manager_callback("SYSTEM", "Proxy stopped")
            server.close()
            await server.wait_closed()
    return server
