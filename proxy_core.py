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
from structures import CapturedRequest, HOP_BY_HOP_HEADERS, MAX_CAPTURE_BODY_SIZE
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
                    method = method_b.decode('ascii')
                    target = target_b.decode('ascii')
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
                        key = match.group(1).decode('ascii')
                        val = match.group(2).decode('ascii').strip()
                        headers.append((key, val))
                        headers_dict[key.lower()] = val
                except ProxyError as e:
                    await self._send_error(400, str(e))
                    return

                if not await self._validate_request(method, headers_dict):
                    return

                # Transfer-Encoding & Content-Length handling
                te = headers_dict.get('transfer-encoding')
                cl = headers_dict.get('content-length')
                if te:
                    if cl and self.strict_mode:
                        headers = [h for h in headers if h[0].lower() != 'content-length']
                        if 'content-length' in headers_dict:
                            del headers_dict['content-length']
                    enc = [e.strip().lower() for e in te.split(',')]
                    if 'chunked' in enc and enc[-1] != 'chunked':
                        await self._send_error(400, "Bad Transfer-Encoding")
                        return
                elif cl:
                    try:
                        if int(cl) < 0:
                            raise ValueError
                    except ValueError:
                        await self._send_error(400, "Invalid Content-Length")
                        return

                if method == 'CONNECT':
                    await self._handle_connect(target)
                    return

                keep_alive = await self._handle_request(
                    method, target, version_b, headers, headers_dict, start_ts
                )
                if not keep_alive:
                    break
        except Exception as e: # pylint: disable=broad-exception-caught
            self.log("ERROR", f"HTTP/1.1 Proxy Error: {e}")
        finally:
            if not self.writer.is_closing():
                self.writer.close()

    async def _validate_request(self, method: str, headers_dict: Dict[str, str]) -> bool:
        """Validates the request method and headers."""
        if method == 'CONNECT' and 'host' not in headers_dict:
            await self._send_error(400, "CONNECT requires Host header")
            return False
        if any(k.startswith(':') for k in headers_dict):
            await self._send_error(400, "Pseudo-header in HTTP/1.1")
            return False
        return True

    async def _handle_connect(self, target: str) -> None:
        """Handles a CONNECT request for tunneling."""
        host, port = self._parse_target(target)
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
                        self.reader, self.writer, target, self.callback,
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
        self, method: str, target: str, version_b: bytes,
        headers: List[Tuple[str, str]], headers_dict: Dict[str, str], start_ts: float
    ) -> bool:
        """Handles a standard HTTP/1.1 request."""
        req_host = self.explicit_host
        if not req_host:
            p = urlparse(target)
            if p.scheme and p.netloc:
                req_host = p.netloc
        if not req_host:
            req_host = headers_dict.get('host')
        if not req_host:
            p = urlparse(target)
            req_host = p.netloc or ""

        scheme = "https" if self.upstream_verify_ssl else "http"
        default_port = 443 if scheme == "https" else 80
        host, port = self._parse_target(req_host if req_host else "", default_port=default_port)

        full_url = urljoin(self.target_override, target.lstrip('/')) if self.target_override else (
            target if target.startswith("http") else f"{scheme}://{host}:{port}{target}"
        )

        if not self._is_url_allowed(full_url, self.scope_pattern):
            await self._send_error(403, "Forbidden by Proxy Scope")
            return False

        body = b""
        te = headers_dict.get('transfer-encoding', '').lower()
        cl = headers_dict.get('content-length')

        if 'chunked' in te:
            body = await self._read_chunked_body()
        elif cl:
            try:
                body = await self._read_bytes(int(cl))
            except ValueError:
                pass

        self._record_capture(method, target, headers, body, scheme, host, start_ts)

        conn = headers_dict.get('connection', '').lower()
        keep_alive = True
        if 'close' in conn or version_b == b'HTTP/1.0':
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

        up_path = target
        if target.startswith("http"):
            p = urlparse(target)
            up_path = p.path if p.path else "/"
            up_path += ("?" + p.query) if p.query else ""

        # [VECTOR OPTIMIZATION] Batch header writes to minimize syscalls
        req_buf = [f"{method} {up_path} {version_b.decode()}\r\n".encode()]
        for k, v in headers:
            if k.lower() not in HOP_BY_HOP_HEADERS:
                req_buf.append(f"{k}: {v}\r\n".encode())
        req_buf.append(f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode())

        u_w.write(b"".join(req_buf))

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
