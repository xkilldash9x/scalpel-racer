# proxy_manager.py

"""
Proxy Manager with Full RFC 9114 QUIC (HTTP/3) Bridging Support.
Uses aioquic to act as a transparent HTTP/3 proxy with upstream bridging.
"""

import asyncio
import logging
import socket
import sys
import os
import ssl
import proxy_core
from typing import Optional, Dict, List, Any, Union, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ProxyManager")

# -- Check for aioquic availability --
HAS_AIOQUIC = False
try:
    from aioquic.asyncio import QuicConnectionProtocol, serve, connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived, HandshakeCompleted, ConnectionTerminated, QuicEvent
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
    HAS_AIOQUIC = True
except ImportError as e:
    # We log the specific error 'e' so we know if it's a missing package or a missing shared library
    log.warning(f"aioquic import failed: {e}. HTTP/3 Proxying will be disabled.")

    # Define dummy classes for type hinting and safe execution
    class QuicConfiguration: pass
    class QuicConnectionProtocol: pass
    class H3Connection: pass
    class QuicEvent: pass
    class H3Event: pass
    class DataReceived: pass
    class HeadersReceived: pass

    # Define dummy functions
    async def serve(*args, **kwargs): raise ImportError("aioquic not installed")
    async def connect(*args, **kwargs): raise ImportError("aioquic not installed")

class CapturedRequest:
    def __init__(self, protocol: str, method: str, url: str, headers: Any, body: bytes = b""):
        self.id = 0
        self.protocol = protocol
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    
    def __repr__(self) -> str:
        return f"<{self.protocol} {self.method} {self.url} ({len(self.body)} bytes)>"

if HAS_AIOQUIC:
    class UpstreamBridge(QuicConnectionProtocol):
        """
        Client protocol acting as the bridge to the Upstream Server.
        Forwards Upstream responses back to the H3ProxyInterceptor.
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3_conn = H3Connection(self._quic)
            self.downstream_interceptor: Optional['H3ProxyInterceptor'] = None
            self.client_stream_id: Optional[int] = None
            
            # Capture response parts
            self.response_headers = []
            self.response_body = bytearray()

        def quic_event_received(self, event: QuicEvent):
            if isinstance(event, StreamDataReceived):
                for h3_event in self._h3_conn.handle_event(event):
                    self._handle_h3_event(h3_event)

        def _handle_h3_event(self, event: H3Event):
            if not self.downstream_interceptor or self.client_stream_id is None:
                return

            if isinstance(event, HeadersReceived):
                self.response_headers = event.headers
                # Forward headers to original client
                self.downstream_interceptor.relay_response_headers(
                    self.client_stream_id, 
                    event.headers, 
                    event.stream_ended
                )
                if event.stream_ended:
                    self._signal_completion()

            elif isinstance(event, DataReceived):
                self.response_body.extend(event.data)
                # Forward data to original client
                self.downstream_interceptor.relay_response_data(
                    self.client_stream_id, 
                    event.data, 
                    event.stream_ended
                )
                if event.stream_ended:
                    self._signal_completion()

        def _signal_completion(self):
            # Signal the interceptor that the transaction is done so it can close the bridge
            if self.downstream_interceptor:
                self.downstream_interceptor.mark_stream_complete(self.client_stream_id)

    class H3ProxyInterceptor(QuicConnectionProtocol):
        """
        Server protocol acting as the HTTP/3 Proxy.
        Intercepts Client requests, connects to Upstream, and relays traffic.
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3_conn = H3Connection(self._quic)
            self.callback: Optional[callable] = None
            
            # Map stream_id -> Context (bridge tasks, queues, completion events)
            self._stream_contexts: Dict[int, Dict[str, Any]] = {}

        def connection_made(self, transport: asyncio.BaseTransport):
            super().connection_made(transport)
            sock = transport.get_extra_info('socket')
            if sock:
                try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except Exception as e: log.debug(f"Could not set socket options: {e}")

        def quic_event_received(self, event: QuicEvent):
            if isinstance(event, StreamDataReceived):
                for h3_event in self._h3_conn.handle_event(event):
                    if isinstance(h3_event, HeadersReceived):
                        asyncio.create_task(self._handle_request_headers(h3_event))
                    elif isinstance(h3_event, DataReceived):
                        self._handle_request_data(h3_event)

        async def _handle_request_headers(self, event: HeadersReceived):
            stream_id = event.stream_id
            headers_dict = {}
            method = ""; scheme = "https"; authority = ""; path = "/"
            
            for name, value in event.headers:
                n = name.decode('utf-8'); v = value.decode('utf-8')
                headers_dict[n] = v
                if n == ":method": method = v
                elif n == ":scheme": scheme = v
                elif n == ":authority": authority = v
                elif n == ":path": path = v

            # 1. Capture the request
            url = f"{scheme}://{authority}{path}"
            req = CapturedRequest("HTTP/3", method, url, headers_dict, b"")
            if self.callback:
                self.callback("CAPTURE", req)

            # 2. Prepare Context
            completion_event = asyncio.Event()
            upstream_queue = asyncio.Queue()
            
            self._stream_contexts[stream_id] = {
                "authority": authority,
                "queue": upstream_queue,
                "completion_event": completion_event,
                "request_body": bytearray(), # For full capture if needed later
                "req_obj": req
            }

            # 3. Establish Upstream Connection Task
            if authority:
                asyncio.create_task(self._bridge_to_upstream(stream_id, authority, event.headers, event.stream_ended))
            else:
                log.error(f"Stream {stream_id}: Missing :authority header, cannot proxy.")
                self._terminate_stream(stream_id, 400)

        def _handle_request_data(self, event: DataReceived):
            sid = event.stream_id
            if sid in self._stream_contexts:
                ctx = self._stream_contexts[sid]
                ctx["request_body"].extend(event.data)
                # Update captured object body
                ctx["req_obj"].body = bytes(ctx["request_body"])
                
                # Enqueue for bridge
                ctx["queue"].put_nowait((event.data, event.stream_ended))

        async def _bridge_to_upstream(self, client_stream_id, authority, headers, fin):
            ctx = self._stream_contexts.get(client_stream_id)
            host = authority.split(":")[0]
            try:
                port = int(authority.split(":")[1])
            except (IndexError, ValueError):
                port = 443

            log.info(f"Bridging Stream {client_stream_id} -> {host}:{port}")
            
            # Upstream Configuration
            config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
            config.verify_mode = ssl.CERT_NONE # Proxying often requires loose verification or custom CA

            try:
                async with connect(
                    host, port, 
                    configuration=config, 
                    create_protocol=UpstreamBridge
                ) as bridge:
                    
                    # Link protocols
                    bridge.downstream_interceptor = self
                    bridge.client_stream_id = client_stream_id
                    
                    # Open Upstream Stream
                    u_stream_id = bridge._quic.get_next_available_stream_id()
                    
                    # Forward Headers
                    bridge._h3_conn.send_headers(u_stream_id, headers, end_stream=fin)
                    bridge.transmit()
                    
                    # Forward Body Loop
                    # We check if we already finished (GET request) or need to stream body
                    if not fin:
                        while True:
                            try:
                                data, is_fin = await ctx["queue"].get()
                                bridge._h3_conn.send_data(u_stream_id, data, end_stream=is_fin)
                                bridge.transmit()
                                if is_fin:
                                    break
                            except asyncio.CancelledError:
                                break
                    
                    # Wait for Response Completion
                    # The bridge protocol will trigger ctx["completion_event"] when response is done
                    await ctx["completion_event"].wait()
            
            except Exception as e:
                log.error(f"Upstream bridge failed for {authority}: {e}")
                self._terminate_stream(client_stream_id, 502)
            finally:
                self._stream_contexts.pop(client_stream_id, None)

        def relay_response_headers(self, stream_id, headers, fin):
            """Called by UpstreamBridge to send headers to client."""
            self._h3_conn.send_headers(stream_id, headers, end_stream=fin)
            self.transmit()

        def relay_response_data(self, stream_id, data, fin):
            """Called by UpstreamBridge to send data to client."""
            self._h3_conn.send_data(stream_id, data, end_stream=fin)
            self.transmit()

        def mark_stream_complete(self, stream_id):
            """Called by UpstreamBridge when response is fully received."""
            if stream_id in self._stream_contexts:
                self._stream_contexts[stream_id]["completion_event"].set()
                
                # Trigger Response Capture Callback here if implemented
                if self.callback:
                    # We could emit a RESPONSE capture event here
                    # self.callback("CAPTURE_RESPONSE", ...)
                    pass

        def _terminate_stream(self, stream_id, status_code):
            headers = [(b":status", str(status_code).encode())]
            self._h3_conn.send_headers(stream_id, headers, end_stream=True)
            self.transmit()

else:
    # Fallback if aioquic is not available
    # This ensures tests and other modules can import these names without crashing
    UpstreamBridge = None
    H3ProxyInterceptor = None

class QuicServer:
    def __init__(self, host: str, port: int, callback: callable, ssl_context_factory=None):
        self.host = host
        self.port = port
        self.callback = callback
        self.ssl_context_factory = ssl_context_factory

    def load_server_ssl_context(self) -> QuicConfiguration:
        """
        Robustly loads certificates for QUIC/TLS 1.3.
        """
        config = QuicConfiguration(is_client=False)
        config.alpn_protocols = ["h3"]
        
        # Priority: explicit factory -> certs dir -> local dir
        cert_found = False
        possible_paths = [
            ("certs/server.crt", "certs/server.key"),
            ("server.crt", "server.key")
        ]
        
        for cert, key in possible_paths:
            if os.path.exists(cert) and os.path.exists(key):
                try:
                    config.load_cert_chain(cert, key)
                    log.info(f"Loaded QUIC certificates from {cert}")
                    cert_found = True
                    break
                except Exception as e:
                    log.error(f"Error loading {cert}: {e}")

        if not cert_found:
            log.warning("No valid QUIC certificates found. H3 Handshake will likely fail.")
        
        return config

    async def start(self):
        if not HAS_AIOQUIC:
            log.error("Cannot start QUIC Server: aioquic library is missing.")
            return

        log.info(f"QUIC (HTTP/3) Listener starting on {self.host}:{self.port}")
        
        config = self.load_server_ssl_context()
        
        def create_protocol(*args, **kwargs):
            p = H3ProxyInterceptor(*args, **kwargs)
            p.callback = self.callback
            return p

        await serve(
            self.host, 
            self.port, 
            configuration=config, 
            create_protocol=create_protocol
        )

class ProxyManager:
    def __init__(self, tcp_port=8080, quic_port=4433, ssl_context_factory=None, external_callback=None, bind_address="127.0.0.1"):
        self.tcp_port = tcp_port
        self.quic_port = quic_port
        self.ssl_context_factory = ssl_context_factory
        self.external_callback = external_callback
        self.bind_address = bind_address
        self.count = 0
        self.quic_server = QuicServer(self.bind_address, self.quic_port, self.unified_capture_callback, ssl_context_factory)
        self.stop_event = asyncio.Event()
        self.proxy_task = None

    def unified_capture_callback(self, protocol: str, source: Any, data: Any = None):
        type_ = protocol
        payload = data if data is not None else source
        source_str = f"{source[0]}:{source[1]}" if isinstance(source, tuple) and len(source) == 2 else (str(source) if source else "<?>")
        
        if type_ == "CAPTURE" and hasattr(payload, 'id'):
            payload.id = self.count
            self.count += 1
            log.info(f"[CAPTURE] #{payload.id} [{payload.protocol}] {payload.method} {payload.url}")
        elif type_ == "QUIC":
            log.info(f"[QUIC] {source_str} {str(data)}")
        elif type_ == "SYSTEM":
            log.info(f"[SYSTEM] {source_str if source != 'SYSTEM' else ''} {payload}")
        elif type_ == "ERROR":
            log.error(f"[ERROR] {source_str}: {payload}")
            
        if self.external_callback:
            try:
                self.external_callback(type_, payload)
            except Exception:
                pass

    async def run(self, target_override=None, scope_regex=None, strict_mode=True):
        log.info("=== Starting Proxy Manager ===")
        scope_pattern = None
        if scope_regex:
            import re
            scope_pattern = re.compile(scope_regex)
            
        def core_adapter(level, msg):
            if level == "CAPTURE":
                self.unified_capture_callback("CAPTURE", "TCP_CLIENT", msg)
            else:
                self.unified_capture_callback(level, "SYSTEM", msg)
                
        self.proxy_task = asyncio.create_task(proxy_core.start_proxy_server(
                self.bind_address, self.tcp_port, core_adapter, target_override=target_override,
                scope_pattern=scope_pattern, ssl_context_factory=self.ssl_context_factory, strict_mode=strict_mode))
        
        await self.quic_server.start()
        
        try:
            await self.stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            if self.proxy_task:
                self.proxy_task.cancel()
                await self.proxy_task

    def stop(self):
        self.stop_event.set()

if __name__ == "__main__":
    manager = ProxyManager(tcp_port=8080, quic_port=4433)
    try:
        asyncio.run(manager.run())
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)