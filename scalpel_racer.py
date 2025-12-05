# scalpel_racer.py
"""
Scalpel Racer - Advanced Race Condition Testing Tool.

This is the main entry point for the Scalpel Racer application.
It orchestrates the entire workflow, from setting up the intercepting proxy server and capturing
traffic to managing the Certificate Authority (CA) and executing various race
condition attack strategies (Auto, SPA, First-Seq).

Key Components:
    - CAManager: Handles dynamic generation of CA certificates for HTTPS interception.
    - CaptureServer: An asyncio-based proxy server that intercepts and logs HTTP/HTTPS requests.
    - run_scan: The high-level function that dispatches the attack to the appropriate engine.
    - main: The CLI entry point handling argument parsing and the interactive UI.
"""

import asyncio
import httpx
import time
import argparse
import sys
import re
import hashlib
import ssl
import os
import datetime
import tempfile
import ipaddress
import platform
import socket
import struct
import threading
import types  # Required for P1 FIX (eof_received patching)
from typing import List, AsyncIterator, Optional, Dict, Union, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
from collections import defaultdict
import numpy as np

from structures import (
    ScanResult, 
    CapturedRequest, 
    MAX_RESPONSE_BODY_READ,
    SYNC_MARKER,
    HOP_BY_HOP_HEADERS
)

# Attempt to import the NativeProxyHandler for H2 interception support
try:
    from proxy_core import NativeProxyHandler
except ImportError:
    NativeProxyHandler = None

DEFAULT_CONCURRENCY = 15
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARMUP = 100 
CA_CERT_FILE = "scalpel_ca.pem"
CA_KEY_FILE = "scalpel_ca.key"

INITIAL_LINE_TIMEOUT = 5.0
HEADERS_TIMEOUT = 10.0
BODY_READ_TIMEOUT = 15.0
TUNNEL_IDLE_TIMEOUT = 30.0
TLS_HANDSHAKE_TIMEOUT = 10.0

try:
    from low_level import HTTP2RaceEngine
    H2_AVAILABLE = True
except ImportError:
    HTTP2RaceEngine = None
    H2_AVAILABLE = False

try:
    from packet_controller import NFQUEUE_AVAILABLE
except ImportError:
    NFQUEUE_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    Encoding = None
    PrivateFormat = None
    NoEncryption = None
    NameOID = None

# Global CA Manager instance (Initialized in main)
CA_MANAGER = None

class CAManager:
    """
    Manages the Certificate Authority (CA) for HTTPS interception.
    """
    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache = {}

    def initialize(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
            self.load_ca()
        else:
            self.generate_ca()

    def load_ca(self):
        print(f"[*] Loading Root CA from {CA_CERT_FILE}")
        try:
            with open(CA_KEY_FILE, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_FILE, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        except Exception as e:
            print(f"[!] Failed to load existing CA: {e}. Regenerating.")
            self.generate_ca()

    def generate_ca(self):
        print(f"[*] Generating new Root CA. Install '{CA_CERT_FILE}' in your browser/OS trust store to intercept HTTPS.")
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Scalpel Racer Debugging CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Scalpel Racer"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365*5))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

        try:
            with open(CA_KEY_FILE, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                ))
            with open(CA_CERT_FILE, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))
        except IOError as e:
            print(f"[!] Error saving CA files: {e}. TLS interception might fail.")

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        cert, key = self.generate_host_cert(hostname)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            # Support both H2 and HTTP/1.1 via ALPN
            context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass 

        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        import shutil
        temp_dir = tempfile.mkdtemp()
        
        try:
            cert_path = os.path.join(temp_dir, "cert.pem")
            key_path = os.path.join(temp_dir, "key.key")

            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            self.cert_cache[hostname] = context
            return context
        
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def generate_host_cert(self, hostname: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        if isinstance(hostname, bytes):
            hostname = hostname.decode('utf-8', errors='ignore')
        try:
            ip = ipaddress.ip_address(hostname)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(hostname)])
 
        now = datetime.datetime.now(datetime.timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert, key


class CaptureServer:
    """
    An asyncio-based proxy server for capturing HTTP and HTTPS traffic.
    """
    def __init__(self, port: int, target_override: str = None, scope_regex: str = None, enable_tunneling: bool = True, bind_address: str = "127.0.0.1"):
        self.port = port
        self.bind_address = bind_address
        self.target_override = target_override
        if self.target_override and not self.target_override.endswith('/'):
            self.target_override += '/'
            
        self.scope_pattern = re.compile(scope_regex) if scope_regex else None
        self.request_log: List[CapturedRequest] = []
        self.server = None
        self.stop_event = asyncio.Event()
        self.ready_event = asyncio.Event()
        self.enable_tunneling = enable_tunneling
        self.proxy_client = None
        self.capture_count = 0 

    def construct_target_url(self, scheme: str, request_line_target: str, normalized_headers: Dict[str, str], explicit_host: Optional[str]) -> str:
        try:
            parsed_target = urlparse(request_line_target)
        except ValueError:
            raise ValueError(f"Invalid format in request target: {request_line_target}")
        
        target_scheme = parsed_target.scheme
        target_host = parsed_target.netloc
        target_path = parsed_target.path
        target_query = parsed_target.query

        if (target_scheme or target_host) and not target_path:
             target_path = "/"
        
        if self.target_override:
            path_to_join = target_path or "/"
            path_with_query = urlunparse((
                '', '', path_to_join, parsed_target.params, target_query, ''
            ))
            return urljoin(self.target_override, path_with_query.lstrip('/'))

        if target_scheme and target_host:
            return request_line_target

        if request_line_target != "*" and not request_line_target.startswith("/"):
            raise ValueError(f"Invalid request target format: {request_line_target}")

        final_scheme = scheme
        final_host = None

        if explicit_host:
            final_host = explicit_host
        elif 'host' in normalized_headers:
            final_host = normalized_headers['host']
        
        if not final_host:
            raise ValueError("Cannot determine target host (Missing Host header or CONNECT context).")

        return urlunparse((
            final_scheme,
            final_host,
            target_path,
            parsed_target.params,
            parsed_target.query,
            ''
         ))

    def _ingest_captured_request(self, captured: CapturedRequest):
        """
        Callback used by NativeProxyHandler (H2) and internal HTTP/1.1 logic 
        to add a captured request to the log.
        """
        captured.id = len(self.request_log)
        self.request_log.append(captured)
        
        self.capture_count += 1
        if self.capture_count % 50 == 0:
             print(f"[*] Captured {self.capture_count} requests...", end='\r', flush=True)

    async def start(self):
        """
        Starts the proxy server.
        """
        if globals().get('CA_MANAGER'):
            try:
                globals().get('CA_MANAGER').initialize()
            except Exception as e:
                print(f"[!] Failed to initialize CA Manager: {e}. Disabling TLS interception.")
                globals()['CA_MANAGER'] = None

        try:
            self.server = await asyncio.start_server(self.handle_client, self.bind_address, self.port, backlog=128)
        except OSError as e:
            print(f"[!] Error: Could not bind to {self.bind_address}:{self.port}. {e}")
            if __name__ == "__main__":
                sys.exit(1)
            self.stop_event.set()
            return

        self.ready_event.set()

        print(f"[*] Proxy listening on {self.bind_address}:{self.port} (Console I/O Optimized)")
        if self.target_override:
            print(f"[*] Target Override Base: {self.target_override}")
    
        async with self.server:
            await self.stop_event.wait()
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            if self.proxy_client:
                await self.proxy_client.aclose()

    async def handle_client(self, reader, writer):
        """
        Handles an incoming client connection.
        """
        try:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=INITIAL_LINE_TIMEOUT)
            except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
                return 

            if not line: return

            decoded_line = line.decode(errors='ignore').strip()
            parts_strict = decoded_line.split(maxsplit=2)
            
            if not parts_strict or len(parts_strict) < 2: 
                return

            method = parts_strict[0].upper()

            if method == "CONNECT":
                path = parts_strict[1]
                while True:
                    try:
                        drain_line = await asyncio.wait_for(reader.readline(), timeout=HEADERS_TIMEOUT)
                    except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
                        return 
                    if not drain_line or drain_line.strip() == b'': 
                        break

                if globals().get('CA_MANAGER'):
                    await self.handle_connect(reader, writer, path)
                else:
                    print("[!] Received CONNECT request but TLS interception is disabled.")
                    return
            elif method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
                 request_target = parts_strict[1]
                 version = parts_strict[2] if len(parts_strict) == 3 else "HTTP/1.0"
                 await self.process_http_request(reader, writer, method, request_target, version, initial_line=line, scheme="http")
            else:
                return

        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass 
        except Exception as e:
            print(f"[!] Error handling request: {e}")
        finally:
            if writer and not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

    async def handle_connect(self, client_reader, client_writer, path):
        """
        Handles the HTTP CONNECT method for establishing TLS tunnels.
        Performs MITM interception and routes based on ALPN (H2 vs HTTP/1.1).
        """
        try:
            # Robust parsing: allow fallback to default port 443 if missing
            if ':' in path:
                host, port_str = path.split(':', 1)
                if port_str and not port_str.isdigit():
                     raise ValueError("Invalid port format")
            else:
                host = path
                
        except ValueError:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid CONNECT target")
            await client_writer.drain()
            return

        loop = asyncio.get_running_loop()
        if not hasattr(loop, 'start_tls'):
             print("[!] Error: TLS interception not supported by the current event loop (missing start_tls).")
             client_writer.write(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\n\r\nTLS interception not supported by event loop")
             await client_writer.drain()
             return

        try:
            ssl_context = globals().get('CA_MANAGER').get_ssl_context(host)
        except Exception as e:
            client_writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\nCertificate generation failed")
            await client_writer.drain()
            return

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        try:
            # [FIX: CRITICAL B01] Robustly get transport and protocol
            transport = client_writer.get_extra_info('transport')
            protocol = None
            if hasattr(client_writer, '_protocol'):
                protocol = client_writer._protocol
            elif transport and hasattr(transport, 'get_protocol'):
                 protocol = transport.get_protocol()
            if transport is None:
                transport = getattr(client_writer, '_transport', None)

            if transport is None or protocol is None:
                return

            # [FIX: CRITICAL B01] Patch protocol.eof_received if missing in current loop
            if hasattr(protocol, 'eof_received'):
                def patched_eof_received(self):
                    return True
                protocol.eof_received = types.MethodType(patched_eof_received, protocol)
            
            # [FIX: CRITICAL B01] Use StreamWriter.start_tls if available (Python 3.11+)
            if hasattr(client_writer, 'start_tls'):
                try:
                    await asyncio.wait_for(
                        client_writer.start_tls(ssl_context, server_side=True),
                        timeout=TLS_HANDSHAKE_TIMEOUT
                    )
                except Exception as e:
                    print(f"[!] TLS handshake failed (StreamWriter.start_tls): {e}")
                    return
            else:
                # Legacy fallback
                # [FIX: CRITICAL B01] Capture the NEW transport returned by start_tls
                try:
                    new_transport = await asyncio.wait_for(
                        loop.start_tls(transport, protocol, ssl_context, server_side=True),
                        timeout=TLS_HANDSHAKE_TIMEOUT
                    )
                except RuntimeError as e:
                    # Catch "cannot reuse already awaited coroutine" or similar errors during TLS upgrade
                    print(f"[!] Critical Runtime Error during TLS handshake (start_tls): {e}")
                    return
                except Exception as e:
                    print(f"[!] TLS handshake failed: {e}")
                    return

                # Refresh reader from protocol if available
                if hasattr(protocol, '_stream_reader') and protocol._stream_reader:
                    client_reader = protocol._stream_reader

                # [FIX: CRITICAL B01] Create a NEW writer using the new SSL transport.
                client_writer = asyncio.StreamWriter(new_transport, protocol, client_reader, loop)

            # -- ALPN DETECTION AND PROTOCOL SWITCHING --
            
            # Retrieve the negotiated protocol from the SSL object
            ssl_obj = client_writer.get_extra_info('ssl_object')
            negotiated_protocol = ssl_obj.selected_alpn_protocol() if ssl_obj else None

            if negotiated_protocol == "h2":
                if NativeProxyHandler:
                    # [H2 PATH] Hand off to the Sans-IO Proxy Core
                    h2_handler = NativeProxyHandler(
                        client_reader=client_reader,
                        client_writer=client_writer,
                        explicit_host=path,
                        capture_callback=self._ingest_captured_request,
                        target_override=self.target_override,
                        scope_pattern=self.scope_pattern,
                        enable_tunneling=self.enable_tunneling  # [FIX] Pass the flag
                    )
                    await h2_handler.run()
                    return # Exit handle_connect, H2 handler manages the rest
                else:
                    print("[!] Negotiated 'h2' but proxy_core.NativeProxyHandler is missing. Closing.")
                    client_writer.close()
                    return

            # -- HTTP/1.1 PATH (Legacy Loop) --
            
            while not client_reader.at_eof() and not client_writer.is_closing():
                try:
                    # P2: The wait_for here is necessary for the IDLE timeout of the tunnel itself.
                    line = await asyncio.wait_for(client_reader.readline(), timeout=TUNNEL_IDLE_TIMEOUT) 
                except asyncio.TimeoutError:
                    break 
                except (ConnectionResetError, asyncio.IncompleteReadError):
                    break

                if not line: 
                    break

                decoded_line = line.decode(errors='ignore').strip()
                parts_strict = decoded_line.split(maxsplit=2)

                if len(parts_strict) < 2: break 

                method = parts_strict[0].upper()
                request_target_in_tunnel = parts_strict[1]
                version = parts_strict[2] if len(parts_strict) == 3 else "HTTP/1.0"

                # Use the original path (host:port or just host) as the explicit_host context
                await self.process_http_request(client_reader, client_writer, method, request_target_in_tunnel, version, initial_line=line, scheme="https", explicit_host=path)

        except (ssl.SSLError, ConnectionResetError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except Exception as e:
            print(f"[!] Unexpected error during TLS interception for {host}: {e}")
        finally:
            # Ensure writer is closed (NativeProxyHandler handles this internally, but good for H1 fallback)
            if client_writer and not client_writer.is_closing():
                 client_writer.close()
                 try:
                     await client_writer.wait_closed()
                 except Exception:
                     pass

    async def process_http_request(self, reader, writer, method, request_target, version, initial_line, scheme, explicit_host=None):
        """
        Parses and processes a standard HTTP request.
        """
        normalized_headers: Dict[str, str] = {}
        original_headers_list: List[tuple[str, str]] = [] 
        content_length = 0
        transfer_encoding_chunked = False
        
        initial_connection_close = False
        if version.upper() in ["HTTP/1.0", "HTTP/0.9"]:
            initial_connection_close = True

        async def read_headers():
            normalized = {}
            original_list = []
            content_len = 0
            conn_close = initial_connection_close
            is_chunked = False

            while True:
                line = await reader.readline()
                if line == b'\r\n' or line == b'\n' or not line: break

                try:
                    line_str = line.decode(errors='ignore').strip()
                
                    if ':' in line_str:
                        key, value = line_str.split(':', 1)
                        original_key = key.strip()
                        value = value.strip()
                        key_lower = original_key.lower()

                        normalized[key_lower] = value
                        original_list.append((original_key, value))

                        if key_lower == 'content-length':
                            try:
                                content_len = int(value)
                            except ValueError:
                                content_len = 0 
                        elif key_lower == 'connection':
                            if 'close' in value.lower():
                                conn_close = True
                            elif 'keep-alive' in value.lower():
                                conn_close = False
                        elif key_lower == 'transfer-encoding':
                             if 'chunked' in value.lower():
                                  is_chunked = True
                except Exception:
                    pass
        
            return normalized, original_list, content_len, conn_close, is_chunked

        async def read_chunked_body():
            chunked_body = bytearray()
            try:
                while True:
                    size_line = await reader.readline()
                    if not size_line:
                        raise asyncio.IncompleteReadError(bytes(chunked_body), None) 

                    parts = size_line.split(b';') 
                    try:
                        chunk_size_hex = parts[0].strip()
                        if not chunk_size_hex:
                            continue
                        chunk_size = int(chunk_size_hex, 16)
                    except ValueError:
                        raise ValueError("Malformed chunk size")

                    if chunk_size == 0:
                        while True:
                            line = await reader.readline()
                            if not line:
                                  raise asyncio.IncompleteReadError(bytes(chunked_body), None)
                            if line.strip() == b'':
                                break
                        break

                    chunk = await reader.readexactly(chunk_size)
                    chunked_body.extend(chunk)

                    crlf = await reader.readline()
                    if not crlf:
                        raise asyncio.IncompleteReadError(bytes(chunked_body), None)

                return bytes(chunked_body)
            except asyncio.IncompleteReadError as e:
                 partial_data = e.partial if hasattr(e, 'partial') and e.partial else b''
                 expected = e.expected if hasattr(e, 'expected') else None
                 raise asyncio.IncompleteReadError(bytes(chunked_body) + partial_data, expected)

        try:
            normalized_headers, original_headers_list, content_length, connection_close, transfer_encoding_chunked = await asyncio.wait_for(read_headers(), timeout=HEADERS_TIMEOUT)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
             return

        body = b""
        if transfer_encoding_chunked:
            try:
                body = await asyncio.wait_for(read_chunked_body(), timeout=BODY_READ_TIMEOUT)
            except asyncio.TimeoutError:
                 if not writer.is_closing():
                     msg = b"Timeout reading chunked request body."
                     writer.write(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                     await writer.drain()
                 return
            except (ConnectionResetError, OSError):
                 return
            except (ValueError, asyncio.IncompleteReadError) as e:
                 if not writer.is_closing():
                    msg = b"Error processing request body."
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                    await writer.drain()
                 return

        elif content_length > 0:
             try:
                  body = await asyncio.wait_for(reader.readexactly(content_length), timeout=BODY_READ_TIMEOUT)
             except asyncio.IncompleteReadError as e:
                  if not writer.is_closing():
                      expected = e.expected if hasattr(e, 'expected') else content_length
                      partial_len = len(e.partial) if hasattr(e, 'partial') else 0
                      msg = f"Incomplete body read. Expected {expected}, got {partial_len}.".encode()
                      writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                      await writer.drain()
                  return
             except asyncio.TimeoutError:
                  if not writer.is_closing():
                      msg = b"Timeout reading request body."
                      writer.write(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                      await writer.drain()
                  return
             except ConnectionResetError:
                  return

        try:
            final_url = self.construct_target_url(scheme, request_target, normalized_headers, explicit_host)
        except ValueError as e:
            if not writer.is_closing():
                msg = str(e).encode('utf-8')
                try:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                    await writer.drain()
                except ConnectionError:
                     pass
            return

        original_headers_dict = dict(original_headers_list)

        if self.scope_pattern and not self.scope_pattern.search(final_url):
            if self.enable_tunneling:
                 await self.tunnel_request(final_url, method, original_headers_dict, body, writer)
            else:
                if not writer.is_closing():
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nOut of scope.")
                    await writer.drain()
            if connection_close and not writer.is_closing():
                writer.close()
            return

        # [B04 FIX] Uses the consolidated HOP_BY_HOP_HEADERS imported from structures.
        safe_headers = {k: v for k, v in original_headers_dict.items()
                        if k.lower() not in HOP_BY_HOP_HEADERS}

        captured = CapturedRequest(0, method, final_url, safe_headers, body)
        
        # Unified ingestion method
        self._ingest_captured_request(captured)

        if self.enable_tunneling:
            await self.tunnel_request(final_url, method, original_headers_dict, body, writer)
        else:
            if not writer.is_closing():
                conn_header = "close" if connection_close else "keep-alive"
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: {conn_header}\r\n\r\nCaptured.".encode('ascii'))
                await writer.drain()

        if connection_close and not writer.is_closing():
            writer.close()

    async def tunnel_request(self, url, method, headers, body, client_writer):
        """
        Tunnels the intercepted request to the upstream server and relays the response.
        """
        if self.proxy_client is None:
            self.proxy_client = httpx.AsyncClient(verify=False, timeout=60.0, http2=True)

        forward_headers = {k: v for k, v in headers.items()
                           if k.lower() not in HOP_BY_HOP_HEADERS}

        try:
            async with self.proxy_client.stream(method, url, content=body, headers=forward_headers) as response:
                
                if client_writer.is_closing(): return

                response_line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
                client_writer.write(response_line.encode('utf-8'))

                response_filter = ['connection', 'keep-alive', 'transfer-encoding', 'proxy-connection', 'upgrade']
                for key, value in response.headers.items():
                    if key.lower() not in response_filter:
                        header_line = f"{key}: {value}\r\n"
                        client_writer.write(header_line.encode('utf-8'))

                client_writer.write(b"\r\n")
                await client_writer.drain()

                async for chunk in response.aiter_raw():
                    if not chunk: continue
                    if client_writer.is_closing(): break
                    client_writer.write(chunk)
                    await client_writer.drain()

        except httpx.RequestError as e:
            if not client_writer.is_closing():
                try:
                    msg = b"Upstream request failed"
                    client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 23\r\n\r\n" + msg)
                    await client_writer.drain()
                except Exception:
                     pass
        except Exception as e:
            pass

async def Last_Byte_Stream_Body(payload: bytes, barrier: asyncio.Barrier, warmup_ms: int) -> AsyncIterator[bytes]:
    """
    Async generator that streams the request body, pausing before the last byte.
    """
    if len(payload) <= 1:
        if warmup_ms > 0:
            await asyncio.sleep(warmup_ms / 1000.0)
        try:
            if barrier: await barrier.wait()
        except asyncio.BrokenBarrierError:
            pass
        yield payload
        return

    yield payload[:-1] 

    if warmup_ms > 0:
        await asyncio.sleep(warmup_ms / 1000.0)

    try:
        if barrier: await barrier.wait() 
    except asyncio.BrokenBarrierError:
        pass

    yield payload[-1:]

async def Staged_Stream_Body(payload: bytes, barriers: List[asyncio.Barrier]) -> AsyncIterator[bytes]:
    """
    Async generator that splits the payload by {{SYNC}} markers.
    """
    parts = payload.split(SYNC_MARKER)
    barrier_idx = 0
    
    for i, part in enumerate(parts):
        if i > 0:
            if barrier_idx < len(barriers):
                try:
                    await barriers[barrier_idx].wait()
                    barrier_idx += 1
                except asyncio.BrokenBarrierError:
                    pass
        
        if part:
            yield part

async def send_probe_advanced(client: httpx.AsyncClient, request: CapturedRequest, payload: bytes, barriers: List[asyncio.Barrier], warmup_ms: int, index: int, is_staged: bool) -> ScanResult:
    """
    Sends a single probe request using httpx with the specified synchronization strategy.
    [FIX] Explicitly recalculates Content-Length to ensure valid headers during edits/streaming.
    """
    start_time = time.perf_counter()
    body_hash = None
    body_snippet = None

    try:
        req_headers = request.headers.copy()
        req_headers["User-Agent"] = "Scalpel-CLI/5.4-Optimized"
        req_headers["X-Scalpel-Probe"] = f"{index}_{int(time.time())}"

        # [FIX] Recalculate Content-Length for correct handling of edited bodies/sync markers
        actual_length = len(payload)
        req_headers["Content-Length"] = str(actual_length)

        has_content_type = any(k.lower() == 'content-type' for k in req_headers.keys())
        
        if not has_content_type and request.method in ["POST", "PUT", "PATCH"] and actual_length > 0:
             req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        content_stream = None
        if is_staged:
            content_stream = Staged_Stream_Body(payload, barriers)
        else:
            barrier = barriers[0] if barriers else None
            content_stream = Last_Byte_Stream_Body(payload, barrier, warmup_ms)
            
        content = content_stream if content_stream else payload

        async with client.stream(
            method=request.method,
            url=request.url,
            content=content,
            headers=req_headers
        ) as response:

            body = await response.aread()
            
            if body:
                body_hash = hashlib.sha256(body).hexdigest()
                body_snippet = body[:100].decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', '')

        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, response.status_code, duration, body_hash, body_snippet)
        
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        return ScanResult(index, 0, duration, error=str(e))

async def run_scan(request: CapturedRequest, concurrency: int, http2: bool, warmup: int, strategy: str = "auto"):
    """
    Orchestrates the race condition attack.
    """
    attack_payload = request.get_attack_payload()
    sync_markers_count = attack_payload.count(SYNC_MARKER)

    use_h2_engine = False
    
    if sync_markers_count > 0:
        if strategy != "auto":
            print("[!] Warning: Staged Attacks ({{SYNC}}) are only supported with the 'auto' strategy. Switching to auto.")
        strategy = "auto"
        
    if strategy in ["spa", "first-seq"]:
        use_h2_engine = True

    if use_h2_engine:
        if not H2_AVAILABLE:
            print(f"[!] Error: Strategy '{strategy}' requires 'h2' library.")
            return

        print(f"\n[!] REPLAYING ATTACK (Advanced H2 Engine): {request.method} {request.url}")
        print(f"[*] Payload: {len(attack_payload)} bytes | Concurrency: {concurrency} | Strategy: {strategy} | Warmup: {warmup}ms")

        def synchronous_h2_attack():
            # Re-import HTTP2RaceEngine locally if the global one is the placeholder (None)
            if HTTP2RaceEngine is None:
                try:
                     from low_level import HTTP2RaceEngine as ImportedH2Engine
                except ImportError:
                     return ImportError("H2 Engine not available (Import failed).")
            else:
                ImportedH2Engine = HTTP2RaceEngine

            engine = ImportedH2Engine(request, concurrency, strategy, warmup)
            try:
                return engine.run_attack()
            except Exception as e:
                return e

        loop = asyncio.get_running_loop()
        result_or_error = await loop.run_in_executor(None, synchronous_h2_attack)

        if isinstance(result_or_error, Exception):
            print(f"[!] Attack failed: {result_or_error}")
            return result_or_error
        
        analyze_results(result_or_error)
        return result_or_error

    barriers = []
    if sync_markers_count > 0:
        for _ in range(sync_markers_count):
            barriers.append(asyncio.Barrier(concurrency))
        strategy_label = f"Staged ({sync_markers_count} sync points)"
        if warmup > 0:
             print("[*] Note: Warmup delay is ignored in Staged Attack mode.")
             warmup = 0
    elif concurrency > 1:
        barriers.append(asyncio.Barrier(concurrency))
        strategy_label = "Last-Byte Sync (LBS)"
    else:
        strategy_label = "Single Request"

    print(f"\n[!] REPLAYING ATTACK (Standard httpx): {request.method} {request.url}")
    print(f"[*] Payload: {len(attack_payload)} bytes | Concurrency: {concurrency} | Strategy: {strategy_label} | Warmup: {warmup}ms | Mode: {'HTTP/2' if http2 else 'HTTP/1.1'}")

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency*2)
    timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=5.0)

    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=timeout, verify=False) as client:
        tasks = [asyncio.create_task(send_probe_advanced(client, request, attack_payload, barriers, warmup, i, sync_markers_count > 0)) for i in range(concurrency)]
        results = await asyncio.gather(*tasks)

    analyze_results(results)
    return results

def analyze_results(results: List[ScanResult]):
    """
    Analyzes and prints statistical data from the scan results.
    """
    if not results:
        print("\n-- Analysis Summary --\n  (No results to analyze)")
        return
        
    successful = [r for r in results if r.error is None]
    
    print("\n-- Analysis Summary --")

    signatures = defaultdict(list)
    for r in successful:
        key = (r.status_code, r.status_code//100, r.body_hash) 
        signatures[key].append(r)

    print("\n[Response Signatures]")
    
    if not signatures:
        print("  (No successful responses)")
    else:
        sorted_keys = sorted(signatures.keys(), key=lambda k: k[0])

        print(f"  {'Count':<6} {'Status':<6} {'Hash (SHA256)':<16} {'Snippet (First 100 chars)'}")
        print("  " + "-" * 90)
        for key in sorted_keys:
            status_code, _, body_hash = key
            group = signatures[key]
            count = len(group)
            snippet = group[0].body_snippet if group and group[0].body_snippet else ""
            hash_short = body_hash[:16] if body_hash else "N/A (Empty)"
            
            print(f"  {count:<6} {status_code:<6} {hash_short:<16} {snippet}")
            
        print("  " + "-" * 90)

        if len(signatures) > 1:
            print("\n  [!] WARNING: Multiple response signatures detected!")
            print("      This strongly indicates a potential race condition or inconsistent state.")
            
            families = set(k[1] for k in signatures.keys())
            if len(families) > 1:
                print("      Observed different status code families (e.g., success vs error).")
        else:
            print("\n  [+] Consistency: All responses are identical (Status Code and Body).")

    if successful:
        timings = [r.duration for r in successful]
        if len(timings) > 0:
            avg = sum(timings) / len(timings)
            min_t = min(timings)
            max_t = max(timings)
            
            if len(timings) > 1:
                std_dev = (sum((t - avg) ** 2 for t in timings) / (len(timings)-1)) ** 0.5
            else:
                 std_dev = 0.0
            
            print("\n[Timing Metrics]")
            print(f"  Average: {avg:.2f}ms")
            print(f"  Min/Max: {min_t:.2f}ms / {max_t:.2f}ms")
            print(f"  Jitter (StdDev): {std_dev:.2f}ms")
            
            if len(timings) > 1:
                print("\n[Timing Distribution (Histogram)]")
                try:
                    bins_count = min(int(len(timings) / 5) + 5, 20) 
                    counts, bins = np.histogram(timings, bins=bins_count)
                    max_count = max(counts) if len(counts) > 0 else 0
                    
                    if max_count > 0:
                        for i in range(len(counts)):
                            bar_len = int((counts[i] / max_count) * 40)
                            bar_display = ('#' * bar_len) if counts[i] > 0 else ''
                            print(f"  {bins[i]:>7.2f}ms - {bins[i+1]:>7.2f}ms | {bar_display} ({counts[i]})")
                except Exception:
                    print("  (Could not generate histogram)")

    errors = [r for r in results if r.error is not None]
    if errors:
        print("\n[Errors]")
        for err in errors:
            print(f"  Probe {err.index}: {err.error} ({err.duration:.2f}ms)")

def edit_request_body(request: CapturedRequest):
    """
    Provides a CLI for editing the body of a captured request.
    """
    print(f"\nEditing Body for Request {request.id}")
    print("Instructions: Use {{SYNC}} to insert synchronization points for Staged Attacks.")
    print("Current Body Preview (first 500 bytes):")
    current_body = request.get_attack_payload()
    print("-" * 30)
    print(current_body.decode(errors='ignore')[:500])
    print("-" * 30)
    
    print("\nEnter the new body (Stop with Ctrl+D (Unix) or Ctrl+Z+Enter (Windows) on a new line):")
    
    lines = []
    
    while True:
        try:
            try:
                line = sys.stdin.readline()
                if not line: 
                    break
                lines.append(line)
            except EOFError:
                break
        except KeyboardInterrupt:
            print("\n[!] Editing cancelled.")
            return
    
    new_body_str = "".join(lines)
    
    if not new_body_str.strip() and current_body:
         try:
             if input("Body is empty. Confirm? (y/N): ").lower() != 'y':
                print("[*] Body unchanged.")
                return
         except (EOFError, KeyboardInterrupt):
             print("\n[*] Body unchanged.")
             return

    try:
        new_body = new_body_str.encode('utf-8')
    except UnicodeEncodeError:
        print("[!] Error: Could not encode input as UTF-8. Using 'replace' strategy.")
        new_body = new_body_str.encode('utf-8', errors='replace')

    request.edited_body = new_body
    print(f"\n[*] Body updated. New length: {len(new_body)} bytes. Sync points: {new_body.count(SYNC_MARKER)}")

def main():
    """
    Main entry point.
    """
    if platform.system() == "Windows":
        try:
            if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception as e:
            print(f"[!] Could not set Windows event loop policy: {e}")

    if CRYPTOGRAPHY_AVAILABLE:
        globals()['CA_MANAGER'] = CAManager()

    parser = argparse.ArgumentParser(description="Scalpel Racer v5.4 (Robustified) - Advanced Race Condition Tester",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-l", "--listen", type=int, default=8080, help="Listening port (default: 8080)")
    parser.add_argument("--bind", type=str, default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("-t", "--target", type=str, help="Target Base URL for override (e.g. https://api.example.com/v1).")
    parser.add_argument("-s", "--scope", type=str, help="Regex scope filter.")

    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrency (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("-w", "--warmup", type=int, default=DEFAULT_WARMUP, help=f"Warm-up delay (ms) (default: {DEFAULT_WARMUP})")
    
    parser.add_argument("--strategy", choices=["auto", "spa", "first-seq"], default="auto",
                        help="Attack strategy:\n"
                             "auto: Use httpx LBS/Staged Attack (Default).\n"
                             "spa: Use HTTP/2 Single Packet Attack (H2 engine).\n"
                             "first-seq: Use HTTP/2 First Sequence Sync (H2 engine, Linux root only).")
    
    parser.add_argument("--http2", action="store_true", help="Force HTTP/2 for 'auto' strategy.")

    args = parser.parse_args()

    if args.strategy == 'first-seq':
        is_linux = sys.platform.startswith("linux")
        is_root = False
        if hasattr(os, 'geteuid'):
            is_root = os.geteuid() == 0
        
        if not is_linux or not is_root:
            print("[!] Warning: 'first-seq' strategy requires Linux and Root privileges.")
        
        if not NFQUEUE_AVAILABLE:
             print("[!] Warning: 'first-seq' strategy requires NetfilterQueue/Scapy. Ensure they are installed.")


    capture_server = CaptureServer(args.listen, args.target, args.scope, enable_tunneling=True, bind_address=args.bind)

    try:
        asyncio.run(capture_server.start())
    except KeyboardInterrupt:
        print("\n[*] Capture stopped. Proceeding to selection menu.", file=sys.stderr, flush=True)
        capture_server.stop_event.set()
    except SystemExit:
        return
    except Exception as e:
        print(f"\n[!] Capture server stopped unexpectedly: {e}")

    if capture_server.proxy_client:
        try:
            asyncio.run(capture_server.proxy_client.aclose())
        except RuntimeError:
            pass
        except Exception as e:
             print(f"[!] Error closing proxy client: {e}")

    log = capture_server.request_log

    if capture_server.capture_count > 0:
        print(f"[*] Total requests captured: {capture_server.capture_count}".ljust(40))

    if not log:
        print("\n[*] No requests captured matching scope.")
        sys.exit(0)

    def display_menu():
        print("\n\n-- Captured Requests --")
        print(f"{'ID':<5} {'Method':<7} {'URL (Size) [Status]'} ")
        print("-" * 100)
        
        display_log = log[-50:]
        if len(log) > 50:
            print(f"  ... (Showing last 50 of {len(log)} requests) ...")

        for req in display_log:
            print(f"{str(req)}")
    
        print("-" * 100)
        print("Commands: [ID] to race | 'e [ID]' to edit body | 'q' to quit")

    while True:
        display_menu()
        
        try:
            choice = input("Enter command: ").strip()
        except (EOFError, KeyboardInterrupt):
             sys.exit(0)
        
        if choice.lower() == 'q':
            sys.exit(0)

        parts = choice.split(maxsplit=1)
        if not parts: continue
        command = parts[0].lower()

        if command == 'e' and len(parts) == 2:
            try:
                 req_id = int(parts[1])
                 selected_req = next((r for r in log if r.id == req_id), None)
                 if selected_req:
                     edit_request_body(selected_req)
                 else:
                     print("Invalid ID.")
            except ValueError:
                 print("Invalid ID format for edit command.")
            continue

        try:
            req_id = int(command)
            selected_req = next((r for r in log if r.id == req_id), None)
            if selected_req:
                try:
                      asyncio.run(run_scan(selected_req, args.concurrency, args.http2, args.warmup, args.strategy))
                except Exception as e:
                       print(f"\n[!] Error during attack execution: {e}")
                
                try:
                    input("\nPress Enter to return to the menu...")
                except (EOFError, KeyboardInterrupt):
                    sys.exit(0)
            else:
                print("Invalid ID.")
        except ValueError:
            print("Invalid command.")

if __name__ == "__main__":
    main()
