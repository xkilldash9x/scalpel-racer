# verify_certs.py
"""
[VECTOR] PKI INFRASTRUCTURE
Handles CA generation and Dynamic Leaf Certificate Signing.
Provides SSLContext factory for MITM interception.
Features:

ECC SECP256R1 Keys (128-bit security, faster handshakes than RSA-3072).
Dynamic generation of leaf certificates for specific hostnames.
Automatic caching of SSLContexts for performance.
Subject Alternative Name (SAN) support (required by modern browsers).
"""
import os
import socket
import datetime
import ssl
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional

# -- Constants --
CA_KEY_PATH = "scalpel_ca.key"
CA_CERT_PATH = "scalpel_ca.pem"
CERTS_DIR = "certs"

class CertManager:
    """
    Manages the internal Certificate Authority and generates/signs
    leaf certificates for intercepted traffic on the fly.
    """
    def __init__(self):
        """
        Initializes the CertManager.

        It initializes the CA key and certificate, the lock, the cache,
        and the shared ephemeral key. It also ensures the certs directory exists
        and loads or generates the CA.
        """
        self.ca_key = None
        self.ca_cert = None
        self.lock = threading.Lock()
        self.cache = {}
        # [VECTOR OPTIMIZATION] Shared Ephemeral Key
        # Reuse a single private key for all leaf certificates to save CPU.
        self.shared_leaf_key = ec.generate_private_key(ec.SECP256R1())

        # Ensure certs directory exists for leaf certificates
        if not os.path.exists(CERTS_DIR):
            os.makedirs(CERTS_DIR)
        
        self._load_or_generate_ca()

    def _load_or_generate_ca(self):
        """
        Loads the existing CA from disk or generates a new one if missing.

        This method checks for the existence of the CA key and certificate.
        If they don't exist, it generates a new ECC P-256 key pair and a self-signed
        CA certificate, then saves them to disk. If they do exist, it loads them.
        """
        if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
            print("[*] Generating new Scalpel CA (ECC P-256)...")
            
            # 1. Generate Private Key (ECC Optimization)
            self.ca_key = ec.generate_private_key(ec.SECP256R1())
            
            # 2. Configure Identity
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Scalpel Racer CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Team Ops"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Automated Security Testing"),
            ])
            
            # 3. Build CA Certificate
            self.ca_cert = x509.CertificateBuilder().subject_name(
                name
            ).issuer_name(
                name
            ).public_key(
                self.ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(self.ca_key, hashes.SHA256())

            # 4. Write Private Key to Disk
            with open(CA_KEY_PATH, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # 5. Write Certificate to Disk
            with open(CA_CERT_PATH, "wb") as f:
                f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
                
            print(f"[+] CA Generated: {CA_CERT_PATH}")
        else:
            # Load existing CA
            with open(CA_KEY_PATH, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_PATH, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def get_context_for_host(self, hostname: str) -> ssl.SSLContext:
        """
        Returns an SSLContext with a certificate valid for the specific hostname.
        Uses caching to avoid regenerating certs for the same host.

        Args:
            hostname (str): The hostname for which to generate the certificate.

        Returns:
            ssl.SSLContext: An SSL context configured with the generated certificate and key.
        """
        with self.lock:
            if hostname in self.cache:
                return self.cache[hostname]

            # Generate Leaf Key/Cert
            # [VECTOR OPTIMIZATION] Use shared key if available
            if self.shared_leaf_key:
                key = self.shared_leaf_key
            else:
                key = ec.generate_private_key(ec.SECP256R1())
            
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.ca_cert.subject
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            )
            
            # SAN (Subject Alternative Name) is required by modern browsers
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            
            cert = builder.sign(self.ca_key, hashes.SHA256())

            # Serialize
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Save to 'certs/' directory
            key_path = os.path.join(CERTS_DIR, f"{hostname}.key")
            cert_path = os.path.join(CERTS_DIR, f"{hostname}.crt")
            
            with open(key_path, "wb") as f: f.write(key_pem)
            with open(cert_path, "wb") as f: f.write(cert_pem)

            # Create and Config Context
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            # ALPN is critical for HTTP/2 negotiation
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            
            self.cache[hostname] = ctx
            return ctx

if __name__ == "__main__":
    cm = CertManager()
    print(f"[+] CA Ready. Install '{CA_CERT_PATH}' to your system trust store to enable interception.")
