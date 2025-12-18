# verify_certs.py
"""
Certificate Authority Manager.
Handles CA generation, storage, and on-the-fly leaf certificate signing.
"""

import os
import sys
import platform
import subprocess
import shutil
import socket
import datetime
import ssl
import threading
import atexit
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional
import permissions

CA_KEY_PATH = "scalpel_ca.key"
CA_CERT_PATH = "scalpel_ca.pem"
CERTS_DIR = "certs"

class CertManager:
    """
    Manages the internal Certificate Authority and generates/signs
    leaf certificates. [VECTOR] Optimized with Shared Ephemeral Keys.
    """
    def __init__(self):
        self.ca_key = None; self.ca_cert = None
        self.lock = threading.Lock(); self.cache = {}
        self.shared_leaf_key = ec.generate_private_key(ec.SECP256R1())
        if not os.path.exists(CERTS_DIR): os.makedirs(CERTS_DIR)
        self._load_or_generate_ca()

    def _load_or_generate_ca(self):
        if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
            print("[*] Generating new Scalpel CA (ECC P-256)...")
            self.ca_key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Scalpel Racer CA")])
            self.ca_cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.ca_key, hashes.SHA256())
            with open(CA_KEY_PATH, "wb") as f: f.write(self.ca_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            with open(CA_CERT_PATH, "wb") as f: f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        else:
            with open(CA_KEY_PATH, "rb") as f: self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_PATH, "rb") as f: self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def get_context_for_host(self, hostname: str) -> ssl.SSLContext:
        with self.lock:
            if hostname in self.cache: return self.cache[hostname]
            key = self.shared_leaf_key
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False).sign(self.ca_key, hashes.SHA256())
            
            key_path = os.path.join(CERTS_DIR, f"{hostname}.key")
            cert_path = os.path.join(CERTS_DIR, f"{hostname}.crt")
            with open(key_path, "wb") as f: f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            with open(cert_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            self.cache[hostname] = ctx
            return ctx

def install_to_trust_store():
    if not os.path.exists(CA_CERT_PATH): return
    system = platform.system()
    try:
        if system == "Linux":
            ca_dir = "/usr/local/share/ca-certificates"
            if os.path.exists(ca_dir) and os.geteuid() == 0:
                shutil.copy(CA_CERT_PATH, os.path.join(ca_dir, "scalpel_racer_ca.crt"))
                subprocess.check_call(["update-ca-certificates"])
        elif system == "Darwin":
            subprocess.check_call(["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", CA_CERT_PATH])
    except Exception as e: print(f"[!] Install failed: {e}")

if __name__ == "__main__":
    cm = CertManager()
    install_to_trust_store()
