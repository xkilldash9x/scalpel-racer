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
from typing import Optional

# Cryptography Imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# -- Import Permission Handler --
# This automatically registers the atexit cleanup hook for permissions
import permissions

# -- Constants --
CA_KEY_PATH = "scalpel_ca.key"
CA_CERT_PATH = "scalpel_ca.pem"
CERTS_DIR = "certs"

class CertManager:
    """
    Manages the internal Certificate Authority and generates/signs
    leaf certificates for intercepted traffic on the fly.
    Includes optimization for Shared Ephemeral Keys to reduce CPU load.
    """
    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.lock = threading.Lock()
        self.cache = {}
        
        # [VECTOR OPTIMIZATION] Shared Ephemeral Key
        # Pre-generating one key for all leaf certs saves massive overhead 
        # during high-traffic interception.
        self.shared_leaf_key = ec.generate_private_key(ec.SECP256R1())

        if not os.path.exists(CERTS_DIR):
            os.makedirs(CERTS_DIR)
        
        self._load_or_generate_ca()

    def _load_or_generate_ca(self):
        """
        Loads the existing CA from disk or generates a new ECC P-256 CA
        if one does not exist.
        """
        if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
            print("[*] Generating new Scalpel CA (ECC P-256)...")
            
            # 1. Generate Private Key
            self.ca_key = ec.generate_private_key(ec.SECP256R1())
            
            # 2. Configure Identity
            # Using specific OIDs makes the cert look more 'official' during inspection
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Scalpel Racer CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Team Ops"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Automated Security Testing"),
            ])
            
            # 3. Build CA Certificate
            # Valid for 10 years (3650 days)
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

            # 4. Write Private Key
            with open(CA_KEY_PATH, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # 5. Write Certificate
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
        Returns an SSLContext configured with a certificate for the specific hostname.
        Uses a read-through cache and shared key optimization.
        """
        with self.lock:
            if hostname in self.cache:
                return self.cache[hostname]

            # [VECTOR OPTIMIZATION] Use shared key if available
            key = self.shared_leaf_key
            
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            # Build the leaf certificate
            # Valid from 1 hour ago (clock skew safety) to 1 year in future
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
            
            # Add SAN (Subject Alternative Name) extension
            # This is mandatory for modern browsers/clients
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
            
            with open(key_path, "wb") as f:
                f.write(key_pem)
            with open(cert_path, "wb") as f:
                f.write(cert_pem)

            # Create and Config Context
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            # Support HTTP/2 and HTTP/1.1
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            
            self.cache[hostname] = ctx
            return ctx

def install_to_trust_store():
    """
    Installs the generated CA certificate to the system trust store.
    Handles Linux (Debian/Ubuntu) and macOS.
    """
    if not os.path.exists(CA_CERT_PATH):
        print(f"[!] CA Certificate not found at {CA_CERT_PATH}")
        return

    system = platform.system()
    
    try:
        if system == "Linux":
            # Debian/Ubuntu/Kali Standard Location
            ca_dir = "/usr/local/share/ca-certificates"
            
            if os.path.exists(ca_dir):
                # Check for Root
                if os.geteuid() != 0:
                    print(f"[!] Root privileges required to install certificate to {ca_dir}.")
                    print(f"    Please run: sudo python3 verify_certs.py")
                    return
                
                # Copy to system store with .crt extension (required by update-ca-certificates)
                dest_path = os.path.join(ca_dir, "scalpel_racer_ca.crt")
                print(f"[*] Copying {CA_CERT_PATH} to {dest_path}...")
                shutil.copy(CA_CERT_PATH, dest_path)
                
                # Update store
                print("[*] Updating CA certificates...")
                subprocess.check_call(["update-ca-certificates"])
                print("[+] CA Certificate installed successfully.")
            else:
                print(f"[!] Directory {ca_dir} not found. Automatic installation not supported for this distro.")
                print(f"    Please manually copy {CA_CERT_PATH} to your trusted CA store.")

        elif system == "Darwin": # MacOS
            print("[*] Detected macOS. Attempting to add to System Keychain (requires sudo)...")
            subprocess.check_call([
                "sudo", "security", "add-trusted-cert", "-d", 
                "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", CA_CERT_PATH
            ])
            print("[+] CA Certificate installed to System Keychain.")

        else:
            print(f"[!] Auto-install not supported for {system}. Please install '{CA_CERT_PATH}' manually.")

    except subprocess.CalledProcessError as e:
        print(f"[!] System command failed: {e}")
    except Exception as e:
        print(f"[!] Failed to install certificate: {e}")

if __name__ == "__main__":
    cm = CertManager()
    print(f"[+] CA Ready at: {os.path.abspath(CA_CERT_PATH)}")
    install_to_trust_store()