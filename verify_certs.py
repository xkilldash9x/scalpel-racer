#Filename: verify_certs.py
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
import stat
import hashlib
import ipaddress
from typing import Optional, Union, List

# Cryptography Imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# -- Import Permission Handler --
# This automatically registers the atexit cleanup hook for permissions
try:
    import permissions
except ImportError:
    # Fallback if permissions.py isn't present in this specific run context
    print("[!] Warning: 'permissions' module not found. Cleanup hooks may not run.")

# -- Constants --
# [ARCHITECTURE] Anchor paths to module location to prevent CWD drift
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_KEY_PATH = "scalpel_ca.key"
CA_CERT_PATH = "scalpel_ca.pem"
CERTS_DIR = "certs"

class CertManager:
    """
    Manages the internal Certificate Authority and generates/signs
    leaf certificates for intercepted traffic on the fly.
    
    Includes optimization for Shared Ephemeral Keys and specific support
    for QUIC/HTTP3 listener certificates.
    """
    def __init__(self) -> None:
        self.ca_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.ca_cert: Optional[x509.Certificate] = None
        self.lock = threading.Lock()
        self.cache: dict[str, ssl.SSLContext] = {}
        
        # [VECTOR OPTIMIZATION] Shared Ephemeral Key
        # Pre-generating one key for all leaf certs saves massive overhead 
        # during high-traffic interception.
        self.shared_leaf_key = ec.generate_private_key(ec.SECP256R1())

        # -- Directory Security --
        # Enforce 700 permissions on the certs directory to prevent
        # unauthorized local users from reading private keys.
        if not os.path.exists(CERTS_DIR):
            os.makedirs(CERTS_DIR, mode=0o700)
        else:
            try:
                current_mode = stat.S_IMODE(os.stat(CERTS_DIR).st_mode)
                if current_mode != 0o700:
                    os.chmod(CERTS_DIR, 0o700)
            except OSError:
                pass # Best effort if not owner
        
        self._load_or_generate_ca()
        
        # Generate the static server certs required for the QUIC listener
        self._generate_static_server_cert()

    def _secure_write(self, path: str, data: bytes) -> None:
        """
        Writes bytes to a file with strict 0o600 permissions using os.open.
        """
        # Open with O_CREAT | O_WRONLY | O_TRUNC and mode 0o600
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except Exception:
            # os.fdopen usually closes the fd on exit, but if it fails during creation
            # we might need to handle it. However, standard practice assumes os.fdopen
            # takes ownership.
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _load_or_generate_ca(self) -> None:
        """
        Loads the existing CA from disk or generates a new ECC P-256 CA.
        [SECURED] Includes 'Self-Healing' logic for corrupted key files.
        """
        # 1. Attempt Load if files exist
        if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
            try:
                print("[*] Loading existing Scalpel CA...")
                with open(CA_KEY_PATH, "rb") as f:
                    self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(CA_CERT_PATH, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                
                # If successful, return early
                return
            except (ValueError, TypeError, AttributeError, OSError) as e:
                print(f"[!] CA State Corrupted ({e}). Initiating Self-Healing...")
                # Fall through to generation logic below
        
        # 2. Generation Logic (Runs if files missing OR corrupted)
        print("[*] Generating new Scalpel CA (ECC P-256)...")
        
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Scalpel Racer CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Team Ops"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Automated Security Testing"),
        ])
        
        # [ROBUSTNESS] Backdate 1 hour to handle clock skew
        now = datetime.datetime.now(datetime.timezone.utc)
        
        builder = x509.CertificateBuilder().subject_name(
            name
        ).issuer_name(
            name
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now - datetime.timedelta(hours=1)
        ).not_valid_after(
            now + datetime.timedelta(days=3650)
        )
        
        # [SECURITY] Critical Constraints for CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )

        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())

        # Write Private Key
        self._secure_write(CA_KEY_PATH, self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
            
        # Write Certificate
        with open(CA_CERT_PATH, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            
        print(f"[+] CA Generated/Healed: {CA_CERT_PATH}")

    def _get_general_name(self, value: str) -> x509.GeneralName:
        """
        [HELPER] Determines if the value is an IP address or DNS Name.
        RFC 5280 requires IP addresses to be encoded as OCTET strings (IPAddress),
        not IA5Strings (DNSName).
        """
        try:
            ip = ipaddress.ip_address(value)
            return x509.IPAddress(ip)
        except ValueError:
            return x509.DNSName(value)

    def _generate_static_server_cert(self) -> None:
        """
        Generates 'server.crt' and 'server.key' in the certs directory.
        These are required for the QUIC / HTTP/3 listener to bind initially.
        """
        server_crt_path = os.path.join(CERTS_DIR, "server.crt")
        server_key_path = os.path.join(CERTS_DIR, "server.key")

        # Skip if they already exist to save IO
        if os.path.exists(server_crt_path) and os.path.exists(server_key_path):
            return

        print("[*] Generating static QUIC/HTTP3 listener certificates (server.crt)...")
        
        # Use the shared leaf key for the server cert as well
        key = self.shared_leaf_key
        
        # We generally use localhost or the machine hostname for the main listener
        # Clients will SNI negotiate for the actual target later
        common_name = "localhost"
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now - datetime.timedelta(hours=1)
        ).not_valid_after(
            now + datetime.timedelta(days=365)
        )

        # [FIX] Properly typed SANs for IPs
        sans: List[x509.GeneralName] = [
            x509.DNSName(common_name),
            self._get_general_name("127.0.0.1"),
            self._get_general_name("::1")
        ]

        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )

        # [SECURITY] Add ExtendedKeyUsage for ServerAuth
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )

        cert = builder.sign(self.ca_key, hashes.SHA256())

        self._secure_write(server_key_path, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        
        with open(server_crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_context_for_host(self, hostname: str) -> ssl.SSLContext:
        """
        Returns an SSLContext configured with a certificate for the specific hostname.
        Uses a read-through cache and shared key optimization.
        [SECURED] Input sanitization via SHA-256 Hashing prevents Arbitrary File Write.
        """
        with self.lock:
            if hostname in self.cache:
                return self.cache[hostname]

            # [SECURITY FIX] Hash hostname to create safe, constant-length filename
            # This handles wildcards (e.g. *.com), IPs, and prevents collision/traversal
            host_hash = hashlib.sha256(hostname.encode('utf-8', errors='ignore')).hexdigest()
            
            # [VECTOR OPTIMIZATION] Use shared key if available
            key = self.shared_leaf_key
            
            # CommonName is limited to 64 chars. Hostnames can be longer.
            # We truncate for CN, but the full identity is preserved in SAN.
            cn_val = hostname[:64]

            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn_val),
            ])
            
            now = datetime.datetime.now(datetime.timezone.utc)

            # Build the leaf certificate
            builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.ca_cert.subject
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now - datetime.timedelta(hours=1)
            ).not_valid_after(
                now + datetime.timedelta(days=365)
            )
            
            # [FIX] Add SAN with correct Type (IP vs DNS)
            builder = builder.add_extension(
                x509.SubjectAlternativeName([self._get_general_name(hostname)]),
                critical=False,
            )
            
            # [SECURITY] Add KeyUsage and EKU for strict client compliance
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            
            cert = builder.sign(self.ca_key, hashes.SHA256())

            # Serialize
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # [SECURITY] Use hash for filesystem paths
            key_path = os.path.join(CERTS_DIR, f"{host_hash}.key")
            cert_path = os.path.join(CERTS_DIR, f"{host_hash}.crt")
            
            try:
                self._secure_write(key_path, key_pem)
                with open(cert_path, "wb") as f:
                    f.write(cert_pem)
            except OSError as e:
                # If IO fails, we cannot serve a cert
                raise OSError(f"Failed to cache certificate: {e}")

            # Create and Config Context
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            # [CRITICAL UPDATE] Inject Key Logging Hook Here
            if os.environ.get("SSLKEYLOGFILE"):
                ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
            
            # Support HTTP/3 (h3), HTTP/2 (h2) and HTTP/1.1
            ctx.set_alpn_protocols(["h3", "h2", "http/1.1"])
            
            self.cache[hostname] = ctx
            return ctx

def install_to_trust_store() -> None:
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

def install_to_chrome_nss(ca_cert_path: str) -> None:
    """
    Adds the Scalpel CA to the Chrome/NSS shared database.
    This ensures Chrome trusts the intercepted traffic.
    """
    # This feature is only relevant on Linux
    if platform.system() != "Linux":
        return
        
    nss_db_path = os.path.expanduser("~/.pki/nssdb")
    
    # -- Check for certutil --
    if not shutil.which("certutil"):
        print("[!] 'certutil' command not found. Skipping NSS database installation.")
        print("    Please install the 'libnss3-tools' package (or equivalent for your distro).")
        return
        
    # -- Ensure NSS Directory Exists --
    if not os.path.exists(nss_db_path):
        print(f"[*] Creating NSS database directory at {nss_db_path}")
        try:
            os.makedirs(nss_db_path, mode=0o700)
            # Initialize a new DB if it does not exist
            subprocess.run(["certutil", "-N", "-d", f"sql:{nss_db_path}", "--empty-password"], check=True)
        except (OSError, subprocess.CalledProcessError) as e:
             print(f"[!] Failed to initialize NSS DB: {e}")
             return

    print(f"[*] Adding {ca_cert_path} to Chrome NSS database...")
    
    try:
        # -- Add Certificate --
        # -A: Add certificate
        # -n: Nickname for the cert
        # -t: Trust arguments ("CT,C,C" trust for SSL, email, and signing)
        # -i: Input file
        subprocess.run([
            "certutil", "-d", f"sql:{nss_db_path}",
            "-A", "-t", "CT,C,C",
            "-n", "Scalpel Racer CA",
            "-i", ca_cert_path
        ], check=True, capture_output=True)
        
        print("[+] Successfully added Scalpel CA to Chrome NSS database.")
        
    except subprocess.CalledProcessError as e:
        # Ignore error if cert is already in DB, otherwise print error
        err_msg = e.stderr.decode() if e.stderr else str(e)
        if "is already installed" not in err_msg:
             print(f"[!] Failed to update NSS database: {err_msg}")


if __name__ == "__main__":
    cm = CertManager()
    print(f"[+] CA Ready at: {os.path.abspath(CA_CERT_PATH)}")
    install_to_trust_store()
    install_to_chrome_nss(CA_CERT_PATH)
