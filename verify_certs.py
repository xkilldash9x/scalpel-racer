# verify_certs.py
"""
Script to generate, verify, and install the Scalpel Racer CA certificate.
[Hardened] Now uses ECC NIST P-256 (SECP256R1) for compliance and security.

Workflow:
1. Checks if `scalpel_ca.key` and `scalpel_ca.pem` exist.
2. Generates them if missing, using local system identity (Hostname/Locale).
3. Verifies the key/cert pair matches.
4. Offers to install the certificate to system and browser trust stores.

Dependencies:
    - cryptography
    - libnss3-tools (installed via script if missing)
"""

import os
import sys
import socket
import locale
import subprocess
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

def run_cmd(cmd, description):
    """Helper to run shell commands with logging."""
    print(f"[*] {description}...")
    try:
        subprocess.check_call(cmd, shell=True)
        print("    -> Success")
    except subprocess.CalledProcessError as e:
        print(f"    [!] Error: {e}")
        return False
    return True

def generate_ca():
    """Generates a new CA private key and self-signed certificate using local system info."""
    print("\n[*] CA files missing. Generating new Scalpel Racer CA (ECC NIST P-256)...")
    print("    -> Detecting local machine identity...")
    
    # 1. Detect Local Info for OpSec (Avoid hardcoding location)
    hostname = socket.gethostname()
    
    # Attempt to pull Country Code from system locale (Python 3.13 compliant)
    try:
        # Replaced deprecated getdefaultlocale() with getlocale()
        # On Linux, getlocale() usually requires setlocale to be called first to be accurate,
        # but for a simple country code heuristic, checking the environment or basic getlocale is sufficient.
        sys_locale = locale.getlocale()
        
        # Fallback if getlocale returns (None, None)
        if not sys_locale or not sys_locale[0]:
            lang = os.environ.get('LANG', 'en_US')
        else:
            lang = sys_locale[0]

        country_code = lang.split('_')[-1].split('.')[0] if '_' in lang else "US"
        
        if len(country_code) != 2:
            country_code = "US"
    except Exception:
        country_code = "US"

    print(f"    -> Using Hostname: {hostname}")
    print(f"    -> Using Country:  {country_code}")

    # 2. Generate Private Key (ECC Upgrade)
    # Using SECP256R1 (NIST P-256) provides 128-bit security, equivalent to RSA-3072
    # but with much smaller keys and faster handshake performance.
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 3. Generate Self-Signed Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Scalpel Racer ({hostname})"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Scalpel Racer CA - {hostname}"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Automated Security Testing"),
    ])
    
    # Secure defaults: SHA256 signature
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    # 4. Write Key to Disk
    with open("scalpel_ca.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # 5. Write Cert to Disk
    with open("scalpel_ca.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("    -> Generated 'scalpel_ca.key' and 'scalpel_ca.pem'")

def install_certs():
    """
    Interactive function to install the CA globally.
    """
    print("\n" + "="*60)
    print("WARNING: SYSTEM MODIFICATION")
    print("="*60)
    print("This script is about to:")
    print("  1. Install 'libnss3-tools' (requires sudo).")
    print("  2. Add 'scalpel_ca.pem' to your Chrome/Chromium NSS database.")
    print("  3. Copy 'scalpel_ca.pem' to system CA store (requires sudo).")
    print("  4. Force refresh system certificates (update-ca-certificates --fresh).")
    print("\nNOTE: You will be prompted for your sudo password.")
    
    choice = input("\nDo you want to proceed? [y/N]: ").strip().lower()
    if choice != 'y':
        print("[-] Aborted.")
        return

    # 1. Install dependencies
    if not run_cmd("sudo apt-get install -y libnss3-tools", "Installing libnss3-tools"):
        return

    # 2. Add to Chrome/NSS Database
    nss_db_path = os.path.expanduser("~/.pki/nssdb")
    cert_path = os.path.abspath("scalpel_ca.pem")
    
    # Ensure NSS DB directory exists
    if not os.path.exists(nss_db_path):
        os.makedirs(nss_db_path, exist_ok=True)

    cmd_nss = f'certutil -d sql:"{nss_db_path}" -A -t "C,," -n "Scalpel Racer CA" -i "{cert_path}"'
    run_cmd(cmd_nss, "Adding certificate to Chrome/NSS Database")

    # 3. Add to System CA Store
    cmd_cp = f"sudo cp '{cert_path}' /usr/local/share/ca-certificates/scalpel_ca.crt"
    if run_cmd(cmd_cp, "Copying certificate to /usr/local/share/ca-certificates/"):
        # 4. Refresh Store
        run_cmd("sudo update-ca-certificates --fresh", "Refreshing system certificate store")
        
    print("\n[+] Installation complete.")
    print("    You may need to restart Chrome/Browsers for changes to take effect.")
    print(f"    For Python scripts, you can run: export SSL_CERT_FILE=\"{cert_path}\"")

def check_pair(): 
    """
    Checks existence, generates if missing, verifies pair, and offers install.
    """
    # Check for existence
    if not os.path.exists("scalpel_ca.key") or not os.path.exists("scalpel_ca.pem"):
        generate_ca() # Generate if missing

    print("[*] Loading scalpel_ca.key...") 
    try:
        with open("scalpel_ca.key", "rb") as f: # Open key file
            private_key = serialization.load_pem_private_key(f.read(), password=None) # Load key
    except Exception as e:
        print(f"[!] FAILED to load Key: {e}")
        return

    print("[*] Loading scalpel_ca.pem...") 
    try: 
        with open("scalpel_ca.pem", "rb") as f: # Open certificate file
            cert = x509.load_pem_x509_certificate(f.read()) # Load certificate
    except Exception as e: 
        print(f"[!] FAILED to load Cert: {e}") 
        return 

    # Extract public numbers
    pub_key_from_cert = cert.public_key() 
    pub_numbers_cert = pub_key_from_cert.public_numbers() 
    pub_numbers_key = private_key.public_key().public_numbers() 

    if pub_numbers_cert == pub_numbers_key: 
        print("\n[+] MATCH: These files are a valid pair.") 
        install_certs() 
    else: 
        print("\n[!] MISMATCH: These files are NOT a pair.") 
        print("    SOLUTION: Delete BOTH files and run this script again to regenerate them.") 

if __name__ == "__main__": 
    check_pair() 
    sys.exit(0)