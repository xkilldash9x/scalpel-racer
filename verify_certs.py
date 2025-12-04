from cryptography import x509
from cryptography.hazmat.primitives import serialization

def check_pair():
    print("[*] Loading scalpel_ca.key...")
    try:
        with open("scalpel_ca.key", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"[!] FAILED to load Key: {e}")
        return

    print("[*] Loading scalpel_ca.pem...")
    try:
        with open("scalpel_ca.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        print(f"[!] FAILED to load Cert: {e}")
        return

    # Extract public numbers
    pub_key_from_cert = cert.public_key()
    pub_numbers_cert = pub_key_from_cert.public_numbers()
    
    pub_numbers_key = private_key.public_key().public_numbers()

    print(f"\n--- Comparison ---")
    print(f"Key  Modulus (first 20 chars): {str(pub_numbers_key.n)[:20]}...")
    print(f"Cert Modulus (first 20 chars): {str(pub_numbers_cert.n)[:20]}...")

    if pub_numbers_cert == pub_numbers_key:
        print("\n[+] MATCH: These files are a valid pair.")
        print("    If you are still getting errors, the issue is likely:")
        print("    1. Chrome has cached the OLD certificate (Clear browsing data/SSL state).")
        print("    2. You trusted the WRONG 'scalpel_ca.pem' in the browser.")
    else:
        print("\n[!] MISMATCH: These files are NOT a pair.")
        print("    The tool is signing with a key that does not match the cert you trusted.")
        print("    SOLUTION: Delete BOTH files and restart scalpel_racer.py.")

if __name__ == "__main__":
    check_pair()