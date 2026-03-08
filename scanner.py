import subprocess
import re


def run_openssl(target, port):
    try:
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{target}:{port}",
            "-servername",
            target,
            "-brief"
        ]

        result = subprocess.run(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=15
        )

        return result.stdout + result.stderr

    except Exception as e:
        print(f"OpenSSL error: {e}")
        return None


def extract_tls_version(output):
    match = re.search(r"Protocol version:\s*(TLSv[0-9.]+)", output)
    return match.group(1) if match else "Unknown"


def extract_cipher(output):
    match = re.search(r"Ciphersuite:\s*([A-Z0-9_\-]+)", output)
    return match.group(1) if match else "Unknown"


def extract_signature(output):
    match = re.search(r"Signature type:\s*([A-Z0-9\-]+)", output)
    return match.group(1) if match else "Unknown"


def extract_hash(output):
    match = re.search(r"Hash used:\s*([A-Z0-9\-]+)", output)
    return match.group(1) if match else "Unknown"


def extract_key_exchange(output):
    match = re.search(r"Server Temp Key:\s*([A-Za-z0-9\-]+)", output)
    return match.group(1) if match else "Unknown"

def print_crypto_inventory(inventory):

    print("\n==============================")
    print("      CRYPTO INVENTORY")
    print("==============================")

    print(f"Target: {inventory['target']}")

    print("\n--- TLS Configuration ---")
    print(f"TLS Version: {inventory['tls_version']}")
    print(f"Cipher Suite: {inventory['cipher_suite']}")
    print(f"Hash Function: {inventory['hash_function']}")
    print(f"Key Exchange: {inventory['key_exchange']}")
    print(f"Signature Algorithm: {inventory['tls_signature']}")

    cert = inventory["certificate"]

    print("\n--- Certificate Details ---")
    print(f"Public Key Algorithm: {cert['public_key_algorithm']}")
    print(f"Key Size: {cert['key_size']} bits")
    print(f"Certificate Signature: {cert['signature_algorithm']}")
    print(f"Issuer: {cert['issuer']}")
    print(f"Expiry: {cert['expiry']}")

def analyze_target(target, port):

    raw_output = run_openssl(target, port)

    if not raw_output:
        print("Failed to retrieve TLS data.")
        return

    tls_version = extract_tls_version(raw_output)
    cipher = extract_cipher(raw_output)
    signature_algo = extract_signature(raw_output)
    hash_algo = extract_hash(raw_output)
    key_exchange = extract_key_exchange(raw_output)

    # ---- Certificate extraction ----
    cert_raw = get_certificate(target, port)
    cert_text = parse_certificate(cert_raw)

    pub_algo, key_size = extract_cert_public_key(cert_text)
    cert_signature = extract_cert_signature(cert_text)
    issuer = extract_cert_issuer(cert_text)
    expiry = extract_cert_expiry(cert_text)

    # ---- Build Crypto Inventory ----
    crypto_inventory = {
        "target": f"{target}:{port}",
        "tls_version": tls_version,
        "cipher_suite": cipher,
        "hash_function": hash_algo,
        "key_exchange": key_exchange,
        "tls_signature": signature_algo,

        "certificate": {
            "public_key_algorithm": pub_algo,
            "key_size": key_size,
            "signature_algorithm": cert_signature,
            "issuer": issuer,
            "expiry": expiry
        }
    }

    print_crypto_inventory(crypto_inventory)

    return crypto_inventory


def get_certificate(target, port):
    try:
        cmd = f"openssl s_client -connect {target}:{port} -servername {target} -showcerts </dev/null"

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )

        return result.stdout

    except Exception as e:
        print(f"Certificate fetch error: {e}")
        return None
    
def parse_certificate(cert_output):
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-text", "-noout"],
            input=cert_output,
            text=True,
            capture_output=True
        )

        return proc.stdout

    except Exception as e:
        print(f"Certificate parse error: {e}")
        return None
    


def extract_cert_public_key(cert_text):
    algo = re.search(r"Public Key Algorithm:\s*(.*)", cert_text)
    size = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)

    algo = algo.group(1).strip() if algo else "Unknown"
    size = size.group(1) if size else "Unknown"

    return algo, size


def extract_cert_signature(cert_text):
    match = re.search(r"Signature Algorithm:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"


def extract_cert_issuer(cert_text):
    match = re.search(r"Issuer:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"


def extract_cert_expiry(cert_text):
    match = re.search(r"Not After\s*:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"