"""scanner.py — CypherQube TLS Scanner (cross-platform OpenSSL)."""
import shutil, subprocess, re
from pathlib import Path

def _openssl_binary() -> str:
    found = shutil.which("openssl")
    if found: return found
    for c in ["/opt/homebrew/opt/openssl@3/bin/openssl",
              "/usr/local/opt/openssl@3/bin/openssl",
              "/usr/bin/openssl", "/usr/local/bin/openssl"]:
        if Path(c).exists(): return c
    raise RuntimeError("openssl not found. Install OpenSSL and add it to PATH.")

def run_openssl(target, port):
    try:
        cmd = [_openssl_binary(), "s_client", "-connect", f"{target}:{port}",
               "-servername", target, "-showcerts"]
        r = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=15)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        print(f"[scanner] Timeout {target}:{port}"); return None
    except RuntimeError as e:
        print(f"[scanner] {e}"); return None
    except Exception as e:
        print(f"[scanner] OpenSSL error: {e}"); return None

def extract_tls_version(o): m=re.search(r"Protocol\s*:\s*(TLSv[\d.]+)",o); return m.group(1) if m else "Unknown"
def extract_cipher(o):      m=re.search(r"Cipher\s*:\s*([A-Z0-9_\-]+)",o);  return m.group(1) if m else "Unknown"
def extract_key_exchange(o):m=re.search(r"Server Temp Key:\s*([A-Za-z0-9\-_]+)",o); return m.group(1) if m else "Unknown"
def extract_signature(o):   m=re.search(r"Peer signature type:\s*([A-Za-z0-9\-_]+)",o); return m.group(1) if m else "Unknown"
def extract_hash(o):        m=re.search(r"Hash used:\s*([A-Za-z0-9\-_]+)",o); return m.group(1) if m else "Unknown"

def get_certificate(target, port):
    try:
        cmd = [_openssl_binary(), "s_client", "-connect", f"{target}:{port}",
               "-servername", target, "-showcerts"]
        r = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=15)
        return r.stdout or None
    except Exception as e:
        print(f"[scanner] Certificate fetch error: {e}"); return None

def extract_first_cert(s):
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", s or "", re.DOTALL)
    return ("-----BEGIN CERTIFICATE-----" + m.group(1) + "-----END CERTIFICATE-----") if m else None

def parse_certificate(pem):
    if not pem: return None
    try:
        r = subprocess.run([_openssl_binary(), "x509", "-text", "-noout"],
                           input=pem, text=True, capture_output=True, timeout=10)
        return r.stdout or None
    except Exception as e:
        print(f"[scanner] cert parse error: {e}"); return None

def extract_cert_public_key(t):
    if not t: return "Unknown","Unknown"
    a=re.search(r"Public Key Algorithm:\s*(.*)",t); s=re.search(r"Public-Key:\s*\((\d+)\s*bit\)",t)
    return (a.group(1).strip() if a else "Unknown"),(s.group(1) if s else "Unknown")

def extract_cert_signature(t):
    if not t: return "Unknown"
    m=re.search(r"Signature Algorithm:\s*(.*)",t); return m.group(1).strip() if m else "Unknown"

def extract_cert_issuer(t):
    if not t: return "Unknown"
    m=re.search(r"Issuer:\s*(.*)",t); return m.group(1).strip() if m else "Unknown"

def extract_cert_expiry(t):
    if not t: return "Unknown"
    m=re.search(r"Not After\s*:\s*(.*)",t); return m.group(1).strip() if m else "Unknown"

def print_crypto_inventory(inv):
    print("\n--- Crypto Inventory ---")
    for k,v in inv.items():
        if k != "certificate": print(f"  {k}: {v}")
    for k,v in inv.get("certificate",{}).items():
        print(f"  cert.{k}: {v}")

def analyze_target(target, port):
    from risk_engine import analyze_quantum_risk, print_risk_report
    raw = run_openssl(target, port)
    if not raw:
        print(f"[scanner] No TLS data from {target}:{port}"); return None
    cert_raw  = get_certificate(target, port)
    cert_pem  = extract_first_cert(cert_raw)
    cert_text = parse_certificate(cert_pem)
    pub_algo, key_size = extract_cert_public_key(cert_text)
    inv = {
        "target": f"{target}:{port}", "port": port,
        "tls_version": extract_tls_version(raw),
        "cipher_suite": extract_cipher(raw),
        "hash_function": extract_hash(raw),
        "key_exchange": extract_key_exchange(raw),
        "tls_signature": extract_signature(raw),
        "certificate": {
            "public_key_algorithm": pub_algo, "key_size": key_size,
            "signature_algorithm": extract_cert_signature(cert_text),
            "issuer": extract_cert_issuer(cert_text),
            "expiry": extract_cert_expiry(cert_text),
        }
    }
    risks, score = analyze_quantum_risk(inv)
    print_crypto_inventory(inv); print_risk_report(risks, score)
    inv["quantum_risk"] = {"risk_score": score, "findings": risks}
    return inv

def scan_target(target: str, port: int = 443) -> dict:
    if not target: raise RuntimeError("Empty target")
    result = analyze_target(target, port)
    if not result: raise Exception(f"Scan failed for {target}:{port}")
    cert = result.get("certificate", {})
    ks = cert.get("key_size")
    return {
        "target": result.get("target",""), "port": result.get("port", port),
        "tls_version": result.get("tls_version") or "Unknown",
        "cipher_suite": result.get("cipher_suite") or "Unknown",
        "key_exchange": result.get("key_exchange") or "Unknown",
        "public_key_algorithm": cert.get("public_key_algorithm") or "Unknown",
        "public_key_size": int(ks) if str(ks).isdigit() else None,
    }
