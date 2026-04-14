import os
import re
import shutil
import subprocess
from risk_engine import analyze_quantum_risk

# Basic regex for valid hostnames / IP addresses passed to OpenSSL.
# Allows labels of alphanumerics and hyphens separated by dots (RFC 1123),
# plus bare IPv4 addresses.  Intentionally conservative — reject anything
# that looks like a shell-injection attempt.
_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?))*$"
)


def _validate_target_port(target: str, port: int) -> None:
    """Validate target domain/IP and port before passing to OpenSSL.

    Uses a conservative RFC-1123 hostname regex to reject shell
    metacharacters and other unexpected input (CWE-78 — OS Command Injection
    prevention).  Port is checked to be an integer in the valid TCP range
    1–65535.

    Raises ValueError for invalid inputs so callers can surface the error
    before any subprocess is invoked.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string.")
    if not _DOMAIN_RE.match(target):
        raise ValueError(f"Invalid target domain: {target!r}")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be an integer in range 1–65535, got: {port!r}")


def _resolve_openssl_bin():
    configured = os.environ.get("CYPHERQUBE_OPENSSL")
    if configured:
        return configured

    discovered = shutil.which("openssl")
    if discovered:
        return discovered

    raise FileNotFoundError(
        "OpenSSL executable not found. "
        "Install openssl and ensure it is on PATH, or set the "
        "CYPHERQUBE_OPENSSL environment variable to the full binary path."
    )


def _run_openssl_command(args, timeout=15, input_text="Q\n"):
    return subprocess.run(
        [_resolve_openssl_bin(), *args],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_openssl(target, port):
    _validate_target_port(target, port)
    try:
        cmd = [
            "s_client",
            "-connect", f"{target}:{port}",
            "-servername", target,
            "-brief",
            "-showcerts"
        ]
        result = _run_openssl_command(cmd)
        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:
        print(f"[scanner] Timeout connecting to {target}:{port}")
        return None
    except Exception as e:
        print(f"[scanner] OpenSSL error: {e}")
        return None

def extract_tls_version(output):
    patterns = [
        r"Protocol\s*:\s*(TLSv[\d.]+)",
        r"New,\s*(TLSv[\d.]+),",
        r"CONNECTION ESTABLISHED\s*\nProtocol version:\s*(TLSv[\d.]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def extract_cipher(output):
    patterns = [
        r"Cipher\s*:\s*([A-Z0-9_\-]+)",
        r"Cipher is\s*([A-Z0-9_\-]+)",
        r"Ciphersuite:\s*([A-Z0-9_\-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def extract_key_exchange(output):
    patterns = [
        r"Negotiated TLS[\d.]+ group:\s*([A-Za-z0-9\-_]+)",
        r"Peer Temp Key:\s*([A-Za-z0-9\-_]+)",
        r"Server Temp Key:\s*([A-Za-z0-9\-_]+)",
        r"Server public key is\s*([A-Za-z0-9\-_]+)",
        r"key exchange:\s*([A-Za-z0-9\-_]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def extract_signature(output):
    patterns = [
        r"Peer signature type:\s*([A-Za-z0-9\-_]+)",
        r"Signature type:\s*([A-Za-z0-9\-_]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def extract_hash(output):
    patterns = [
        r"Hash used:\s*([A-Za-z0-9\-_]+)",
        r"Hash algorithm:\s*([A-Za-z0-9\-_]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def get_certificate(target, port):
    _validate_target_port(target, port)
    try:
        cmd = [
            "s_client",
            "-connect", f"{target}:{port}",
            "-servername", target,
            "-showcerts"
        ]

        result = _run_openssl_command(cmd)

        return result.stdout if result.stdout else None

    except Exception as e:
        print(f"[scanner] Certificate fetch error: {e}")
        return None
    
def extract_first_cert(cert_output):
    # Guard: return None if there's nothing to parse
    if not cert_output:
        return None

    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        cert_output,
        re.DOTALL
    )
    if match:
        return "-----BEGIN CERTIFICATE-----" + match.group(1) + "-----END CERTIFICATE-----"
    return None

def parse_certificate(cert_output):
    """Parse raw PEM output through openssl x509 -text."""
    if not cert_output:
        return None
    try:
        proc = _run_openssl_command(
            ["x509", "-text", "-noout"],
            timeout=10,
            input_text=cert_output,
        )
        return proc.stdout if proc.stdout else None

    except Exception as e:
        print(f"[scanner] Certificate parse error: {e}")
        return None


def extract_cert_public_key(cert_text):
    if not cert_text:
        return "Unknown", "Unknown"

    algo = re.search(r"Public Key Algorithm:\s*(.*)", cert_text)
    size = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)

    algo_val = algo.group(1).strip() if algo else "Unknown"
    size_val = size.group(1) if size else "Unknown"

    return algo_val, size_val


def extract_cert_signature(cert_text):
    if not cert_text:
        return "Unknown"
    match = re.search(r"Signature Algorithm:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"


def extract_cert_issuer(cert_text):
    if not cert_text:
        return "Unknown"
    match = re.search(r"Issuer:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"


def extract_cert_expiry(cert_text):
    if not cert_text:
        return "Unknown"
    match = re.search(r"Not After\s*:\s*(.*)", cert_text)
    return match.group(1).strip() if match else "Unknown"


def print_crypto_inventory(inventory):
    print("\n==============================")
    print("      CRYPTO INVENTORY")
    print("==============================")
    print(f"Target: {inventory['target']}")

    print("\n--- TLS Configuration ---")
    print(f"TLS Version  : {inventory['tls_version']}")
    print(f"Cipher Suite : {inventory['cipher_suite']}")
    print(f"Hash Function: {inventory['hash_function']}")
    print(f"Key Exchange : {inventory['key_exchange']}")
    print(f"TLS Signature: {inventory['tls_signature']}")

    cert = inventory["certificate"]
    print("\n--- Certificate Details ---")
    print(f"Public Key Algorithm: {cert['public_key_algorithm']}")
    print(f"Key Size            : {cert['key_size']} bits")
    print(f"Cert Signature      : {cert['signature_algorithm']}")
    print(f"Issuer              : {cert['issuer']}")
    print(f"Expiry              : {cert['expiry']}")


# Display ordering used by print_risk_report() — lower number = shown first.
# NOTE: this is for CLI output ordering only, not for risk scoring.
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "UNKNOWN": 3, "INFO": 4, "PASS": 5}


def _ascii_cli(text: str) -> str:
    return (
        str(text)
        .replace("—", "-")
        .replace("–", "-")
        .replace("→", "->")
        .replace("â†'", "->")
        .replace("…", "...")
    )


def print_risk_report(findings, score):
    """CLI helper that prints findings using ASCII-safe separators."""
    label = "CRITICAL" if score >= 7 else "MODERATE" if score >= 4 else "LOW"
    divider = "-" * 60

    print(f"\n{divider}")
    print(_ascii_cli(f"  QUANTUM RISK SCORE : {score}/10  [{label}]"))
    print(divider)

    if not findings:
        print("  No quantum vulnerabilities detected.")
    else:
        sorted_findings = sorted(
            findings,
            key=lambda f: SEV_ORDER.get(f.get("severity", "UNKNOWN"), 99)
        )
        for f in sorted_findings:
            sev      = f.get("severity", "?")
            category = f.get("category", "")
            finding  = f.get("finding", "")
            rem      = f.get("remediation", "")
            print(_ascii_cli(f"\n  [{sev}] {category}"))
            print(_ascii_cli(f"  {finding}"))
            if rem:
                print(_ascii_cli(f"  -> {rem}"))

    print(f"\n{divider}\n")


def analyze_target(target, port):
    """
    Full TLS scan pipeline:
      1. Run openssl s_client -brief  → TLS version, cipher, hash, key exchange, signature
      2. Run openssl s_client -showcerts + x509 -text → certificate details
      3. Build crypto inventory dict
      4. Run quantum risk engine → findings + score
      5. Return full report dict
    """

    raw_output = run_openssl(target, port)

    if not raw_output:
        print(f"[scanner] Failed to retrieve TLS data from {target}:{port}")
        return None

    tls_version    = extract_tls_version(raw_output)
    cipher         = extract_cipher(raw_output)
    signature_algo = extract_signature(raw_output)
    hash_algo      = extract_hash(raw_output)
    key_exchange   = extract_key_exchange(raw_output)

    cert_raw  = get_certificate(target, port)
    cert_pem  = extract_first_cert(cert_raw)   # safe: guards None internally
    cert_text = parse_certificate(cert_pem)    # safe: guards None internally

    pub_algo, key_size = extract_cert_public_key(cert_text)
    cert_signature     = extract_cert_signature(cert_text)
    issuer             = extract_cert_issuer(cert_text)
    expiry             = extract_cert_expiry(cert_text)

    crypto_inventory = {
        "target":        f"{target}:{port}",
        "port":          port,
        "tls_version":   tls_version,
        "cipher_suite":  cipher,
        "hash_function": hash_algo,
        "key_exchange":  key_exchange,
        "tls_signature": signature_algo,
        "certificate": {
            "public_key_algorithm": pub_algo,
            "key_size":             key_size,
            "signature_algorithm":  cert_signature,
            "issuer":               issuer,
            "expiry":               expiry,
        }
    }

    risks, score = analyze_quantum_risk(crypto_inventory)

    print_crypto_inventory(crypto_inventory)
    print_risk_report(risks, score)

    crypto_inventory["quantum_risk"] = {
        "risk_score": score,
        "findings":   risks,
    }

    return crypto_inventory


def scan_target(target: str, port: int = 443) -> dict:
    """
    Wrapper for testing compatibility.
    Converts analyze_target() output into flat structure.
    """

    if not target:
        raise RuntimeError(f"Scan failed for {target}:{port}")

    result = analyze_target(target, port)

    if not result:
        raise Exception("Scan failed")

    cert = result.get("certificate", {})

    return {
        "target": result.get("target", ""),
        "port": result.get("port", port),
        "tls_version": result.get("tls_version") or "Unknown",
        "cipher_suite": result.get("cipher_suite") or "Unknown",
        "key_exchange": result.get("key_exchange") or "Unknown",
        "public_key_algorithm": cert.get("public_key_algorithm") or "Unknown",
        "public_key_size": int(cert.get("key_size")) if str(cert.get("key_size")).isdigit() else None,
    }