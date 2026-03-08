# ─── Quantum Vulnerability Definitions ───────────────────────────────────────

QUANTUM_VULNERABLE = [
    "RSA", "ECDSA", "ECDH", "X25519", "X448", "id-ecPublicKey"
]

PARTIAL_RISK = [
    "SHA1", "SHA224", "SHA256"
]

QUANTUM_SAFE = [
    "AES_256", "AES256", "TLS_AES_256"
]

# ─── Remediation Map ──────────────────────────────────────────────────────────
# Maps finding category → remediation advice

REMEDIATION = {
    "key_exchange": (
        "Migrate key exchange to a post-quantum algorithm. "
        "NIST-recommended options: CRYSTALS-Kyber (ML-KEM, FIPS 203) for key encapsulation, "
        "or hybrid X25519+Kyber schemes supported in OpenSSL 3.x / BoringSSL. "
        "Prioritise this — key exchange is exposed to 'harvest now, decrypt later' attacks."
    ),
    "tls_signature": (
        "Replace TLS handshake signature with a post-quantum algorithm. "
        "NIST-standardised: CRYSTALS-Dilithium (ML-DSA, FIPS 204) or FALCON (FN-DSA, FIPS 206). "
        "Ensure your TLS library (OpenSSL 3.3+, liboqs) supports the chosen scheme."
    ),
    "cert_pubkey": (
        "Reissue the certificate with a post-quantum public key algorithm. "
        "Use ML-DSA (Dilithium) or SLH-DSA (SPHINCS+, FIPS 205) for the certificate signature. "
        "Co-ordinate with your CA — most major CAs are rolling out PQC certificate support in 2024-2025."
    ),
    "hash_weak": (
        "Upgrade the hash function to SHA-384 or SHA-512. "
        "SHA-256 has its effective security halved by Grover's algorithm (128-bit post-quantum). "
        "SHA-384 / SHA-512 retain acceptable post-quantum security margins."
    ),
    "cipher_safe": (
        "AES-256 cipher is acceptable. Grover's algorithm reduces effective key length to 128 bits, "
        "which remains within acceptable security margins for the foreseeable future. No action required."
    ),
}


# ─── Core Analysis ────────────────────────────────────────────────────────────

def analyze_quantum_risk(inventory):
    """
    Analyse a crypto inventory dict and return (findings, score).
    Each finding is a dict: { category, finding, severity, remediation }
    """
    findings = []
    score = 0

    key_exchange = inventory.get("key_exchange", "")
    signature    = inventory.get("tls_signature", "")
    cipher       = inventory.get("cipher_suite", "")
    hash_algo    = inventory.get("hash_function", "")
    cert_algo    = inventory.get("certificate", {}).get("public_key_algorithm", "")

    # Key exchange
    if any(v in key_exchange for v in QUANTUM_VULNERABLE):
        findings.append({
            "category":    "Key Exchange",
            "finding":     f"{key_exchange} is vulnerable to Shor's Algorithm",
            "severity":    "CRITICAL",
            "remediation": REMEDIATION["key_exchange"],
        })
        score += 3

    # TLS signature
    if any(v in signature for v in QUANTUM_VULNERABLE):
        findings.append({
            "category":    "TLS Signature",
            "finding":     f"{signature} signature is vulnerable to Shor's Algorithm",
            "severity":    "HIGH",
            "remediation": REMEDIATION["tls_signature"],
        })
        score += 3

    # Certificate public key
    if any(v in cert_algo for v in QUANTUM_VULNERABLE):
        findings.append({
            "category":    "Certificate Public Key",
            "finding":     f"{cert_algo} public key is vulnerable to Shor's Algorithm",
            "severity":    "HIGH",
            "remediation": REMEDIATION["cert_pubkey"],
        })
        score += 3

    # Hash function
    if any(v in hash_algo for v in PARTIAL_RISK):
        findings.append({
            "category":    "Hash Function",
            "finding":     f"{hash_algo} has reduced strength under Grover's Algorithm",
            "severity":    "MEDIUM",
            "remediation": REMEDIATION["hash_weak"],
        })
        score += 1

    # Cipher (informational)
    if any(v in cipher for v in QUANTUM_SAFE):
        findings.append({
            "category":    "Cipher Suite",
            "finding":     f"{cipher} cipher is Grover-resistant (AES-256)",
            "severity":    "INFO",
            "remediation": REMEDIATION["cipher_safe"],
        })

    return findings, min(score, 10)


# ─── CLI Print Helper ─────────────────────────────────────────────────────────

def print_risk_report(findings, score):
    print("\n==============================")
    print("    QUANTUM RISK REPORT")
    print("==============================")
    print(f"Risk Score: {score}/10")
    print()

    if not findings:
        print("No significant quantum risks detected.")
        return

    for f in findings:
        print(f"[{f['severity']}] {f['category']}")
        print(f"  Finding:     {f['finding']}")
        print(f"  Remediation: {f['remediation']}")
        print()