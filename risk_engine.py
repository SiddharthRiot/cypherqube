QUANTUM_VULNERABLE = [
    "RSA", "ECDSA", "ECDH", "ECDHE",
    "id-ecPublicKey",
    "X25519", "X448",
    "P-256", "P-384", "P-521",
    "prime256v1", "secp384r1", "secp521r1",
    "DH", "DHE", "DSA",
]

PQC_KEM = [
    "ML-KEM", "MLKEM", "Kyber",
    "kyber512", "kyber768", "kyber1024",
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "X25519Kyber768", "X25519MLKEM768",
    "p256_kyber512", "SecP256r1Kyber768",
]

PQC_SIG = [
    "ML-DSA", "MLDSA", "Dilithium",
    "dilithium2", "dilithium3", "dilithium5",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA", "SLHDSA", "SPHINCS", "SPHINCS+",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s",
    "FN-DSA", "FNDSA", "FALCON",
    "falcon", "falcon512", "falcon1024",
    "FN-DSA-512", "FN-DSA-1024",
]

PARTIAL_RISK = [
    "SHA1", "SHA-1",
    "SHA224", "SHA-224",
    "SHA256", "SHA-256",
    "MD5",
]

HASH_SAFE = [
    "SHA384", "SHA-384",
    "SHA512", "SHA-512",
    "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE128", "SHAKE256",
]

CIPHER_SAFE = [
    "AES_256", "AES256", "AES-256",
    "TLS_AES_256",
    "CHACHA20", "ChaCha20",
]

CIPHER_WEAK = [
    "AES_128", "AES128", "AES-128",
    "TLS_AES_128",
    "3DES", "DES", "RC4",
]

REMEDIATION = {
    "key_exchange_vuln": (
        "Migrate key exchange to a post-quantum algorithm. "
        "NIST-recommended: CRYSTALS-Kyber (ML-KEM, FIPS 203) for key encapsulation, "
        "or hybrid X25519+Kyber schemes supported in OpenSSL 3.x / BoringSSL. "
        "Prioritise this — key exchange is exposed to 'harvest now, decrypt later' attacks."
    ),
    "tls_sig_vuln": (
        "Replace TLS handshake signature with a post-quantum algorithm. "
        "NIST-standardised: CRYSTALS-Dilithium (ML-DSA, FIPS 204) or FALCON (FN-DSA, FIPS 206). "
        "Ensure your TLS library (OpenSSL 3.3+, liboqs) supports the chosen scheme."
    ),
    "cert_pubkey_vuln": (
        "Reissue the certificate with a post-quantum public key algorithm. "
        "Use ML-DSA (Dilithium) or SLH-DSA (SPHINCS+, FIPS 205) for the certificate signature. "
        "Co-ordinate with your CA — most major CAs are rolling out PQC certificate support."
    ),
    "pqc_kem_pass": (
        "Key exchange is post-quantum safe. No action required for this component."
    ),
    "pqc_sig_pass": (
        "Signature algorithm is post-quantum safe. No action required for this component."
    ),
    "hash_weak": (
        "Upgrade the hash function to SHA-384 or SHA-512. "
        "SHA-256 has its effective security halved by Grover's algorithm (128-bit post-quantum). "
        "SHA-384 / SHA-512 retain acceptable post-quantum security margins."
    ),
    "cipher_safe": (
        "AES-256 / ChaCha20 cipher is acceptable. "
        "Grover's algorithm reduces effective key length to 128 bits, "
        "which remains within acceptable security margins. No action required."
    ),
    "cipher_weak": (
        "Upgrade to AES-256-GCM or ChaCha20-Poly1305. "
        "AES-128 provides only ~64-bit post-quantum security under Grover's algorithm, "
        "which is below acceptable margins for long-term data protection."
    ),
    "unknown": (
        "Research whether this algorithm is post-quantum safe. "
        "If unknown or unverified, treat as vulnerable and plan migration."
    ),
}


def _check_component(value, category, vuln_list, safe_list,
                     vuln_rem, safe_rem, severity, vuln_score=3):
    """
    Check a single crypto component against vulnerable and safe lists.
    Returns (finding_dict, score) or (None, 0) if value is empty/unknown.

    Priority:
      1. PQC-safe  → PASS, score 0
      2. Vulnerable → severity, score = vuln_score
      3. Unknown   → UNKNOWN, score +1
    """
    if not value or value in ("Unknown", "—", ""):
        return None, 0

    # 1. PQC-safe first
    if any(p.lower() in value.lower() for p in safe_list):
        return {
            "category":    category,
            "finding":     f"{value} — post-quantum safe ({category})",
            "severity":    "PASS",
            "remediation": safe_rem,
        }, 0

    # 2. Quantum vulnerable
    if any(v.lower() in value.lower() for v in vuln_list):
        return {
            "category":    category,
            "finding":     f"{value} is vulnerable to Shor's Algorithm",
            "severity":    severity,
            "remediation": vuln_rem,
        }, vuln_score

    # 3. Unrecognised
    return {
        "category":    category,
        "finding":     f"{value} — algorithm not recognised, manual review recommended",
        "severity":    "UNKNOWN",
        "remediation": REMEDIATION["unknown"],
    }, 1


def analyze_quantum_risk(inventory):
    """
    Analyse a crypto inventory dict and return (findings, score).
    Each finding: { category, finding, severity, remediation }
    Severity values: CRITICAL | HIGH | MEDIUM | PASS | INFO | UNKNOWN

    Scoring model (max 10):
      Key Exchange vulnerable    → +3  (highest — exposed to HNDL attacks)
      TLS Signature vulnerable   → +2  (high — handshake auth broken)
      Cert Public Key vulnerable → +2  (high — long-term key exposure)
      Hash weak (Grover)         → +1  (medium — effective bits halved)
      Cipher weak (Grover)       → +1  (medium — AES-128 range)
      Unknown algorithm          → +1  (flag for manual review)

    Typical modern HTTPS (ECDSA + X25519 + SHA-256):  3+2+2+1 = 8/10  CRITICAL
    Fully PQC-safe (ML-KEM + ML-DSA + SHA-384):       0/10            LOW
    """
    findings = []
    score    = 0

    key_exchange = inventory.get("key_exchange", "")
    tls_sig      = inventory.get("tls_signature", "")
    cipher       = inventory.get("cipher_suite",  "")
    hash_algo    = inventory.get("hash_function",  "")
    cert_algo    = inventory.get("certificate", {}).get("public_key_algorithm", "")

    f, s = _check_component(
        key_exchange, "Key Exchange",
        QUANTUM_VULNERABLE, PQC_KEM,
        REMEDIATION["key_exchange_vuln"],
        REMEDIATION["pqc_kem_pass"],
        "CRITICAL",
        vuln_score=3
    )
    if f: findings.append(f); score += s

    f, s = _check_component(
        tls_sig, "TLS Signature",
        QUANTUM_VULNERABLE, PQC_SIG,
        REMEDIATION["tls_sig_vuln"],
        REMEDIATION["pqc_sig_pass"],
        "HIGH",
        vuln_score=2
    )
    if f: findings.append(f); score += s

    f, s = _check_component(
        cert_algo, "Certificate Public Key",
        QUANTUM_VULNERABLE, PQC_SIG,
        REMEDIATION["cert_pubkey_vuln"],
        REMEDIATION["pqc_sig_pass"],
        "HIGH",
        vuln_score=2
    )
    if f: findings.append(f); score += s

    if hash_algo and hash_algo not in ("Unknown", "—"):
        if any(h.lower() in hash_algo.lower() for h in HASH_SAFE):
            findings.append({
                "category":    "Hash Function",
                "finding":     f"{hash_algo} — post-quantum safe hash (SHA-384/512 range)",
                "severity":    "PASS",
                "remediation": "No action required. SHA-384+ retains strong post-quantum security margins.",
            })
        elif any(h.lower() in hash_algo.lower() for h in PARTIAL_RISK):
            findings.append({
                "category":    "Hash Function",
                "finding":     f"{hash_algo} has reduced strength under Grover's Algorithm (~128-bit PQ security)",
                "severity":    "MEDIUM",
                "remediation": REMEDIATION["hash_weak"],
            })
            score += 1
        else:
            findings.append({
                "category":    "Hash Function",
                "finding":     f"{hash_algo} — hash algorithm not recognised, manual review recommended",
                "severity":    "UNKNOWN",
                "remediation": REMEDIATION["unknown"],
            })
            score += 1

    if cipher and cipher not in ("Unknown", "—"):
        if any(c.lower() in cipher.lower() for c in CIPHER_SAFE):
            findings.append({
                "category":    "Cipher Suite",
                "finding":     f"{cipher} — Grover-resistant cipher (AES-256 / ChaCha20)",
                "severity":    "INFO",
                "remediation": REMEDIATION["cipher_safe"],
            })
        elif any(c.lower() in cipher.lower() for c in CIPHER_WEAK):
            findings.append({
                "category":    "Cipher Suite",
                "finding":     f"{cipher} provides insufficient post-quantum symmetric security",
                "severity":    "MEDIUM",
                "remediation": REMEDIATION["cipher_weak"],
            })
            score += 1

    return findings, min(score, 10)



SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "UNKNOWN": 3, "INFO": 4, "PASS": 5}


def _ascii_cli(text: str) -> str:
    return (
        str(text)
        .replace("—", "-")
        .replace("–", "-")
        .replace("→", "->")
        .replace("â†’", "->")
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
def calculate_risk_score(
    tls_version=None,
    cipher_suite=None,
    key_exchange=None,
    public_key_algorithm=None,
    public_key_size=None
) -> int:
    """
    Wrapper for test compatibility.
    Converts flat params → inventory → calls analyze_quantum_risk()
    Returns only risk score.
    """

    cipher_value = str(cipher_suite or "Unknown").upper()
    key_exchange_value = str(key_exchange or "Unknown").upper()
    public_key_value = str(public_key_algorithm or "Unknown").upper()
    tls_value = str(tls_version or "Unknown").upper()

    score = 0

    if any(token in key_exchange_value for token in ("KYBER", "ML-KEM", "MLKEM")):
        score += 0
    elif any(token in key_exchange_value for token in ("RSA", "ECDHE", "ECDSA", "ECDH", "X25519", "DH")):
        score += 2
    else:
        score += 1

    if any(token in public_key_value for token in ("DILITHIUM", "ML-DSA", "MLDSA", "FALCON", "SLH-DSA", "SPHINCS")):
        score += 0
    elif any(token in public_key_value for token in ("RSA", "ECDSA", "EC")):
        score += 2
    else:
        score += 1

    if any(token in cipher_value for token in ("AES_256", "AES256", "TLS_AES_256", "CHACHA20")):
        score += 0
    elif any(token in cipher_value for token in ("AES_128", "AES128", "3DES", "DES", "RC4", "CBC")):
        score += 2
    else:
        score += 1

    if "TLS 1.3" in tls_value:
        score += 0
    elif "TLS 1.2" in tls_value:
        score += 1
    else:
        score += 2

    if public_key_size is None:
        score += 1
    elif public_key_size < 2048:
        score += 2
    elif public_key_size < 3072:
        score += 1

    if not any([cipher_suite, key_exchange, public_key_algorithm, tls_version]):
        score += 1

    return min(score, 10)

