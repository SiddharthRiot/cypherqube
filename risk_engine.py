# Algorithms vulnerable to Shor's Algorithm
QUANTUM_VULNERABLE = [
    "RSA",
    "ECDSA",
    "ECDH",
    "X25519",
    "X448",
    "id-ecPublicKey"
]

# Hashes partially affected by Grover
PARTIAL_RISK = [
    "SHA1",
    "SHA224",
    "SHA256"
]

# Symmetric algorithms considered safer
QUANTUM_SAFE = [
    "AES_256",
    "AES256",
    "TLS_AES_256"
]


def analyze_quantum_risk(inventory):

    risks = []
    score = 0

    key_exchange = inventory["key_exchange"]
    signature = inventory["tls_signature"]
    cipher = inventory["cipher_suite"]
    hash_algo = inventory["hash_function"]
    cert_algo = inventory["certificate"]["public_key_algorithm"]

    # Key exchange check
    if any(v in key_exchange for v in QUANTUM_VULNERABLE):
        risks.append(f"{key_exchange} Key Exchange → Quantum Vulnerable (Shor)")
        score += 3

    # TLS signature
    if any(v in signature for v in QUANTUM_VULNERABLE):
        risks.append(f"{signature} Signature → Quantum Vulnerable (Shor)")
        score += 3

    # Certificate public key
    if any(v in cert_algo for v in QUANTUM_VULNERABLE):
        risks.append(f"{cert_algo} Public Key → Quantum Vulnerable (Shor)")
        score += 3

    # Hash check
    if any(v in hash_algo for v in PARTIAL_RISK):
        risks.append(f"{hash_algo} Hash → Reduced strength under Grover")
        score += 1

    # Cipher check
    if any(v in cipher for v in QUANTUM_SAFE):
        risks.append(f"{cipher} Cipher → Acceptable (Grover Resistant)")

    return risks, score



def print_risk_report(risks, score):

    print("\n==============================")
    print("     QUANTUM RISK ANALYSIS")
    print("==============================")

    if not risks:
        print("No major quantum risks detected.")
    else:
        for r in risks:
            print(f"- {r}")

    print("\nQuantum Risk Score:", score, "/10")

    if score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    print("Overall Quantum Risk Level:", level)