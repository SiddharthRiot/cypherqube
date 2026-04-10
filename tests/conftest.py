import pytest


@pytest.fixture
def sample_scan_report():
    return {
        "target": "example.com:443",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "hash_function": "SHA384",
        "key_exchange": "X25519MLKEM768",
        "tls_signature": "ML-DSA",
        "certificate": {
            "public_key_algorithm": "ML-DSA",
            "key_size": "4096",
            "signature_algorithm": "ML-DSA",
            "issuer": "Example CA",
            "expiry": "Dec 31 23:59:59 2030 GMT",
        },
        "quantum_risk": {"risk_score": 1, "findings": []},
    }
