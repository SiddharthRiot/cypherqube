"""tests/conftest.py — Shared fixtures. No real network calls."""
import pytest
from unittest.mock import patch, MagicMock

FAKE_TLS_OUTPUT = """
CONNECTED(00000003)
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
Peer signature type: ECDSA
Hash used: SHA256
"""
FAKE_CERT_TEXT = """
Certificate:
    Public Key Algorithm: id-ecPublicKey
    Public-Key: (256 bit)
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: C=US, O=Google Trust Services, CN=WR2
    Validity
        Not After : Jun 10 08:25:00 2025 GMT
"""
FAKE_SCAN_RESULT = {
    "target":"google.com:443","port":443,"tls_version":"TLSv1.3",
    "cipher_suite":"TLS_AES_256_GCM_SHA384","key_exchange":"X25519",
    "public_key_algorithm":"id-ecPublicKey","public_key_size":256,
}
FAKE_INVENTORY = {
    "target":"google.com:443","port":443,"tls_version":"TLSv1.3",
    "cipher_suite":"TLS_AES_256_GCM_SHA384","hash_function":"SHA256",
    "key_exchange":"X25519","tls_signature":"ECDSA",
    "certificate":{"public_key_algorithm":"id-ecPublicKey","key_size":"256",
                   "signature_algorithm":"ecdsa-with-SHA256",
                   "issuer":"Google Trust Services","expiry":"Jun 10 2025"},
    "quantum_risk":{"risk_score":7,"findings":[{
        "category":"Key Exchange","finding":"X25519 vulnerable to Shor",
        "severity":"CRITICAL","remediation":"Migrate to ML-KEM."}]},
}

@pytest.fixture
def mock_openssl_run():
    mr = MagicMock(); mr.stdout = FAKE_TLS_OUTPUT; mr.stderr = ""
    with patch("subprocess.run", return_value=mr) as m: yield m

@pytest.fixture
def mock_analyze_target():
    with patch("scanner.analyze_target", return_value=FAKE_INVENTORY) as m: yield m
