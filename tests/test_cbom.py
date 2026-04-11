import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
"""
tests/test_cbom.py — Unit tests for CBOM Generator
"""

from core.cbom import CBOMGenerator


def test_add_entry_basic():
    cbom = CBOMGenerator()

    cbom.add_entry(
        target="example.com",
        port=443,
        protocol="HTTPS",
        tls_version="TLS 1.2",
        cipher_suite="RSA_WITH_AES_128_GCM",
        key_exchange="RSA",
        certificate_issuer="Let's Encrypt",
        public_key_algorithm="RSA",
        public_key_size=2048
    )

    entries = cbom.to_dict()

    assert len(entries) == 1
    assert entries[0]["target"] == "example.com"
    assert entries[0]["quantum_safe"] is False

def test_quantum_safe_detection():
    cbom = CBOMGenerator()

    cbom.add_entry(
        target="secure-pqc.com",
        port=443,
        protocol="HTTPS",
        tls_version="TLS 1.3",
        cipher_suite="KYBER_AES_256",
        key_exchange="KYBER",
        public_key_algorithm="DILITHIUM",
        public_key_size=4096
    )

    entry = cbom.to_dict()[0]

    assert entry["quantum_safe"] is True


def test_cbom_summary():
    cbom = CBOMGenerator()

    # Unsafe
    cbom.add_entry(
        target="old.com",
        port=443,
        protocol="HTTPS",
        cipher_suite="RSA_WITH_AES_128_GCM",
        key_exchange="RSA",
        public_key_algorithm="RSA"
    )

    # Safe
    cbom.add_entry(
        target="new.com",
        port=443,
        protocol="HTTPS",
        cipher_suite="KYBER_AES_256",
        key_exchange="KYBER",
        public_key_algorithm="DILITHIUM"
    )

    summary = cbom.summary()

    assert summary["total_assets"] == 2
    assert summary["quantum_safe"] == 1
    assert summary["not_quantum_safe"] == 1
    assert summary["risk_ratio"] == "1/2"


def test_empty_cbom():
    cbom = CBOMGenerator()

    summary = cbom.summary()

    assert summary["total_assets"] == 0
    assert summary["quantum_safe"] == 0
    assert summary["not_quantum_safe"] == 0
    assert summary["risk_ratio"] == "0/0"


def test_clear_cbom():
    cbom = CBOMGenerator()

    cbom.add_entry(
        target="temp.com",
        port=443,
        protocol="HTTPS"
    )

    assert len(cbom.entries) == 1

    cbom.clear()

    assert len(cbom.entries) == 0


def test_missing_crypto_data():
    cbom = CBOMGenerator()

    cbom.add_entry(
        target="unknown.com",
        port=443,
        protocol="HTTPS"
    )

    entry = cbom.to_dict()[0]

    assert entry["quantum_safe"] is False
