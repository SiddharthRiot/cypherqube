"""tests/test_scanner.py — Scanner tests using mocked subprocess."""
import sys, pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import (extract_tls_version, extract_cipher, extract_key_exchange,
                     extract_signature, extract_hash, extract_cert_public_key,
                     extract_cert_signature, extract_cert_issuer, extract_cert_expiry,
                     extract_first_cert, scan_target)

FAKE_TLS = """
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
Peer signature type: ECDSA
Hash used: SHA256
"""
FAKE_CERT = """
Public Key Algorithm: id-ecPublicKey
Public-Key: (256 bit)
Signature Algorithm: ecdsa-with-SHA256
Issuer: C=US, O=Google Trust Services, CN=WR2
Not After : Jun 10 08:25:00 2025 GMT
"""
FAKE_INV = {
    "target":"google.com:443","port":443,"tls_version":"TLSv1.3",
    "cipher_suite":"TLS_AES_256_GCM_SHA384","hash_function":"SHA256",
    "key_exchange":"X25519","tls_signature":"ECDSA",
    "certificate":{"public_key_algorithm":"id-ecPublicKey","key_size":"256",
                   "signature_algorithm":"ecdsa-with-SHA256",
                   "issuer":"Google Trust Services","expiry":"Jun 10 2025"},
    "quantum_risk":{"risk_score":7,"findings":[]},
}

def test_extract_tls_version():    assert extract_tls_version(FAKE_TLS) == "TLSv1.3"
def test_extract_cipher():         assert extract_cipher(FAKE_TLS) == "TLS_AES_256_GCM_SHA384"
def test_extract_key_exchange():   assert extract_key_exchange(FAKE_TLS) == "X25519"
def test_extract_signature():      assert extract_signature(FAKE_TLS) == "ECDSA"
def test_extract_hash():           assert extract_hash(FAKE_TLS) == "SHA256"
def test_extract_cert_public_key():
    algo, size = extract_cert_public_key(FAKE_CERT)
    assert algo == "id-ecPublicKey"; assert size == "256"
def test_extract_cert_signature(): assert "ecdsa" in extract_cert_signature(FAKE_CERT).lower()
def test_extract_cert_issuer():    assert "Google" in extract_cert_issuer(FAKE_CERT)
def test_extract_cert_expiry():    assert "2025" in extract_cert_expiry(FAKE_CERT)
def test_extract_first_cert_none():assert extract_first_cert("no cert") is None
def test_unknown_fallback():
    assert extract_tls_version("x") == "Unknown"
    assert extract_cipher("x") == "Unknown"

def _mock_inv(**overrides):
    return {**FAKE_INV, **overrides}

def test_scan_valid_target():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        r = scan_target("google.com", 443)
        for k in ["target","port","tls_version","cipher_suite","key_exchange",
                  "public_key_algorithm","public_key_size"]:
            assert k in r

def test_tls_version_present():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        r = scan_target("google.com", 443)
        assert r["tls_version"] and "TLS" in r["tls_version"]

def test_cipher_suite_present():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        assert isinstance(scan_target("google.com",443)["cipher_suite"], str)

def test_invalid_host():
    with patch("scanner.analyze_target", return_value=None):
        with pytest.raises(Exception): scan_target("invalid.nonexistent.domain", 443)

def test_empty_target():
    with pytest.raises(Exception): scan_target("", 443)
"""Unit tests for the scanner."""

import time

import pytest

from modules import scanner as scanner_module


@pytest.fixture
def mock_scan(monkeypatch, sample_scan_report):
    def fake_analyze_target(target, port):
        if target == "invalid.nonexistent.domain":
            raise RuntimeError("DNS resolution failed")
        if not target:
            raise RuntimeError("Scan failed")

        report = dict(sample_scan_report)
        report["target"] = f"{target}:{port}"
        report["port"] = port
        return report

    monkeypatch.setattr(scanner_module, "analyze_target", fake_analyze_target)
    return fake_analyze_target


def test_scan_valid_target(mock_scan):
    result = scanner_module.scan_target("google.com", 443)

    assert isinstance(result, dict)

    expected_keys = [
        "target",
        "port",
        "tls_version",
        "cipher_suite",
        "key_exchange",
        "public_key_algorithm",
        "public_key_size",
    ]

    for key in expected_keys:
        assert key in result


def test_tls_version_present(mock_scan):
    result = scanner_module.scan_target("google.com", 443)

    assert result["tls_version"] is not None
    assert "TLS" in result["tls_version"]


def test_cipher_suite_present(mock_scan):
    result = scanner_module.scan_target("google.com", 443)

    assert result["cipher_suite"] is not None
    assert isinstance(result["cipher_suite"], str)


def test_invalid_host(mock_scan):
    with pytest.raises(Exception):
        scanner_module.scan_target("invalid.nonexistent.domain", 443)


def test_custom_port(mock_scan):
    result = scanner_module.scan_target("google.com", 443)
    assert result["port"] == 443

def test_custom_port():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        assert scan_target("google.com", 443)["port"] == 443

def test_missing_fields_handled():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        r = scan_target("google.com", 443)
        assert "public_key_algorithm" in r and "public_key_size" in r

def test_deterministic_output():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        assert scan_target("g.com",443)["tls_version"] == scan_target("g.com",443)["tls_version"]

def test_scan_performance():
    import time
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        t = time.time(); scan_target("google.com",443)
        assert time.time()-t < 5

def test_https_target():
    with patch("scanner.analyze_target", return_value=_mock_inv()):
        r = scan_target("google.com",443)
        assert r["port"]==443 and r["tls_version"].startswith("TLS")
def test_missing_fields_handled(mock_scan):
    result = scanner_module.scan_target("google.com", 443)

    assert "public_key_algorithm" in result
    assert "public_key_size" in result


def test_deterministic_output(mock_scan):
    result1 = scanner_module.scan_target("google.com", 443)
    result2 = scanner_module.scan_target("google.com", 443)

    assert result1["tls_version"] == result2["tls_version"]


def test_https_target(mock_scan):
    result = scanner_module.scan_target("google.com", 443)

    assert result["port"] == 443
    assert result["tls_version"].startswith("TLS")


def test_scan_performance(mock_scan):
    start = time.time()
    scanner_module.scan_target("google.com", 443)
    end = time.time()

    assert (end - start) < 10


def test_empty_target(mock_scan):
    with pytest.raises(Exception):
        scanner_module.scan_target("", 443)
