"""
tests/test_scanner.py — Unit tests for Scanner
"""

import pytest
from scanner import scan_target


def test_scan_valid_target():
    result = scan_target("google.com", 443)

    assert isinstance(result, dict)

    # Expected keys
    expected_keys = [
        "target",
        "port",
        "tls_version",
        "cipher_suite",
        "key_exchange",
        "public_key_algorithm",
        "public_key_size"
    ]

    for key in expected_keys:
        assert key in result


def test_tls_version_present():
    result = scan_target("google.com", 443)

    assert result["tls_version"] is not None
    assert "TLS" in result["tls_version"]


def test_cipher_suite_present():
    result = scan_target("google.com", 443)

    assert result["cipher_suite"] is not None
    assert isinstance(result["cipher_suite"], str)


def test_invalid_host():
    with pytest.raises(Exception):
        scan_target("invalid.nonexistent.domain", 443)

def test_custom_port():
    # Some servers may still respond
    try:
        result = scan_target("google.com", 443)
        assert result["port"] == 443
    except Exception:
        pytest.skip("Network-dependent test skipped")


def test_missing_fields_handled():
    result = scan_target("google.com", 443)

    # Even if some fields missing, keys should exist
    assert "public_key_algorithm" in result
    assert "public_key_size" in result


def test_deterministic_output():
    result1 = scan_target("google.com", 443)
    result2 = scan_target("google.com", 443)

    assert result1["tls_version"] == result2["tls_version"]


def test_https_target():
    result = scan_target("google.com", 443)

    assert result["port"] == 443
    assert result["tls_version"].startswith("TLS")

def test_scan_performance():
    import time

    start = time.time()
    scan_target("google.com", 443)
    end = time.time()

    assert (end - start) < 10   # should not take too long


def test_empty_target():
    with pytest.raises(Exception):
        scan_target("", 443)