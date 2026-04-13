"""Unit tests for the scanner."""

import time

import pytest

from modules import scanner as scanner_module
# _validate_target_port is a private helper in the top-level scanner module;
# import it directly so we can unit-test the guard in isolation.
import scanner as _scanner_core
_validate_target_port = _scanner_core._validate_target_port


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------

class TestValidateTargetPort:
    """_validate_target_port must reject bad inputs before any subprocess call."""

    def test_valid_domain_and_port(self):
        # Should not raise
        _validate_target_port("example.com", 443)
        _validate_target_port("sub.example.co.uk", 8443)
        _validate_target_port("a", 1)
        _validate_target_port("192.168.1.1", 65535)

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_target_port("", 443)

    def test_none_target_raises(self):
        with pytest.raises(ValueError):
            _validate_target_port(None, 443)

    def test_target_with_shell_metacharacters_raises(self):
        for bad in ("evil.com; ls", "evil.com && id", "evil.com|cat", "evil.com`id`"):
            with pytest.raises(ValueError, match="Invalid target"):
                _validate_target_port(bad, 443)

    def test_target_with_path_component_raises(self):
        with pytest.raises(ValueError, match="Invalid target"):
            _validate_target_port("example.com/path", 443)

    def test_target_with_port_embedded_raises(self):
        with pytest.raises(ValueError, match="Invalid target"):
            _validate_target_port("example.com:443", 443)

    def test_port_zero_raises(self):
        with pytest.raises(ValueError, match="1.65535"):
            _validate_target_port("example.com", 0)

    def test_port_too_high_raises(self):
        with pytest.raises(ValueError, match="1.65535"):
            _validate_target_port("example.com", 65536)

    def test_port_negative_raises(self):
        with pytest.raises(ValueError, match="1.65535"):
            _validate_target_port("example.com", -1)

    def test_port_string_raises(self):
        with pytest.raises(ValueError):
            _validate_target_port("example.com", "443")

    def test_port_float_raises(self):
        with pytest.raises(ValueError):
            _validate_target_port("example.com", 443.0)


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
