"""Package-facing scanner functions."""

from scanner import (
    extract_cert_expiry,
    extract_cert_issuer,
    extract_cert_public_key,
    extract_cert_signature,
    extract_cipher,
    extract_first_cert,
    extract_hash,
    extract_key_exchange,
    extract_signature,
    extract_tls_version,
    get_certificate,
    parse_certificate,
    print_crypto_inventory,
    run_openssl,
)
from scanner import analyze_target as _analyze_target


def analyze_target(target, port):
    return _analyze_target(target, port)


def scan_target(target: str, port: int = 443) -> dict:
    if not target:
        raise RuntimeError(f"Scan failed for {target}:{port}")

    result = analyze_target(target, port)
    if not result:
        raise RuntimeError(f"Scan failed for {target}:{port}")

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


__all__ = [
    "analyze_target",
    "extract_cert_expiry",
    "extract_cert_issuer",
    "extract_cert_public_key",
    "extract_cert_signature",
    "extract_cipher",
    "extract_first_cert",
    "extract_hash",
    "extract_key_exchange",
    "extract_signature",
    "extract_tls_version",
    "get_certificate",
    "parse_certificate",
    "print_crypto_inventory",
    "run_openssl",
    "scan_target",
]
