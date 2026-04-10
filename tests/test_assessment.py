"""Tests for integrated assessment orchestration."""

from modules.assessment import assess_target, batch_assess_targets, build_assessment
from reports import generate_pdf_report


def _classical_report(target="legacy.example:443"):
    return {
        "target": target,
        "port": 443,
        "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "hash_function": "SHA256",
        "key_exchange": "X25519",
        "tls_signature": "ECDSA",
        "certificate": {
            "public_key_algorithm": "RSA",
            "key_size": "2048",
            "signature_algorithm": "sha256WithRSAEncryption",
            "issuer": "Legacy CA",
            "expiry": "Dec 31 23:59:59 2030 GMT",
        },
        "quantum_risk": {
            "risk_score": 8,
            "findings": [
                {
                    "category": "Key Exchange",
                    "finding": "X25519 is vulnerable to Shor's Algorithm",
                    "severity": "CRITICAL",
                    "remediation": "Migrate key exchange to ML-KEM (FIPS 203) or a hybrid X25519+Kyber deployment.",
                },
                {
                    "category": "TLS Signature",
                    "finding": "ECDSA is vulnerable to Shor's Algorithm",
                    "severity": "HIGH",
                    "remediation": "Replace TLS handshake signatures with ML-DSA (FIPS 204) or FN-DSA (FIPS 206).",
                },
            ],
        },
    }


def _pqc_report(target="pqc.example:443"):
    return {
        "target": target,
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
            "issuer": "PQC CA",
            "expiry": "Dec 31 23:59:59 2035 GMT",
        },
        "quantum_risk": {
            "risk_score": 1,
            "findings": [
                {
                    "category": "Key Exchange",
                    "finding": "X25519MLKEM768 — post-quantum safe (Key Exchange)",
                    "severity": "PASS",
                    "remediation": "Key exchange is post-quantum safe. No action required.",
                }
            ],
        },
    }


def test_build_assessment_integrates_cbom_remediation_and_nist():
    assessment = build_assessment(_classical_report())

    assert assessment["summary"]["risk_score"] == 8
    assert assessment["cbom"]["summary"]["total_assets"] == 1
    assert assessment["cbom"]["entries"][0]["risk_label"] == "Critical Risk"
    assert assessment["remediation"][0]["component"] == "Key Exchange"
    assert assessment["remediation"][0]["hndl_priority"] is True
    assert any(ref["id"] == "FIPS 203" for ref in assessment["nist_references"])


def test_build_assessment_keeps_pass_findings_but_skips_noisy_remediation():
    assessment = build_assessment(_pqc_report())

    assert assessment["findings"][0]["severity"] == "PASS"
    assert assessment["remediation"] == []
    assert assessment["summary"]["quantum_safe"] is True


def test_assess_target_uses_shared_orchestrator():
    assessment = assess_target("legacy.example", scan_func=lambda target, port: _classical_report(f"{target}:{port}"))

    assert assessment["target"] == "legacy.example:443"
    assert assessment["inventory"]["certificate"]["issuer"] == "Legacy CA"


def test_batch_assess_targets_aggregates_results_errors_cbom_and_remediation():
    def fake_scan(target, port):
        if target == "bad.example":
            raise RuntimeError("connection failed")
        if target == "pqc.example":
            return _pqc_report(f"{target}:{port}")
        return _classical_report(f"{target}:{port}")

    batch = batch_assess_targets(["legacy.example", "bad.example", "pqc.example"], scan_func=fake_scan)

    assert batch["summary"]["successful"] == 2
    assert batch["summary"]["failed"] == 1
    assert batch["cbom"]["summary"]["total_assets"] == 2
    assert batch["errors"][0]["target"] == "bad.example"
    assert batch["remediation_summary"][0]["component"] == "Key Exchange"


def test_generate_pdf_report_accepts_integrated_assessment():
    pdf_bytes = generate_pdf_report(build_assessment(_classical_report()))

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
