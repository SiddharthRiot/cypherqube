"""Assessment orchestration for single-target and bulk scans."""

from collections import Counter

from core import CBOMGenerator, determine_badge, standards_for_text
from .scanner import analyze_target as scan_inventory


def normalize_target(target: str) -> str:
    return str(target or "").replace("https://", "").replace("http://", "").split("/")[0].strip()


def risk_meta(score: int) -> tuple[str, str]:
    if score >= 7:
        return "Critical Risk", "critical"
    if score >= 4:
        return "Moderate Risk", "medium"
    return "Low Risk", "safe"


def _priority_value(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "UNKNOWN": 3, "INFO": 4, "PASS": 5}.get(severity, 9)


def _build_remediation_items(findings: list[dict]) -> list[dict]:
    remediation_items = []

    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in {"PASS", "INFO"}:
            continue

        category = finding.get("category", "General")
        issue = finding.get("finding", "")
        recommended_action = finding.get("remediation", "")
        standards = standards_for_text(recommended_action) or standards_for_text(issue)

        if category == "Key Exchange":
            migration_target = "Adopt ML-KEM or a hybrid X25519+ML-KEM deployment path."
        elif category in {"TLS Signature", "Certificate Public Key"}:
            migration_target = "Migrate to ML-DSA, SLH-DSA, or FN-DSA where ecosystem support permits."
        elif category == "Hash Function":
            migration_target = "Prefer SHA-384 or SHA-512 for stronger post-quantum security margins."
        elif category == "Cipher Suite":
            migration_target = "Prefer AES-256-GCM or ChaCha20-Poly1305 for long-term protection."
        else:
            migration_target = "Review this control and align it with NIST PQC migration guidance."

        remediation_items.append(
            {
                "component": category,
                "issue": issue,
                "priority": severity,
                "recommended_action": recommended_action,
                "implementation_hint": migration_target,
                "nist_references": standards,
                "hndl_priority": category == "Key Exchange" and severity in {"CRITICAL", "HIGH"},
            }
        )

    return sorted(
        remediation_items,
        key=lambda item: (_priority_value(item["priority"]), 0 if item["hndl_priority"] else 1, item["component"]),
    )


def _build_nist_references(findings: list[dict], remediation: list[dict]) -> list[dict]:
    references = {}

    for finding in findings:
        for reference in standards_for_text(finding.get("finding", "")) + standards_for_text(finding.get("remediation", "")):
            references[reference["id"]] = reference

    for item in remediation:
        for reference in item.get("nist_references", []):
            references[reference["id"]] = reference

    return list(references.values())


def _build_cbom(raw_report: dict, score: int, risk_label: str) -> dict:
    cert = raw_report.get("certificate", {})
    generator = CBOMGenerator()
    generator.add_entry(
        target=str(raw_report.get("target", "")).split(":")[0],
        port=raw_report.get("port", 443),
        protocol="HTTPS",
        tls_version=raw_report.get("tls_version"),
        cipher_suite=raw_report.get("cipher_suite"),
        key_exchange=raw_report.get("key_exchange"),
        certificate_issuer=cert.get("issuer"),
        public_key_algorithm=cert.get("public_key_algorithm"),
        public_key_size=int(cert.get("key_size")) if str(cert.get("key_size")).isdigit() else None,
        tls_signature=raw_report.get("tls_signature"),
        certificate_signature_algorithm=cert.get("signature_algorithm"),
        hash_function=raw_report.get("hash_function"),
        risk_score=score,
        risk_label=risk_label,
        pqc_readiness="Quantum Safe" if score <= 3 else "Migration Needed",
    )
    return {"entries": generator.to_dict(), "summary": generator.summary()}


def _legacy_inventory_projection(raw_report: dict) -> dict:
    projected = dict(raw_report)
    projected.pop("quantum_risk", None)
    return projected


def build_assessment(raw_report: dict) -> dict:
    if not raw_report:
        raise RuntimeError("Scan returned no data")

    findings = list(raw_report.get("quantum_risk", {}).get("findings", []))
    score = int(raw_report.get("quantum_risk", {}).get("risk_score", 0))
    risk_label, risk_css = risk_meta(score)
    badge = determine_badge(score, raw_report.get("target", ""))
    remediation = _build_remediation_items(findings)
    nist_references = _build_nist_references(findings, remediation)
    cbom = _build_cbom(raw_report, score, risk_label)

    assessment = {
        "target": raw_report.get("target", ""),
        "port": raw_report.get("port", 443),
        "inventory": _legacy_inventory_projection(raw_report),
        "quantum_risk": raw_report.get("quantum_risk", {"risk_score": score, "findings": findings}),
        "findings": findings,
        "remediation": remediation,
        "nist_references": nist_references,
        "badge": badge.to_dict(),
        "cbom": cbom,
        "summary": {
            "risk_score": score,
            "risk_label": risk_label,
            "risk_css": risk_css,
            "finding_count": len(findings),
            "remediation_count": len(remediation),
            "quantum_safe": score <= 3,
            "hndl_exposure": any(item.get("hndl_priority") for item in remediation),
        },
    }

    assessment.update(assessment["inventory"])
    return assessment


def assess_target(target: str, port: int = 443, *, scan_func=None) -> dict:
    normalized = normalize_target(target)
    if not normalized:
        raise RuntimeError(f"Scan failed for {target}:{port}")

    report = (scan_func or scan_inventory)(normalized, port)
    if not report:
        raise RuntimeError(f"Scan failed for {normalized}:{port}")
    return build_assessment(report)


def batch_assess_targets(targets: list, *, default_port: int = 443, scan_func=None) -> dict:
    results = []
    errors = []
    cbom_entries = []
    remediation_counter = Counter()
    nist_references = {}
    risk_distribution = {"critical": 0, "medium": 0, "safe": 0}

    for item in targets:
        raw_target = item["target"] if isinstance(item, dict) else item
        port = item.get("port", default_port) if isinstance(item, dict) else default_port
        normalized = normalize_target(raw_target)

        if not normalized:
            errors.append({"target": str(raw_target), "port": port, "error": "Empty target"})
            continue

        try:
            assessment = assess_target(normalized, port, scan_func=scan_func)
        except Exception as exc:
            errors.append({"target": normalized, "port": port, "error": str(exc)})
            continue

        results.append(assessment)
        cbom_entries.extend(assessment["cbom"]["entries"])

        score_css = assessment["summary"]["risk_css"]
        risk_distribution[score_css] += 1

        for item in assessment["remediation"]:
            remediation_counter[(item["component"], item["priority"], item["recommended_action"])] += 1

        for reference in assessment["nist_references"]:
            nist_references[reference["id"]] = reference

    cbom_summary = {
        "entries": cbom_entries,
        "summary": {
            "total_assets": len(cbom_entries),
            "quantum_safe": sum(1 for entry in cbom_entries if entry.get("quantum_safe")),
            "not_quantum_safe": sum(1 for entry in cbom_entries if not entry.get("quantum_safe")),
            "risk_ratio": (
                f"{sum(1 for entry in cbom_entries if not entry.get('quantum_safe'))}/{len(cbom_entries)}"
                if cbom_entries
                else "0/0"
            ),
        },
    }

    remediation_summary = [
        {
            "component": component,
            "priority": priority,
            "recommended_action": action,
            "affected_targets": count,
        }
        for (component, priority, action), count in remediation_counter.most_common()
    ]

    return {
        "results": results,
        "errors": errors,
        "summary": {
            "requested": len(targets),
            "successful": len(results),
            "failed": len(errors),
            "risk_distribution": risk_distribution,
        },
        "cbom": cbom_summary,
        "remediation_summary": remediation_summary,
        "nist_summary": list(nist_references.values()),
    }
