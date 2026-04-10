"""tests/test_pdf_report.py — PDF and JSON report generation tests."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import pytest
from pdf_report import generate_pdf_report
from reports.generator import generate_json_report, get_pdf_bytes, generate_summary_text

def _inv(score=0, findings=None, target="test.com:443"):
    return {"target":target,"port":443,"tls_version":"TLSv1.3",
            "cipher_suite":"TLS_AES_256_GCM_SHA384","hash_function":"SHA384",
            "key_exchange":"X25519","tls_signature":"ECDSA",
            "certificate":{"public_key_algorithm":"id-ecPublicKey","key_size":"256",
                           "signature_algorithm":"ecdsa-with-SHA256",
                           "issuer":"Test CA","expiry":"Jan 1 2026"},
            "quantum_risk":{"risk_score":score,"findings":findings or []}}

_CRIT = {"category":"Key Exchange","finding":"X25519 vulnerable","severity":"CRITICAL","remediation":"Migrate."}
_PASS = {"category":"Cipher","finding":"AES-256 safe","severity":"PASS","remediation":"None needed."}

def test_pdf_returns_bytes():       assert isinstance(generate_pdf_report(_inv(8,[_CRIT])), bytes)
def test_pdf_magic():               assert generate_pdf_report(_inv(8,[_CRIT]))[:4] == b"%PDF"
def test_pdf_zero_findings():       assert len(generate_pdf_report(_inv(0,[]))) > 100
def test_pdf_all_pass():            assert isinstance(generate_pdf_report(_inv(0,[_PASS]*3)), bytes)
def test_pdf_all_critical():        assert isinstance(generate_pdf_report(_inv(10,[_CRIT]*5)), bytes)
def test_pdf_missing_cert():
    inv = _inv(5); inv.pop("certificate")
    assert isinstance(generate_pdf_report(inv), bytes)
def test_get_pdf_bytes():           assert get_pdf_bytes(_inv(3))[:4] == b"%PDF"
def test_json_valid():
    p = json.loads(generate_json_report(_inv(7,[_CRIT])))
    assert p["target"]=="test.com:443" and p["quantum_risk"]["risk_score"]==7
def test_json_findings():
    p = json.loads(generate_json_report(_inv(7,[_CRIT])))
    assert p["quantum_risk"]["findings"][0]["severity"]=="CRITICAL"
def test_json_empty():              assert json.loads(generate_json_report(_inv()))["quantum_risk"]["findings"]==[]
def test_json_saves_file(tmp_path):
    out=str(tmp_path/"r.json"); generate_json_report(_inv(), output_path=out)
    assert Path(out).exists() and "target" in json.loads(Path(out).read_text())
def test_summary_has_target():      assert "test.com:443" in generate_summary_text(_inv(8,[_CRIT]))
def test_summary_zero_findings():   assert "No quantum" in generate_summary_text(_inv())
