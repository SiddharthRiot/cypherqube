import streamlit as st
import json
import pandas as pd
from pdf_report import generate_pdf_report
# from scanner import analyze_target  # Uncomment when scanner module is available

# ─── Mock scanner ─────────────────────────────────────────────────────────────
def analyze_target(target, port):
    return {
        "target": f"{target}:{port}",
        "port": port,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "X25519",
        "hash_function": "SHA256",
        "tls_signature": "ECDSA",
        "certificate": {
            "public_key_algorithm": "id-ecPublicKey",
            "key_size": 256,
            "signature_algorithm": "sha256WithECDSAEncryption",
            "issuer": "CN=R3, O=Let's Encrypt, C=US",
            "expiry": "2025-12-31 00:00:00"
        },
        "quantum_risk": {
            "risk_score": 7,
            "findings": [
                {
                    "category": "Key Exchange",
                    "finding": "X25519 is vulnerable to Shor's Algorithm",
                    "severity": "CRITICAL",
                    "remediation": "Migrate key exchange to a post-quantum algorithm. NIST-recommended options: CRYSTALS-Kyber (ML-KEM, FIPS 203) for key encapsulation, or hybrid X25519+Kyber schemes supported in OpenSSL 3.x / BoringSSL. Prioritise this — key exchange is exposed to 'harvest now, decrypt later' attacks."
                },
                {
                    "category": "TLS Signature",
                    "finding": "ECDSA signature is vulnerable to Shor's Algorithm",
                    "severity": "HIGH",
                    "remediation": "Replace TLS handshake signature with a post-quantum algorithm. NIST-standardised: CRYSTALS-Dilithium (ML-DSA, FIPS 204) or FALCON (FN-DSA, FIPS 206). Ensure your TLS library (OpenSSL 3.3+, liboqs) supports the chosen scheme."
                },
                {
                    "category": "Certificate Public Key",
                    "finding": "id-ecPublicKey public key is vulnerable to Shor's Algorithm",
                    "severity": "HIGH",
                    "remediation": "Reissue the certificate with a post-quantum public key algorithm. Use ML-DSA (Dilithium) or SLH-DSA (SPHINCS+, FIPS 205) for the certificate signature. Co-ordinate with your CA — most major CAs are rolling out PQC certificate support in 2024-2025."
                },
                {
                    "category": "Hash Function",
                    "finding": "SHA256 has reduced strength under Grover's Algorithm",
                    "severity": "MEDIUM",
                    "remediation": "Upgrade the hash function to SHA-384 or SHA-512. SHA-256 has its effective security halved by Grover's algorithm (128-bit post-quantum). SHA-384 / SHA-512 retain acceptable post-quantum security margins."
                },
                {
                    "category": "Cipher Suite",
                    "finding": "TLS_AES_256_GCM_SHA384 cipher is Grover-resistant (AES-256)",
                    "severity": "INFO",
                    "remediation": "AES-256 cipher is acceptable. Grover's algorithm reduces effective key length to 128 bits, which remains within acceptable security margins for the foreseeable future. No action required."
                }
            ]
        }
    }
# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CypherQube — TLS Scanner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=IBM+Plex+Sans:wght@300;400;500;600&family=IBM+Plex+Sans+Condensed:wght@600;700&display=swap');

:root {
    --bg0:           #141414;
    --bg1:           #1c1c1c;
    --bg2:           #222222;
    --bg3:           #2a2a2a;
    --border:        #333333;
    --border-hi:     #444444;
    --text-1:        #e8e8e8;
    --text-2:        #a0a0a0;
    --text-3:        #606060;
    --red:           #e05252;
    --red-dim:       rgba(224,82,82,0.1);
    --red-border:    rgba(224,82,82,0.25);
    --amber:         #d4903a;
    --amber-dim:     rgba(212,144,58,0.09);
    --amber-border:  rgba(212,144,58,0.28);
    --green:         #52a878;
    --green-dim:     rgba(82,168,120,0.09);
    --green-border:  rgba(82,168,120,0.28);
    --blue:          #5b8db8;
    --blue-dim:      rgba(91,141,184,0.09);
    --blue-border:   rgba(91,141,184,0.28);
    --font-sans:     'IBM Plex Sans', sans-serif;
    --font-cond:     'IBM Plex Sans Condensed', sans-serif;
    --font-mono:     'IBM Plex Mono', monospace;
}

html, body, [class*="css"] {
    background-color: var(--bg0) !important;
    color: var(--text-1) !important;
    font-family: var(--font-sans) !important;
}
.stApp { background: var(--bg0) !important; }
.main .block-container { padding: 0 2.5rem 3rem !important; max-width: 1360px !important; }
#MainMenu, footer, .stDeployButton { display: none !important; }

/* Top bar */
.cq-topbar {
    background: var(--bg1);
    border-bottom: 1px solid var(--border);
    padding: 0 2.5rem;
    display: flex; align-items: center; justify-content: space-between;
    height: 52px; margin: 0 -2.5rem 2rem;
    position: sticky; top: 0; z-index: 100;
}
.cq-brand {
    font-family: var(--font-cond); font-weight: 700; font-size: 1.1rem;
    color: var(--text-1); text-transform: uppercase; letter-spacing: 0.08em;
    display: flex; align-items: center; gap: 10px;
}
.cq-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--green); box-shadow: 0 0 6px var(--green);
    animation: blink 3s ease-in-out infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.cq-topbar-meta { display:flex; align-items:center; gap:24px; }
.cq-topbar-item {
    font-family: var(--font-mono); font-size: 0.65rem; color: var(--text-3);
    letter-spacing: 0.08em; display:flex; align-items:center; gap:6px;
}
.cq-topbar-item span { color: var(--text-2); }

/* Section */
.cq-section { display:flex; align-items:center; gap:10px; margin-bottom:0.75rem; }
.cq-section-title { font-family:var(--font-mono); font-size:0.6rem; letter-spacing:0.3em; text-transform:uppercase; color:var(--text-3); white-space:nowrap; }
.cq-section-line  { flex:1; height:1px; background:var(--border); }

/* Card */
.cq-card { background:var(--bg1); border:1px solid var(--border); padding:1.2rem 1.4rem; margin-bottom:1rem; }
.cq-card-header {
    font-family:var(--font-mono); font-size:0.6rem; letter-spacing:0.25em; text-transform:uppercase;
    color:var(--text-3); padding-bottom:0.75rem; margin-bottom:1rem;
    border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:center;
}

/* Inputs */
.stTextInput input, .stNumberInput input {
    background:var(--bg2) !important; border:1px solid var(--border) !important;
    border-radius:2px !important; color:var(--text-1) !important;
    font-family:var(--font-mono) !important; font-size:0.85rem !important;
    transition:border-color 0.15s !important;
}
.stTextInput input:focus, .stNumberInput input:focus {
    border-color:var(--border-hi) !important; box-shadow:none !important;
}
.stTextInput label, .stNumberInput label {
    font-family:var(--font-mono) !important; font-size:0.6rem !important;
    letter-spacing:0.2em !important; text-transform:uppercase !important; color:var(--text-3) !important;
}

/* Button */
.stButton > button {
    background:var(--bg3) !important; border:1px solid var(--border-hi) !important;
    color:var(--text-1) !important; font-family:var(--font-mono) !important;
    font-size:0.7rem !important; letter-spacing:0.2em !important; text-transform:uppercase !important;
    border-radius:2px !important; padding:0.6rem 1.6rem !important; transition:background 0.15s !important;
}
.stButton > button:hover { background:#2e2e2e !important; border-color:#555 !important; }

/* Stat row */
.cq-stat-row { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--border); border:1px solid var(--border); margin-bottom:1.5rem; }
.cq-stat { background:var(--bg1); padding:1.1rem 1.3rem; }
.cq-stat-label { font-family:var(--font-mono); font-size:0.58rem; letter-spacing:0.22em; text-transform:uppercase; color:var(--text-3); margin-bottom:0.45rem; }
.cq-stat-value { font-family:var(--font-cond); font-weight:600; font-size:1.05rem; color:var(--text-1); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.cq-stat-value.large { font-size:1.55rem; font-weight:700; }
.val-red   { color:var(--red)   !important; }
.val-amber { color:var(--amber) !important; }
.val-green { color:var(--green) !important; }

/* Risk banner */
.cq-risk-row { display:flex; align-items:center; gap:12px; padding:0.8rem 1.2rem; border:1px solid; margin-bottom:1.5rem; font-family:var(--font-mono); font-size:0.7rem; letter-spacing:0.12em; }
.cq-risk-row.high   { border-color:var(--red-border);   background:var(--red-dim);   color:var(--red); }
.cq-risk-row.medium { border-color:var(--amber-border); background:var(--amber-dim); color:var(--amber); }
.cq-risk-row.low    { border-color:var(--green-border); background:var(--green-dim); color:var(--green); }
.cq-risk-badge { font-family:var(--font-cond); font-weight:700; font-size:0.7rem; letter-spacing:0.15em; padding:2px 8px; border:1px solid currentColor; }

/* Finding cards */
.cq-finding-card {
    border:1px solid var(--border);
    background:var(--bg1);
    margin-bottom:0.6rem;
    overflow:hidden;
}
.cq-finding-top {
    display:flex; align-items:flex-start; gap:12px;
    padding:0.9rem 1rem 0.75rem;
}
.cq-sev-pill {
    font-family:var(--font-mono); font-size:0.6rem; letter-spacing:0.12em;
    padding:2px 7px; border:1px solid; flex-shrink:0; margin-top:2px;
    text-transform:uppercase;
}
.sev-CRITICAL, .sev-HIGH   { border-color:var(--red-border);   color:var(--red);   background:var(--red-dim); }
.sev-MEDIUM                 { border-color:var(--amber-border); color:var(--amber); background:var(--amber-dim); }
.sev-INFO                   { border-color:var(--blue-border);  color:var(--blue);  background:var(--blue-dim); }
.sev-LOW                    { border-color:var(--green-border); color:var(--green); background:var(--green-dim); }

.cq-finding-category { font-family:var(--font-sans); font-weight:600; font-size:0.85rem; color:var(--text-1); margin-bottom:3px; }
.cq-finding-text     { font-family:var(--font-sans); font-size:0.83rem; color:var(--text-2); line-height:1.45; }

.cq-remediation {
    background:var(--bg2);
    border-top:1px solid var(--border);
    padding:0.75rem 1rem;
}
.cq-rem-label { font-family:var(--font-mono); font-size:0.56rem; letter-spacing:0.25em; text-transform:uppercase; color:var(--text-3); margin-bottom:4px; }
.cq-rem-text  { font-family:var(--font-sans); font-size:0.82rem; color:var(--text-2); line-height:1.5; }

/* KV table */
.cq-kv-table { width:100%; border-collapse:collapse; }
.cq-kv-table tr { border-bottom:1px solid var(--border); }
.cq-kv-table tr:last-child { border-bottom:none; }
.cq-kv-table td { padding:0.55rem 0; vertical-align:top; }
.cq-kv-key { font-family:var(--font-mono); font-size:0.64rem; letter-spacing:0.15em; text-transform:uppercase; color:var(--text-3); width:38%; padding-right:1rem; }
.cq-kv-val { font-family:var(--font-mono); font-size:0.8rem; color:var(--text-1); }

/* Download */
.stDownloadButton > button {
    background:transparent !important; border:1px solid var(--border) !important;
    color:var(--text-2) !important; font-family:var(--font-mono) !important;
    font-size:0.65rem !important; letter-spacing:0.18em !important; text-transform:uppercase !important;
    border-radius:2px !important;
}
.stDownloadButton > button:hover { border-color:var(--border-hi) !important; color:var(--text-1) !important; }

/* File uploader */
[data-testid="stFileUploader"] { background:var(--bg1) !important; border:1px dashed var(--border) !important; border-radius:2px !important; }

/* JSON */
.stJson > div { background:var(--bg2) !important; border:1px solid var(--border) !important; border-radius:2px !important; font-family:var(--font-mono) !important; font-size:0.76rem !important; }

/* Dataframe */
.stDataFrame { border:1px solid var(--border) !important; }
.stDataFrame th { background:var(--bg2) !important; color:var(--text-3) !important; font-family:var(--font-mono) !important; font-size:0.6rem !important; letter-spacing:0.18em !important; text-transform:uppercase !important; border:none !important; border-bottom:1px solid var(--border) !important; }
.stDataFrame td { font-family:var(--font-mono) !important; font-size:0.78rem !important; color:var(--text-2) !important; border-color:var(--border) !important; }

/* Progress */
.stProgress > div > div { background:var(--bg3) !important; border:1px solid var(--border) !important; border-radius:2px !important; }
.stProgress > div > div > div { background:var(--blue) !important; border-radius:1px !important; }

hr { border:none !important; border-top:1px solid var(--border) !important; margin:1.8rem 0 !important; }
::-webkit-scrollbar { width:5px; }
::-webkit-scrollbar-track { background:var(--bg0); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
</style>
""", unsafe_allow_html=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def normalize_target(t):
    return t.replace("https://","").replace("http://","").split("/")[0].strip()

def risk_meta(score):
    if score >= 7:   return "CRITICAL", "high",   "val-red"
    elif score >= 4: return "MODERATE", "medium",  "val-amber"
    else:            return "LOW",      "low",     "val-green"


# ─── Top bar ──────────────────────────────────────────────────────────────────

st.markdown("""
<div class="cq-topbar">
    <div class="cq-brand">
        <div class="cq-dot"></div>
        CypherQube
        <span style="font-weight:300;color:#555;font-size:0.75rem;margin-left:4px;">
            TLS / Quantum Risk Scanner
        </span>
    </div>
    <div class="cq-topbar-meta">
        <div class="cq-topbar-item">ENGINE <span>OpenSSL 3.x</span></div>
        <div class="cq-topbar-item">MODE <span>ACTIVE</span></div>
        <div class="cq-topbar-item">VERSION <span>2.1.0</span></div>
    </div>
</div>
""", unsafe_allow_html=True)


# ─── Scan Input ───────────────────────────────────────────────────────────────

st.markdown('<div class="cq-section"><div class="cq-section-title">Target</div><div class="cq-section-line"></div></div>', unsafe_allow_html=True)

c1, c2, c3 = st.columns([4, 1, 1])
with c1:
    target = st.text_input("DOMAIN", placeholder="e.g. github.com")
with c2:
    port = st.number_input("PORT", min_value=1, max_value=65535, value=443)
with c3:
    st.markdown("<br>", unsafe_allow_html=True)
    scan_button = st.button("Run Scan", use_container_width=True)


# ─── Results ──────────────────────────────────────────────────────────────────

if scan_button:
    if not target:
        st.error("Enter a target domain to continue.")
    else:
        target = normalize_target(target)
        with st.spinner(f"Scanning {target}:{port}..."):
            report = analyze_target(target, port)

        if report:
            tls          = report.get("tls_version", "—")
            cipher       = report.get("cipher_suite", "—")
            key_exchange = report.get("key_exchange", "—")
            cert         = report.get("certificate", {})
            risk         = report.get("quantum_risk", {})
            score        = risk.get("risk_score", 0)
            findings     = risk.get("findings", [])

            label, css, val_cls = risk_meta(score)

            st.markdown('<div class="cq-section" style="margin-top:1.5rem;"><div class="cq-section-title">Results</div><div class="cq-section-line"></div></div>', unsafe_allow_html=True)

            # Stat row
            st.markdown(f"""
            <div class="cq-stat-row">
                <div class="cq-stat">
                    <div class="cq-stat-label">TLS Version</div>
                    <div class="cq-stat-value">{tls}</div>
                </div>
                <div class="cq-stat">
                    <div class="cq-stat-label">Cipher Suite</div>
                    <div class="cq-stat-value" style="font-size:0.82rem;">{cipher}</div>
                </div>
                <div class="cq-stat">
                    <div class="cq-stat-label">Key Exchange</div>
                    <div class="cq-stat-value">{key_exchange}</div>
                </div>
                <div class="cq-stat">
                    <div class="cq-stat-label">Quantum Risk Score</div>
                    <div class="cq-stat-value large {val_cls}">{score}<span style="font-size:0.85rem;font-weight:400;color:#555">/10</span></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Risk banner
            desc = {
                "high":   f"Post-quantum vulnerabilities detected on {target}:{port}. Immediate remediation recommended.",
                "medium": f"Moderate quantum risk on {target}:{port}. Plan migration to PQC algorithms.",
                "low":    f"No significant quantum vulnerabilities found on {target}:{port}.",
            }
            st.markdown(f"""
            <div class="cq-risk-row {css}">
                <span class="cq-risk-badge">{label}</span>
                <span style="font-size:0.72rem;letter-spacing:0.06em;">{desc[css]}</span>
            </div>
            """, unsafe_allow_html=True)

            # Two columns
            left, right = st.columns([5, 4])

            with left:
                # ── Findings + Remediation ────────────────────────────────
                st.markdown(f"""
                <div class="cq-card">
                    <div class="cq-card-header">
                        <span>Quantum Risk Findings</span>
                        <span style="color:var(--text-3)">{len(findings)} finding(s)</span>
                    </div>
                """, unsafe_allow_html=True)

                if findings:
                    for f in findings:
                        sev      = f.get("severity", "INFO")
                        category = f.get("category", "")
                        finding  = f.get("finding", "")
                        rem      = f.get("remediation", "")
                        sev_css  = f"sev-{sev}"

                        st.markdown(f"""
                        <div class="cq-finding-card">
                            <div class="cq-finding-top">
                                <span class="cq-sev-pill {sev_css}">{sev}</span>
                                <div>
                                    <div class="cq-finding-category">{category}</div>
                                    <div class="cq-finding-text">{finding}</div>
                                </div>
                            </div>
                            <div class="cq-remediation">
                                <div class="cq-rem-label">Remediation</div>
                                <div class="cq-rem-text">{rem}</div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cq-finding-card">
                        <div class="cq-finding-top">
                            <span class="cq-sev-pill sev-LOW">PASS</span>
                            <div class="cq-finding-text">No quantum vulnerabilities detected. Configuration appears post-quantum safe.</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown('</div>', unsafe_allow_html=True)

            with right:
                # ── Certificate Details ───────────────────────────────────
                pub_alg  = cert.get("public_key_algorithm", "—")
                key_size = cert.get("key_size", "—")
                sig_alg  = cert.get("signature_algorithm", "—")
                issuer   = cert.get("issuer", "—")
                expiry   = cert.get("expiry", "—")

                st.markdown(f"""
                <div class="cq-card">
                    <div class="cq-card-header"><span>Certificate Details</span></div>
                    <table class="cq-kv-table">
                        <tr><td class="cq-kv-key">Public Key Algo</td><td class="cq-kv-val">{pub_alg}</td></tr>
                        <tr><td class="cq-kv-key">Key Size</td><td class="cq-kv-val">{key_size} bits</td></tr>
                        <tr><td class="cq-kv-key">Signature Algo</td><td class="cq-kv-val" style="font-size:0.72rem;">{sig_alg}</td></tr>
                        <tr><td class="cq-kv-key">Issuer</td><td class="cq-kv-val" style="font-size:0.72rem;word-break:break-all;">{issuer}</td></tr>
                        <tr><td class="cq-kv-key">Expiry</td><td class="cq-kv-val">{expiry}</td></tr>
                    </table>
                </div>
                """, unsafe_allow_html=True)

            # ── Export buttons ────────────────────────────────────────────
            st.markdown('<div class="cq-section" style="margin-top:0.5rem;"><div class="cq-section-title">Export</div><div class="cq-section-line"></div></div>', unsafe_allow_html=True)

            col_json, col_pdf, _ = st.columns([1, 1, 4])

            with col_json:
                st.download_button(
                    label="↓ JSON Report",
                    data=json.dumps(report, indent=4),
                    file_name=f"cypherqube_{target.replace(':','_')}.json",
                    mime="application/json",
                    use_container_width=True
                )

            with col_pdf:
                pdf_bytes = generate_pdf_report(report)
                st.download_button(
                    label="↓ PDF Report",
                    data=pdf_bytes,
                    file_name=f"cypherqube_{target.replace(':','_')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

            # ── Raw inventory ──────────────────────────────────────────────
            with st.expander("Raw Crypto Inventory (JSON)"):
                st.json(report)


# ─── Bulk Scanner ─────────────────────────────────────────────────────────────

st.markdown("<hr>", unsafe_allow_html=True)
st.markdown('<div class="cq-section"><div class="cq-section-title">Bulk Scan</div><div class="cq-section-line"></div></div>', unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload targets.txt — one domain per line", type=["txt"])

if uploaded_file:
    domains = [d.strip() for d in uploaded_file.read().decode().splitlines() if d.strip()]
    results = []
    progress = st.progress(0)

    for i, d in enumerate(domains):
        r = analyze_target(normalize_target(d), 443)
        if r:
            results.append(r)
        progress.progress((i + 1) / len(domains))

    st.markdown(f'<div class="cq-section" style="margin-top:1rem;"><div class="cq-section-title">{len(results)} Targets Scanned</div><div class="cq-section-line"></div></div>', unsafe_allow_html=True)

    table = []
    for r in results:
        s = r["quantum_risk"]["risk_score"]
        lbl, _, _ = risk_meta(s)
        table.append({
            "Target":       r["target"],
            "TLS":          r["tls_version"],
            "Cipher":       r["cipher_suite"],
            "Key Exchange": r["key_exchange"],
            "Risk Score":   s,
            "Risk Level":   lbl,
        })

    st.dataframe(pd.DataFrame(table), use_container_width=True)

    bcol1, bcol2, _ = st.columns([1, 1, 4])
    with bcol1:
        st.download_button("↓ Bulk JSON", json.dumps(results, indent=4),
                           "cypherqube_bulk.json", "application/json", use_container_width=True)


# ─── Footer ───────────────────────────────────────────────────────────────────

st.markdown("""
<div style="margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--border);
    display:flex;justify-content:space-between;">
    <span style="font-family:var(--font-mono);font-size:0.55rem;color:var(--text-3);letter-spacing:0.2em;">CYPHERCUBE © 2025</span>
    <span style="font-family:var(--font-mono);font-size:0.55rem;color:var(--text-3);letter-spacing:0.2em;">POST-QUANTUM CRYPTOGRAPHY READINESS</span>
</div>
""", unsafe_allow_html=True)