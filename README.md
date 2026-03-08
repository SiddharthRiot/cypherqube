# ⬡ CypherQube — TLS / Quantum Risk Scanner

A proof-of-concept security tool that scans TLS services, builds a cryptographic inventory, and assesses **post-quantum risk** based on NIST PQC standards (FIPS 203/204/205/206).

---

## Features

- 🔍 **TLS Scanning** — connects via OpenSSL, extracts TLS version, cipher suite, key exchange, hash, and signature algorithms
- 📜 **Certificate Analysis** — parses public key algorithm, key size, issuer, and expiry
- ⚛️ **Quantum Risk Scoring** — scores 0–10 based on vulnerability to Shor's and Grover's algorithms
- ✅ **PQC Algorithm Recognition** — detects NIST-standard ML-KEM, ML-DSA, SLH-DSA, FN-DSA
- 🛠️ **Remediation Guidance** — per-finding migration advice to post-quantum alternatives
- 📊 **Streamlit Dashboard** — visual UI with graphite SIEM-style theme
- 📄 **PDF Export** — professional dark-themed report with findings and remediation
- 🖥️ **CLI Mode** — scan from terminal, export JSON or PDF

---

## Project Structure

```
cypherQube/
├── app.py            # Streamlit web dashboard
├── cli.py           # CLI entry point
├── scanner.py        # OpenSSL TLS scanner & certificate parser
├── risk_engine.py    # Quantum risk scoring engine
├── pdf_report.py     # PDF report generator (reportlab)
└── requirements.txt
```

---

## Installation

```bash
git clone https://github.com/Sumit0x00/cypherqube.git
cd cypherqube

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

**Requirements:** OpenSSL must be installed on your system.

```bash
# Ubuntu/Debian
sudo apt install openssl

# macOS
brew install openssl
```

---

## Usage

### Web Dashboard
```bash
streamlit run app.py
```

### CLI — Single Target
```bash
python main.py github.com
python main.py github.com --port 443 --json report.json
python main.py github.com --pdf report.pdf
```

### CLI — JSON + PDF together
```bash
python main.py example.com --json out.json --pdf out.pdf
```

---

## Risk Scoring

| Score | Level    | Meaning                                      |
|-------|----------|----------------------------------------------|
| 7–10  | CRITICAL | Multiple components vulnerable to Shor's algorithm |
| 4–6   | MODERATE | Partial vulnerability, migration recommended |
| 0–3   | LOW      | Minimal quantum risk                         |

### Severity Levels

| Severity | Description |
|----------|-------------|
| CRITICAL | Key exchange broken by Shor's algorithm (+3) |
| HIGH     | Signature / cert public key broken by Shor's (+3 each) |
| MEDIUM   | Hash/cipher weakened by Grover's algorithm (+1) |
| PASS     | NIST PQC algorithm detected — post-quantum safe |
| INFO     | Informational, no score impact |
| UNKNOWN  | Unrecognised algorithm, manual review needed (+1) |

---

## NIST PQC Algorithms Recognised

| Standard | Algorithm | Type |
|----------|-----------|------|
| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | Key Encapsulation |
| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | Digital Signature |
| FIPS 205 | SLH-DSA (SPHINCS+) | Digital Signature |
| FIPS 206 | FN-DSA (FALCON) | Digital Signature |

Hybrid schemes (e.g. `X25519MLKEM768`, `X25519Kyber768`) are also recognised.

---

## Requirements

```
streamlit
reportlab
pandas
```

---

## License

MIT License — built for educational and research purposes.
