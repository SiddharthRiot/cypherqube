<div align="center">

<br/>

<img src="favicon.png" width="100" alt="CypherQube"/>

<br/>
<br/>

# ⬡ CypherQube

<h3>TLS / Quantum Risk Scanner</h3>

<h4><i>The only open-source tool that tells you exactly how vulnerable<br/>
your TLS infrastructure is to quantum computer attacks — right now.</i></h4>

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-721412?style=for-the-badge&logo=openssl&logoColor=white)
![NIST](https://img.shields.io/badge/NIST-PQC%20FIPS%20203--206-00875A?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

<br/>

![PNB](https://img.shields.io/badge/🏆%20PNB%20CyberSecurity-Hackathon%202026-FFD700?style=for-the-badge)
![IIT](https://img.shields.io/badge/🏛️%20IIT-Kanpur-003366?style=for-the-badge)
![Team](https://img.shields.io/badge/👥%20Team-Threat%20Lab-8B0000?style=for-the-badge)

<br/>
<br/>

[🚀 Quick Start](#️-installation) &nbsp;•&nbsp;
[✨ Features](#-features) &nbsp;•&nbsp;
[📊 Dashboard](#-usage) &nbsp;•&nbsp;
[🔬 Risk Scoring](#-risk-scoring) &nbsp;•&nbsp;
[🔐 NIST PQC](#-nist-pqc-algorithms-recognised) &nbsp;•&nbsp;
[👥 Team](#-team) &nbsp;•&nbsp;
[📚 References](#-references)

<br/>

---

### 🔴 95% of servers are quantum-vulnerable right now.
### CypherQube finds them in seconds.

---

</div>

<br/>

## 🧠 The Problem — Why This Matters

<br/>

The internet runs on cryptography — RSA, ECDSA, and Diffie-Hellman
protect **every HTTPS connection, every banking transaction, every
government communication** you make today.

**These algorithms will be broken by quantum computers.**

IBM, Google, and China are racing to build fault-tolerant quantum
machines. When they arrive, a quantum computer running
**Shor's Algorithm** can crack RSA-2048 in minutes — the same
encryption that would take classical computers billions of years.

<br/>

| | THE QUANTUM THREAT |
|---|---|
| **TODAY** | Harvest Now, Decrypt Later attacks |
| **NEAR FUTURE** | Quantum computers break RSA/ECDSA |
| **THE RISK** | All your past encrypted data exposed |
| **THE SOLUTION** | Migrate to NIST PQC algorithms NOW |
| **THE TOOL** | CypherQube scans and tells you what to fix — before it's too late |

<br/>

### 🎯 What is "Harvest Now, Decrypt Later"?

Adversaries are **already collecting** your encrypted traffic today —
storing it on hard drives — waiting for quantum computers to arrive
so they can decrypt it retroactively.

> *Your data encrypted today with RSA is NOT safe for the long term.*
> *Migration to post-quantum cryptography cannot wait.*

<br/>

### 📊 The Scale of the Problem

| Statistic | |
|---|---|
| **~95%** | of public servers still use quantum-vulnerable key exchange |
| **~99%** | of HTTPS connections use RSA or ECDSA certificates |
| **0** | open-source tools that scan and score PQC readiness (before CypherQube) |

<br/>

---

## ✨ Features

<br/>

| Feature | Description |
|---|---|
| 🔍 **TLS Scanning** | Connect to any domain:port via OpenSSL. Extract TLS version, cipher suite, key exchange, hash & signature algorithms |
| 📜 **Certificate Analysis** | Parse full X.509 certificate — public key algo, key size, issuer, subject CN, Not Before / Not After dates |
| ⚛️ **Quantum Risk Scoring** | Score 0–10 based on vulnerability to Shor's and Grover's algorithms. CRITICAL / MODERATE / LOW classification |
| ✅ **PQC Recognition** | Detects NIST FIPS 203/204/205/206 — ML-KEM, ML-DSA, SLH-DSA, FN-DSA. Marks post-quantum safe algorithms PASS |
| 🛠️ **Remediation Guidance** | Per-finding specific migration advice. Exact NIST algorithm replacement for every vulnerable component found |
| 📊 **Streamlit Dashboard** | Dark SIEM-style web UI at localhost:8501. Real-time results, findings, cert details, and risk score reference guide |
| 📄 **PDF Export** | Professional dark-themed report with all findings, scores, recommendations — ready for audit and compliance submission |
| 🖥️ **CLI Mode** | Full terminal interface with JSON and PDF export flags. Scriptable for automation pipelines |
| 🔁 **Bulk Scanning** | Scan up to 5 domains simultaneously. Batch results table with risk levels — one click to assess entire infrastructure |

<br/>

---

## ⚙️ Installation

<br/>

### Prerequisites

Before installing CypherQube, make sure you have:

```
✅  Python 3.10 or higher
✅  OpenSSL installed on your system
✅  Git installed
✅  pip (comes with Python)
```

<br/>

### Step 1 — Clone the Repository
```bash
git clone https://github.com/SiddharthRiot/cypherqube.git
cd cypherqube
```

<br/>

### Step 2 — Create Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate — Linux / macOS
source .venv/bin/activate

# Activate — Windows
.venv\Scripts\activate
```

<br/>

### Step 3 — Install Python Dependencies
```bash
pip install -r requirements.txt
```

<br/>

### Step 4 — Install OpenSSL
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install openssl

# macOS (using Homebrew)
brew install openssl

# Windows
# Download installer from:
# https://slproweb.com/products/Win32OpenSSL.html
# Choose Win64 OpenSSL v3.x — add to PATH during install
```

<br/>

### Step 5 — Verify Installation
```bash
# Check Python
python --version

# Check OpenSSL
openssl version

# You should see something like:
# Python 3.11.4
# OpenSSL 3.1.2
```

<br/>

---

## 🚀 Usage

<br/>

### 🌐 Web Dashboard
```bash
python -m streamlit run app.py
```

Open your browser and go to:
```
http://localhost:8501
```

You will see the full CypherQube dark SIEM-style dashboard with:
- Domain input field and port selector
- RUN SCAN button
- Real-time results (TLS version, cipher suite, key exchange, risk score)
- Quantum risk findings with severity badges
- Recommended remediation for each finding
- Full X.509 certificate details panel
- Risk score reference guide
- Bulk target assessment panel

<br/>

### ⌨️ CLI — Single Target Scan
```bash
# Basic scan — prints results to terminal
python main.py github.com

# Scan on custom port
python main.py github.com --port 8443

# Export results as JSON
python main.py github.com --json report.json

# Export results as PDF
python main.py github.com --pdf report.pdf

# Export both JSON and PDF together
python main.py github.com --json out.json --pdf out.pdf
```

<br/>

### 🔁 Bulk Target Scan
```bash
# Via dashboard — paste multiple domains in the Bulk Scan panel:
https://www.code.com
https://www.google.com
https://www.youtube.com

# Click Run Bulk Assessment
# Results table shows TLS version, cipher suite, key exchange,
# risk score and risk level for all targets
```

<br/>

### 📤 Example Output
```
Target        : github.com:443
TLS Version   : TLSv1.3
Cipher Suite  : TLS_AES_256_GCM_SHA384
Key Exchange  : X25519
Risk Score    : 7/10
Risk Level    : CRITICAL

Findings:
  [CRITICAL]  Key Exchange — X25519 vulnerable to Shor's Algorithm
              → Migrate to ML-KEM (CRYSTALS-Kyber, FIPS 203)

  [HIGH]      TLS Signature — ECDSA vulnerable to Shor's Algorithm
              → Replace with ML-DSA (CRYSTALS-Dilithium, FIPS 204)

  [MEDIUM]    Hash Function — SHA-256 weakened by Grover's Algorithm
              → Upgrade to SHA-384 or SHA-512
```

<br/>

---

## 📊 Risk Scoring

<br/>

### How the Score is Calculated

| Component | Score Impact | Threat |
|---|:---:|---|
| Key Exchange (ECDH / X25519 / RSA) | +3 pts | Shor's Algorithm |
| TLS Signature (ECDSA / RSA) | +3 pts | Shor's Algorithm |
| Certificate Public Key | +3 pts | Shor's Algorithm |
| Hash Function (SHA-256 / MD5) | +1 pt | Grover's Algorithm |
| Unknown Algorithm | +1 pt | Unverified |
| NIST PQC Algorithm Detected | 0 pts | ✅ PASS |

> **Start Score = 0.** Points are added per vulnerable component found. Final score is classified as CRITICAL / MODERATE / LOW.

<br/>

### Score Levels

| Score | Level | Badge | Meaning |
|:---:|:---:|:---:|---|
| 7–10 | CRITICAL | 🔴 | Multiple components vulnerable to Shor's algorithm. Immediate migration required. |
| 4–6  | MODERATE | 🟠 | Partial vulnerability detected. Migration strongly recommended. |
| 0–3  | LOW      | 🟢 | Minimal quantum risk. Monitor for future standard updates. |

<br/>

### Severity Levels

| Severity | Trigger | Score Impact |
|:---:|---|:---:|
| 🔴 CRITICAL | Key exchange algorithm broken by Shor's (X25519, ECDH, DH) | +3 |
| 🟠 HIGH | TLS signature or certificate public key broken by Shor's (ECDSA, RSA) | +3 each |
| 🟡 MEDIUM | Hash function or cipher weakened by Grover's algorithm (SHA-256, AES-128) | +1 |
| 🟢 PASS | NIST PQC standard algorithm detected — post-quantum safe | 0 |
| 🔵 INFO | Informational finding — no direct vulnerability, no score impact | 0 |
| ⚪ UNKNOWN | Unrecognised algorithm — cannot assess, manual review recommended | +1 |

<br/>

---

## 🔐 NIST PQC Algorithms Recognised

<br/>

CypherQube recognises all four NIST post-quantum cryptography
standards finalised in 2024 and marks them as **PASS** with
zero score penalty:

<br/>

| Standard | Algorithm | Full Name | Type | Status |
|:---:|:---:|---|:---:|:---:|
| FIPS 203 | **ML-KEM** | CRYSTALS-Kyber | Key Encapsulation | ✅ Final |
| FIPS 204 | **ML-DSA** | CRYSTALS-Dilithium | Digital Signature | ✅ Final |
| FIPS 205 | **SLH-DSA** | SPHINCS+ | Digital Signature | ✅ Final |
| FIPS 206 | **FN-DSA** | FALCON | Digital Signature | ✅ Final |

<br/>

### Hybrid Schemes Recognised

| Scheme | Type |
|---|---|
| `X25519MLKEM768` | Hybrid key exchange (classical + post-quantum) |
| `X25519Kyber768` | Hybrid key exchange (classical + post-quantum) |

> These hybrid schemes provide both classical and post-quantum
> security simultaneously — recognised and marked safe by CypherQube.

<br/>

---

## 🔒 Security Philosophy

<br/>

**CypherQube is a PASSIVE scanner.**

It performs only standard TLS handshakes — identical to what your browser does when visiting a website.

| | |
|---|---|
| ✅ | No exploit payloads sent |
| ✅ | No data modified on target server |
| ✅ | No intrusive probing |
| ✅ | No authentication required |
| ✅ | Works on any publicly accessible TLS endpoint |

> *It reads. It reports. It never touches.*

<br/>

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web dashboard UI |
| `reportlab` | PDF report generation |
| `pandas` | Data handling and batch scan results |

Install all with:
```bash
pip install -r requirements.txt
```

<br/>

---

## 🗺️ Roadmap

<br/>

| Detection | Integration | Intelligence |
|---|---|---|
| ☐ Hybrid PQC TLS detection | ☐ CI/CD pipeline plugin | ☐ Internet-wide PQC dataset |
| ☐ Full TLS 1.3 extension parsing | ☐ Nmap / Shodan API | ☐ Automated migration recommendations |
| ☐ OCSP & cert chain depth | ☐ SIEM webhook alerts | ☐ Multi-org SaaS dashboard |
| ☐ JA3 / JA3S fingerprinting | ☐ REST API for 3rd-party tools | ☐ Community algo updates |
| | ☐ GitHub Actions support | |

<br/>

---

## 📚 References

<br/>

| # | Reference | Description | Link |
|:---:|---|---|:---:|
| 1 | NIST FIPS 203 | ML-KEM (CRYSTALS-Kyber) Key Encapsulation Standard | [🔗 Link](https://csrc.nist.gov/pubs/fips/203/final) |
| 2 | NIST FIPS 204 | ML-DSA (CRYSTALS-Dilithium) Digital Signature Standard | [🔗 Link](https://csrc.nist.gov/pubs/fips/204/final) |
| 3 | NIST FIPS 205 | SLH-DSA (SPHINCS+) Digital Signature Standard | [🔗 Link](https://csrc.nist.gov/pubs/fips/205/final) |
| 4 | NIST FIPS 206 | FN-DSA (FALCON) Digital Signature Standard | [🔗 Link](https://csrc.nist.gov/pubs/fips/206/ipd) |
| 5 | OpenSSL | TLS/SSL and crypto library used for scanning | [🔗 Link](https://github.com/openssl/openssl) |
| 6 | CERT-In CBOM | Cryptographic Bill of Materials guidelines | [🔗 Link](https://www.cert-in.org.in) |
| 7 | RBI Circular | Quantum safe infrastructure mandate for banks | [🔗 Link](https://www.rbi.org.in) |
| 8 | PNB Hackathon | PSB CyberSecurity Hackathon 2026 problem statement | [🔗 Link](https://www.pnbindia.in) |

<br/>

---

## 👥 Team

<br/>

<div align="center">

<h3>⬡ TEAM THREAT LAB</h3>
<h4>PNB CyberSecurity Hackathon 2026 &nbsp;|&nbsp; IIT Kanpur</h4>

<br/>

<table>
  <tr>
    <td align="center" width="220">
      <br/>
      <img src="https://img.shields.io/badge/-%20%F0%9F%91%91%20TEAM%20LEADER%20-FFD700?style=for-the-badge" />
      <br/><br/>
      <b>Sumit</b>
      <br/>
      <sub>Full Stack Development</sub>
      <br/>
      <sub>Security Research</sub>
      <br/>
      <sub>Architecture Design</sub>
      <br/><br/>
      <a href="https://github.com/Sumit0x00">
        <img src="https://img.shields.io/badge/GitHub-Sumit0x00-181717?style=flat-square&logo=github"/>
      </a>
      <br/><br/>
    </td>
    <td align="center" width="220">
      <br/>
      <img src="https://img.shields.io/badge/-%20%F0%9F%92%BB%20DEVELOPER%20-4F46E5?style=for-the-badge" />
      <br/><br/>
      <b>Sidharth Kumar</b>
      <br/>
      <sub>Backend Development</sub>
      <br/>
      <sub>Risk Engine</sub>
      <br/>
      <sub>Scanner Module</sub>
      <br/><br/>
      <img src="https://img.shields.io/badge/GitHub-Developer-181717?style=flat-square&logo=github"/>
      <br/><br/>
    </td>
    <td align="center" width="220">
      <br/>
      <img src="https://img.shields.io/badge/-%20%F0%9F%A7%AA%20TESTER%20-22C55E?style=for-the-badge" />
      <br/><br/>
      <b>Rahul Rajak</b>
      <br/>
      <sub>Quality Assurance</sub>
      <br/>
      <sub>Testing & Validation</sub>
      <br/>
      <sub>Bug Reporting</sub>
      <br/><br/>
      <img src="https://img.shields.io/badge/GitHub-Tester-181717?style=flat-square&logo=github"/>
      <br/><br/>
    </td>
    <td align="center" width="220">
      <br/>
      <img src="https://img.shields.io/badge/-%20%F0%9F%8E%A8%20DESIGNER%20-EC4899?style=for-the-badge" />
      <br/><br/>
      <b>Roshan Pandit</b>
      <br/>
      <sub>UI/UX Design</sub>
      <br/>
      <sub>Documentation</sub>
      <br/>
      <sub>Presentation</sub>
      <br/><br/>
      <img src="https://img.shields.io/badge/GitHub-Designer-181717?style=flat-square&logo=github"/>
      <br/><br/>
    </td>
  </tr>
</table>

<br/>

![IIT Kanpur](https://img.shields.io/badge/🏛️%20Indian%20Institute%20of%20Technology-Kanpur-003366?style=for-the-badge)

<br/>

</div>

---

<div align="center">

<br/>

## ⬡ CypherQube

<h3><i>Scan today. Migrate before Q-Day.</i></h3>

<br/>

**Built with ❤️ by Team Threat Lab &nbsp;|&nbsp; IIT Kanpur**

<br/>

![visitors](https://visitor-badge.laobi.icu/badge?page_id=SiddhathRiot.cypherqube&left_color=black&right_color=red)

<br/>

*If this project helped you, please consider giving it a ⭐ on GitHub*

<br/>

</div>