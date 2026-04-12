# GitHub Copilot PR Review Instructions
## CypherQube — TLS/Quantum Risk Scanner
## Stack: Python 3.10+, Streamlit, OpenSSL (subprocess), ReportLab, Pandas

---

## Project Architecture (Read This First)

CypherQube is a **security tool** — a passive TLS scanner that detects quantum vulnerabilities in cryptographic configurations. Every PR must be reviewed with a security-first mindset.

### Module Responsibilities (Do NOT let these bleed into each other)

| File | Responsibility | What Must NOT Be Here |
|---|---|---|
| `scanner.py` | OpenSSL subprocess calls, raw output parsing, regex extraction | UI logic, risk scoring, print statements beyond debug |
| `risk_engine.py` | Pure scoring logic, algorithm classification, remediation text | Subprocess calls, Streamlit imports, I/O operations |
| `app.py` | Streamlit UI, user input handling, display only | Business logic, risk scoring, direct OpenSSL calls |
| `cli.py` | CLI argument parsing, output formatting | UI/Streamlit imports, business logic |
| `pdf_report.py` | ReportLab PDF generation only | Scanner logic, risk scoring |

**Flag any PR that violates this separation.**

---

## SECURITY (Always Blocking — Flag Everything)

This is a security product. Security flaws here are doubly unacceptable.

### Subprocess & OpenSSL Safety
- **NEVER allow `shell=True`** in any `subprocess.run()`, `subprocess.Popen()`, or similar call. CypherQube uses `_run_openssl_command()` with list args — flag any deviation from this pattern.
- User-supplied `target` (domain) and `port` values **must be validated** before being passed to any subprocess. Flag if a domain/port is passed directly without sanitisation.
- Port must be validated as an integer in range 1–65535. Flag string ports passed to f-strings that go into shell args.
- Domain inputs must be checked against a basic regex or allowlist pattern — flag raw user input passed directly to `_run_openssl_command()`.
- The hardcoded `DEFAULT_OPENSSL_PATH = r"D:\OpenSSL\..."` in `scanner.py` is a Windows dev path. Flag any PR that doesn't abstract this properly for cross-platform use.

### Secrets & Credentials
- No API keys, tokens, passwords, or internal IPs hardcoded anywhere.
- No `.env` files committed. Ensure `.gitignore` covers them.
- Flag any new environment variable that isn't documented in README.

### Output Sanitisation
- OpenSSL stdout/stderr is parsed via regex in `scanner.py`. Flag any PR that uses `.split()` or direct string indexing on raw OpenSSL output instead of regex with proper groups.
- `extract_*` functions must handle `None` and empty string gracefully — they already return `"Unknown"` as default. Flag if new extractors break this pattern.

---

## RISK ENGINE INTEGRITY (Always Blocking for risk_engine.py changes)

The risk engine is the core of CypherQube. Accuracy here directly affects scan results.

### Algorithm Lists (QUANTUM_VULNERABLE, PQC_KEM, PQC_SIG, etc.)
- Any addition to `QUANTUM_VULNERABLE`, `PQC_KEM`, `PQC_SIG`, `PARTIAL_RISK`, `HASH_SAFE`, `CIPHER_SAFE`, `CIPHER_WEAK` **must include**:
  - The NIST standard or RFC reference as a comment next to the entry
  - A corresponding test case in `/tests/` that verifies the new algorithm is classified correctly
  - An update to the NIST PQC table in `README.md` if it's a new recognised PQC algorithm
- Flag additions without all three of the above.

### Scoring Logic
- `analyze_quantum_risk()` must remain **pure** — no I/O, no subprocess calls, no Streamlit calls, no `print()` statements. Flag any such addition.
- Score must be capped at 10 via `min(score, 10)`. Flag if this cap is removed.
- The `_check_component()` function checks PQC-safe **before** vulnerable — this priority order must not be reversed. Flag any change to this order.
- `calculate_risk_score()` is a test-compatibility wrapper with a different scoring model than `analyze_quantum_risk()`. Flag any PR that conflates the two or removes either.

### Remediation Text (REMEDIATION dict)
- Remediation strings must reference specific NIST FIPS standards (203/204/205/206) where applicable.
- Flag vague remediation text like "upgrade your crypto" without specific algorithm recommendations.
- Flag any PR that removes the "harvest now, decrypt later" reference from key exchange remediation — this is intentional and critical context.

---

## CODE QUALITY

### General Python
- No `except: pass` or bare `except Exception` without handling. Every caught exception must be surfaced appropriately, but **do not require `print()` in every module**: `print()` is acceptable in CLI/UI layers (for example `cli.py`), Streamlit-facing code should use UI/display mechanisms as appropriate, and core modules should prefer structured logging or propagate errors upward. In particular, keep `risk_engine.py` pure/no I/O, and do not add non-debug `print()` calls to `scanner.py`.
- No `eval()`, `exec()`, or dynamic imports.
- Type hints are encouraged on new functions. Flag functions with 4+ params that have no type hints.
- f-strings preferred over `.format()` or `%` formatting — consistent with existing code.
- All new public functions must have a docstring. `_private` helpers can be brief.

### scanner.py Specific
- All `extract_*` functions follow the pattern: try multiple regex patterns in order, return `"Unknown"` on failure. New extractors **must** follow this pattern.
- `run_openssl()` and `get_certificate()` both go through `_run_openssl_command()`. Flag any PR that calls `subprocess.run()` directly outside this wrapper.
- `analyze_target()` is the main pipeline — flag PRs that add new steps to this function without updating the docstring that describes the pipeline steps.

### app.py / Streamlit Specific
- All business logic (scanning, scoring) must go through `scanner.analyze_target()` or `risk_engine.analyze_quantum_risk()` — not implemented inline in `app.py`.
- Streamlit state must use `st.session_state` for anything that needs to persist across reruns. Flag raw Python variables used for scan results.
- Bulk scan (up to 5 domains) — flag any PR that raises this limit without performance/rate-limiting consideration.
- Flag any `st.write()` calls that print raw dict output — results must be formatted before display.

### pdf_report.py Specific
- All colours must use the existing dark-theme colour variables — flag hardcoded hex values like `#FF0000`.
- Flag any PDF layout changes that don't include a screenshot or rendered output in the PR description — PDF layout bugs are invisible in code review without visuals.
- ReportLab `Table` objects must specify `colWidths` — flag tables without explicit column widths (causes layout breaks on different page sizes).

---

## TESTING

### What Requires Tests
- Any new algorithm added to `QUANTUM_VULNERABLE`, `PQC_KEM`, `PQC_SIG`, etc. → test that `analyze_quantum_risk()` classifies it correctly.
- Any change to scoring weights → test that known inventory dicts produce the expected score.
- Any new `extract_*` function in `scanner.py` → test with sample OpenSSL output strings.
- Any new CLI flag in `cli.py` → test the argument parser.

### Test Quality
- Tests must use **real-ish OpenSSL output strings** as fixtures — not just `{"key_exchange": "X25519"}` dicts where a regex extractor is being tested.
- Flag tests that only assert `result is not None` — assertions must check actual values.
- Flag tests that mock `subprocess.run` at the wrong level — mock `_run_openssl_command`, not `subprocess.run` directly.
- Score tests must check both the `score` value and the `severity` of specific findings, not just one.

---

## PR STRUCTURE

### Title Format
All PR titles must use conventional commits:
```
feat:     New feature (new algorithm detection, new scan mode)
fix:      Bug fix
security: Security fix (ALWAYS flag for extra review)
perf:     Performance improvement
refactor: Code restructure, no behaviour change
test:     Test additions/fixes only
docs:     Documentation only
chore:    Dependency updates, CI config, tooling
```

Flag PRs with titles like "fixed stuff", "updates", "WIP" — these must be renamed before merge.

### Description Must Include
- **What changed** — which modules, what behaviour
- **Why** — the problem being solved or feature being added
- **How to test** — manual steps or test commands to verify
- For `pdf_report.py` changes: a screenshot of the PDF output
- For scoring changes: before/after score comparison for at least 2 known targets (e.g. `github.com:443`, `google.com:443`)
- For new algorithm support: the NIST/RFC reference link

### Size
- PRs over 400 lines changed (excluding test files and `requirements.txt`) should be flagged for breakdown unless they are a single atomic feature.
- PRs that touch both `risk_engine.py` AND `scanner.py` AND `app.py` in the same change should be flagged — these are likely doing too much at once.

---

## Review Comment Prefixes

Use these consistently so the team can triage comments:

| Prefix | Meaning | Blocks Merge? |
|---|---|---|
| `[BLOCKING]` | Must be fixed before merge | Yes |
| `[SECURITY]` | Security concern — always treated as blocking | Yes |
| `[TEST-REQUIRED]` | Missing test that must be added | Yes |
| `[SUGGESTION]` | Optional improvement, not required | No |
| `[QUESTION]` | Needs clarification before approving | Hold |
| `[NIST-REF]` | Missing NIST standard reference | Yes (for algorithm changes) |
| `[PERF]` | Performance concern worth discussing | No (unless severe) |

---

## ✅ Merge Checklist (Copilot Should Verify All of These)

- [ ] No `shell=True` in any subprocess call
- [ ] User inputs (domain, port) validated before reaching OpenSSL
- [ ] No hardcoded secrets, keys, or internal paths
- [ ] `risk_engine.py` remains pure (no I/O, no Streamlit, no subprocess)
- [ ] `app.py` contains no business logic
- [ ] New algorithms have NIST references and tests
- [ ] All new `extract_*` functions return `"Unknown"` on failure
- [ ] PR title follows conventional commits format
- [ ] PR description explains what, why, and how to test
- [ ] PDF changes include a screenshot
- [ ] Score changes include before/after comparison
