"""
tests/test_risk_engine.py — Unit tests for Risk Engine
"""

from modules.risk_engine import calculate_risk_score


def test_high_risk_rsa():
    score = calculate_risk_score(
        tls_version="TLS 1.2",
        cipher_suite="RSA_WITH_AES_128_GCM",
        key_exchange="RSA",
        public_key_algorithm="RSA",
        public_key_size=2048
    )

    assert isinstance(score, int)
    assert score >= 7   # RSA = high quantum risk


def test_low_risk_pqc():
    score = calculate_risk_score(
        tls_version="TLS 1.3",
        cipher_suite="KYBER_AES_256",
        key_exchange="KYBER",
        public_key_algorithm="DILITHIUM",
        public_key_size=4096
    )

    assert isinstance(score, int)
    assert score <= 2   # PQC = low risk


def test_medium_risk_mixed():
    score = calculate_risk_score(
        tls_version="TLS 1.3",
        cipher_suite="ECDHE_RSA_WITH_AES_256_GCM",
        key_exchange="ECDHE",
        public_key_algorithm="RSA",
        public_key_size=2048
    )

    assert 3 <= score <= 6   # Mixed crypto = medium risk

def test_weak_tls_version():
    score = calculate_risk_score(
        tls_version="TLS 1.1",
        cipher_suite="RSA_WITH_AES_128_CBC",
        key_exchange="RSA",
        public_key_algorithm="RSA",
        public_key_size=1024
    )

    assert score >= 8   # Weak TLS + weak key = very high risk


def test_strong_but_not_quantum_safe():
    score = calculate_risk_score(
        tls_version="TLS 1.3",
        cipher_suite="ECDHE_ECDSA_WITH_AES_256_GCM",
        key_exchange="ECDHE",
        public_key_algorithm="ECDSA",
        public_key_size=384
    )

    assert 4 <= score <= 7   # Strong classical ≠ quantum safe


def test_missing_data():
    score = calculate_risk_score(
        tls_version=None,
        cipher_suite=None,
        key_exchange=None,
        public_key_algorithm=None,
        public_key_size=None
    )

    assert isinstance(score, int)
    assert score >= 5   # Unknown = risky assumption


def test_score_bounds():
    score = calculate_risk_score(
        tls_version="TLS 1.3",
        cipher_suite="KYBER_AES_256",
        key_exchange="KYBER",
        public_key_algorithm="DILITHIUM",
        public_key_size=4096
    )

    assert 0 <= score <= 10


def test_deterministic_behavior():
    params = dict(
        tls_version="TLS 1.2",
        cipher_suite="RSA_WITH_AES_128_GCM",
        key_exchange="RSA",
        public_key_algorithm="RSA",
        public_key_size=2048
    )

    score1 = calculate_risk_score(**params)
    score2 = calculate_risk_score(**params)

    assert score1 == score2  # Same input → same output


def test_risk_increases_with_weaker_keys():
    strong = calculate_risk_score(
        tls_version="TLS 1.3",
        cipher_suite="ECDHE_RSA_WITH_AES_256_GCM",
        key_exchange="ECDHE",
        public_key_algorithm="RSA",
        public_key_size=4096
    )

    weak = calculate_risk_score(
        tls_version="TLS 1.2",
        cipher_suite="RSA_WITH_AES_128_CBC",
        key_exchange="RSA",
        public_key_algorithm="RSA",
        public_key_size=1024
    )

    assert weak > strong
