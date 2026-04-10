"""Structured NIST PQC reference data."""

NIST_PQC_STANDARDS = {
    "FIPS 203": {
        "id": "FIPS 203",
        "name": "ML-KEM",
        "family": "Key Encapsulation",
        "algorithms": ["ML-KEM", "MLKEM", "KYBER", "X25519MLKEM768", "X25519KYBER768"],
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "FIPS 204": {
        "id": "FIPS 204",
        "name": "ML-DSA",
        "family": "Digital Signatures",
        "algorithms": ["ML-DSA", "MLDSA", "DILITHIUM"],
        "url": "https://csrc.nist.gov/pubs/fips/204/final",
    },
    "FIPS 205": {
        "id": "FIPS 205",
        "name": "SLH-DSA",
        "family": "Digital Signatures",
        "algorithms": ["SLH-DSA", "SLHDSA", "SPHINCS", "SPHINCS+"],
        "url": "https://csrc.nist.gov/pubs/fips/205/final",
    },
    "FIPS 206": {
        "id": "FIPS 206",
        "name": "FN-DSA",
        "family": "Digital Signatures",
        "algorithms": ["FN-DSA", "FNDSA", "FALCON"],
        "url": "https://csrc.nist.gov/pubs/fips/206/final",
    },
}


def standards_for_text(value: str) -> list[dict]:
    """Return matching NIST standards for an algorithm label."""
    if not value:
        return []

    value_upper = value.upper()
    matches = []
    for standard in NIST_PQC_STANDARDS.values():
        if any(token in value_upper for token in standard["algorithms"]):
            matches.append(standard)
    return matches
