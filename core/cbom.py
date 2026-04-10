"""
core/cbom.py — CypherQube Cryptographic Bill of Materials (CBOM)

Purpose:
Generate structured crypto inventory for scanned assets.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Optional


@dataclass
class CBOMEntry:
    target: str
    port: int
    protocol: str  # HTTPS / TLS / API
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    key_exchange: Optional[str]
    certificate_issuer: Optional[str]
    public_key_algorithm: Optional[str]
    public_key_size: Optional[int]
    tls_signature: Optional[str]
    certificate_signature_algorithm: Optional[str]
    hash_function: Optional[str]
    risk_score: Optional[int]
    risk_label: Optional[str]
    pqc_readiness: Optional[str]
    quantum_safe: bool


class CBOMGenerator:
    def __init__(self):
        self.entries: List[CBOMEntry] = []

    def add_entry(
        self,
        target: str,
        port: int,
        protocol: str,
        tls_version: str = None,
        cipher_suite: str = None,
        key_exchange: str = None,
        certificate_issuer: str = None,
        public_key_algorithm: str = None,
        public_key_size: int = None,
        tls_signature: str = None,
        certificate_signature_algorithm: str = None,
        hash_function: str = None,
        risk_score: int = None,
        risk_label: str = None,
        pqc_readiness: str = None,
    ):
        quantum_safe = self._is_quantum_safe(
            cipher_suite,
            key_exchange,
            public_key_algorithm
        )

        entry = CBOMEntry(
            target=target,
            port=port,
            protocol=protocol,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            key_exchange=key_exchange,
            certificate_issuer=certificate_issuer,
            public_key_algorithm=public_key_algorithm,
            public_key_size=public_key_size,
            tls_signature=tls_signature,
            certificate_signature_algorithm=certificate_signature_algorithm,
            hash_function=hash_function,
            risk_score=risk_score,
            risk_label=risk_label,
            pqc_readiness=pqc_readiness,
            quantum_safe=quantum_safe,
        )

        self.entries.append(entry)

    def _is_quantum_safe(
        self,
        cipher: str,
        key_exchange: str,
        pubkey_algo: str
    ) -> bool:
        """
        Basic PQC check (can upgrade later)
        """

        if not cipher and not key_exchange and not pubkey_algo:
            return False

        # Known unsafe (quantum vulnerable)
        vulnerable_algos = ["RSA", "ECDHE", "ECDSA", "DH"]

        combined = f"{cipher} {key_exchange} {pubkey_algo}".upper()

        for algo in vulnerable_algos:
            if algo in combined:
                return False

        pqc_keywords = ["KYBER", "DILITHIUM", "FALCON"]

        for pqc in pqc_keywords:
            if pqc in combined:
                return True

        return False

    def to_dict(self) -> List[Dict]:
        return [asdict(entry) for entry in self.entries]

    def summary(self) -> Dict:
        total = len(self.entries)
        safe = sum(1 for e in self.entries if e.quantum_safe)
        unsafe = total - safe

        return {
            "total_assets": total,
            "quantum_safe": safe,
            "not_quantum_safe": unsafe,
            "risk_ratio": f"{unsafe}/{total}" if total else "0/0"
        }

    def clear(self):
        self.entries = []


if __name__ == "__main__":
    cbom = CBOMGenerator()

    cbom.add_entry(
        target="example.com",
        port=443,
        protocol="HTTPS",
        tls_version="TLS 1.2",
        cipher_suite="RSA_WITH_AES_128_GCM",
        key_exchange="RSA",
        certificate_issuer="Let's Encrypt",
        public_key_algorithm="RSA",
        public_key_size=2048
    )

    cbom.add_entry(
        target="secure-pqc.com",
        port=443,
        protocol="HTTPS",
        tls_version="TLS 1.3",
        cipher_suite="KYBER_AES_256",
        key_exchange="KYBER",
        public_key_algorithm="DILITHIUM",
        public_key_size=4096
    )

    print("\nCBOM Entries:")
    for e in cbom.to_dict():
        print(e)

    print("\nSummary:")
    print(cbom.summary())
