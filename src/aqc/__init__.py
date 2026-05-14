"""Aegis Quantum-Cognitive (AQC).

A B2B open-source auditing tool that bridges Post-Quantum Cryptography
readiness, DARPA N3-class neural interfaces, and JADC2 tactical fabrics.

It identifies "Harvest Now, Decrypt Later" (HNDL) exposure on
bio/neural telemetry streams and produces a Cryptographic Bill of
Materials (CBOM) plus a Quantum-Resistant Identity-First Segmentation
remediation policy.
"""

from __future__ import annotations

__all__ = [
    "__version__",
    "PQC_APPROVED",
    "CLASSICAL_VULNERABLE",
    "BANNER",
]

__version__: str = "0.1.0"

PQC_APPROVED: frozenset[str] = frozenset(
    {
        "ML-KEM",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "KYBER",
        "ML-DSA",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "DILITHIUM",
        "SLH-DSA",
        "SPHINCS+",
        "FALCON",
        "FALCON-512",
        "FALCON-1024",
    }
)

CLASSICAL_VULNERABLE: frozenset[str] = frozenset(
    {
        "RSA",
        "RSA-1024",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "ECC",
        "ECDSA",
        "ECDH",
        "ECDHE",
        "X25519",
        "X448",
        "DH",
        "DHE",
        "DSA",
        "TLS_RSA",
        "TLS_ECDHE_RSA",
        "TLS_ECDHE_ECDSA",
    }
)

BANNER: str = r"""
   ___                _      ___                  _                 
  / _ \              (_)    / _ \                | |                
 / /_\ \ ___  __ _ _ ___   / /_\ \_   _  __ _ _ _| |_ _   _ _ __ ___
 |  _  |/ _ \/ _` | / __|  |  _  | | | |/ _` | '_| __| | | | '_ ` _ \
 | | | |  __/ (_| | \__ \  | | | | |_| | (_| | | | |_| |_| | | | | | |
 \_| |_/\___|\__, |_|___/  \_| |_/\__,_|\__,_|_|  \__|\__,_|_| |_| |_|
              __/ |
             |___/        Quantum-Cognitive Defense Suite v{version}
"""
