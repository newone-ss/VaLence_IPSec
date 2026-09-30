"""
tunneltwin.seal -- Cryptographic integrity engine, Merkle tree audit trail, and Ed25519 attestation.
"""

from tunneltwin.seal.attestation import (
    generate_attestation_certificate,
    save_attestation_certificate,
)
from tunneltwin.seal.engine import (
    SealReceipt,
    VerificationReport,
    seal_scan_run,
    verify_scan_run,
)
from tunneltwin.seal.merkle import (
    compute_merkle_root,
    hash_leaf,
    serialize_finding,
    serialize_remediation,
)
from tunneltwin.seal.signer import (
    get_or_create_keypair,
    sign_merkle_root,
    verify_signature,
)

__all__ = [
    "compute_merkle_root",
    "hash_leaf",
    "serialize_finding",
    "serialize_remediation",
    "get_or_create_keypair",
    "sign_merkle_root",
    "verify_signature",
    "seal_scan_run",
    "verify_scan_run",
    "SealReceipt",
    "VerificationReport",
    "generate_attestation_certificate",
    "save_attestation_certificate",
]
