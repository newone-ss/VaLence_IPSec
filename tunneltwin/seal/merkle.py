"""
tunneltwin.seal.merkle -- Deterministic SHA-256 Merkle Tree Engine.

Serializes assessment findings, remediations, and evidence records canonically
and constructs a cryptographic binary Merkle tree over the leaf digests.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tunneltwin.core.db import Finding, Remediation


def serialize_finding(finding: Finding) -> dict[str, Any]:
    """Serialize a Finding into canonical key-value dictionary."""
    status_str = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    return {
        "type": "finding",
        "rule_id": str(finding.rule_id).strip(),
        "rule_framework": str(finding.rule_framework).strip(),
        "parameter": str(finding.parameter).strip(),
        "status": status_str.strip().upper(),
        "severity": str(finding.severity).strip().upper(),
        "detail": str(finding.detail).strip(),
        "evidence_refs": str(finding.evidence_refs).strip(),
    }


def serialize_remediation(remediation: Remediation) -> dict[str, Any]:
    """Serialize a Remediation into canonical key-value dictionary."""
    status_str = remediation.status.value if hasattr(remediation.status, "value") else str(remediation.status)
    return {
        "type": "remediation",
        "finding_id": remediation.finding_id,
        "vendor": str(remediation.vendor).strip(),
        "diff_text": str(remediation.diff_text).strip(),
        "status": status_str.strip().upper(),
    }


def canonical_json(data: dict[str, Any]) -> str:
    """Format dictionary as sorted, compact canonical JSON without whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_leaf(data: dict[str, Any]) -> str:
    """Compute SHA-256 digest of canonically serialized dictionary."""
    payload = canonical_json(data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Compute binary Merkle tree root hash from a list of leaf SHA-256 digests.

    Conventions:
    - Empty list -> SHA-256 of b"EMPTY_TREE"
    - Single leaf -> that leaf digest
    - Odd length at any level -> duplicate last digest (RFC 6962 convention)
    - Node combination: SHA-256(left_hex + right_hex)
    """
    if not leaf_hashes:
        return hashlib.sha256(b"EMPTY_TREE").hexdigest()

    current_layer = list(leaf_hashes)

    while len(current_layer) > 1:
        if len(current_layer) % 2 != 0:
            current_layer.append(current_layer[-1])

        next_layer: list[str] = []
        for i in range(0, len(current_layer), 2):
            combined = (current_layer[i] + current_layer[i + 1]).encode("utf-8")
            parent_hash = hashlib.sha256(combined).hexdigest()
            next_layer.append(parent_hash)

        current_layer = next_layer

    return current_layer[0]
