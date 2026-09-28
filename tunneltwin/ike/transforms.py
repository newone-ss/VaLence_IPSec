"""
IKE Transform Proposal Generator for Elimination Scanning.

Generates comprehensive sets of IKEv2 and IKEv1 transform proposals
covering all known cryptographic suites.  These are used by the
elimination scanner to discover what a responder accepts.

Strategy:
  1. Start with the full proposal set.
  2. Send to target, observe accepted/rejected.
  3. Eliminate rejected transforms.
  4. Repeat until NO_PROPOSAL_CHOSEN to find the exact boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tunneltwin.ike.constants import (
    DHGroup,
    EncryptionAlgorithm,
    IKEv1AuthMethod,
    IKEv1EncryptionType,
    IKEv1GroupType,
    IKEv1HashType,
    IntegrityAlgorithmID,
    PRFAlgorithm,
    TransformType,
)

if TYPE_CHECKING:
    from tunneltwin.ike.codec import IKEv1TransformSpec

# ═══════════════════════════════════════════════════════════════════════
#  IKEv2 Transform Sets
# ═══════════════════════════════════════════════════════════════════════

# Standard AEAD ciphers (no separate integrity algorithm needed)
IKEV2_AEAD_CIPHERS: list[tuple[int, int | None]] = [
    # (algorithm_id, key_length_or_None)
    (EncryptionAlgorithm.ENCR_AES_GCM_16, 256),
    (EncryptionAlgorithm.ENCR_AES_GCM_16, 128),
    (EncryptionAlgorithm.ENCR_AES_GCM_12, 256),
    (EncryptionAlgorithm.ENCR_AES_GCM_12, 128),
    (EncryptionAlgorithm.ENCR_AES_GCM_8, 256),
    (EncryptionAlgorithm.ENCR_AES_GCM_8, 128),
    (EncryptionAlgorithm.ENCR_CHACHA20_POLY1305, None),
]

# Standard non-AEAD ciphers (require a separate integrity algorithm)
IKEV2_NON_AEAD_CIPHERS: list[tuple[int, int | None]] = [
    (EncryptionAlgorithm.ENCR_AES_CBC, 256),
    (EncryptionAlgorithm.ENCR_AES_CBC, 128),
    (EncryptionAlgorithm.ENCR_3DES, None),
    (EncryptionAlgorithm.ENCR_DES, None),
]

IKEV2_INTEGRITY_ALGORITHMS: list[int] = [
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_512_256,
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_384_192,
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128,
    IntegrityAlgorithmID.AUTH_HMAC_SHA1_96,
    IntegrityAlgorithmID.AUTH_HMAC_MD5_96,
]

IKEV2_PRF_ALGORITHMS: list[int] = [
    PRFAlgorithm.PRF_HMAC_SHA2_512,
    PRFAlgorithm.PRF_HMAC_SHA2_384,
    PRFAlgorithm.PRF_HMAC_SHA2_256,
    PRFAlgorithm.PRF_HMAC_SHA1,
    PRFAlgorithm.PRF_HMAC_MD5,
]

IKEV2_DH_GROUPS: list[int] = [
    DHGroup.CURVE_25519,
    DHGroup.ECP_521,
    DHGroup.ECP_384,
    DHGroup.ECP_256,
    DHGroup.MODP_8192,
    DHGroup.MODP_4096,
    DHGroup.MODP_3072,
    DHGroup.MODP_2048,
    DHGroup.MODP_1536,
    DHGroup.MODP_1024,
    DHGroup.MODP_768,
]


@dataclass
class IKEv2ProposalSpec:
    """
    Specification for an IKEv2 proposal to be sent in an SA payload.

    Each proposal contains one or more transforms of each type.
    The responder selects one of each type.
    """

    encryption: tuple[int, int | None]  # (algorithm_id, key_length|None)
    prf: int
    integrity: int | None = None  # None for AEAD ciphers
    dh_group: int = DHGroup.MODP_2048

    def to_transforms(self) -> list[tuple[int, int, int | None]]:
        """Convert to list of (transform_type, transform_id, key_length)."""
        transforms: list[tuple[int, int, int | None]] = []

        # Encryption
        encr_id, key_len = self.encryption
        transforms.append((TransformType.ENCR, encr_id, key_len))

        # PRF
        transforms.append((TransformType.PRF, self.prf, None))

        # Integrity (MUST NOT be present for AEAD ciphers: RFC 7296 §3.3, RFC 5282 §4.2)
        if self.integrity is not None and self.integrity != IntegrityAlgorithmID.AUTH_NONE:
            transforms.append((TransformType.INTEG, self.integrity, None))

        # DH Group
        transforms.append((TransformType.DH, self.dh_group, None))

        return transforms


def generate_ikev2_full_proposal_set(dh_group: int) -> list[list[tuple[int, int, int | None]]]:
    """
    Generate the full set of IKEv2 proposals for a single DH group.

    Each proposal is a unique (encryption, prf, integrity) combination.
    All proposals share the same DH group so we can test with one KE payload.

    Returns a list of proposal transform lists.
    """
    proposals: list[list[tuple[int, int, int | None]]] = []

    # AEAD proposals (integrity = NONE)
    for encr_id, key_len in IKEV2_AEAD_CIPHERS:
        for prf in IKEV2_PRF_ALGORITHMS:
            spec = IKEv2ProposalSpec(
                encryption=(encr_id, key_len),
                prf=prf,
                integrity=None,
                dh_group=dh_group,
            )
            proposals.append(spec.to_transforms())

    # Non-AEAD proposals (need integrity algorithm)
    for encr_id, key_len in IKEV2_NON_AEAD_CIPHERS:
        for integ in IKEV2_INTEGRITY_ALGORITHMS:
            for prf in IKEV2_PRF_ALGORITHMS:
                spec = IKEv2ProposalSpec(
                    encryption=(encr_id, key_len),
                    prf=prf,
                    integrity=integ,
                    dh_group=dh_group,
                )
                proposals.append(spec.to_transforms())

    return proposals


def generate_ikev2_dh_group_proposals(dh_group: int | None = None) -> list[list[tuple[int, int, int | None]]]:
    """
    Generate diverse proposals per DH group to discover which groups the
    responder accepts.

    Proposals cover:
      1. AEAD: AES-256-GCM + PRF-SHA384 (strong profile)
      2. AEAD: AES-128-GCM + PRF-SHA256
      3. Non-AEAD: AES-256-CBC + SHA2-256 + PRF-SHA2-256 (mixed profile)
      4. Non-AEAD: AES-128-CBC + SHA1 + PRF-SHA1 (legacy-cbc profile)
      5. Non-AEAD: 3DES-CBC + SHA1 + PRF-SHA1 (legacy fallback)
    """
    groups = [dh_group] if dh_group is not None else IKEV2_DH_GROUPS
    proposals: list[list[tuple[int, int, int | None]]] = []

    for grp in groups:
        # 1. AES-256-GCM (modern / strong)
        proposals.append(
            IKEv2ProposalSpec(
                encryption=(EncryptionAlgorithm.ENCR_AES_GCM_16, 256),
                prf=PRFAlgorithm.PRF_HMAC_SHA2_384,
                integrity=None,
                dh_group=grp,
            ).to_transforms()
        )
        # 2. AES-128-GCM
        proposals.append(
            IKEv2ProposalSpec(
                encryption=(EncryptionAlgorithm.ENCR_AES_GCM_16, 128),
                prf=PRFAlgorithm.PRF_HMAC_SHA2_256,
                integrity=None,
                dh_group=grp,
            ).to_transforms()
        )
        # 3. AES-256-CBC (standard enterprise / mixed)
        proposals.append(
            IKEv2ProposalSpec(
                encryption=(EncryptionAlgorithm.ENCR_AES_CBC, 256),
                prf=PRFAlgorithm.PRF_HMAC_SHA2_256,
                integrity=IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128,
                dh_group=grp,
            ).to_transforms()
        )
        # 4. AES-128-CBC + SHA1 (legacy-cbc)
        proposals.append(
            IKEv2ProposalSpec(
                encryption=(EncryptionAlgorithm.ENCR_AES_CBC, 128),
                prf=PRFAlgorithm.PRF_HMAC_SHA1,
                integrity=IntegrityAlgorithmID.AUTH_HMAC_SHA1_96,
                dh_group=grp,
            ).to_transforms()
        )
        # 5. 3DES-CBC (legacy fallback)
        proposals.append(
            IKEv2ProposalSpec(
                encryption=(EncryptionAlgorithm.ENCR_3DES, None),
                prf=PRFAlgorithm.PRF_HMAC_SHA1,
                integrity=IntegrityAlgorithmID.AUTH_HMAC_SHA1_96,
                dh_group=grp,
            ).to_transforms()
        )

    return proposals


def generate_ikev2_elimination_batch(
    dh_group: int,
    exclude_encr: set[tuple[int, int | None]] | None = None,
    exclude_prf: set[int] | None = None,
    exclude_integ: set[int] | None = None,
) -> list[list[tuple[int, int, int | None]]]:
    """
    Generate proposals for elimination scanning within a given DH group.

    exclude_* sets allow removing already-rejected transforms from
    subsequent iterations.
    """
    if exclude_encr is None:
        exclude_encr = set()
    if exclude_prf is None:
        exclude_prf = set()
    if exclude_integ is None:
        exclude_integ = set()

    proposals: list[list[tuple[int, int, int | None]]] = []

    # AEAD
    for encr_id, key_len in IKEV2_AEAD_CIPHERS:
        if (encr_id, key_len) in exclude_encr:
            continue
        for prf in IKEV2_PRF_ALGORITHMS:
            if prf in exclude_prf:
                continue
            spec = IKEv2ProposalSpec(
                encryption=(encr_id, key_len),
                prf=prf,
                integrity=None,
                dh_group=dh_group,
            )
            proposals.append(spec.to_transforms())

    # Non-AEAD
    for encr_id, key_len in IKEV2_NON_AEAD_CIPHERS:
        if (encr_id, key_len) in exclude_encr:
            continue
        for integ in IKEV2_INTEGRITY_ALGORITHMS:
            if integ in exclude_integ:
                continue
            for prf in IKEV2_PRF_ALGORITHMS:
                if prf in exclude_prf:
                    continue
                spec = IKEv2ProposalSpec(
                    encryption=(encr_id, key_len),
                    prf=prf,
                    integrity=integ,
                    dh_group=dh_group,
                )
                proposals.append(spec.to_transforms())

    return proposals


# ═══════════════════════════════════════════════════════════════════════
#  IKEv1 Transform Sets
# ═══════════════════════════════════════════════════════════════════════

IKEV1_ENCRYPTIONS: list[tuple[int, int | None]] = [
    # (IKEv1EncryptionType, key_length_or_None)
    (IKEv1EncryptionType.AES_CBC, 256),
    (IKEv1EncryptionType.AES_CBC, 128),
    (IKEv1EncryptionType.THREE_DES_CBC, None),
    (IKEv1EncryptionType.DES_CBC, None),
]

IKEV1_HASHES: list[int] = [
    IKEv1HashType.SHA2_256,
    IKEv1HashType.SHA2_384,
    IKEv1HashType.SHA2_512,
    IKEv1HashType.SHA1,
    IKEv1HashType.MD5,
]

IKEV1_DH_GROUPS: list[int] = [
    IKEv1GroupType.ECP_384,
    IKEv1GroupType.ECP_256,
    IKEv1GroupType.MODP_4096,
    IKEv1GroupType.MODP_3072,
    IKEv1GroupType.MODP_2048,
    IKEv1GroupType.MODP_1536,
    IKEv1GroupType.MODP_1024,
    IKEv1GroupType.MODP_768,
]


@dataclass
class IKEv1ProposalResult:
    """Result of IKEv1 proposal negotiation."""

    encryption: int
    key_length: int | None
    hash_alg: int
    auth_method: int
    dh_group: int


def generate_ikev1_full_transform_set(
    auth_method: int = IKEv1AuthMethod.PSK,
    exclude_encr: set[tuple[int, int | None]] | None = None,
    exclude_hash: set[int] | None = None,
    exclude_dh: set[int] | None = None,
) -> list[IKEv1TransformSpec]:
    """
    Generate full IKEv1 Main Mode transform set for batched proposal.

    Returns list of IKEv1TransformSpec for all (encryption, hash, dh_group) combos.
    """
    from tunneltwin.ike.codec import IKEv1TransformSpec as _IKEv1TransformSpec

    if exclude_encr is None:
        exclude_encr = set()
    if exclude_hash is None:
        exclude_hash = set()
    if exclude_dh is None:
        exclude_dh = set()

    specs: list[_IKEv1TransformSpec] = []

    for encr_id, key_len in IKEV1_ENCRYPTIONS:
        if (encr_id, key_len) in exclude_encr:
            continue
        for hash_alg in IKEV1_HASHES:
            if hash_alg in exclude_hash:
                continue
            for dh_group in IKEV1_DH_GROUPS:
                if dh_group in exclude_dh:
                    continue
                specs.append(
                    _IKEv1TransformSpec(
                        encryption=encr_id,
                        hash_alg=hash_alg,
                        auth_method=auth_method,
                        dh_group=dh_group,
                        key_length=key_len,
                    )
                )

    return specs
