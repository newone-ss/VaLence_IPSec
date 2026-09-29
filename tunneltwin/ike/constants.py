"""
IKEv2 and IKEv1 Protocol Constants — RFC 7296, RFC 2409, RFC 3526, RFC 5903.

All numeric identifiers are sourced directly from IANA IKE registries.
No code copied from any external repository; all values from official RFCs.
"""

from __future__ import annotations

from enum import IntEnum

# ─── IKE Header ─────────────────────────────────────────────────────
# RFC 7296 §3.1 — IKE Header Format

IKE_HEADER_LENGTH = 28  # Fixed IKE header is always 28 bytes
IKE_SA_INIT_SPI_ZERO = b"\x00" * 8  # Responder SPI is 0 in IKE_SA_INIT
NON_ESP_MARKER = b"\x00" * 4  # 4 zero bytes prepended on port 4500


class ExchangeType(IntEnum):
    """RFC 7296 §3.1 — Exchange Type field values."""

    # IKEv2
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37

    # IKEv1 (RFC 2408)
    IKEV1_BASE = 1
    IKEV1_IDENTITY_PROTECTION = 2  # Main Mode
    IKEV1_AUTHENTICATION_ONLY = 3
    IKEV1_AGGRESSIVE = 4
    IKEV1_INFORMATIONAL = 5


class IKEFlag(IntEnum):
    """RFC 7296 §3.1 — Flags field bits."""

    INITIATOR = 0x08
    VERSION = 0x10
    RESPONSE = 0x20


IKEV2_MAJOR = 2
IKEV2_MINOR = 0
IKEV1_MAJOR = 1
IKEV1_MINOR = 0


# ─── Payload Types ──────────────────────────────────────────────────
# RFC 7296 §3.2 — Next Payload Type values


class PayloadType(IntEnum):
    """Payload type identifiers from IANA registry."""

    NONE = 0  # No Next Payload

    # IKEv2 payloads (33+)
    SA = 33  # Security Association
    KE = 34  # Key Exchange
    IDI = 35  # Identification — Initiator
    IDR = 36  # Identification — Responder
    CERT = 37  # Certificate
    CERTREQ = 38  # Certificate Request
    AUTH = 39  # Authentication
    NONCE = 40  # Nonce
    NOTIFY = 41  # Notify
    DELETE = 42  # Delete
    VENDOR_ID = 43  # Vendor ID
    TSI = 44  # Traffic Selector — Initiator
    TSR = 45  # Traffic Selector — Responder
    SK = 46  # Encrypted and Authenticated
    CP = 47  # Configuration
    EAP = 48  # Extensible Authentication

    # IKEv1 payloads (RFC 2408)
    IKEV1_SA = 1
    IKEV1_PROPOSAL = 2
    IKEV1_TRANSFORM = 3
    IKEV1_KE = 4
    IKEV1_ID = 5
    IKEV1_CERT = 6
    IKEV1_CERTREQ = 7
    IKEV1_HASH = 8
    IKEV1_SIG = 9
    IKEV1_NONCE = 10
    IKEV1_NOTIFY = 11
    IKEV1_DELETE = 12
    IKEV1_VENDOR_ID = 13


# ─── IKEv2 Transform Types ─────────────────────────────────────────
# RFC 7296 §3.3.2


class TransformType(IntEnum):
    """IKEv2 Transform Type identifiers."""

    ENCR = 1  # Encryption Algorithm
    PRF = 2  # Pseudorandom Function
    INTEG = 3  # Integrity Algorithm
    DH = 4  # Diffie-Hellman Group
    ESN = 5  # Extended Sequence Numbers


# ─── Encryption Algorithms ──────────────────────────────────────────
# IANA "IKEv2 Transform Type 1 — Encryption Algorithm" registry


class EncryptionAlgorithm(IntEnum):
    """IANA Transform Type 1 — Encryption Algorithm IDs."""

    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_BLOWFISH = 7
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_CHACHA20_POLY1305 = 28


# ─── PRF Algorithms ─────────────────────────────────────────────────
# IANA "IKEv2 Transform Type 2 — Pseudo-random Function" registry


class PRFAlgorithm(IntEnum):
    """IANA Transform Type 2 — PRF Algorithm IDs."""

    PRF_HMAC_MD5 = 1
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_XCBC = 4


# ─── Integrity Algorithms ───────────────────────────────────────────
# IANA "IKEv2 Transform Type 3 — Integrity Algorithm" registry


class IntegrityAlgorithmID(IntEnum):
    """IANA Transform Type 3 — Integrity Algorithm IDs."""

    AUTH_NONE = 0
    AUTH_HMAC_MD5_96 = 1
    AUTH_HMAC_SHA1_96 = 2
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14


# ─── Diffie-Hellman Groups ──────────────────────────────────────────
# IANA "IKEv2 Transform Type 4 — Diffie-Hellman Group" registry
# RFC 3526, RFC 5903, RFC 8031


class DHGroup(IntEnum):
    """IANA Transform Type 4 — Diffie-Hellman Group IDs."""

    DH_NONE = 0
    MODP_768 = 1
    MODP_1024 = 2
    MODP_1536 = 5
    MODP_2048 = 14
    MODP_3072 = 15
    MODP_4096 = 16
    MODP_6144 = 17
    MODP_8192 = 18
    ECP_256 = 19
    ECP_384 = 20
    ECP_521 = 21
    CURVE_25519 = 31
    CURVE_448 = 32


# ─── Notify Message Types ───────────────────────────────────────────
# RFC 7296 §3.10.1


class NotifyType(IntEnum):
    """IKEv2 Notify Message Type identifiers."""

    # Error types (1-16383)
    UNSUPPORTED_CRITICAL_PAYLOAD = 1
    INVALID_IKE_SPI = 4
    INVALID_MAJOR_VERSION = 5
    INVALID_SYNTAX = 7
    INVALID_MESSAGE_ID = 9
    INVALID_SPI = 11
    NO_PROPOSAL_CHOSEN = 14
    INVALID_KE_PAYLOAD = 17
    AUTHENTICATION_FAILED = 24
    SINGLE_PAIR_REQUIRED = 34
    NO_ADDITIONAL_SAS = 35
    INTERNAL_ADDRESS_FAILURE = 36
    FAILED_CP_REQUIRED = 37
    TS_UNACCEPTABLE = 38
    INVALID_SELECTORS = 39

    # Status types (16384+)
    INITIAL_CONTACT = 16384
    SET_WINDOW_SIZE = 16385
    ADDITIONAL_TS_POSSIBLE = 16386
    IPCOMP_SUPPORTED = 16387
    NAT_DETECTION_SOURCE_IP = 16388
    NAT_DETECTION_DESTINATION_IP = 16389
    COOKIE = 16390
    USE_TRANSPORT_MODE = 16391
    REKEY_SA = 16393
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394
    NON_FIRST_FRAGMENTS_ALSO = 16395
    REDIRECT_SUPPORTED = 16406
    REDIRECT = 16407
    IKEV2_FRAGMENTATION_SUPPORTED = 16430


# ─── IKEv1 Transform IDs ────────────────────────────────────────────
# RFC 2409, IANA "IKEv1 Phase I Transform" registry


class IKEv1EncryptionType(IntEnum):
    """IKEv1 Phase 1 Encryption Algorithm IDs (attribute type 1)."""

    DES_CBC = 1
    IDEA_CBC = 2
    BLOWFISH_CBC = 3
    THREE_DES_CBC = 5
    AES_CBC = 7


class IKEv1HashType(IntEnum):
    """IKEv1 Phase 1 Hash Algorithm IDs (attribute type 2)."""

    MD5 = 1
    SHA1 = 2
    SHA2_256 = 4
    SHA2_384 = 5
    SHA2_512 = 6


class IKEv1AuthMethod(IntEnum):
    """IKEv1 Phase 1 Authentication Method (attribute type 3)."""

    PSK = 1
    DSS_SIG = 2
    RSA_SIG = 3
    RSA_ENC = 4
    RSA_REV_ENC = 5


class IKEv1GroupType(IntEnum):
    """IKEv1 DH Group IDs (attribute type 4). Same numbering as IKEv2."""

    MODP_768 = 1
    MODP_1024 = 2
    MODP_1536 = 5
    MODP_2048 = 14
    MODP_3072 = 15
    MODP_4096 = 16
    ECP_256 = 19
    ECP_384 = 20


class IKEv1LifeType(IntEnum):
    """IKEv1 SA Life Type attribute (attribute type 11)."""

    SECONDS = 1
    KILOBYTES = 2


# IKEv1 SA attribute type IDs (RFC 2409 Appendix A)
IKEV1_ATTR_ENCRYPTION = 1
IKEV1_ATTR_HASH = 2
IKEV1_ATTR_AUTH_METHOD = 3
IKEV1_ATTR_GROUP_DESC = 4
IKEV1_ATTR_LIFE_TYPE = 11
IKEV1_ATTR_LIFE_DURATION = 12
IKEV1_ATTR_KEY_LENGTH = 14


# ─── ISAKMP DOI / Protocol IDs ──────────────────────────────────────
# RFC 2408

ISAKMP_DOI_IPSEC = 1
ISAKMP_SIT_IDENTITY = 1
ISAKMP_PROTO_ISAKMP = 1
ISAKMP_PROTO_IPSEC_AH = 2
ISAKMP_PROTO_IPSEC_ESP = 3


# ─── Human-Readable Mappings ────────────────────────────────────────

ENCRYPTION_NAMES: dict[int, str] = {
    EncryptionAlgorithm.ENCR_DES: "DES",
    EncryptionAlgorithm.ENCR_3DES: "3DES",
    EncryptionAlgorithm.ENCR_AES_CBC: "AES-CBC",
    EncryptionAlgorithm.ENCR_AES_CTR: "AES-CTR",
    EncryptionAlgorithm.ENCR_AES_GCM_8: "AES-GCM-8",
    EncryptionAlgorithm.ENCR_AES_GCM_12: "AES-GCM-12",
    EncryptionAlgorithm.ENCR_AES_GCM_16: "AES-GCM-16",
    EncryptionAlgorithm.ENCR_CHACHA20_POLY1305: "CHACHA20-POLY1305",
}

PRF_NAMES: dict[int, str] = {
    PRFAlgorithm.PRF_HMAC_MD5: "PRF-HMAC-MD5",
    PRFAlgorithm.PRF_HMAC_SHA1: "PRF-HMAC-SHA1",
    PRFAlgorithm.PRF_HMAC_SHA2_256: "PRF-HMAC-SHA2-256",
    PRFAlgorithm.PRF_HMAC_SHA2_384: "PRF-HMAC-SHA2-384",
    PRFAlgorithm.PRF_HMAC_SHA2_512: "PRF-HMAC-SHA2-512",
}

INTEGRITY_NAMES: dict[int, str] = {
    IntegrityAlgorithmID.AUTH_NONE: "NONE",
    IntegrityAlgorithmID.AUTH_HMAC_MD5_96: "HMAC-MD5-96",
    IntegrityAlgorithmID.AUTH_HMAC_SHA1_96: "HMAC-SHA1-96",
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128: "HMAC-SHA2-256-128",
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_384_192: "HMAC-SHA2-384-192",
    IntegrityAlgorithmID.AUTH_HMAC_SHA2_512_256: "HMAC-SHA2-512-256",
}

DH_GROUP_NAMES: dict[int, str] = {
    DHGroup.DH_NONE: "NONE",
    DHGroup.MODP_768: "MODP-768",
    DHGroup.MODP_1024: "MODP-1024",
    DHGroup.MODP_1536: "MODP-1536",
    DHGroup.MODP_2048: "MODP-2048",
    DHGroup.MODP_3072: "MODP-3072",
    DHGroup.MODP_4096: "MODP-4096",
    DHGroup.MODP_6144: "MODP-6144",
    DHGroup.MODP_8192: "MODP-8192",
    DHGroup.ECP_256: "ECP-256",
    DHGroup.ECP_384: "ECP-384",
    DHGroup.ECP_521: "ECP-521",
    DHGroup.CURVE_25519: "CURVE-25519",
    DHGroup.CURVE_448: "CURVE-448",
}

# DH group key exchange data sizes in bytes (for dummy KE payloads)
DH_GROUP_KE_SIZES: dict[int, int] = {
    DHGroup.MODP_768: 96,
    DHGroup.MODP_1024: 128,
    DHGroup.MODP_1536: 192,
    DHGroup.MODP_2048: 256,
    DHGroup.MODP_3072: 384,
    DHGroup.MODP_4096: 512,
    DHGroup.MODP_6144: 768,
    DHGroup.MODP_8192: 1024,
    DHGroup.ECP_256: 64,
    DHGroup.ECP_384: 96,
    DHGroup.ECP_521: 132,
    DHGroup.CURVE_25519: 32,
    DHGroup.CURVE_448: 56,
}
