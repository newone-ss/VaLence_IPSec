"""
IKEv2 and IKEv1 Binary Packet Codec — RFC 7296, RFC 2409.

Pure-Python struct-based builder and parser for IKE_SA_INIT (IKEv2) and
Main Mode Phase 1 (IKEv1) messages.  No Scapy dependency — this codec is
reused by both the active prober and the PCAP analyser.

Layout references:
    IKEv2 header   — RFC 7296 §3.1      (28 bytes)
    SA payload     — RFC 7296 §3.3
    KE payload     — RFC 7296 §3.4
    Nonce payload  — RFC 7296 §3.9
    Notify payload — RFC 7296 §3.10
    IKEv1 header   — RFC 2408 §3.1      (28 bytes, same layout)
    IKEv1 SA       — RFC 2408 §3.4 / RFC 2409 §5
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from tunneltwin.ike.constants import (
    DH_GROUP_KE_SIZES,
    IKE_HEADER_LENGTH,
    IKEV1_ATTR_AUTH_METHOD,
    IKEV1_ATTR_ENCRYPTION,
    IKEV1_ATTR_GROUP_DESC,
    IKEV1_ATTR_HASH,
    IKEV1_ATTR_KEY_LENGTH,
    IKEV1_ATTR_LIFE_DURATION,
    IKEV1_ATTR_LIFE_TYPE,
    ISAKMP_DOI_IPSEC,
    ISAKMP_PROTO_ISAKMP,
    ISAKMP_SIT_IDENTITY,
    NON_ESP_MARKER,
    DHGroup,
    ExchangeType,
    IKEFlag,
    IKEv1AuthMethod,
    IKEv1GroupType,
    IKEv1LifeType,
    NotifyType,
    PayloadType,
)

# ═══════════════════════════════════════════════════════════════════════
#  Parsed data structures
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class ParsedTransform:
    """A single IKEv2 transform (encryption, prf, integrity, or DH)."""

    transform_type: int  # TransformType enum value
    transform_id: int  # Algorithm ID from IANA registry
    key_length: int | None = None  # Only for variable-key ciphers like AES-CBC


@dataclass
class ParsedProposal:
    """A single IKEv2 SA proposal containing transforms."""

    proposal_num: int
    protocol_id: int  # 1=IKE, 2=AH, 3=ESP
    spi: bytes = b""
    transforms: list[ParsedTransform] = field(default_factory=list)


@dataclass
class ParsedNotify:
    """A single IKEv2 Notify payload."""

    protocol_id: int
    spi_size: int
    notify_type: int
    spi: bytes = b""
    notification_data: bytes = b""


@dataclass
class ParsedKE:
    """A parsed Key Exchange payload."""

    dh_group: int
    ke_data: bytes = b""


@dataclass
class IKEv1Transform:
    """A single IKEv1 transform with attributes."""

    transform_num: int
    transform_id: int  # Always 1 for KEY_IKE
    attributes: dict[int, int] = field(default_factory=dict)


@dataclass
class IKEv1Proposal:
    """A single IKEv1 proposal."""

    proposal_num: int
    protocol_id: int
    spi: bytes = b""
    transforms: list[IKEv1Transform] = field(default_factory=list)


@dataclass
class ParsedIKEMessage:
    """Complete parsed IKE message (works for both IKEv2 and IKEv1)."""

    initiator_spi: bytes
    responder_spi: bytes
    major_version: int
    minor_version: int
    exchange_type: int
    flags: int
    message_id: int
    # Parsed payload contents
    proposals: list[ParsedProposal] = field(default_factory=list)
    notifies: list[ParsedNotify] = field(default_factory=list)
    ke: ParsedKE | None = None
    nonce: bytes = b""
    vendor_ids: list[bytes] = field(default_factory=list)
    raw_payloads: list[tuple[int, bytes]] = field(default_factory=list)
    # IKEv1 specific
    ikev1_proposals: list[IKEv1Proposal] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & IKEFlag.RESPONSE)

    @property
    def is_ikev2(self) -> bool:
        return self.major_version == 2

    @property
    def is_ikev1(self) -> bool:
        return self.major_version == 1

    def get_notify_types(self) -> list[int]:
        return [n.notify_type for n in self.notifies]

    def has_notify(self, notify_type: int) -> bool:
        return any(n.notify_type == notify_type for n in self.notifies)

    def get_cookie(self) -> bytes | None:
        """Extract COOKIE notification data if present (RFC 7296 §2.6)."""
        for n in self.notifies:
            if n.notify_type == NotifyType.COOKIE:
                return n.notification_data
        return None

    def get_invalid_ke_group(self) -> int | None:
        """Extract the preferred DH group from an INVALID_KE_PAYLOAD notify."""
        for n in self.notifies:
            if n.notify_type == NotifyType.INVALID_KE_PAYLOAD and len(n.notification_data) >= 2:
                return struct.unpack("!H", n.notification_data[:2])[0]
        return None


# ═══════════════════════════════════════════════════════════════════════
#  IKEv2 Packet Builder
# ═══════════════════════════════════════════════════════════════════════


def _build_transform(
    transform_type: int,
    transform_id: int,
    is_last: bool,
    key_length: int | None = None,
) -> bytes:
    """Build a single IKEv2 Transform sub-structure (RFC 7296 §3.3.2)."""
    # Transform attributes (key length for variable-key ciphers)
    attrs = b""
    if key_length is not None:
        # Attribute Format: TV (bit 15 set = short), type=14 (Key Length)
        attrs = struct.pack("!HH", 0x800E, key_length)

    # Transform header: last_or_more(1) + reserved(1) + length(2) + type(1) + reserved(1) + id(2)
    transform_length = 8 + len(attrs)
    last_flag = 0 if is_last else 3  # 0 = last, 3 = more
    header = struct.pack("!BBH BBH", last_flag, 0, transform_length, transform_type, 0, transform_id)
    return header + attrs


def _build_proposal(
    proposal_num: int,
    transforms: list[tuple[int, int, int | None]],
    is_last: bool,
    protocol_id: int = 1,  # 1 = IKE
) -> bytes:
    """
    Build a single IKEv2 Proposal sub-structure (RFC 7296 §3.3.1).

    transforms: list of (transform_type, transform_id, key_length_or_None)
    """
    # Build transform payloads
    transforms_data = b""
    for idx, (tt, tid, kl) in enumerate(transforms):
        is_last_transform = idx == len(transforms) - 1
        transforms_data += _build_transform(tt, tid, is_last_transform, kl)

    # Proposal header: last_or_more(1) + reserved(1) + length(2) +
    #   proposal_num(1) + protocol_id(1) + spi_size(1) + num_transforms(1)
    spi_size = 0  # No SPI in IKE_SA_INIT proposals
    proposal_length = 8 + spi_size + len(transforms_data)
    last_flag = 0 if is_last else 2  # 0 = last, 2 = more
    header = struct.pack(
        "!BBH BBBB",
        last_flag,
        0,
        proposal_length,
        proposal_num,
        protocol_id,
        spi_size,
        len(transforms),
    )
    return header + transforms_data


def build_sa_payload(
    proposals: list[list[tuple[int, int, int | None]]],
    next_payload: int = PayloadType.NONE,
    protocol_id: int = 1,
) -> bytes:
    """
    Build a complete IKEv2 SA payload (RFC 7296 §3.3).

    proposals: list of proposal transform lists
    Each proposal is: list of (transform_type, transform_id, key_length|None)
    """
    proposals_data = b""
    for idx, prop_transforms in enumerate(proposals):
        is_last = idx == len(proposals) - 1
        proposals_data += _build_proposal(idx + 1, prop_transforms, is_last, protocol_id)

    # Generic payload header: next_payload(1) + critical(1) + length(2)
    payload_length = 4 + len(proposals_data)
    header = struct.pack("!BBH", next_payload, 0, payload_length)
    return header + proposals_data


def generate_ke_data_for_group(dh_group: int) -> bytes:
    """
    Generate RFC-compliant Key Exchange data for a DH group (RFC 7296 §3.4, RFC 5903 §3).

    For NIST elliptic curves (ECP-256, ECP-384, ECP-521), generates a point on the curve
    in raw uncompressed format (X || Y) without the 0x04 prefix byte as required by strongSwan.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if dh_group == DHGroup.ECP_256:
            key = ec.generate_private_key(ec.SECP256R1())
            return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
        elif dh_group == DHGroup.ECP_384:
            key = ec.generate_private_key(ec.SECP384R1())
            return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
        elif dh_group == DHGroup.ECP_521:
            key = ec.generate_private_key(ec.SECP521R1())
            return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
        elif dh_group == DHGroup.CURVE_25519:
            key_x = x25519.X25519PrivateKey.generate()
            return key_x.public_key().public_bytes_raw()
    except (ImportError, ValueError, TypeError):
        pass

    ke_size = DH_GROUP_KE_SIZES.get(dh_group, 256)
    return os.urandom(ke_size)


def build_ke_payload(
    dh_group: int,
    next_payload: int = PayloadType.NONE,
    ke_data: bytes | None = None,
) -> bytes:
    """
    Build a KE payload with valid key exchange data (RFC 7296 §3.4).

    Uses the correct byte length and valid curve points for the specified DH group.
    """
    if ke_data is None:
        ke_data = generate_ke_data_for_group(dh_group)

    # KE header: next_payload(1) + critical(1) + length(2) + dh_group(2) + reserved(2)
    payload_length = 4 + 4 + len(ke_data)  # generic header + KE-specific header + data
    header = struct.pack("!BBH HH", next_payload, 0, payload_length, dh_group, 0)
    return header + ke_data


def build_nonce_payload(
    nonce_data: bytes | None = None,
    next_payload: int = PayloadType.NONE,
) -> bytes:
    """Build a Nonce payload (RFC 7296 §3.9)."""
    if nonce_data is None:
        nonce_data = os.urandom(32)

    payload_length = 4 + len(nonce_data)
    header = struct.pack("!BBH", next_payload, 0, payload_length)
    return header + nonce_data


def build_notify_payload(
    notify_type: int,
    notification_data: bytes = b"",
    protocol_id: int = 0,
    spi: bytes = b"",
    next_payload: int = PayloadType.NONE,
) -> bytes:
    """Build a Notify payload (RFC 7296 §3.10)."""
    spi_size = len(spi)
    # Notify header: protocol_id(1) + spi_size(1) + notify_type(2)
    notify_header = struct.pack("!BBH", protocol_id, spi_size, notify_type)
    payload_data = notify_header + spi + notification_data
    payload_length = 4 + len(payload_data)
    header = struct.pack("!BBH", next_payload, 0, payload_length)
    return header + payload_data


def build_ike_header(
    initiator_spi: bytes,
    responder_spi: bytes,
    next_payload: int,
    major_version: int,
    minor_version: int,
    exchange_type: int,
    flags: int,
    message_id: int,
    total_length: int,
) -> bytes:
    """Build the 28-byte IKE header (RFC 7296 §3.1 / RFC 2408 §3.1)."""
    version_byte = (major_version << 4) | (minor_version & 0x0F)
    return struct.pack(
        "!8s8sBBBBI",
        initiator_spi,
        responder_spi,
        next_payload,
        version_byte,
        exchange_type,
        flags,
        message_id,
    ) + struct.pack("!I", total_length)


def build_ikev2_sa_init(
    proposals: list[list[tuple[int, int, int | None]]],
    dh_group: int,
    initiator_spi: bytes | None = None,
    cookie: bytes | None = None,
) -> bytes:
    """
    Build a complete IKEv2 IKE_SA_INIT request packet.

    If cookie is provided, prepend a COOKIE Notify payload (RFC 7296 §2.6).
    """
    if initiator_spi is None:
        initiator_spi = os.urandom(8)

    # Build payloads in reverse chain order to set next_payload correctly
    nonce = build_nonce_payload(next_payload=PayloadType.NONE)
    ke = build_ke_payload(dh_group, next_payload=PayloadType.NONCE)
    sa = build_sa_payload(proposals, next_payload=PayloadType.KE)

    payloads = sa + ke + nonce
    first_payload = PayloadType.SA

    # If cookie is present, prepend COOKIE notify before SA
    if cookie is not None:
        cookie_notify = build_notify_payload(
            notify_type=NotifyType.COOKIE,
            notification_data=cookie,
            next_payload=PayloadType.SA,
        )
        payloads = cookie_notify + payloads
        first_payload = PayloadType.NOTIFY

    total_length = IKE_HEADER_LENGTH + len(payloads)
    header = build_ike_header(
        initiator_spi=initiator_spi,
        responder_spi=b"\x00" * 8,
        next_payload=first_payload,
        major_version=2,
        minor_version=0,
        exchange_type=ExchangeType.IKE_SA_INIT,
        flags=IKEFlag.INITIATOR,
        message_id=0,
        total_length=total_length,
    )
    return header + payloads


# ═══════════════════════════════════════════════════════════════════════
#  IKEv1 Packet Builder (Main Mode Phase 1)
# ═══════════════════════════════════════════════════════════════════════


def _build_ikev1_attribute(attr_type: int, attr_value: int, is_tv: bool = True) -> bytes:
    """
    Build a single IKEv1 SA attribute (RFC 2408 §3.3).

    TV format (is_tv=True): type has bit 15 set, 2-byte value
    TLV format (is_tv=False): type without bit 15, 2-byte length, then value bytes
    """
    if is_tv:
        return struct.pack("!HH", 0x8000 | attr_type, attr_value)
    else:
        # For life duration, encode as 4-byte big-endian
        value_bytes = struct.pack("!I", attr_value)
        return struct.pack("!HH", attr_type, len(value_bytes)) + value_bytes


def build_ikev1_transform_payload(
    transform_num: int,
    encryption: int,
    hash_alg: int,
    auth_method: int,
    dh_group: int,
    is_last: bool,
    key_length: int | None = None,
    lifetime_seconds: int = 86400,
) -> bytes:
    """Build a single IKEv1 Transform payload (RFC 2408 §3.6, RFC 2409 §5)."""
    attrs = b""
    attrs += _build_ikev1_attribute(IKEV1_ATTR_ENCRYPTION, encryption)
    attrs += _build_ikev1_attribute(IKEV1_ATTR_HASH, hash_alg)
    attrs += _build_ikev1_attribute(IKEV1_ATTR_AUTH_METHOD, auth_method)
    attrs += _build_ikev1_attribute(IKEV1_ATTR_GROUP_DESC, dh_group)
    if key_length is not None:
        attrs += _build_ikev1_attribute(IKEV1_ATTR_KEY_LENGTH, key_length)
    # Lifetime
    attrs += _build_ikev1_attribute(IKEV1_ATTR_LIFE_TYPE, IKEv1LifeType.SECONDS)
    attrs += _build_ikev1_attribute(IKEV1_ATTR_LIFE_DURATION, lifetime_seconds, is_tv=False)

    # Transform header: next_payload(1) + reserved(1) + length(2) + transform_num(1) + transform_id(1) + reserved(2)
    transform_length = 8 + len(attrs)
    next_flag = 0 if is_last else PayloadType.IKEV1_TRANSFORM
    header = struct.pack("!BBH BBH", next_flag, 0, transform_length, transform_num, 1, 0)  # transform_id=1 (KEY_IKE)
    return header + attrs


def build_ikev1_proposal_payload(
    transforms_data: bytes,
    num_transforms: int,
    next_payload: int = PayloadType.NONE,
) -> bytes:
    """Build an IKEv1 Proposal payload (RFC 2408 §3.5)."""
    # proposal_num=1, protocol_id=ISAKMP, spi_size=0
    spi_size = 0
    proposal_length = 8 + spi_size + len(transforms_data)
    header = struct.pack(
        "!BBH BBBB",
        next_payload,
        0,
        proposal_length,
        1,  # proposal_num
        ISAKMP_PROTO_ISAKMP,
        spi_size,
        num_transforms,
    )
    return header + transforms_data


def build_ikev1_sa_payload(
    proposal_data: bytes,
    next_payload: int = PayloadType.NONE,
) -> bytes:
    """Build an IKEv1 SA payload (RFC 2408 §3.4, RFC 2409 §5)."""
    # DOI (4 bytes) + Situation (4 bytes) + proposals
    doi_sit = struct.pack("!II", ISAKMP_DOI_IPSEC, ISAKMP_SIT_IDENTITY)
    payload_data = doi_sit + proposal_data
    payload_length = 4 + len(payload_data)
    header = struct.pack("!BBH", next_payload, 0, payload_length)
    return header + payload_data


@dataclass
class IKEv1TransformSpec:
    """Specification for a single IKEv1 transform to offer."""

    encryption: int
    hash_alg: int
    auth_method: int = IKEv1AuthMethod.PSK
    dh_group: int = IKEv1GroupType.MODP_1024
    key_length: int | None = None
    lifetime_seconds: int = 86400


def build_ikev1_main_mode_request(
    transform_specs: list[IKEv1TransformSpec],
    initiator_spi: bytes | None = None,
) -> bytes:
    """
    Build a complete IKEv1 Main Mode (Identity Protection) SA request.

    Packs multiple transforms into a single proposal per RFC 2409 §5.
    """
    if initiator_spi is None:
        initiator_spi = os.urandom(8)

    # Build transforms
    transforms_data = b""
    for idx, spec in enumerate(transform_specs):
        is_last = idx == len(transform_specs) - 1
        transforms_data += build_ikev1_transform_payload(
            transform_num=idx + 1,
            encryption=spec.encryption,
            hash_alg=spec.hash_alg,
            auth_method=spec.auth_method,
            dh_group=spec.dh_group,
            is_last=is_last,
            key_length=spec.key_length,
            lifetime_seconds=spec.lifetime_seconds,
        )

    proposal = build_ikev1_proposal_payload(transforms_data, len(transform_specs))
    sa_payload = build_ikev1_sa_payload(proposal, next_payload=PayloadType.NONE)

    total_length = IKE_HEADER_LENGTH + len(sa_payload)
    header = build_ike_header(
        initiator_spi=initiator_spi,
        responder_spi=b"\x00" * 8,
        next_payload=PayloadType.IKEV1_SA,
        major_version=1,
        minor_version=0,
        exchange_type=ExchangeType.IKEV1_IDENTITY_PROTECTION,
        flags=0,
        message_id=0,
        total_length=total_length,
    )
    return header + sa_payload


# ═══════════════════════════════════════════════════════════════════════
#  IKE Packet Parser
# ═══════════════════════════════════════════════════════════════════════


class IKEParseError(Exception):
    """Raised when an IKE packet cannot be parsed."""


def _parse_ikev2_transforms(data: bytes) -> list[ParsedTransform]:
    """Parse the transform sub-structures inside an IKEv2 proposal."""
    transforms: list[ParsedTransform] = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        last_flag, _, tf_length, tf_type, _, tf_id = struct.unpack_from("!BBH BBH", data, offset)
        key_length: int | None = None

        # Parse attributes (looking for key length)
        attr_offset = offset + 8
        while attr_offset < offset + tf_length:
            if attr_offset + 4 > len(data):
                break
            attr_type, attr_value = struct.unpack_from("!HH", data, attr_offset)
            if attr_type & 0x8000:  # TV format
                actual_type = attr_type & 0x7FFF
                if actual_type == 14:  # Key Length attribute
                    key_length = attr_value
                attr_offset += 4
            else:  # TLV format
                attr_len = attr_value
                attr_offset += 4 + attr_len

        transforms.append(ParsedTransform(transform_type=tf_type, transform_id=tf_id, key_length=key_length))

        if last_flag == 0:  # Last transform
            break
        offset += tf_length

    return transforms


def _parse_ikev2_proposals(data: bytes) -> list[ParsedProposal]:
    """Parse proposal sub-structures inside an IKEv2 SA payload."""
    proposals: list[ParsedProposal] = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        last_flag, _, prop_length, prop_num, proto_id, spi_size, num_transforms = struct.unpack_from(
            "!BBH BBBB", data, offset
        )

        spi = b""
        if spi_size > 0:
            spi = data[offset + 8 : offset + 8 + spi_size]

        transforms_start = offset + 8 + spi_size
        transforms_data = data[transforms_start : offset + prop_length]
        transforms = _parse_ikev2_transforms(transforms_data)

        proposals.append(
            ParsedProposal(
                proposal_num=prop_num,
                protocol_id=proto_id,
                spi=spi,
                transforms=transforms,
            )
        )

        if last_flag == 0:  # Last proposal
            break
        offset += prop_length

    return proposals


def _parse_ikev1_attributes(data: bytes) -> dict[int, int]:
    """Parse IKEv1 SA attributes (TV and TLV formats)."""
    attrs: dict[int, int] = {}
    offset = 0

    while offset < len(data):
        if offset + 4 > len(data):
            break
        attr_type, attr_val_or_len = struct.unpack_from("!HH", data, offset)

        if attr_type & 0x8000:  # TV format (short value)
            actual_type = attr_type & 0x7FFF
            attrs[actual_type] = attr_val_or_len
            offset += 4
        else:  # TLV format (variable length)
            val_len = attr_val_or_len
            if offset + 4 + val_len > len(data):
                break
            val_data = data[offset + 4 : offset + 4 + val_len]
            # Convert to integer (handles 2-byte and 4-byte life durations)
            val_int = int.from_bytes(val_data, byteorder="big")
            attrs[attr_type] = val_int
            offset += 4 + val_len

    return attrs


def _parse_ikev1_transforms(data: bytes) -> list[IKEv1Transform]:
    """Parse transform payloads inside an IKEv1 proposal."""
    transforms: list[IKEv1Transform] = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        next_flag, _, tf_length, tf_num, tf_id, _ = struct.unpack_from("!BBH BBH", data, offset)

        attrs_data = data[offset + 8 : offset + tf_length]
        attributes = _parse_ikev1_attributes(attrs_data)

        transforms.append(IKEv1Transform(transform_num=tf_num, transform_id=tf_id, attributes=attributes))

        if next_flag == 0:
            break
        offset += tf_length

    return transforms


def _parse_ikev1_proposals(data: bytes) -> list[IKEv1Proposal]:
    """Parse proposal sub-structures inside an IKEv1 SA payload (after DOI+SIT)."""
    proposals: list[IKEv1Proposal] = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        next_flag, _, prop_length, prop_num, proto_id, spi_size, num_transforms = struct.unpack_from(
            "!BBH BBBB", data, offset
        )

        spi = b""
        if spi_size > 0:
            spi = data[offset + 8 : offset + 8 + spi_size]

        transforms_start = offset + 8 + spi_size
        transforms_data = data[transforms_start : offset + prop_length]
        transforms = _parse_ikev1_transforms(transforms_data)

        proposals.append(
            IKEv1Proposal(
                proposal_num=prop_num,
                protocol_id=proto_id,
                spi=spi,
                transforms=transforms,
            )
        )

        if next_flag == 0:
            break
        offset += prop_length

    return proposals


def parse_ike_message(data: bytes) -> ParsedIKEMessage:
    """
    Parse a raw IKE packet (IKEv2 or IKEv1) into a ParsedIKEMessage.

    Handles port-4500 non-ESP marker prefix automatically.
    """
    # Strip non-ESP marker if present on port 4500
    if len(data) >= 4 and data[:4] == NON_ESP_MARKER:
        data = data[4:]

    if len(data) < IKE_HEADER_LENGTH:
        raise IKEParseError(f"Packet too short for IKE header: {len(data)} < {IKE_HEADER_LENGTH}")

    # Parse 28-byte IKE header
    i_spi = data[0:8]
    r_spi = data[8:16]
    next_payload, version_byte, exchange_type, flags = struct.unpack_from("!BBBB", data, 16)
    message_id = struct.unpack_from("!I", data, 20)[0]
    total_length = struct.unpack_from("!I", data, 24)[0]

    major_version = (version_byte >> 4) & 0x0F
    minor_version = version_byte & 0x0F

    if total_length > len(data):
        total_length = len(data)  # Tolerate truncated packets

    msg = ParsedIKEMessage(
        initiator_spi=i_spi,
        responder_spi=r_spi,
        major_version=major_version,
        minor_version=minor_version,
        exchange_type=exchange_type,
        flags=flags,
        message_id=message_id,
    )

    # Walk the payload chain
    offset = IKE_HEADER_LENGTH
    current_payload_type = next_payload

    while current_payload_type != PayloadType.NONE and offset < total_length:
        if offset + 4 > total_length:
            break

        np_next, critical_byte, payload_length = struct.unpack_from("!BBH", data, offset)

        if payload_length < 4:
            break  # Invalid payload length

        payload_data = data[offset + 4 : offset + payload_length]

        # Dispatch by payload type
        if major_version == 2:
            _parse_ikev2_payload(msg, current_payload_type, payload_data)
        elif major_version == 1:
            _parse_ikev1_payload(msg, current_payload_type, payload_data)

        msg.raw_payloads.append((current_payload_type, payload_data))

        offset += payload_length
        current_payload_type = np_next

    return msg


def _parse_ikev2_payload(msg: ParsedIKEMessage, payload_type: int, data: bytes) -> None:
    """Parse a single IKEv2 payload and add results to msg."""
    if payload_type == PayloadType.SA:
        msg.proposals = _parse_ikev2_proposals(data)

    elif payload_type == PayloadType.KE:
        if len(data) >= 4:
            dh_group, _ = struct.unpack_from("!HH", data, 0)
            msg.ke = ParsedKE(dh_group=dh_group, ke_data=data[4:])

    elif payload_type == PayloadType.NONCE:
        msg.nonce = data

    elif payload_type == PayloadType.NOTIFY:
        if len(data) >= 4:
            proto_id, spi_size, notify_type = struct.unpack_from("!BBH", data, 0)
            spi = data[4 : 4 + spi_size] if spi_size > 0 else b""
            notification_data = data[4 + spi_size :]
            msg.notifies.append(
                ParsedNotify(
                    protocol_id=proto_id,
                    spi_size=spi_size,
                    notify_type=notify_type,
                    spi=spi,
                    notification_data=notification_data,
                )
            )

    elif payload_type == PayloadType.VENDOR_ID:
        msg.vendor_ids.append(data)


def _parse_ikev1_payload(msg: ParsedIKEMessage, payload_type: int, data: bytes) -> None:
    """Parse a single IKEv1 payload and add results to msg."""
    if payload_type == PayloadType.IKEV1_SA:
        # IKEv1 SA payload: DOI(4) + Situation(4) + proposals
        if len(data) >= 8:
            proposals_data = data[8:]
            msg.ikev1_proposals = _parse_ikev1_proposals(proposals_data)

    elif payload_type == PayloadType.IKEV1_NOTIFY:
        if len(data) >= 12:
            # DOI(4) + proto_id(1) + spi_size(1) + notify_type(2) + SPI + notification_data
            _, proto_id, spi_size, notify_type = struct.unpack_from("!IBBH", data, 0)
            spi = data[8 : 8 + spi_size] if spi_size > 0 else b""
            notification_data = data[8 + spi_size :]
            msg.notifies.append(
                ParsedNotify(
                    protocol_id=proto_id,
                    spi_size=spi_size,
                    notify_type=notify_type,
                    spi=spi,
                    notification_data=notification_data,
                )
            )

    elif payload_type == PayloadType.IKEV1_VENDOR_ID:
        msg.vendor_ids.append(data)
