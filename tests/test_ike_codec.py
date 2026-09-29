"""
Unit tests for the IKE binary codec (build/parse round-trip).

Tests cover:
  - IKEv2 header build + parse round-trip
  - IKEv2 SA payload with proposals and transforms
  - IKEv2 KE payload
  - IKEv2 Nonce payload
  - IKEv2 Notify payload (including COOKIE, INVALID_KE_PAYLOAD)
  - IKEv2 IKE_SA_INIT full message build + parse
  - IKEv1 Main Mode full message build + parse
  - Non-ESP marker stripping on port 4500
  - Truncated / malformed packet handling
"""

import os
import struct

import pytest

from tunneltwin.ike.codec import (
    IKEParseError,
    IKEv1TransformSpec,
    build_ike_header,
    build_ikev1_main_mode_request,
    build_ikev2_sa_init,
    build_ke_payload,
    build_nonce_payload,
    build_notify_payload,
    build_sa_payload,
    parse_ike_message,
)
from tunneltwin.ike.constants import (
    DH_GROUP_KE_SIZES,
    IKE_HEADER_LENGTH,
    NON_ESP_MARKER,
    DHGroup,
    EncryptionAlgorithm,
    ExchangeType,
    IKEFlag,
    IKEv1AuthMethod,
    IKEv1EncryptionType,
    IKEv1GroupType,
    IKEv1HashType,
    IntegrityAlgorithmID,
    NotifyType,
    PayloadType,
    PRFAlgorithm,
    TransformType,
)

# ─── Header tests ─────────────────────────────────────────────────


class TestIKEHeader:
    def test_header_length(self):
        header = build_ike_header(
            initiator_spi=b"\x01" * 8,
            responder_spi=b"\x02" * 8,
            next_payload=PayloadType.SA,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=28,
        )
        assert len(header) == IKE_HEADER_LENGTH

    def test_header_round_trip(self):
        i_spi = os.urandom(8)
        r_spi = os.urandom(8)
        header = build_ike_header(
            initiator_spi=i_spi,
            responder_spi=r_spi,
            next_payload=PayloadType.SA,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=42,
            total_length=28,
        )
        msg = parse_ike_message(header)
        assert msg.initiator_spi == i_spi
        assert msg.responder_spi == r_spi
        assert msg.major_version == 2
        assert msg.minor_version == 0
        assert msg.exchange_type == ExchangeType.IKE_SA_INIT
        assert msg.flags == IKEFlag.INITIATOR
        assert msg.message_id == 42

    def test_version_byte_encoding(self):
        """Verify version byte packing: major in high nibble, minor in low."""
        header = build_ike_header(
            initiator_spi=b"\x00" * 8,
            responder_spi=b"\x00" * 8,
            next_payload=0,
            major_version=2,
            minor_version=0,
            exchange_type=34,
            flags=0,
            message_id=0,
            total_length=28,
        )
        version_byte = header[17]
        assert (version_byte >> 4) == 2  # major
        assert (version_byte & 0x0F) == 0  # minor


# ─── IKEv2 SA payload tests ──────────────────────────────────────


class TestIKEv2SAPayload:
    def test_single_proposal_round_trip(self):
        transforms = [
            (TransformType.ENCR, EncryptionAlgorithm.ENCR_AES_CBC, 256),
            (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA2_256, None),
            (TransformType.INTEG, IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128, None),
            (TransformType.DH, DHGroup.MODP_2048, None),
        ]
        sa_data = build_sa_payload([transforms], next_payload=PayloadType.NONE)

        # Wrap in IKE header to parse
        total_len = IKE_HEADER_LENGTH + len(sa_data)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.SA,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + sa_data)
        assert len(msg.proposals) == 1

        prop = msg.proposals[0]
        assert prop.proposal_num == 1
        assert prop.protocol_id == 1  # IKE
        assert len(prop.transforms) == 4

        # Verify transform types and IDs
        encr_tf = [t for t in prop.transforms if t.transform_type == TransformType.ENCR]
        assert len(encr_tf) == 1
        assert encr_tf[0].transform_id == EncryptionAlgorithm.ENCR_AES_CBC
        assert encr_tf[0].key_length == 256

        dh_tf = [t for t in prop.transforms if t.transform_type == TransformType.DH]
        assert len(dh_tf) == 1
        assert dh_tf[0].transform_id == DHGroup.MODP_2048

    def test_multiple_proposals(self):
        prop1 = [
            (TransformType.ENCR, EncryptionAlgorithm.ENCR_AES_GCM_16, 256),
            (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA2_256, None),
            (TransformType.INTEG, IntegrityAlgorithmID.AUTH_NONE, None),
            (TransformType.DH, DHGroup.ECP_384, None),
        ]
        prop2 = [
            (TransformType.ENCR, EncryptionAlgorithm.ENCR_3DES, None),
            (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA1, None),
            (TransformType.INTEG, IntegrityAlgorithmID.AUTH_HMAC_SHA1_96, None),
            (TransformType.DH, DHGroup.MODP_1024, None),
        ]
        sa_data = build_sa_payload([prop1, prop2], next_payload=PayloadType.NONE)

        total_len = IKE_HEADER_LENGTH + len(sa_data)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.SA,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + sa_data)
        assert len(msg.proposals) == 2
        assert msg.proposals[0].proposal_num == 1
        assert msg.proposals[1].proposal_num == 2


# ─── KE and Nonce payload tests ──────────────────────────────────


class TestKEPayload:
    def test_ke_payload_round_trip(self):
        ke_data = build_ke_payload(DHGroup.MODP_2048, next_payload=PayloadType.NONE)

        total_len = IKE_HEADER_LENGTH + len(ke_data)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.KE,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + ke_data)
        assert msg.ke is not None
        assert msg.ke.dh_group == DHGroup.MODP_2048
        assert len(msg.ke.ke_data) == DH_GROUP_KE_SIZES[DHGroup.MODP_2048]


class TestNoncePayload:
    def test_nonce_payload_round_trip(self):
        nonce_bytes = os.urandom(32)
        nonce_data = build_nonce_payload(nonce_bytes, next_payload=PayloadType.NONE)

        total_len = IKE_HEADER_LENGTH + len(nonce_data)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.NONCE,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + nonce_data)
        assert msg.nonce == nonce_bytes


# ─── Notify payload tests ────────────────────────────────────────


class TestNotifyPayload:
    def test_notify_no_proposal_chosen(self):
        notify = build_notify_payload(NotifyType.NO_PROPOSAL_CHOSEN, next_payload=PayloadType.NONE)

        total_len = IKE_HEADER_LENGTH + len(notify)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=os.urandom(8),
            next_payload=PayloadType.NOTIFY,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.RESPONSE,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + notify)
        assert msg.has_notify(NotifyType.NO_PROPOSAL_CHOSEN)

    def test_notify_invalid_ke_payload(self):
        """INVALID_KE_PAYLOAD carries the preferred DH group as 2-byte notification data."""
        preferred_group = struct.pack("!H", DHGroup.ECP_384)
        notify = build_notify_payload(
            NotifyType.INVALID_KE_PAYLOAD,
            notification_data=preferred_group,
            next_payload=PayloadType.NONE,
        )

        total_len = IKE_HEADER_LENGTH + len(notify)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=os.urandom(8),
            next_payload=PayloadType.NOTIFY,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.RESPONSE,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + notify)
        assert msg.has_notify(NotifyType.INVALID_KE_PAYLOAD)
        assert msg.get_invalid_ke_group() == DHGroup.ECP_384

    def test_cookie_notify_round_trip(self):
        """Test COOKIE notify with arbitrary cookie data."""
        cookie_data = os.urandom(64)
        notify = build_notify_payload(
            NotifyType.COOKIE,
            notification_data=cookie_data,
            next_payload=PayloadType.NONE,
        )

        total_len = IKE_HEADER_LENGTH + len(notify)
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.NOTIFY,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.RESPONSE,
            message_id=0,
            total_length=total_len,
        )

        msg = parse_ike_message(header + notify)
        assert msg.has_notify(NotifyType.COOKIE)
        assert msg.get_cookie() == cookie_data


# ─── Full IKEv2 IKE_SA_INIT build+parse ─────────────────────────


class TestIKEv2SAInit:
    def test_sa_init_build_and_parse(self):
        proposals = [
            [
                (TransformType.ENCR, EncryptionAlgorithm.ENCR_AES_CBC, 256),
                (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA2_256, None),
                (TransformType.INTEG, IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128, None),
                (TransformType.DH, DHGroup.MODP_2048, None),
            ],
        ]
        packet = build_ikev2_sa_init(proposals, dh_group=DHGroup.MODP_2048)

        msg = parse_ike_message(packet)
        assert msg.is_ikev2
        assert msg.exchange_type == ExchangeType.IKE_SA_INIT
        assert msg.flags & IKEFlag.INITIATOR
        assert msg.message_id == 0
        assert len(msg.proposals) >= 1
        assert msg.ke is not None
        assert msg.ke.dh_group == DHGroup.MODP_2048
        assert len(msg.nonce) == 32

    def test_sa_init_with_cookie(self):
        cookie_data = os.urandom(64)
        proposals = [
            [
                (TransformType.ENCR, EncryptionAlgorithm.ENCR_AES_CBC, 128),
                (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA1, None),
                (TransformType.INTEG, IntegrityAlgorithmID.AUTH_HMAC_SHA1_96, None),
                (TransformType.DH, DHGroup.MODP_1024, None),
            ],
        ]
        packet = build_ikev2_sa_init(proposals, dh_group=DHGroup.MODP_1024, cookie=cookie_data)

        msg = parse_ike_message(packet)
        assert msg.has_notify(NotifyType.COOKIE)
        assert msg.get_cookie() == cookie_data
        assert len(msg.proposals) >= 1

    def test_non_esp_marker_stripping(self):
        """Parser must strip 4 zero-byte non-ESP marker prefix (port 4500)."""
        proposals = [
            [
                (TransformType.ENCR, EncryptionAlgorithm.ENCR_AES_CBC, 256),
                (TransformType.PRF, PRFAlgorithm.PRF_HMAC_SHA2_256, None),
                (TransformType.INTEG, IntegrityAlgorithmID.AUTH_HMAC_SHA2_256_128, None),
                (TransformType.DH, DHGroup.MODP_2048, None),
            ],
        ]
        packet = build_ikev2_sa_init(proposals, dh_group=DHGroup.MODP_2048)
        packet_with_marker = NON_ESP_MARKER + packet

        msg = parse_ike_message(packet_with_marker)
        assert msg.is_ikev2
        assert msg.exchange_type == ExchangeType.IKE_SA_INIT


# ─── IKEv1 Main Mode tests ───────────────────────────────────────


class TestIKEv1MainMode:
    def test_ikev1_build_and_parse(self):
        specs = [
            IKEv1TransformSpec(
                encryption=IKEv1EncryptionType.THREE_DES_CBC,
                hash_alg=IKEv1HashType.SHA1,
                auth_method=IKEv1AuthMethod.PSK,
                dh_group=IKEv1GroupType.MODP_1024,
            ),
            IKEv1TransformSpec(
                encryption=IKEv1EncryptionType.AES_CBC,
                hash_alg=IKEv1HashType.SHA2_256,
                auth_method=IKEv1AuthMethod.PSK,
                dh_group=IKEv1GroupType.MODP_2048,
                key_length=256,
            ),
        ]
        packet = build_ikev1_main_mode_request(specs)

        msg = parse_ike_message(packet)
        assert msg.is_ikev1
        assert msg.exchange_type == ExchangeType.IKEV1_IDENTITY_PROTECTION
        assert len(msg.ikev1_proposals) >= 1

        # The proposal should contain 2 transforms
        prop = msg.ikev1_proposals[0]
        assert len(prop.transforms) == 2

        # First transform: 3DES + SHA1 + PSK + MODP_1024
        tf1 = prop.transforms[0]
        assert tf1.attributes.get(1) == IKEv1EncryptionType.THREE_DES_CBC  # attr type 1 = encryption
        assert tf1.attributes.get(2) == IKEv1HashType.SHA1  # attr type 2 = hash
        assert tf1.attributes.get(3) == IKEv1AuthMethod.PSK  # attr type 3 = auth
        assert tf1.attributes.get(4) == IKEv1GroupType.MODP_1024  # attr type 4 = group

        # Second transform: AES-256 + SHA256 + PSK + MODP_2048
        tf2 = prop.transforms[1]
        assert tf2.attributes.get(1) == IKEv1EncryptionType.AES_CBC
        assert tf2.attributes.get(2) == IKEv1HashType.SHA2_256
        assert tf2.attributes.get(14) == 256  # attr type 14 = key length


# ─── Error handling tests ─────────────────────────────────────────


class TestErrorHandling:
    def test_truncated_packet_raises(self):
        with pytest.raises(IKEParseError):
            parse_ike_message(b"\x00" * 10)

    def test_empty_packet_raises(self):
        with pytest.raises(IKEParseError):
            parse_ike_message(b"")

    def test_truncated_payload_graceful(self):
        """A truncated payload chain should not crash — just parse what it can."""
        header = build_ike_header(
            initiator_spi=os.urandom(8),
            responder_spi=b"\x00" * 8,
            next_payload=PayloadType.SA,
            major_version=2,
            minor_version=0,
            exchange_type=ExchangeType.IKE_SA_INIT,
            flags=IKEFlag.INITIATOR,
            message_id=0,
            total_length=40,  # Claim 40 bytes but only provide header
        )
        # Parser should handle gracefully (no crash)
        msg = parse_ike_message(header)
        assert msg.initiator_spi is not None
