"""RFC 4303 structural consistency check.

Before any classifier sees an ESP flow we can throw away cipher/ICV
combinations that are arithmetically impossible given the observed
ciphertext length. This is a pure arithmetic filter -- it narrows the
candidate set, it never picks a winner, so it cannot be wrong in a way
that produces a false finding.
"""

from __future__ import annotations

from dataclasses import dataclass

ESP_HEADER_LEN = 8  # SPI(4) + Sequence(4)
MIN_TRAILER = 2  # Pad Length(1) + Next Header(1)
MAX_PAD = 255


@dataclass(frozen=True)
class EspSuite:
    """One (encryption, integrity) combination with its wire arithmetic."""

    enc: str
    auth: str | None
    block_size: int  # 0 => stream or AEAD, no block alignment constraint
    iv_len: int
    icv_len: int
    aead: bool

    @property
    def label(self) -> str:
        return f"{self.enc}/{self.auth}" if self.auth else self.enc


# TunnelTwin only needs the suites the Phase 0-4 lab can actually produce,
# plus the common ones a real fleet will be found running.
SUITES: tuple[EspSuite, ...] = (
    EspSuite("ENCR_3DES", "AUTH_HMAC_SHA1_96", 8, 8, 12, False),
    EspSuite("ENCR_AES_CBC", "AUTH_HMAC_SHA1_96", 16, 16, 12, False),
    EspSuite("ENCR_AES_CBC", "AUTH_HMAC_SHA2_256_128", 16, 16, 16, False),
    EspSuite("ENCR_AES_CBC", "AUTH_HMAC_SHA2_384_192", 16, 16, 24, False),
    EspSuite("ENCR_AES_CBC", "AUTH_HMAC_SHA2_512_256", 16, 16, 32, False),
    EspSuite("ENCR_AES_CTR", "AUTH_HMAC_SHA2_256_128", 0, 8, 16, False),
    EspSuite("ENCR_AES_GCM_16", None, 0, 8, 16, True),
    EspSuite("ENCR_AES_GCM_12", None, 0, 8, 12, True),
    EspSuite("ENCR_AES_GCM_8", None, 0, 8, 8, True),
    EspSuite("ENCR_NULL", "AUTH_HMAC_SHA1_96", 0, 0, 12, False),
    EspSuite("ENCR_NULL", "AUTH_HMAC_SHA2_256_128", 0, 0, 16, False),
)


def consistent_suites(esp_len: int) -> list[EspSuite]:
    """Return every suite whose arithmetic fits an ESP packet of ``esp_len``.

    ``esp_len`` is the total ESP bytes on the wire -- SPI through ICV, i.e.
    the IPv4 total length minus the IP header, or the IPv6 payload length
    when ESP is the only payload.
    """
    out: list[EspSuite] = []
    if esp_len <= ESP_HEADER_LEN:
        return out
    for suite in SUITES:
        body = esp_len - ESP_HEADER_LEN - suite.iv_len - suite.icv_len
        if body < MIN_TRAILER:
            continue
        if suite.block_size and body % suite.block_size != 0:
            continue
        # Pad Length must be representable, so plaintext cannot exceed
        # the block-aligned maximum implied by the observed length.
        if body - MIN_TRAILER > MAX_PAD + 65535:
            continue
        out.append(suite)
    return out


def narrow_by_lengths(esp_lengths: list[int]) -> list[EspSuite]:
    """Intersect the per-packet candidate sets across a whole flow.

    A flow's packets all use the same SA, so the suite must be consistent
    with every packet length observed. Intersecting collapses the
    candidate set hard for long flows.
    """
    if not esp_lengths:
        return list(SUITES)
    candidates: set[str] = {s.label for s in consistent_suites(esp_lengths[0])}
    for length in esp_lengths[1:]:
        candidates &= {s.label for s in consistent_suites(length)}
        if not candidates:
            break
    return [s for s in SUITES if s.label in candidates]


def tunnel_vs_transport_prior(esp_len: int, ip_total_len: int) -> str:
    """Cheap structural prior: tunnel-mode ESP carries an inner IP header,
    so its payload is at least ~20 bytes larger than the outer IP payload
    for the same transport content. This is a *prior*, not a verdict --
    the classifier is what decides, and the prior is exposed as a feature.
    """
    if ip_total_len <= 0:
        return "unknown"
    ratio = esp_len / ip_total_len
    if ratio > 0.9:
        return "tunnel"
    return "transport_or_unknown"
