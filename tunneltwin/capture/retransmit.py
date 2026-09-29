"""IKE retransmit de-duplication.

The exit criteria call this out explicitly: a retransmitted IKE packet
must not be double-counted as a new negotiation attempt. UDP gives us no
transport-level protection against this, so we do it at the IKE layer by
keying on the fields that are stable across a retransmit -- SPIs,
exchange type, and message ID -- and collapsing duplicates inside a
short window.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from tunneltwin.ike.codec import parse_ike_message  # Phase 1, reused

logger = logging.getLogger(__name__)

DEFAULT_WINDOW = 30.0  # seconds; charon's default retransmit ceiling


@dataclass(frozen=True)
class IkeExchange:
    ts: float
    src: str
    dst: str
    initiator_spi: bytes
    responder_spi: bytes
    major_version: int
    exchange_type: int
    message_id: int
    opens_negotiation: bool  # True iff this packet opens a new IKE exchange
    retransmit: bool


def opens_negotiation(initiator_spi: bytes, responder_spi: bytes) -> bool:
    """True iff this packet is the first packet of a new IKE exchange.

    Per RFC 7296 §2.6 the responder SPI is zero until the responder
    chooses one. This holds for IKEv2 and for IKEv1 main-mode AND
    aggressive-mode packet 1, so it is correct across all modes the
    Phase 0-4 lab can produce.
    """
    zero = b"\x00" * 8
    return responder_spi == zero and initiator_spi != zero


def _dedupe_key(ip, msg) -> tuple:
    return (
        ip.src,
        ip.dst,
        msg.initiator_spi,
        msg.responder_spi,
        msg.exchange_type,
        msg.message_id,
    )


def classify_exchanges(packets, window: float = DEFAULT_WINDOW) -> list[IkeExchange]:
    """Return one :class:`IkeExchange` per unique negotiation message.

    ``packets`` is an iterable of the ``IpPacket`` objects produced by
    :func:`tunneltwin.capture.pcap.iter_ike`. Unparsable payloads are
    skipped rather than raising, because a live capture will always
    contain some noise on port 500.
    """
    seen: dict[tuple, float] = {}
    out: list[IkeExchange] = []
    for ip in packets:
        try:
            msg = parse_ike_message(ip.payload)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to parse IKE message from %s: %s", ip.src, exc)
            continue
        if msg is None:
            continue
        key = _dedupe_key(ip, msg)
        last = seen.get(key)
        retransmit = last is not None and (ip.ts - last) <= window
        if not retransmit:
            seen[key] = ip.ts
        out.append(
            IkeExchange(
                ts=ip.ts,
                src=ip.src,
                dst=ip.dst,
                initiator_spi=msg.initiator_spi,
                responder_spi=msg.responder_spi,
                major_version=msg.major_version,
                exchange_type=msg.exchange_type,
                message_id=msg.message_id,
                opens_negotiation=opens_negotiation(msg.initiator_spi, msg.responder_spi),
                retransmit=retransmit,
            )
        )
    return out


def unique_attempt_count(packets, window: float = DEFAULT_WINDOW) -> int:
    """Count negotiation attempts, ignoring retransmits."""
    return sum(1 for e in classify_exchanges(packets, window) if e.opens_negotiation and not e.retransmit)
