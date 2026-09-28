"""
Async IKE Probe Scanner — Elimination Scan Engine.

Implements the complete probe strategy:
  1. Consent-gated allowlist check (double barrier).
  2. IKEv2 DH group discovery via parallel proposals.
  3. IKEv2 elimination scan within accepted DH group.
  4. IKEv1 Main Mode batched-proposal elimination.
  5. Cookie handling (RFC 7296 §2.6): detect and retry.
  6. Timeouts (300ms initial, exponential backoff, capped retries).
  7. Global rate limiting with jitter.

All results carry OBSERVED provenance.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass

from tunneltwin.ike.codec import (
    IKEParseError,
    build_ikev1_main_mode_request,
    build_ikev2_sa_init,
    parse_ike_message,
)
from tunneltwin.ike.constants import (
    DH_GROUP_NAMES,
    IKEV1_ATTR_AUTH_METHOD,
    IKEV1_ATTR_ENCRYPTION,
    IKEV1_ATTR_GROUP_DESC,
    IKEV1_ATTR_HASH,
    IKEV1_ATTR_KEY_LENGTH,
    NON_ESP_MARKER,
    NotifyType,
    TransformType,
)
from tunneltwin.ike.transforms import (
    IKEV2_DH_GROUPS,
    generate_ikev1_full_transform_set,
    generate_ikev2_dh_group_proposals,
    generate_ikev2_elimination_batch,
)
from tunneltwin.probe.allowlist import ConsentDeniedError, TargetAllowlist
from tunneltwin.probe.result import (
    AcceptedTransform,
    GatewayScanResult,
    IKEv1AcceptedTransform,
    ScanStatus,
)

logger = logging.getLogger("tunneltwin.probe")


# ═══════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class ScanConfig:
    """Scanner configuration with timeout, retry, and rate limit settings."""

    initial_timeout_ms: int = 300
    max_retries: int = 3
    backoff_factor: float = 2.0
    max_timeout_ms: int = 5000
    jitter_range_ms: int = 50  # Random jitter added to each probe
    rate_limit_delay_ms: int = 10  # Minimum delay between probes to same target
    use_port_4500: bool = False  # If True, use port 4500 with non-ESP marker
    try_ikev1: bool = True  # Also attempt IKEv1 Main Mode scan


# ═══════════════════════════════════════════════════════════════════════
#  Async UDP Transport
# ═══════════════════════════════════════════════════════════════════════


class _IKEProtocol(asyncio.DatagramProtocol):
    """Minimal async UDP protocol for IKE probing."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self._response_future: asyncio.Future[bytes] | None = None
        self._closed = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._response_future and not self._response_future.done():
            self._response_future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if self._response_future and not self._response_future.done():
            self._response_future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self._closed = True
        if self._response_future and not self._response_future.done():
            self._response_future.set_exception(ConnectionError(f"Connection lost: {exc}"))

    async def send_and_receive(
        self,
        data: bytes,
        target: tuple[str, int],
        timeout_s: float,
    ) -> bytes | None:
        """Send a datagram and wait for one response with timeout."""
        if self.transport is None or self._closed:
            return None

        loop = asyncio.get_running_loop()
        self._response_future = loop.create_future()

        try:
            self.transport.sendto(data, target)
            return await asyncio.wait_for(self._response_future, timeout=timeout_s)
        except TimeoutError:
            return None
        except (ConnectionError, OSError):
            return None
        finally:
            self._response_future = None


async def _create_udp_socket() -> tuple[asyncio.DatagramTransport, _IKEProtocol]:
    """Create a bound UDP socket for IKE probing."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _IKEProtocol,
        local_addr=("0.0.0.0", 0),  # noqa: S104
    )
    return transport, protocol  # type: ignore[return-value]


# ═══════════════════════════════════════════════════════════════════════
#  Core Probe Functions
# ═══════════════════════════════════════════════════════════════════════


async def _send_probe(
    protocol: _IKEProtocol,
    packet: bytes,
    target_ip: str,
    target_port: int,
    config: ScanConfig,
) -> bytes | None:
    """
    Send an IKE probe with retries, exponential backoff, and jitter.

    Returns raw response bytes, or None if all retries exhausted.
    """
    # Add non-ESP marker for port 4500
    if target_port == 4500:
        packet = NON_ESP_MARKER + packet

    timeout_ms = config.initial_timeout_ms

    for attempt in range(config.max_retries + 1):
        # Add jitter
        jitter = random.randint(0, config.jitter_range_ms) / 1000.0  # noqa: S311
        timeout_s = (timeout_ms / 1000.0) + jitter

        logger.debug(
            "Probe attempt %d/%d to %s:%d (timeout=%.0fms)",
            attempt + 1,
            config.max_retries + 1,
            target_ip,
            target_port,
            timeout_ms,
        )

        response = await protocol.send_and_receive(packet, (target_ip, target_port), timeout_s)

        if response is not None:
            return response

        # Exponential backoff for next attempt
        timeout_ms = min(int(timeout_ms * config.backoff_factor), config.max_timeout_ms)

    return None


async def _rate_limit_delay(config: ScanConfig) -> None:
    """Apply rate limiting delay between probes."""
    if config.rate_limit_delay_ms > 0:
        delay = config.rate_limit_delay_ms / 1000.0
        jitter = random.randint(0, config.jitter_range_ms) / 1000.0  # noqa: S311
        await asyncio.sleep(delay + jitter)


# ═══════════════════════════════════════════════════════════════════════
#  IKEv2 Scan Logic
# ═══════════════════════════════════════════════════════════════════════


async def _ikev2_discover_dh_groups(
    protocol: _IKEProtocol,
    target_ip: str,
    target_port: int,
    config: ScanConfig,
    result: GatewayScanResult,
) -> int | None:
    """
    Discover which DH groups the responder accepts.

    Strategy: Send proposals with each DH group. An accepted group returns
    an SA response; a rejected group returns INVALID_KE_PAYLOAD with the
    preferred group, or NO_PROPOSAL_CHOSEN.

    Returns the first accepted DH group ID, or None if none accepted.
    """
    first_accepted_group: int | None = None
    cookie: bytes | None = None

    for dh_group in IKEV2_DH_GROUPS:
        group_name = DH_GROUP_NAMES.get(dh_group, f"DH-{dh_group}")

        # Build diverse proposals with this DH group covering AEAD, CBC, and legacy ciphers
        single_proposal = generate_ikev2_dh_group_proposals(dh_group=dh_group)
        if not single_proposal:
            continue

        packet = build_ikev2_sa_init(
            proposals=single_proposal,
            dh_group=dh_group,
            cookie=cookie,
        )
        result.probe_count += 1

        response_data = await _send_probe(protocol, packet, target_ip, target_port, config)

        if response_data is None:
            logger.debug("No response for DH group %s — marking as timeout", group_name)
            result.add_rejected_dh_group(group_name, "timeout")
            await _rate_limit_delay(config)
            continue

        try:
            msg = parse_ike_message(response_data)
        except IKEParseError as exc:
            logger.warning("Failed to parse response for DH group %s: %s", group_name, exc)
            result.add_rejected_dh_group(group_name, f"parse_error: {exc}")
            await _rate_limit_delay(config)
            continue

        # Cookie handling (RFC 7296 §2.6)
        response_cookie = msg.get_cookie()
        if response_cookie is not None:
            logger.info("Cookie required by %s:%d — retrying with cookie", target_ip, target_port)
            result.mark_cookie_required(True)
            cookie = response_cookie

            # Retry this same DH group with the cookie
            packet = build_ikev2_sa_init(
                proposals=single_proposal,
                dh_group=dh_group,
                cookie=cookie,
            )
            result.probe_count += 1
            response_data = await _send_probe(protocol, packet, target_ip, target_port, config)

            if response_data is None:
                result.add_rejected_dh_group(group_name, "timeout after cookie retry")
                await _rate_limit_delay(config)
                continue

            try:
                msg = parse_ike_message(response_data)
            except IKEParseError:
                result.add_rejected_dh_group(group_name, "parse_error after cookie")
                await _rate_limit_delay(config)
                continue

        # Check if this group was accepted
        if msg.has_notify(NotifyType.NO_PROPOSAL_CHOSEN):
            result.add_rejected_dh_group(group_name, "NO_PROPOSAL_CHOSEN")
        elif msg.has_notify(NotifyType.INVALID_KE_PAYLOAD):
            result.mark_observed_ike_version("IKEv2")
            preferred = msg.get_invalid_ke_group()
            preferred_name = DH_GROUP_NAMES.get(preferred, f"DH-{preferred}") if preferred else "unknown"
            result.add_rejected_dh_group(
                group_name,
                f"INVALID_KE_PAYLOAD (preferred: {preferred_name})",
            )
        elif msg.proposals:
            # SA response received — this group is accepted
            result.add_accepted_dh_group(group_name)
            result.mark_observed_ike_version("IKEv2")
            if msg.responder_spi != b"\x00" * 8:
                result.responder_spi = msg.responder_spi

            # Extract accepted transforms from the response SA
            for prop in msg.proposals:
                for tf in prop.transforms:
                    result.accepted_transforms.append(
                        AcceptedTransform(
                            transform_type=tf.transform_type,
                            transform_id=tf.transform_id,
                            key_length=tf.key_length,
                        )
                    )

            if first_accepted_group is None:
                first_accepted_group = dh_group
        else:
            # Unexpected response — log but continue
            logger.debug("Unexpected response for DH group %s (no proposals, no notifies)", group_name)

        if not result.cookie_required.is_known():
            result.mark_cookie_required(False)

        await _rate_limit_delay(config)

    return first_accepted_group


async def _ikev2_elimination_scan(
    protocol: _IKEProtocol,
    target_ip: str,
    target_port: int,
    dh_group: int,
    config: ScanConfig,
    result: GatewayScanResult,
) -> None:
    """
    Perform elimination scan within an accepted DH group.

    Send all proposals, observe what's accepted, then iteratively remove
    the accepted transform and re-probe until NO_PROPOSAL_CHOSEN.
    This maps the complete set of acceptable transforms.
    """
    excluded_encr: set[tuple[int, int | None]] = set()
    excluded_prf: set[int] = set()
    excluded_integ: set[int] = set()
    cookie: bytes | None = None
    max_iterations = 20  # Safety limit

    for iteration in range(max_iterations):
        proposals = generate_ikev2_elimination_batch(
            dh_group=dh_group,
            exclude_encr=excluded_encr,
            exclude_prf=excluded_prf,
            exclude_integ=excluded_integ,
        )

        if not proposals:
            logger.debug("No more proposals to test — elimination complete")
            break

        # Limit proposals per packet (most implementations accept ~30 max)
        batch = proposals[:28]

        packet = build_ikev2_sa_init(
            proposals=batch,
            dh_group=dh_group,
            cookie=cookie,
        )
        result.probe_count += 1

        response_data = await _send_probe(protocol, packet, target_ip, target_port, config)

        if response_data is None:
            logger.debug("Timeout during elimination scan iteration %d", iteration)
            break

        try:
            msg = parse_ike_message(response_data)
        except IKEParseError:
            break

        # Handle cookie
        response_cookie = msg.get_cookie()
        if response_cookie is not None:
            cookie = response_cookie
            result.mark_cookie_required(True)
            # Retry same batch with cookie
            packet = build_ikev2_sa_init(proposals=batch, dh_group=dh_group, cookie=cookie)
            result.probe_count += 1
            response_data = await _send_probe(protocol, packet, target_ip, target_port, config)
            if response_data is None:
                break
            try:
                msg = parse_ike_message(response_data)
            except IKEParseError:
                break

        if msg.has_notify(NotifyType.NO_PROPOSAL_CHOSEN):
            logger.debug("NO_PROPOSAL_CHOSEN — elimination complete at iteration %d", iteration)
            break

        if msg.proposals:
            # Record accepted transforms and exclude them for next round
            for prop in msg.proposals:
                for tf in prop.transforms:
                    accepted = AcceptedTransform(
                        transform_type=tf.transform_type,
                        transform_id=tf.transform_id,
                        key_length=tf.key_length,
                    )
                    # Deduplicate
                    if not any(
                        a.transform_type == accepted.transform_type
                        and a.transform_id == accepted.transform_id
                        and a.key_length == accepted.key_length
                        for a in result.accepted_transforms
                    ):
                        result.accepted_transforms.append(accepted)

                    # Add to exclusion sets for next iteration
                    if tf.transform_type == TransformType.ENCR:
                        excluded_encr.add((tf.transform_id, tf.key_length))
                    elif tf.transform_type == TransformType.PRF:
                        excluded_prf.add(tf.transform_id)
                    elif tf.transform_type == TransformType.INTEG:
                        excluded_integ.add(tf.transform_id)

        await _rate_limit_delay(config)


# ═══════════════════════════════════════════════════════════════════════
#  IKEv1 Main Mode Scan Logic
# ═══════════════════════════════════════════════════════════════════════


async def _ikev1_scan(
    protocol: _IKEProtocol,
    target_ip: str,
    target_port: int,
    config: ScanConfig,
    result: GatewayScanResult,
) -> None:
    """
    Perform IKEv1 Main Mode batched-proposal elimination scan.

    Sends all known (encryption, hash, dh_group) combinations in a single SA,
    observes which transform the responder selects, then excludes it and repeats.
    """
    excluded_encr: set[tuple[int, int | None]] = set()
    excluded_hash: set[int] = set()
    excluded_dh: set[int] = set()
    batch_size = 30
    max_iterations = 15
    for _iteration in range(max_iterations):
        transform_specs = generate_ikev1_full_transform_set(
            exclude_encr=excluded_encr,
            exclude_hash=excluded_hash,
            exclude_dh=excluded_dh,
        )

        if not transform_specs:
            break

        found_in_iteration = False

        for batch_start in range(0, len(transform_specs), batch_size):
            batch = transform_specs[batch_start : batch_start + batch_size]

            packet = build_ikev1_main_mode_request(batch)
            result.probe_count += 1

            response_data = await _send_probe(protocol, packet, target_ip, target_port, config)

            if response_data is None:
                continue

            try:
                msg = parse_ike_message(response_data)
            except IKEParseError:
                continue

            if msg.is_ikev1 and not result.ike_version_detected.is_known():
                result.mark_observed_ike_version("IKEv1")

            # Check for accepted proposal
            if msg.ikev1_proposals:
                if result.ike_version_detected.is_known() and result.ike_version_detected.value == "IKEv2":
                    result.mark_observed_ike_version("IKEv1/IKEv2")
                else:
                    result.mark_observed_ike_version("IKEv1")
                found_in_iteration = True
                for prop in msg.ikev1_proposals:
                    for tf in prop.transforms:
                        encr = tf.attributes.get(IKEV1_ATTR_ENCRYPTION, 0)
                        hash_alg = tf.attributes.get(IKEV1_ATTR_HASH, 0)
                        auth = tf.attributes.get(IKEV1_ATTR_AUTH_METHOD, 0)
                        dh = tf.attributes.get(IKEV1_ATTR_GROUP_DESC, 0)
                        key_len = tf.attributes.get(IKEV1_ATTR_KEY_LENGTH)

                        accepted = IKEv1AcceptedTransform(
                            encryption=encr,
                            hash_alg=hash_alg,
                            auth_method=auth,
                            dh_group=dh,
                            key_length=key_len,
                        )

                        if not any(
                            a.encryption == accepted.encryption
                            and a.hash_alg == accepted.hash_alg
                            and a.dh_group == accepted.dh_group
                            and a.key_length == accepted.key_length
                            for a in result.ikev1_accepted
                        ):
                            result.ikev1_accepted.append(accepted)

                        # Exclude the accepted combination for next iteration
                        excluded_encr.add((encr, key_len))
                        excluded_dh.add(dh)

                await _rate_limit_delay(config)
                break  # Advance to next iteration with exclusions

            await _rate_limit_delay(config)

        if not found_in_iteration:
            # None of the batches were accepted in this pass
            break


# ═══════════════════════════════════════════════════════════════════════
#  Public API: Full Gateway Scan
# ═══════════════════════════════════════════════════════════════════════


async def scan_gateway(
    target_ip: str,
    allowlist: TargetAllowlist,
    config: ScanConfig | None = None,
    target_port: int = 500,
) -> GatewayScanResult:
    """
    Perform a complete IKE gateway scan.

    Orchestration:
      1. Verify target against consent-gated allowlist.
      2. IKEv2 DH group discovery.
      3. IKEv2 elimination scan within accepted groups.
      4. (Optional) IKEv1 Main Mode scan.
      5. Return results with OBSERVED provenance on all findings.
    """
    if config is None:
        config = ScanConfig()

    result = GatewayScanResult(
        target_ip=target_ip,
        target_port=target_port,
        scan_status=ScanStatus.ERROR,
    )

    # Gate 1 & 2: Consent-gated allowlist check
    try:
        allowlist.verify(target_ip)
    except ConsentDeniedError as exc:
        result.scan_status = ScanStatus.CONSENT_DENIED
        result.error_message = str(exc)
        logger.warning("Consent denied for %s: %s", target_ip, exc)
        return result

    result.start_timer()

    transport: asyncio.DatagramTransport | None = None
    try:
        transport, protocol = await _create_udp_socket()

        # Phase 1: IKEv2 DH group discovery
        logger.info("Starting IKEv2 DH group discovery for %s:%d", target_ip, target_port)
        accepted_dh = await _ikev2_discover_dh_groups(protocol, target_ip, target_port, config, result)

        if accepted_dh is not None:
            # Phase 2: Elimination scan within accepted DH group
            logger.info(
                "Starting IKEv2 elimination scan for %s:%d (DH group: %s)",
                target_ip,
                target_port,
                DH_GROUP_NAMES.get(accepted_dh, str(accepted_dh)),
            )
            await _ikev2_elimination_scan(protocol, target_ip, target_port, accepted_dh, config, result)

        # Phase 3: IKEv1 scan (if enabled and we haven't already detected IKEv2)
        if config.try_ikev1:
            logger.info("Starting IKEv1 Main Mode scan for %s:%d", target_ip, target_port)
            await _ikev1_scan(protocol, target_ip, target_port, config, result)

        # Determine final scan status
        if result.accepted_transforms or result.ikev1_accepted:
            result.scan_status = ScanStatus.SUCCESS
        elif result.accepted_dh_groups or result.rejected_dh_groups:
            result.scan_status = ScanStatus.SUCCESS  # We got responses, even if all rejected
        else:
            result.scan_status = ScanStatus.TIMEOUT

    except OSError as exc:
        result.scan_status = ScanStatus.ERROR
        result.error_message = str(exc)
        logger.error("OS error scanning %s:%d: %s", target_ip, target_port, exc)
    finally:
        result.stop_timer()
        if transport is not None:
            transport.close()

    return result


async def scan_multiple_gateways(
    targets: list[tuple[str, int]],
    allowlist: TargetAllowlist,
    config: ScanConfig | None = None,
) -> list[GatewayScanResult]:
    """
    Scan multiple gateways sequentially (respects rate limits).

    For parallel scanning of independent targets, use asyncio.gather()
    with separate scan_gateway() calls.
    """
    if config is None:
        config = ScanConfig()

    results: list[GatewayScanResult] = []

    for target_ip, target_port in targets:
        result = await scan_gateway(target_ip, allowlist, config, target_port)
        results.append(result)

    return results
