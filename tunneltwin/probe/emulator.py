"""
tunneltwin.probe.emulator — Async IKE-responder fleet emulator.

Simulates node_count IKE-responder gateways with random probe latencies,
profile distribution (30% weak / 50% strong / 20% legacy), and persists
the full Target → ScanRun → Fact graph into the database.

Every generated fact description contains the exact string [SIMULATED].
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from sqlmodel import Session

from tunneltwin.core.db import (
    Fact,
    Gateway,
    ProvenanceEnum,
    Seal,
    SealType,
    ScanRun,
    ScanStatus,
    Target,
    engine,
    init_db,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SIMULATED_TAG: Final[str] = "[SIMULATED]"
_OPERATOR: Final[str] = "emulator"
_CONCURRENCY: Final[int] = 50
_LATENCY_MIN_MS: Final[float] = 10.0
_LATENCY_MAX_MS: Final[float] = 500.0

# Profile distribution weights  [weak=30%, strong=50%, legacy=20%]
_PROFILES: Final[list[str]] = ["weak", "strong", "legacy"]
_PROFILE_WEIGHTS: Final[list[float]] = [0.30, 0.50, 0.20]

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

_PROFILE_SPECS: Final[dict[str, dict[str, str]]] = {
    "weak": {
        "ike_version":      "IKEv1",
        "cipher":           "3des",
        "integrity":        "md5",
        "dh_group":         "modp1024",
        "auth_method":      "psk",
        "pfs_group":        "modp1024",
        "phase1_lifetime":  "86400",
        "phase2_lifetime":  "28800",
    },
    "strong": {
        "ike_version":      "IKEv2",
        "cipher":           "aes256gcm",
        "integrity":        "none",      # AEAD — no separate integrity
        "dh_group":         "ecp384",
        "auth_method":      "ecdsa-sig",
        "pfs_group":        "ecp384",
        "phase1_lifetime":  "14400",
        "phase2_lifetime":  "3600",
    },
    "legacy": {
        "ike_version":      "IKEv2",
        "cipher":           "aes128",
        "integrity":        "sha1",
        "dh_group":         "modp2048",
        "auth_method":      "rsa-sig",
        "pfs_group":        "modp2048",
        "phase1_lifetime":  "28800",
        "phase2_lifetime":  "7200",
    },
}

_VENDORS: Final[list[str]] = [
    "cisco_ios", "strongswan", "fortios", "paloalto", "checkpoint", "juniper", "generic",
]

_OWNER_POOL: Final[list[str]] = [
    "Security-Operations-Center",
    "Red-Team",
    "Network-Engineering",
    "Compliance-Audit",
    "NTRO-Internal",
    "Lab-Testbed",
]

_SEVERITY_MAP: Final[dict[str, str]] = {
    "weak":   "CRITICAL",
    "strong": "INFO",
    "legacy": "HIGH",
}

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class _SimNode:
    """All generated data for one emulated gateway node."""

    index: int
    ip: str
    cidr: str
    port: int
    vendor: str
    owner: str
    profile: str
    latency_ms: float
    responded: bool
    nat_traversal: bool
    inferred_confidence: float

    @classmethod
    def generate(cls, index: int) -> "_SimNode":
        ip = _random_ip()
        profile = random.choices(_PROFILES, weights=_PROFILE_WEIGHTS, k=1)[0]
        return cls(
            index=index,
            ip=ip,
            cidr=_cidr24(ip),
            port=random.choices([500, 4500], weights=[0.70, 0.30], k=1)[0],
            vendor=random.choice(_VENDORS),
            owner=random.choice(_OWNER_POOL),
            profile=profile,
            latency_ms=random.uniform(_LATENCY_MIN_MS, _LATENCY_MAX_MS),
            responded=random.random() < 0.82,
            nat_traversal=random.random() < 0.40,
            inferred_confidence=round(random.uniform(0.55, 0.99), 4),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_ip() -> str:
    block = random.randint(0, 2)
    if block == 0:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    elif block == 1:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def _cidr24(ip: str) -> str:
    return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Synchronous DB writer — runs inside asyncio.to_thread()
# ---------------------------------------------------------------------------


def _write_node(node: _SimNode, previous_hash: str | None) -> str:
    """
    Insert one simulated node's full object graph into the database.

    Graph: Target → ScanRun → Gateway → Fact ×N → Seal
    Returns the SHA-256 hash of the created Seal for Merkle chaining.
    Every fact/finding note contains the exact string [SIMULATED].
    """
    spec = _PROFILE_SPECS[node.profile]
    severity = _SEVERITY_MAP[node.profile]
    src = f"emulator:node#{node.index:04d}"
    sim = _SIMULATED_TAG

    with Session(engine) as session:
        # ── Target ────────────────────────────────────────────────────────
        target = Target(
            ip_or_cidr=node.cidr,
            owner=node.owner,
            description=(
                f"{sim} node#{node.index:04d} | profile={node.profile} "
                f"vendor={node.vendor} latency={node.latency_ms:.1f}ms"
            ),
            consent_verified=True,
            created_at=_now(),
        )
        session.add(target)
        session.flush()

        # ── ScanRun ───────────────────────────────────────────────────────
        t = _now()
        scan_run = ScanRun(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            scan_type="probe",
            started_at=t,
            finished_at=t,
            operator=_OPERATOR,
            notes=(
                f"{sim} emulated IKE probe | profile={node.profile} "
                f"severity={severity} latency={node.latency_ms:.1f}ms"
            ),
        )
        session.add(scan_run)
        session.flush()

        # ── Gateway ───────────────────────────────────────────────────────
        gateway = Gateway(
            scan_run_id=scan_run.id,
            target_id=target.id,
            ip_address=node.ip,
            port=node.port,
            ike_version=spec["ike_version"],
            vendor_type=node.vendor,
            provenance=ProvenanceEnum.OBSERVED,
            responded=node.responded,
            nat_traversal=node.nat_traversal,
            raw_fingerprint=f"{sim} {node.vendor} fingerprint",
            discovered_at=_now(),
        )
        session.add(gateway)
        session.flush()

        # ── Facts (OBSERVED) ──────────────────────────────────────────────
        observed: list[tuple[str, str]] = [
            ("ike_version",   spec["ike_version"]),
            ("cipher",        spec["cipher"]),
            ("integrity",     spec["integrity"]),
            ("dh_group",      spec["dh_group"]),
            ("auth_method",   spec["auth_method"]),
            ("port",          str(node.port)),
            ("responded",     str(node.responded).lower()),
            ("nat_traversal", str(node.nat_traversal).lower()),
            ("vendor",        node.vendor),
            ("profile",       node.profile),
            ("severity",      severity),
            ("latency_ms",    f"{node.latency_ms:.2f}"),
        ]

        for param, value in observed:
            session.add(Fact(
                scan_run_id=scan_run.id,
                gateway_id=gateway.id,
                parameter=param,
                raw_value=value,
                provenance=ProvenanceEnum.OBSERVED,
                confidence=1.0,
                source_ref=src,
                notes=f"{sim} observed param '{param}' profile={node.profile}",
                recorded_at=_now(),
            ))

        # ── Facts (INFERRED) ──────────────────────────────────────────────
        inferred: list[tuple[str, str, float]] = [
            ("pfs_group",       spec["pfs_group"],       node.inferred_confidence),
            ("phase1_lifetime", spec["phase1_lifetime"],  round(node.inferred_confidence * 0.92, 4)),
            ("phase2_lifetime", spec["phase2_lifetime"],  round(node.inferred_confidence * 0.87, 4)),
        ]

        for param, value, conf in inferred:
            session.add(Fact(
                scan_run_id=scan_run.id,
                gateway_id=gateway.id,
                parameter=param,
                raw_value=value,
                provenance=ProvenanceEnum.INFERRED,
                confidence=conf,
                source_ref=src,
                notes=f"{sim} inferred param '{param}' conf={conf:.4f} profile={node.profile}",
                recorded_at=_now(),
            ))

        # ── Seal ──────────────────────────────────────────────────────────
        payload = json.dumps({
            "target_id":   target.id,
            "scan_run_id": scan_run.id,
            "gateway_id":  gateway.id,
            "ip":          node.ip,
            "profile":     node.profile,
            "index":       node.index,
            "tag":         sim,
            "ts":          _now().isoformat(),
        }, sort_keys=True)

        this_hash = _sha256(payload)
        merkle_root = _sha256((previous_hash or "") + this_hash)

        session.add(Seal(
            scan_run_id=scan_run.id,
            seal_type=SealType.SCAN,
            entity_type="scan_run",
            entity_id=scan_run.id,
            sha256_hash=this_hash,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            signed_by=_OPERATOR,
            sealed_at=_now(),
            notes=f"{sim} auto-sealed by emulator node#{node.index:04d}",
        ))

        session.commit()
        return this_hash


# ---------------------------------------------------------------------------
# Async task wrapper
# ---------------------------------------------------------------------------


async def _simulate_node(
    node: _SimNode,
    semaphore: asyncio.Semaphore,
    chain: list[str | None],
    lock: asyncio.Lock,
) -> None:
    """
    Simulate IKE probe latency, then write the node to the DB.
    Semaphore bounds concurrent writer threads.
    Lock serialises Merkle chain updates.
    """
    async with semaphore:
        # Simulate IKE round-trip latency (non-blocking)
        await asyncio.sleep(node.latency_ms / 1_000.0)

        async with lock:
            prev = chain[0]

        new_hash = await asyncio.to_thread(_write_node, node, prev)

        async with lock:
            chain[0] = new_hash


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_emulator(
    node_count: int = 1000,
    db_session: Session | None = None,  # accepted for API compat; emulator manages its own sessions
) -> dict[str, object]:
    """
    Asynchronously simulate `node_count` IKE-responder gateways and insert
    them into the database.

    Profile distribution
    --------------------
    - 30% weak   — IKEv1 / 3DES / MD5 / MODP-1024   (severity: CRITICAL)
    - 50% strong — IKEv2 / AES-256-GCM / ECP-384     (severity: INFO)
    - 20% legacy — IKEv2 / AES-128-CBC / SHA1         (severity: HIGH)

    Probe latency
    -------------
    Each task awaits a simulated round-trip of 10 ms – 500 ms before writing,
    matching realistic IKE SA_INIT response timing.

    Every generated fact note contains the exact string [SIMULATED].

    Parameters
    ----------
    node_count : int
        Number of gateway nodes to emulate. Default 1 000.
    db_session : Session | None
        Ignored — emulator manages per-node sessions internally to allow
        concurrent writes. Accepted for interface compatibility.

    Returns
    -------
    dict with keys: count, weak, strong, legacy, elapsed_s, merkle_root
    """
    log.info("%s Initialising schema for %d nodes …", _SIMULATED_TAG, node_count)
    init_db()

    nodes = [_SimNode.generate(i) for i in range(1, node_count + 1)]

    profile_counts: dict[str, int] = {"weak": 0, "strong": 0, "legacy": 0}
    for n in nodes:
        profile_counts[n.profile] += 1

    log.info(
        "%s Profile split — weak=%d strong=%d legacy=%d",
        _SIMULATED_TAG,
        profile_counts["weak"],
        profile_counts["strong"],
        profile_counts["legacy"],
    )

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    lock = asyncio.Lock()
    chain: list[str | None] = [None]

    completed = 0
    t0 = time.perf_counter()

    async def _tracked(node: _SimNode) -> None:
        nonlocal completed
        await _simulate_node(node, semaphore, chain, lock)
        completed += 1
        if completed % 100 == 0 or completed == node_count:
            elapsed = time.perf_counter() - t0
            log.info(
                "%s %d/%d inserted  (%.1f nodes/s)",
                _SIMULATED_TAG, completed, node_count,
                completed / elapsed if elapsed else 0.0,
            )

    await asyncio.gather(*[asyncio.create_task(_tracked(n)) for n in nodes])

    elapsed = time.perf_counter() - t0
    final_root = chain[0] or ""

    log.info(
        "%s Complete — %d nodes in %.2fs | Merkle root: %s",
        _SIMULATED_TAG, node_count, elapsed, final_root,
    )

    return {
        "count":      node_count,
        "weak":       profile_counts["weak"],
        "strong":     profile_counts["strong"],
        "legacy":     profile_counts["legacy"],
        "elapsed_s":  round(elapsed, 3),
        "merkle_root": final_root,
    }


# ---------------------------------------------------------------------------
# CLI shim
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    _p = argparse.ArgumentParser(
        prog="python -m tunneltwin.probe.emulator",
        description="Insert N simulated IKE-responder gateways tagged [SIMULATED].",
    )
    _p.add_argument("--count", type=int, default=1000, metavar="N")
    _p.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    _args = _p.parse_args()

    logging.basicConfig(
        level=getattr(logging, _args.log_level),
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    asyncio.run(run_emulator(node_count=_args.count))
