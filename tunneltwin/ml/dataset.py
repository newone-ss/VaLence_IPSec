"""Build the labelled feature table for the Phase 5 classifiers.

Labels come from a manifest JSON, or -- for lab captures -- from a
directory naming convention:

    lab/captures/<profile>/<pattern>/<capture>.pcap

e.g. ``lab/captures/strong/bulk/session1.pcap``.
Profile is one of: weak, mixed, strong, legacy-cbc.
Pattern is one of: bulk, chatty.

Directory-derived labels are fine for training data we generated ourselves;
every flow still carries its source path so a reviewer can trace any row
back to a capture file.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from tunneltwin.capture.esp_features import ALL_FEATURE_NAMES, extract_conversation
from tunneltwin.capture.pcap import IpPacket, iter_ip

DEFAULT_MANIFEST = Path("lab/captures/manifest.json")


@dataclass
class LabelledFlow:
    source: str
    profile: str  # weak, mixed, strong, legacy-cbc
    traffic_pattern: str  # bulk, chatty
    daemon: str
    features: dict[str, float]


def _group_conversations(packets: Iterable[IpPacket]) -> dict[tuple[str, str], list[IpPacket]]:
    convs: dict[tuple[str, str], list[IpPacket]] = {}
    for pkt in packets:
        if pkt.proto != 50:  # ESP only; IKE handled separately
            continue
        convs.setdefault(pkt.conversation_key, []).append(pkt)
    return convs


def _labels_from_dir(path: Path, root: Path) -> tuple[str, str, str]:
    rel = path.relative_to(root)
    parts = rel.parts
    if len(parts) >= 2:
        profile = parts[0]
        pattern = parts[1]
    else:
        profile = "unknown"
        pattern = "unknown"
    daemon = "strongswan"  # CORE captures are all strongSwan
    return profile, pattern, daemon


def build_dataset(
    root: str | Path,
    *,
    manifest: str | Path | None = None,
    spectral: bool = False,  # CORE uses spectral=False
) -> list[LabelledFlow]:
    root = Path(root)
    manifest_path = Path(manifest) if manifest else root / "manifest.json"
    explicit: dict[str, dict[str, str]] = {}
    if manifest_path.is_file():
        explicit = json.loads(manifest_path.read_text(encoding="utf-8"))

    rows: list[LabelledFlow] = []
    for pcap in sorted(root.rglob("*.pcap")) + sorted(root.rglob("*.pcapng")):
        rel = str(pcap.relative_to(root)).replace("\\", "/")
        meta = explicit.get(rel)
        if meta:
            profile = meta["profile"]
            traffic_pattern = meta["traffic_pattern"]
            daemon = meta.get("daemon", "strongswan")
        else:
            profile, traffic_pattern, daemon = _labels_from_dir(pcap, root)

        convs = _group_conversations(iter_ip(pcap))
        for idx, packets in enumerate(convs.values()):
            feats = extract_conversation(packets, spectral=spectral)
            if feats is None:
                continue
            rows.append(
                LabelledFlow(
                    source=f"{rel}#conv{idx}",
                    profile=profile,
                    traffic_pattern=traffic_pattern,
                    daemon=daemon,
                    features=feats,
                )
            )
    return rows


def to_matrix(
    rows: list[LabelledFlow], feature_names: tuple[str, ...] = ALL_FEATURE_NAMES
) -> tuple[list[list[float]], list[str]]:
    groups = [r.source.split("#")[0] for r in rows]
    matrix = [[r.features.get(name, 0.0) for name in feature_names] for r in rows]
    return matrix, groups


def dump_rows(rows: list[LabelledFlow], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(r) for r in rows], indent=2), encoding="utf-8")
