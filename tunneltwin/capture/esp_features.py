"""ESP flow feature extraction.

A bidirectional ESP conversation is split into two unidirectional flows
(keyed by SPI, which is what actually distinguishes the SAs) and then
folded into one conversation-level feature dict. Every feature here is
computed from observable wire data only: SPI, sequence number, packet
length, timing, direction. Nothing inside the ciphertext is assumed.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from tunneltwin.capture.pcap import IpPacket

_SIZE_BIN = 64
_SIZE_MAX_BIN = 24  # 24 * 64 = 1536 bytes, plus one overflow bin

BASE_FEATURE_NAMES: tuple[str, ...] = (
    "n_packets",
    "size_mean",
    "size_std",
    "size_min",
    "size_max",
    "size_median",
    "size_entropy",
    "size_over_1400_ratio",
    "size_under_128_ratio",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_median",
    "iat_p95",
    "burst_ratio_10ms",
    "burst_ratio_50ms",
    "byte_rate",
    "seq_gap_ratio",
    "seq_reorder_ratio",
    "seq_span_per_packet",
)

CONV_FEATURE_NAMES: tuple[str, ...] = (
    "fwd_pkt_ratio",
    "fwd_byte_ratio",
    "conv_pkt_count",
    "size_mean_ratio",
    "iat_mean_ratio",
)

SPECTRAL_FEATURE_NAMES: tuple[str, ...] = tuple(f"fft_bin_{i}" for i in range(8))

ALL_FEATURE_NAMES: tuple[str, ...] = BASE_FEATURE_NAMES + CONV_FEATURE_NAMES + SPECTRAL_FEATURE_NAMES


@dataclass(frozen=True)
class _Flow:
    key: tuple[str, str, int]
    sizes: list[int]
    times: list[float]
    seqs: list[int]


def _flow_key(pkt: IpPacket) -> tuple[str, str, int]:
    if len(pkt.payload) < 8:
        return (pkt.src, pkt.dst, -1)
    spi = int.from_bytes(pkt.payload[0:4], "big")
    return (pkt.src, pkt.dst, spi)


def _collect(packets: list[IpPacket]) -> dict[tuple[str, str, int], _Flow]:
    groups: dict[tuple[str, str, int], _Flow] = {}
    for pkt in packets:
        if len(pkt.payload) < 8:
            continue
        key = _flow_key(pkt)
        seq = int.from_bytes(pkt.payload[4:8], "big")
        size = len(pkt.payload)
        flow = groups.get(key)
        if flow is None:
            groups[key] = _Flow(key, [size], [pkt.ts], [seq])
        else:
            flow.sizes.append(size)
            flow.times.append(pkt.ts)
            flow.seqs.append(seq)
    return groups


ESP_HEADER_LEN = 8


def _entropy(counts: Counter[int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    acc = 0.0
    for c in counts.values():
        p = c / total
        acc -= p * math.log2(p)
    return acc


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _mean_std(vals: list[float]) -> tuple[float, float]:
    if not vals:
        return 0.0, 0.0
    m = sum(vals) / len(vals)
    if len(vals) < 2:
        return m, 0.0
    var = sum((v - m) ** 2 for v in vals) / (len(vals) - 1)
    return m, math.sqrt(var)


def _flow_features(flow: _Flow) -> dict[str, float]:
    sizes = flow.sizes
    times = sorted(flow.times)
    n = len(sizes)
    out: dict[str, float] = {"n_packets": float(n)}

    size_mean, size_std = _mean_std([float(s) for s in sizes])
    sorted_sizes = sorted(float(s) for s in sizes)
    out["size_mean"] = size_mean
    out["size_std"] = size_std
    out["size_min"] = sorted_sizes[0] if sorted_sizes else 0.0
    out["size_max"] = sorted_sizes[-1] if sorted_sizes else 0.0
    out["size_median"] = _percentile(sorted_sizes, 0.5)
    bins = Counter(min(s // _SIZE_BIN, _SIZE_MAX_BIN) for s in sizes)
    out["size_entropy"] = _entropy(bins)
    out["size_over_1400_ratio"] = sum(1 for s in sizes if s > 1400) / n if n else 0.0
    out["size_under_128_ratio"] = sum(1 for s in sizes if s < 128) / n if n else 0.0

    iats = [b - a for a, b in zip(times, times[1:], strict=False) if b >= a]
    iat_mean, iat_std = _mean_std(iats)
    sorted_iat = sorted(iats)
    out["iat_mean"] = iat_mean
    out["iat_std"] = iat_std
    out["iat_min"] = sorted_iat[0] if sorted_iat else 0.0
    out["iat_max"] = sorted_iat[-1] if sorted_iat else 0.0
    out["iat_median"] = _percentile(sorted_iat, 0.5)
    out["iat_p95"] = _percentile(sorted_iat, 0.95)
    out["burst_ratio_10ms"] = sum(1 for v in iats if v <= 0.010) / len(iats) if iats else 0.0
    out["burst_ratio_50ms"] = sum(1 for v in iats if v <= 0.050) / len(iats) if iats else 0.0
    span = (times[-1] - times[0]) if len(times) > 1 else 0.0
    out["byte_rate"] = (sum(sizes) / span) if span > 0 else 0.0

    seqs = flow.seqs
    gaps = reorders = 0
    for prev, cur in zip(seqs, seqs[1:], strict=False):
        delta = cur - prev
        if delta == 1:
            continue
        if delta <= 0:
            reorders += 1
        elif delta > 1:
            gaps += 1
    denom = max(1, len(seqs) - 1)
    out["seq_gap_ratio"] = gaps / denom
    out["seq_reorder_ratio"] = reorders / denom
    if seqs:
        span_seq = max(seqs) - min(seqs) + 1
        out["seq_span_per_packet"] = span_seq / len(seqs)
    else:
        out["seq_span_per_packet"] = 0.0
    return out


def extract_conversation(
    packets: list[IpPacket],
    *,
    spectral: bool = False,
    spectral_bins: int = 8,
) -> dict[str, float] | None:
    """Fold one ESP conversation into a single flat feature dict.

    Returns ``None`` if the conversation has no usable ESP packets, so the
    caller can skip it rather than train on an all-zero row.

    CORE path uses spectral=False.
    """
    flows = _collect(packets)
    if not flows:
        return None

    merged: dict[str, float] = {}
    per_flow: list[dict[str, float]] = [_flow_features(f) for f in flows.values()]
    for name in BASE_FEATURE_NAMES:
        vals = [f[name] for f in per_flow]
        merged[name] = sum(vals) / len(vals) if vals else 0.0

    total_pkts = sum(f["n_packets"] for f in per_flow) or 1.0
    total_bytes = sum(f["size_mean"] * f["n_packets"] for f in per_flow)
    fwd = max(flows.values(), key=lambda f: len(f.sizes))
    merged["fwd_pkt_ratio"] = len(fwd.sizes) / total_pkts
    merged["fwd_byte_ratio"] = sum(fwd.sizes) / total_bytes if total_bytes > 0 else 0.0
    merged["conv_pkt_count"] = total_pkts
    merged["size_mean_ratio"] = per_flow[0]["size_mean"] / (per_flow[-1]["size_mean"] or 1.0)
    merged["iat_mean_ratio"] = per_flow[0]["iat_mean"] / (per_flow[-1]["iat_mean"] or 1e-9)

    if spectral:
        from tunneltwin.capture.spectral import spectral_features

        merged.update(spectral_features(sorted(fwd.times), spectral_bins))
    else:
        for name in SPECTRAL_FEATURE_NAMES[:spectral_bins]:
            merged[name] = 0.0

    return merged
