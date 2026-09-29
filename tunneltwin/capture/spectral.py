"""Spectral feature group: FFT over a flow's inter-arrival times.

The Phase 5 exit criteria require the classifier accuracy to be reported
WITH and WITHOUT this group as an explicit before/after comparison, so
this module is deliberately separable -- ``extract_conversation(...,
spectral=False)`` produces the ablated feature table from the exact same
code path.
"""

from __future__ import annotations

import math

import tunneltwin.capture.esp_features as _esp

_TOP_BINS = 8


def _real_fft_magnitudes(x: list[float]) -> list[float]:
    """Real FFT magnitudes, zero-padded to the next power of two.

    Uses numpy when available; falls back to a pure-Python DFT so the
    unit tests and any offline analysis path do not require the ML extra.
    """
    if not x:
        return []
    try:
        import numpy as np  # type: ignore[import-not-found]

        arr = np.asarray(x, dtype=np.float64)
        n = 1
        while n < arr.size:
            n <<= 1
        padded_arr = np.zeros(n, dtype=np.float64)
        padded_arr[: arr.size] = arr - arr.mean()
        return [float(v) for v in np.abs(np.fft.rfft(padded_arr))]
    except ImportError:
        mean = sum(x) / len(x)
        centred = [v - mean for v in x]
        n = 1
        while n < len(centred):
            n <<= 1
        padded_list: list[float] = centred + [0.0] * (n - len(centred))
        out: list[float] = []
        for k in range(n // 2 + 1):
            re = im = 0.0
            for t, v in enumerate(padded_list):
                ang = -2.0 * math.pi * k * t / n
                re += v * math.cos(ang)
                im += v * math.sin(ang)
            out.append(math.hypot(re, im))
        return out


def spectral_features(times: list[float], n_bins: int = _TOP_BINS) -> dict[str, float]:
    """Top-``n_bins`` FFT magnitudes of the inter-arrival-time signal.

    DC is dropped (it is just the mean, already a base feature). Bins are
    normalised by the total non-DC energy so the values are comparable
    across flows of very different packet counts.
    """
    out: dict[str, float] = {f"fft_bin_{i}": 0.0 for i in range(n_bins)}
    if len(times) < 4:
        return out

    iats = [b - a for a, b in zip(times, times[1:], strict=False) if b >= a]
    if len(iats) < 4:
        return out

    mags = _real_fft_magnitudes(iats)
    if len(mags) <= 1:
        return out
    non_dc = mags[1:]
    total = sum(non_dc)
    if total <= 0:
        return out

    ranked = sorted(range(len(non_dc)), key=lambda i: non_dc[i], reverse=True)
    for slot, idx in enumerate(ranked[:n_bins]):
        out[f"fft_bin_{slot}"] = non_dc[idx] / total
    return out


# Re-exported so esp_features can import without a cycle.
def _declared_names(n: int = _TOP_BINS) -> tuple[str, ...]:
    return tuple(f"fft_bin_{i}" for i in range(n))


if _declared_names() != _esp.SPECTRAL_FEATURE_NAMES:
    raise RuntimeError("Spectral feature names out of sync with esp_features")
