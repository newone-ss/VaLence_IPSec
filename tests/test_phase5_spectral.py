# tests/test_phase5_spectral.py
from tunneltwin.capture.esp_features import (
    ALL_FEATURE_NAMES,
    extract_conversation,
)
from tunneltwin.capture.pcap import IpPacket
from tunneltwin.capture.spectral import spectral_features


def _esp(ts, spi, seq, size, src="10.0.0.1", dst="10.0.0.2"):
    payload = spi.to_bytes(4, "big") + seq.to_bytes(4, "big") + bytes(size - 8)
    return IpPacket(ts, src, dst, 50, size + 20, 20, payload, False)


def test_spectral_keys_are_stable():
    feats = spectral_features([0.0, 0.01, 0.02, 0.031, 0.041, 0.05])
    assert set(feats) == {f"fft_bin_{i}" for i in range(8)}
    assert all(0.0 <= v <= 1.0 for v in feats.values())


def test_spectral_ablation_changes_vector():
    pkts = [_esp(i * 0.01, 0x1111, i, 100) for i in range(20)]
    with_fft = extract_conversation(pkts, spectral=True)
    without = extract_conversation(pkts, spectral=False)
    assert with_fft is not None and without is not None
    assert any(with_fft[n] != without[n] for n in ALL_FEATURE_NAMES if n.startswith("fft_"))
    assert all(without[n] == 0.0 for n in ALL_FEATURE_NAMES if n.startswith("fft_"))


def test_multiplexed_flows_do_not_share_iat_series():
    """Two concurrent SAs on the same host pair must be windowed separately."""
    a = [_esp(i * 0.005, 0xAAAA, i, 1200) for i in range(10)]
    b = [_esp(i * 0.050 + 0.002, 0xBBBB, i, 80) for i in range(10)]
    fa = extract_conversation(a)
    fb = extract_conversation(b)
    assert fa is not None and fb is not None
    assert fa["size_mean"] > 10 * fb["size_mean"]
    assert fa["iat_mean"] < fb["iat_mean"]
