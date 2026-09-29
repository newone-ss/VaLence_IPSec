"""Impairment and multiplexing test harness.

Phase 5 requires accuracy under real-network effects to be measured, not
asserted. Everything here shells out to ``tc`` and therefore only runs on
the Linux lab host. On any other platform the functions raise a clear
``RuntimeError`` rather than silently returning clean-lab numbers.
"""

from __future__ import annotations

import platform
import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path

NETEM_CONDITIONS: tuple[tuple[str, str | None], ...] = (
    ("clean", None),
    ("jitter", "delay 20ms 10ms distribution normal"),
    ("loss", "loss 5%"),
    ("reorder", "delay 10ms reorder 25% 50%"),
    ("jitter+loss", "delay 20ms 10ms loss 2%"),
)


@dataclass
class ConditionResult:
    condition: str
    n_flows: int
    accuracy: float
    delta_vs_clean: float


def _require_linux_tc() -> None:
    if platform.system() != "Linux":
        raise RuntimeError(
            "netem impairment testing requires Linux (tc). Run this from the "
            "WSL2/lab host that owns the Phase 0 namespaces. Refusing to "
            "produce a fabricated 'clean lab' number on "
            f"{platform.system()}."
        )
    if shutil.which("tc") is None:
        raise RuntimeError("tc not found on PATH; install iproute2")


def apply_netem(iface: str, spec: str, ns: str | None = None) -> None:
    _require_linux_tc()
    prefix = ["ip", "netns", "exec", ns] if ns else []
    subprocess.run(  # nosec # noqa: S603,S607
        [*prefix, "tc", "qdisc", "del", "dev", iface, "root"],  # noqa: S607
        check=False,
        capture_output=True,
    )
    if spec:
        subprocess.run(  # nosec # noqa: S603,S607
            [*prefix, "tc", "qdisc", "add", "dev", iface, "root", "netem", *spec.split()],  # noqa: S607
            check=True,
        )


def clear_netem(iface: str, ns: str | None = None) -> None:
    _require_linux_tc()
    prefix = ["ip", "netns", "exec", ns] if ns else []
    subprocess.run(  # nosec # noqa: S603,S607
        [*prefix, "tc", "qdisc", "del", "dev", iface, "root"],  # noqa: S607
        check=False,
        capture_output=True,
    )


def capture_during(
    iface: str,
    seconds: float,
    out_path: Path,
    *,
    ns: str | None = None,
    bpf: str = "ip proto \\esp or udp port 500 or udp port 4500",
) -> Path:
    _require_linux_tc()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = ["ip", "netns", "exec", ns] if ns else []
    proc = subprocess.Popen(  # nosec # noqa: S603,S607
        [*prefix, "tcpdump", "-i", iface, "-w", str(out_path), "-s", "0", "-U", bpf],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(seconds)
    proc.terminate()
    proc.wait(timeout=10)
    return out_path


def evaluate_condition(
    condition: str,
    clean_accuracy: float,
    measured_accuracy: float,
    n_flows: int,
) -> ConditionResult:
    return ConditionResult(
        condition=condition,
        n_flows=n_flows,
        accuracy=measured_accuracy,
        delta_vs_clean=measured_accuracy - clean_accuracy,
    )


def multiplexing_note() -> str:
    """The feature extractor windows per flow, keyed by SPI.

    Multiple concurrent ESP flows through one tunnel produce separate
    ``(src, dst, spi)`` groups, so their IAT series never interleave and
    a burst in flow A cannot inflate flow B's burst_ratio. The
    ``test_phase5_multiplex.py`` unit test asserts exactly this on
    synthetic input, which is why the property is testable without a lab.
    """
    return "per-flow windowing keyed by (src,dst,spi); concurrent flows do not share an IAT series"
