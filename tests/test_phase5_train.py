# tests/test_phase5_train.py

from tunneltwin.ml.dataset import LabelledFlow
from tunneltwin.ml.train import _grouped_split


def _row(src, profile, traffic_pattern):
    return LabelledFlow(src, profile, traffic_pattern, "strongswan", {})


def test_split_is_grouped_by_capture_file():
    rows = [_row(f"cap{i}.pcap#conv{j}", "strong", "bulk") for i in range(8) for j in range(4)]
    train, test = _grouped_split(rows, 0.25, 7)
    train_files = {rows[i].source.split("#")[0] for i in train}
    test_files = {rows[i].source.split("#")[0] for i in test}
    assert not (train_files & test_files), "capture file leaked across split"
