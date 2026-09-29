# Phase 5 CORE — Evidence Summary

**Status as of 2026-09-29 (Linux/WSL2 host)**: Complete & empirically verified on real live testbed captures. All models trained, held-out accuracy numbers measured, clean-vs-impaired robustness evaluated, and retransmissions verified under real packet loss.

---

## CORE Exit Criteria (from ROLE.txt)

| # | Criterion | Status | Real Output / Artifact |
|---|-----------|--------|------------------------|
| 1 | Trained model with held-out accuracy number | **PASSED** | `lab/models/train_report.json`: `traffic_pattern` 1.0000, `profile` 0.6667 |
| 2 | Side-by-side clean-vs-impaired accuracy from real captures | **PASSED** | `lab/models/impairment.json`: clean 0.7500, jitter 0.7500, loss 0.7500, reorder 0.7500, jitter+loss 0.7500 |
| 3 | `docs/evidence/phase5_summary.md` populated with real output | **PASSED** | Populated below directly from lab runner output |

---

## Real Empirical Model Performance (WSL2 / Linux Lab Host)

Execution command:
```bash
cd /mnt/c/Users/piyus/OneDrive/Desktop/project/Shield && PYTHONPATH=. python3 lab/run_phase5_ml.py --captures lab/captures --out lab/models
```

### 1. Held-Out Accuracy (CORE Targets)

Split methodology: **Grouped by capture file session** (`_grouped_split()`, 25% held-out test split, seed=1337). 18 training flows across sessions, 6 test flows from unseen capture sessions.

| Target | Model Backend | Held-Out Test Accuracy | Per-Class Recall |
|---|---|---|---|
| **traffic_pattern** | `lightgbm` | **1.0000 (100.0%)** | `bulk`: 1.0000, `chatty`: 1.0000 |
| **profile** | `lightgbm` | **0.6667 (66.7%)** | `mixed`: 1.0000, `strong`: 0.6667, `weak`: 0.5000 |

### 2. Robustness Check: Clean vs. Impaired Accuracy (Netem)

Evaluation across 20 real PCAPs generated under Linux `tc netem` impairment conditions on `veth-left`:

| Condition | Specification | Accuracy | Delta vs. Clean | Flows Tested |
|---|---|---|---|---|
| **clean** | None (baseline wire) | **0.7500** | +0.0000 | 4 flows (1 per profile) |
| **jitter** | `delay 20ms 10ms distribution normal` | **0.7500** | +0.0000 | 4 flows (1 per profile) |
| **loss** | `loss 5%` | **0.7500** | +0.0000 | 4 flows (1 per profile) |
| **reorder** | `delay 10ms reorder 25% 50%` | **0.7500** | +0.0000 | 4 flows (1 per profile) |
| **jitter+loss** | `delay 20ms 10ms loss 2%` | **0.7500** | +0.0000 | 4 flows (1 per profile) |

### 3. TreeSHAP Local Explainability Sample (`lab/models/shap_sample.json`)

Top-3 contributing features explaining a live prediction on `legacy-cbc/bulk`:
- **Predicted Profile**: `legacy-cbc`
- **Model Confidence**: `0.9996` (99.96%)
- **Explanation Method**: `tree_shap`
- **Top Contributing Features**:
  1. `size_max`: `+4.9551` (strongest positive driver toward legacy-cbc due to large bulk MTU payload framing)
  2. `size_mean`: `+2.4160` (positive contribution from bulk transmission packet sizes)
  3. `iat_std`: `-1.7177` (low inter-arrival variance in bulk transfer acts as moderating signal)

### 4. IKE Retransmit Deduplication Verification (`lab/force_retransmit.sh`)

Execution command:
```bash
bash lab/force_retransmit.sh
```
- **Method**: Applied 20% loss (`tc netem loss 20%`) during `IKE_SA_INIT` negotiation.
- **Wire Capture**: 6 IKE packets captured on port 500/4500.
- **Deduplication Output**:
  ```text
  unique_attempt_count = 1
  PASS: retransmit correctly de-duplicated
  ```

---

## Unit Test Results (Pure Python)

All run via: `pytest -v tests/ -k "phase5"`

```text
tests/test_phase5_pcap.py::test_decode_ipv4_udp_roundtrip PASSED         [  7%]
tests/test_phase5_pcap.py::test_non_udp_ignored_by_iter_ike_contract PASSED [ 15%]
tests/test_phase5_retransmit.py::test_sa_init_from_initiator_opens_negotiation PASSED [ 23%]
tests/test_phase5_retransmit.py::test_sa_init_reply_does_not_open_negotiation PASSED [ 30%]
tests/test_phase5_retransmit.py::test_all_zero_is_not_a_negotiation_open PASSED [ 38%]
tests/test_phase5_retransmit.py::test_subsequent_packet_does_not_open_negotiation PASSED [ 46%]
tests/test_phase5_rfc4303.py::test_cbc_length_must_be_block_aligned PASSED [ 53%]
tests/test_phase5_rfc4303.py::test_gcm_has_no_alignment_constraint PASSED [ 61%]
tests/test_phase5_rfc4303.py::test_intersection_shrinks_candidate_set PASSED [ 69%]
tests/test_phase5_spectral.py::test_spectral_keys_are_stable PASSED      [ 76%]
tests/test_phase5_spectral.py::test_spectral_ablation_changes_vector PASSED [ 84%]
tests/test_phase5_spectral.py::test_multiplexed_flows_do_not_share_iat_series PASSED [ 92%]
tests/test_phase5_train.py::test_split_is_grouped_by_capture_file PASSED [100%]
```

**Total: 13 Phase 5 tests passed.**

---

## Code Quality Gates

```bash
ruff check . && ruff format --check .
mypy tunneltwin --ignore-missing-imports
bandit -r tunneltwin/
```
All quality gates pass with 0 errors across all 38 source files.

---

## CORE Implementation Scope Summary

### Capture & Decode
- `tunneltwin/capture/pcap.py` — dependency-free PCAP/PCAPNG reader, Ethernet/SLL/raw/IP decode, IPv4/IPv6, UDP/TCP/ESP/AH
- `tunneltwin/capture/rfc4303.py` — arithmetic filter narrowing cipher/ICV candidates by observed ESP length
- `tunneltwin/capture/esp_features.py` — per-SPI flow windowing, 21 base + 5 conv features, `extract_conversation(spectral=False)` for CORE
- `tunneltwin/capture/spectral.py` — FFT over IAT (OPTIONAL, not wired into CORE)
- `tunneltwin/capture/retransmit.py` — IKE retransmit de-dup via `(src,dst,initiator_spi,responder_spi,exchange_type,message_id)` within 30s window; `opens_negotiation()` predicate

### ML Pipeline (CORE targets)
- `tunneltwin/ml/dataset.py` — labels from `lab/captures/<profile>/<pattern>/` (profile ∈ {weak,mixed,strong,legacy-cbc}, pattern ∈ {bulk,chatty})
- `tunneltwin/ml/train.py` — grouped-by-capture-file split, LightGBM/RF, targets: `profile` (4-way), `traffic_pattern` (binary)
- `tunneltwin/ml/explain.py` — TreeSHAP top-3 per prediction
- `tunneltwin/ml/robustness.py` — netem harness supporting per-namespace execution on Linux

### Lab Scripts
- `lab/generate_captures.sh` — brings up each profile, generates bulk (iperf3) and chatty (pings) traffic, saves to `lab/captures/<profile>/<pattern>/`
- `lab/generate_impairments.sh` — generates all 20 netem captures (clean, jitter, loss, reorder, jitter+loss across 4 profiles)
- `lab/netem.sh` — captures under clean/jitter/loss/reorder/jitter+loss for 4 CORE profiles
- `lab/force_retransmit.sh` — forces IKE retransmit via 20% loss, verifies `unique_attempt_count == 1`
- `lab/run_phase5_ml.py` — end-to-end training and robustness evaluation runner

---

## Verification Checklist (CORE)

- [x] 4 profiles × 2 patterns = 8 capture directories exist under `lab/captures/` (24 total PCAPs)
- [x] Each directory has ≥ 1 `.pcap` file with genuine wire ESP traffic
- [x] `lab/run_phase5_ml.py` runs without error on WSL2
- [x] `train_report.json` shows accuracy for `profile` and `traffic_pattern`
- [x] `impairment.json` has 5 conditions with real measured accuracy numbers
- [x] `shap_sample.json` exists with top-3 features and method (`tree_shap`)
- [x] `force_retransmit.sh` prints `PASS: retransmit correctly de-duplicated`
- [x] This document updated with real numbers directly traceable to lab execution