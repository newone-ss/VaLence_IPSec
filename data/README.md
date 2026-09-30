# TunnelTwin — Machine Learning Training & Testing Dataset Card
**AI-Powered IPsec Protocol Analyzer & Cryptographic Assessment Framework**  
*Problem Statement 26160 (NTRO / SIH 2026)*

---

## 1. Dataset Overview

This dataset was generated on a real virtual network namespace testbed running live IPsec VPN tunnels with Linux network emulation (`tc netem`). It provides both **raw packet captures (.pcap)** and **extracted tabular feature datasets (.csv)** for evaluating machine learning classifiers on encrypted ESP (Encapsulating Security Payload) traffic without decrypting payloads.

### Dataset Files in this Directory

| File | Type | Flows / Records | Description |
| :--- | :--- | :--- | :--- |
| **`train_dataset.csv`** | CSV | **18 flows** | Baseline training set across profiles (`bulk` & `chatty` traffic) |
| **`test_dataset.csv`** | CSV | **6 flows** | Unseen held-out test set grouped by independent capture sessions |
| **`impairment_test_dataset.csv`** | CSV | **20 flows** | Robustness evaluation set under 5 channel impairment conditions (`tc netem`) |
| **`full_dataset.csv`** | CSV | **44 flows** | Consolidated dataset with `split` tags (`train`, `test`, `impairment_test`) |
| **`dataset_manifest.json`** | JSON | Metadata | Machine-readable schema, features, and split specification |

---

## 2. Raw Packet Captures Source (`lab/captures/`)

All CSV records are directly extracted from genuine wire packet captures in [`lab/captures/`](file:///c:/Users/piyus/OneDrive/Desktop/project/Shield/lab/captures):

```text
lab/captures/
├── weak/            # 3DES-CBC / DES / MD5 / HMAC-SHA1-96 / MODP-1024
│   ├── bulk/        # 3 iperf3 high-volume transfer sessions (cap_1, cap_2, cap_3)
│   ├── chatty/      # 3 ping/burst interactive sessions (cap_1, cap_2, cap_3)
│   ├── clean/       # Baseline unimpaired wire capture
│   ├── jitter/      # delay 20ms 10ms distribution normal
│   ├── loss/        # loss 5%
│   ├── reorder/     # delay 10ms reorder 25% 50%
│   └── jitter+loss/ # delay 20ms 10ms loss 2%
├── mixed/           # AES-CBC-128 / HMAC-SHA2-256 / ECP-256
├── strong/          # AES-256-GCM / PRF-HMAC-SHA2-384 / ECP-384
├── legacy-cbc/      # AES-CBC-256 / HMAC-SHA1-96
└── retransmit/      # IKE_SA_INIT negotiation capture under 20% loss for deduplication
```

---

## 3. Classification Targets

1. **`profile` (4-class cryptographic suite identifier)**:
   - `weak`: Legacy weak algorithms violating NIST SP 800-77r1 (3DES, SHA-1, DH Group 2).
   - `legacy-cbc`: CBC mode with separate integrity check (susceptible to padding oracle attacks).
   - `mixed`: Acceptable modern symmetric cipher with legacy key exchange parameters.
   - `strong`: Modern AEAD suites meeting CNSA 2.0 / Suite B specifications (AES-GCM-256).

2. **`traffic_pattern` (Binary traffic mode)**:
   - `bulk`: Throughput-heavy file transfers generated via `iperf3`.
   - `chatty`: Low-latency interactive requests and ICMP echo bursts.

---

## 4. Feature Dictionary (34 Extracted Features)

Every row in the tabular dataset contains the following 34 features extracted from bi-directional ESP conversations:

### Packet Sizing (8 Features)
- `size_mean`: Mean packet length (bytes).
- `size_std`: Standard deviation of packet lengths.
- `size_min`: Minimum observed packet length.
- `size_max`: Maximum observed packet length (differentiates MTU bulk transfers).
- `size_median`: Median packet size.
- `size_entropy`: Shannon entropy of byte length distribution.
- `size_over_1400_ratio`: Fraction of packets larger than 1400 bytes (MTU fill indicator).
- `size_under_128_ratio`: Fraction of packets under 128 bytes (control / handshake indicator).

### Inter-Arrival Timing (7 Features)
- `iat_mean`: Mean inter-arrival time between consecutive packets (seconds).
- `iat_std`: Standard deviation of inter-arrival times.
- `iat_min`: Minimum IAT.
- `iat_max`: Maximum idle period between packets.
- `iat_median`: Median IAT.
- `iat_p95`: 95th percentile of packet arrival intervals.
- `byte_rate`: Empirical wire throughput in bytes per second.

### Burst & Sequencing (5 Features)
- `burst_ratio_10ms`: Fraction of packets arriving within 10ms of preceding packet.
- `burst_ratio_50ms`: Fraction of packets arriving within 50ms of preceding packet.
- `seq_gap_ratio`: Fraction of sequence number gaps (packet drop indicator).
- `seq_reorder_ratio`: Fraction of out-of-order ESP sequence numbers.
- `seq_span_per_packet`: Ratio of sequence number span to total packet count.

### Bi-Directional Asymmetry (5 Features)
- `fwd_pkt_ratio`: Ratio of forward packets to total packets.
- `fwd_byte_ratio`: Ratio of forward bytes to total conversation volume.
- `conv_pkt_count`: Total packet count in conversation.
- `size_mean_ratio`: Ratio of forward mean packet size to reverse mean size.
- `iat_mean_ratio`: Ratio of forward mean IAT to reverse mean IAT.

### Spectral FFT Energy (8 Features)
- `fft_bin_0` to `fft_bin_7`: Frequency energy distribution bins from Fast Fourier Transform over inter-arrival series.

---

## 5. Train / Test Split Integrity Guarantee

A common flaw in network traffic machine learning is **row-level random splitting**, which leaks packets from the same capture file into both training and testing sets, resulting in artificially inflated accuracy numbers.

TunnelTwin enforces **Grouped-by-Capture-Session Splitting**:
- The split is computed on `source_pcap` session boundaries (`_grouped_split()`).
- All packets and flows from a single capture file are assigned strictly to **either** the train set or the test set.
- **Result**: Zero data leakage; test accuracy reflects generalization to completely unseen network sessions.

---

## 6. Benchmark Evaluation Results

Trained using LightGBM (`LGBMClassifier`, 300 estimators, lr=0.05, seed=1337):

| Target | Model Backend | Held-Out Test Accuracy | Per-Class Recall |
| :--- | :--- | :--- | :--- |
| **`traffic_pattern`** | LightGBM | **1.0000 (100.0%)** | `bulk`: 1.0000, `chatty`: 1.0000 |
| **`profile`** | LightGBM | **0.6667 (66.7%)** | `mixed`: 1.0000, `strong`: 0.6667, `weak`: 0.5000 |

### Robustness Under Netem Channel Impairments (`impairment_test_dataset.csv`)

| Impairment Condition | Network Emulation Parameter | Model Accuracy | Delta vs. Clean |
| :--- | :--- | :--- | :--- |
| **Clean Wire** | Baseline (no distortion) | **75.0%** | +0.0% |
| **Jitter** | `delay 20ms 10ms distribution normal` | **75.0%** | +0.0% |
| **Packet Loss** | `loss 5%` | **75.0%** | +0.0% |
| **Packet Reorder** | `delay 10ms reorder 25% 50%` | **75.0%** | +0.0% |
| **Jitter + Loss** | `delay 20ms 10ms loss 2%` | **75.0%** | +0.0% |

---

## 7. How to Inspect or Re-Train

### Inspect in Python / Pandas
```python
import pandas as pd

train_df = pd.read_csv("data/train_dataset.csv")
test_df = pd.read_csv("data/test_dataset.csv")

print(f"Train samples: {len(train_df)}, Features: {train_df.shape[1]}")
print(f"Test samples:  {len(test_df)}, Features: {test_df.shape[1]}")
print(train_df[["profile", "traffic_pattern", "size_mean", "byte_rate"]].head())
```

### Re-Train or Re-Generate
```bash
# Re-extract and train models
python lab/run_phase5_ml.py --captures lab/captures --out lab/models

# Re-export CSV datasets
python scratch/export_dataset.py
```
