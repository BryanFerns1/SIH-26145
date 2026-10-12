# UniGuard Char-CNN v4 — DNS Threat Detection Engine
### Smart India Hackathon 2026 (SIH26145) — Team CeaserX
**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (Data Diode / TAP)**

[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passing-brightgreen.svg)]()
[![Model](https://img.shields.io/badge/Model-HybridNet__v4%20(944K%20params)-blue.svg)]()
[![SIH Compliance](https://img.shields.io/badge/SIH26145-Compliant-success.svg)]()
[![Accuracy](https://img.shields.io/badge/Accuracy-93.21%25-informational.svg)]()
[![DNS Tunnel F1](https://img.shields.io/badge/DNS%20Tunnel%20F1-1.0000%20(100%25)-brightgreen.svg)]()
[![ONNX Runtime](https://img.shields.io/badge/ONNX%20Parity-Verified%20(3.58e--7)-brightgreen.svg)]()

---

## Executive Summary

**UniGuard** is a production-grade, deep learning-powered passive DNS threat detection engine engineered specifically for **unidirectional network environments (hardware data diodes / receive-only TAPs)**.

In physical data diode architectures, the sensor monitors raw client-to-server ingress queries only. Server responses (`RCODE`, `NXDOMAIN`, answer RR sets, TTL, response size) are physically absent. UniGuard detects **Domain Generation Algorithms (DGA)** and **DNS Tunnelling / C2 Exfiltration** directly from raw Fully Qualified Domain Names (FQDNs) with zero decryption, zero payload reassembly, and zero reliance on server response signals.

---

## Trained Model Specifications & Architecture

### Model: `HybridNet_v4` (`version 5.0.0`)
- **Total Trainable Parameters**: **943,923** *(Strictly within the `< 1,000,000` edge/sensor budget)*
- **Input 1 (Character Tokens)**: Tensor shape `(Batch, 128)` — RFC 1035 tokenized character sequence with internal dot preservation.
- **Input 2 (Lexical Evidence Features)**: Tensor shape `(Batch, 18)` — Handcrafted lexical statistics normalized via `feature_stats.npz`.
- **Character Vocabulary Size**: **41** (`a-z`, `0-9`, `-`, `_`, `.`, `<PAD>`, `<UNK>`).
- **Post-Training Calibration**: Temperature Scaling ($T \approx 1.0124$) via L-BFGS to produce well-calibrated posterior probabilities.

```
Input 1: Char Tokens (B, 128)      Input 2: Lexical Features (B, 18)
         │                                      │
    Embedding(41, 48)                    Linear(18→64) + ReLU
         │                                      │
  ┌──────┼──────┬──────┐               ┌────────┼────────┐
  │Conv  │Conv  │Conv  │Conv           │ feat_to_conv    │ gate_proj
  │k=3   │k=5   │k=7   │k=9           │ Linear(64→512)  │ Linear(64→320)
  └──┬───┴──┬───┴──┬───┴──┬───┘        └────────┬────────┘────────┬
     └──────┴──────┴──────┘                     │                 │
           Concat (512ch)                       │                 │
           BatchNorm1d                          │                 │
                │ ← ─── Early Feature Modulation┘                 │
           BiGRU (hidden=160, bidirectional=320)                  │
                │ ← ─── Sigmoid Lexical Gating ───────────────────┘
        ┌───────┴───────┐
    Masked MaxPool  Masked AvgPool
        └───────┬───────┘
       [max ‖ avg ‖ feats] (704-dim)
                │
           Linear(704→128) + ReLU + Dropout(0.25)
                │
           Linear(128→3) (Raw Logits)
                │
           Temperature Scaling (T=1.0124) → Calibrated Softmax
```

---

## The 18 Extracted Lexical Evidence Features

UniGuard extracts 18 query-side lexical features that encode linguistic, statistical, and structural anomalies:

| # | Feature Name | Description & Security Relevance |
|---|--------------|----------------------------------|
| 1 | `length` | Total FQDN character length (tunnels skew long). |
| 2 | `log_len` | Log-transformed length for distribution smoothing. |
| 3 | `entropy` | Shannon entropy of domain character distribution. |
| 4 | `norm_entropy` | Shannon entropy normalized by $\log_2(\text{length})$. |
| 5 | `digit_ratio` | Fraction of numeric digits (`0-9`). |
| 6 | `alpha_ratio` | Fraction of alphabetic characters (`a-z`). |
| 7 | `vowel_ratio` | Ratio of vowels to total letters (detects consonant-heavy DGAs). |
| 8 | `max_consonant_run`| Longest contiguous streak of consonants. |
| 9 | `sep_ratio` | Fraction of separator characters (`-`, `_`, `.`). |
| 10 | `unique_char_ratio` | Unique characters divided by length. |
| 11 | `n_labels` | Number of dot-separated sub-labels. |
| 12 | `max_label_len` | Character length of the longest label. |
| 13 | `mean_label_len` | Average length of labels. |
| 14 | `hex_fraction` | Ratio of hexadecimal characters (indicates hex-encoded exfil). |
| 15 | `base32_fraction` | Ratio of Base32 characters (indicates Base32-encoded tunnels). |
| 16 | `base64_fraction` | Ratio of Base64 characters (detects base64-encoded payloads). |
| 17 | `dict_word_ratio` | Proportion of dictionary-like n-grams / English tokens. |
| 18 | `subdomain_entropy`| Shannon entropy calculated strictly on subdomain labels. |

---

## Benchmark & Holdout Evaluation Results

Evaluated on the independent **10,769-sample holdout test partition** (`outputs/sih_classification_report.json`):

### Classification Performance Matrix

| Threat Class | Support | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | FPR @ 95% TPR |
|--------------|---------|-----------|--------|----------|---------|--------|---------------|
| **Benign** | 7,000 | **92.12%** | **97.93%** | **94.94%** | 0.9636 | 0.9774 | 13.61% |
| **DGA** | 2,146 | **91.50%** | **72.69%** | **81.02%** | 0.9482 | 0.8831 | 31.23% |
| **DNS Tunnel** | 1,623 | **100.00%** | **100.00%** | **100.00%** | **1.0000** | **1.0000** | **0.00%** |
| **Macro Average** | 10,769 | **94.54%** | **90.21%** | **91.99%** | **0.9706** | **0.9535** | — |
| **Weighted Average** | 10,769 | **93.19%** | **93.21%** | **92.93%** | — | — | — |

- **Overall Accuracy**: **93.21%**
- **DNS Tunnel Detection**: **Zero False Positives and Zero False Negatives** across 1,623 active tunnelling samples.
- **Calibrated Decision Thresholds** (`outputs/thresholds.json`):
  - DGA Threshold: `0.655`
  - DNS Tunnel Threshold: `0.100`
  - Calibrated Macro F1: **92.13%**

### Confusion Matrix (Test Set: 10,769 Samples)

```
                 Predicted Benign   Predicted DGA   Predicted Tunnel
Actual Benign         6,855              145               0
Actual DGA             586             1,560               0
Actual Tunnel            0                 0           1,623
```

### Inference Latency & Throughput (CPU Benchmark)

| Batch Size | Total Queries | Throughput (QPS) | Median Latency ($p_{50}$) | $p_{95}$ Latency | $p_{99}$ Latency |
|------------|---------------|------------------|---------------------------|------------------|------------------|
| **1 (Single Query)** | 200 | **58.9 QPS** | 16.77 ms | 19.03 ms | 24.20 ms |
| **64 (Mini-batch)** | 12,800 | **361.3 QPS** | 176.56 ms | 189.49 ms | 198.80 ms |
| **512 (High Throughput)** | 102,400 | **388.7 QPS** | 1,314.55 ms | 1,359.43 ms | 1,395.76 ms |

*Hardware: Intel CPU. Latencies further accelerate under ONNX Runtime with OpenVINO / TensorRT execution providers.*

---

## ONNX Export & Parity Verification

The model is exported to standard **ONNX (Opset 14)** with embedded temperature scaling:
- **ONNX Artifact**: `outputs/uniguard_charcnn.onnx` (`outputs/uniguard_charcnn.onnx.data`)
- **Max Absolute Discrepancy**: **$3.58 \times 10^{-7}$** (Verified numerical parity between PyTorch and ONNX Runtime).
- **Parity Status**: `PASS` (`outputs/onnx_verification.json`).

---

## SIH26145 Security Alert Schema

UniGuard generates machine-readable, auditable JSON security alerts designed for direct ingestion by Security Operations Center (SOC) SIEMs and SOAR platforms:

```json
{
  "timestamp": "2026-10-04T15:06:15Z",
  "flow_id": "673fbb39-44d5-45dc-a6ec-c529fa91da26",
  "target_domain": "4f2a.b8c1.d9e3.f0a2.7b6c.exfil.net",
  "threat_class": "dns_tunnel",
  "confidence": 0.8790,
  "severity": "CRITICAL",
  "evidence": {
    "benign_score": 0.1210,
    "dga_score": 0.0000,
    "dns_tunnel_score": 0.8790,
    "shannon_entropy": 3.8421,
    "normalized_entropy": 0.8210,
    "fqdn_length": 34,
    "subdomain_depth": 5,
    "hex_fraction": 0.735,
    "base32_fraction": 0.0,
    "base64_fraction": 0.0,
    "consonant_ratio": 0.650
  },
  "mitre_attack": {
    "technique_id": "T1071.004",
    "technique_name": "Application Layer Protocol: DNS",
    "tactic": "Command and Control / Exfiltration"
  },
  "observability_caveat": "unidirectional_passive_ingress_only",
  "evidence_hash_sha256": "4b684cb84e77dd62bc38bbd6d246607bf4ec1c5eeff645e7392be32338f9219e"
}
```

### MITRE ATT&CK Mapping
- **DGA Domains**: [T1568.002](https://attack.mitre.org/techniques/T1568/002/) — *Dynamic Resolution: Domain Generation Algorithms (Command and Control)*
- **DNS Tunnelling**: [T1071.004](https://attack.mitre.org/techniques/T1071/004/) — *Application Layer Protocol: DNS (Command and Control / Exfiltration)*
- **Tamper Evidence**: Cryptographic SHA-256 seal computed over domain, timestamp, and evidence block.

---

## Directory & File Structure

```
Char-Cnn/
├── config.py                  # Hyperparameters, 41-char vocabulary, MITRE ATT&CK mapping
├── preprocess.py              # RFC 1035 cleaning, Punycode normalization, tokenization
├── evidence_features.py       # 18 query-side lexical feature extractors
├── dataset.py                 # PyTorch Dataset, tokeniser, and feature normalizer
├── splitter.py                # Leakage-free GroupShuffleSplit by SLD (tldextract)
├── model.py                   # HybridNet_v4 architecture (Conv-k3,5,7,9 + BiGRU + Gating)
├── losses.py                  # Alpha-weighted Focal Loss (gamma=2.0) with sqrt dampening
├── calibration.py             # Post-training Temperature Scaling (L-BFGS)
├── train.py                   # Engine with AMP, gradient clipping, OneCycleLR
├── evaluate.py                # Accuracy, ROC/PR curves, threshold grid-search
├── alert.py                   # SIH26145 JSON alert serializer with SHA-256 hashing
├── export_onnx.py             # ONNX export and PyTorch vs. ONNX parity validator
├── sih_compliance_eval.py     # SIH26145 defense evaluation and compliance verification
├── uniguard_diode_tap.py      # Unidirectional TAP / data diode PCAP & stream listener
├── predict.py                 # Interactive CLI, test suite, and single-domain predictor
├── test_uniguard.py           # Unit test suite (6 tests verifying all core constraints)
├── meta.json                  # Metadata specification for UniGuard v5.0.0
├── requirements.txt           # Python package requirements
├── README.md                  # System documentation
└── outputs/                   # Trained models, metrics, and ONNX weights
    ├── hybridnet_v4_best.pt        # Trained PyTorch model checkpoint
    ├── hybridnet_v4_calibrated.pt  # Calibrated model with temperature scalar
    ├── uniguard_charcnn.onnx       # Exported ONNX model (Opset 14)
    ├── uniguard_charcnn.onnx.data  # External tensor weight storage
    ├── feature_stats.npz           # Mean and standard deviation for 18 features
    ├── thresholds.json             # Calibrated decision thresholds
    ├── sih_classification_report.json # Holdout test set metrics
    ├── benchmark_results.json      # Latency and throughput benchmarks
    ├── onnx_verification.json      # ONNX vs. PyTorch parity verification log
    ├── confusion_matrix_v4_full.png # Full confusion matrix visualization
    └── roc_pr_curves.png           # Multi-class ROC and Precision-Recall curves
```

---

## Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Comprehensive Unit Tests
Validates RFC 1035 preprocessing, 18-feature extraction, parameter limit `<1M`, unidirectional diode compliance, and SIH alert formatting:
```bash
python test_uniguard.py
```

### 3. Run Inference on Any Domain
```bash
# Single domain inspection with probabilities
python predict.py "0100abcd1234567890abcdef.tunnel-exfil.net"

# Generate SIH26145 compliant JSON alert
python predict.py "4f2a.b8c1.d9e3.exfil.net" --alert

# Interactive CLI loop
python predict.py
```

### 4. Run the 24-Domain Representative Security Test Suite
Tests real-world CDN domains, Google/Microsoft corporate domains, known DGAs (CryptoLocker, Conficker), and DNS tunneling payloads:
```bash
python predict.py --test-suite
```

### 5. Simulate Unidirectional Diode / TAP Traffic Stream
Demonstrates passive query ingestion, ONNX/PyTorch batched inference, and automatic SIH alert generation for non-benign traffic:
```bash
python uniguard_diode_tap.py
```

### 6. Export or Re-Verify ONNX Numerical Parity
```bash
python export_onnx.py
```

### 7. Run SIH Compliance & Defense Evaluation
```bash
python sih_compliance_eval.py --alert-demo
```

---

*UniGuard — SIH26145 (Smart India Hackathon 2026) | Team CeaserX*
