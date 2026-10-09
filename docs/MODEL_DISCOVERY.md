# UniGuard — Model Discovery Report (Phase 0)

**Date**: 2026-10-04  
**Team**: CeaserX · SIH26145  

---

## Summary of Discovered Models

| # | Model | Retained source snapshot | Format | Params | Dataset | Role |
|---|-------|-------------------------|--------|--------|---------|------|
| 1 | **Char-CNN DNS** (HybridNet_v4) | `scratch/model_extract/charcnn/CHAR-Cnn anti/Char-Cnn/` | ONNX (opset 14) | 943,923 | DNS Threats multiclass | DGA + DNS Tunnel detection from domain names |
| 2 | **LightGBM Binary** | `scratch/model_extract/newmodel/newmodel/` | LightGBM native text | N/A (tree) | CIC-IDS2017 Improved | Binary attack/benign flow classification |
| 3 | **LightGBM Multi** | `scratch/model_extract/newmodel/newmodel/` | LightGBM native text | N/A (tree) | CIC-IDS2017 Improved | 10-class attack type classification |
| 4 | **Isolation Forest** | `scratch/model_extract/newmodel/newmodel/` | sklearn joblib | 300 trees | CIC-IDS2017 (benign only) | Unsupervised anomaly scoring |
| 5 | **1D-CNN Beacon** | `scratch/model_extract/training/training/` | ONNX (opset 13, tf2onnx) | 21,697 | CTU-13 | Botnet C2 beaconing from packet sequences |

---

## Model 1: Char-CNN DNS Threat Detector

### Files
- `backend/artifacts/charcnn/uniguard_charcnn.onnx` (102 KB) + `.onnx.data` (3.8 MB)
- `backend/artifacts/charcnn/feature_stats.npz` (mean/std for 18 features)
- `backend/artifacts/charcnn/thresholds.json`
- `backend/artifacts/charcnn/meta.json`

### ONNX Input/Output Signature
| Direction | Name | Type | Shape | Description |
|-----------|------|------|-------|-------------|
| Input | `token_ids` | int64 | (B, 128) | Character token IDs |
| Input | `lexical_features` | float32 | (B, 18) | Normalized lexical features |
| Output | `probabilities` | float32 | (B, 3) | Calibrated softmax [benign, dga, dns_tunnel] |

### Preprocessing Pipeline (must be reproduced exactly)
1. **Clean**: strip, remove protocol/port, lowercase, punycode-encode, strip trailing dot, collapse consecutive dots, clip to 253 chars
2. **Tokenize**: map each character to `CHAR2IDX` (a=2, b=3, ..., .=40; UNK=1, PAD=0), pad/truncate to 128
3. **Extract 18 features**: length, log_len, entropy, norm_entropy, digit_ratio, alpha_ratio, vowel_ratio, max_consonant_run, sep_ratio, unique_char_ratio, n_labels, max_label_len, mean_label_len, hex_fraction, base32_fraction, base64_fraction, dict_word_ratio, subdomain_entropy
4. **Normalize features**: z-score using `feature_stats.npz` (mean and std per feature)

### Calibration
- Temperature scaling: T = 1.0124 (embedded in ONNX model)
- Output probabilities are already calibrated

### Thresholds
- DGA: prob[1] > 0.655
- DNS Tunnel: prob[2] > 0.100

### Validation Metrics
| Class | Precision | Recall | F1 | ROC-AUC | Support |
|-------|-----------|--------|-----|---------|---------|
| Benign | 92.12% | 97.93% | 94.94% | 0.964 | 7,000 |
| DGA | 91.50% | 72.69% | 81.02% | 0.948 | 2,146 |
| DNS Tunnel | 100.00% | 100.00% | 100.00% | 1.000 | 1,623 |
| **Overall Accuracy** | | | **93.21%** | | 10,769 |

---

## Model 2 & 3: LightGBM Binary + Multiclass

### Files
- `backend/artifacts/lgbm_iforest/lgbm_binary.txt` — Binary classifier
- `backend/artifacts/lgbm_iforest/lgbm_multi.txt` — 10-class classifier
- `backend/artifacts/lgbm_iforest/calibrator_binary.joblib` — CalibratedClassifierCV wrapper
- `backend/artifacts/lgbm_iforest/calibrator_multi.joblib` — CalibratedClassifierCV wrapper

### Feature Spec (38 features, CRITICAL ORDER)
**28 base features** (all forward-direction only):
```
Flow Duration, Total Fwd Packet, Total Length of Fwd Packet,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean,
Fwd Packet Length Std, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std,
Fwd IAT Max, Fwd IAT Min, Fwd PSH Flags, Fwd URG Flags,
Fwd RST Flags, Fwd Header Length, Fwd Packets/s,
SYN Flag Count, FIN Flag Count, RST Flag Count,
PSH Flag Count, ACK Flag Count, URG Flag Count,
Subflow Fwd Packets, Subflow Fwd Bytes, FWD Init Win Bytes,
Fwd Act Data Pkts, Fwd Seg Size Min, Fwd Segment Size Avg
```

**10 derived features** (computed from base):
```
d_fwd_bytes_per_pkt     = Total Length of Fwd Packet / Total Fwd Packet
d_fwd_hdr_per_pkt       = Fwd Header Length / Total Fwd Packet
d_fwd_pkts_per_s        = Total Fwd Packet / (Flow Duration / 1e6)
d_fwd_bytes_per_s       = Total Length of Fwd Packet / (Flow Duration / 1e6)
d_fwd_iat_cv            = Fwd IAT Std / Fwd IAT Mean
d_fwd_len_cv            = Fwd Packet Length Std / Fwd Packet Length Mean
d_fwd_len_range         = Fwd Packet Length Max - Fwd Packet Length Min
d_subflow_bytes_per_pkt = Subflow Fwd Bytes / Subflow Fwd Packets
d_fwd_hdr_ratio         = Fwd Header Length / Total Length of Fwd Packet
d_fwd_active_ratio      = Fwd Act Data Pkts / Total Fwd Packet
```

**FORBIDDEN**: Any column with "Bwd", "Backward", "Down/Up Ratio", bidirectional "Flow IAT", bidirectional "Packet Length" stats, raw IPs/ports as features.

### Preprocessing
1. Select 28 base features (exact column names, strip whitespace)
2. Convert to float32, replace inf with NaN
3. Compute 10 derived features (div-by-zero → NaN)
4. For IForest: `log1p(clip(x, lower=0))` on all 38 features, fill NaN with 0
5. **Note**: Flow Duration in CIC-IDS2017 is in **microseconds**

### Thresholds
| Tier | Score | Target FPR |
|------|-------|------------|
| Binary HIGH | 0.1452 | 0.2% |
| Binary REVIEW | 0.0056 | 1.0% |
| IForest REVIEW | 0.0847 | 1.0% |

### 10-Class Labels
`BENIGN, Botnet, DDoS, DoS GoldenEye, DoS Hulk, DoS Slow, FTP-Patator, Portscan, SSH-Patator, Web Attack`

### Validation Metrics
| Metric | Value |
|--------|-------|
| Binary Recall (HIGH) | 99.56% |
| Binary FPR (HIGH) | 0.31% |
| Throughput (1 core) | 13,209 flows/sec |
| P99 Latency | 15.6 ms |

---

## Model 4: Isolation Forest

### Files
- `backend/artifacts/lgbm_iforest/iforest.joblib`

### Specification
- **Type**: Unsupervised anomaly detection
- **Training**: Benign flows only from CIC-IDS2017
- **Input**: 38 features (same as LightGBM), after `log1p(clip(x, 0))` transform
- **Output**: `anomaly_score = -decision_function(X)` (higher = more anomalous)
- **Anomaly normalisation**: min-max to [0, 1] for ensemble scoring
- **Threshold**: 0.0847 for REVIEW tier

### Zero-Day Detection Capability
| Attack Class | Detection Rate |
|-------------|---------------|
| Portscan | 78.7% |
| DDoS | 1.8% |
| Botnet/Web Attack | 0.0% |

---

## Model 5: 1D-CNN Beacon Detector

### Files
- `backend/artifacts/beacon_cnn/model.onnx` (92 KB)
- `backend/artifacts/beacon_cnn/calibrator.pkl` (isotonic regression)
- `backend/artifacts/beacon_cnn/meta.json`

### ONNX Input/Output Signature
| Direction | Name | Type | Shape | Description |
|-----------|------|------|-------|-------------|
| Input | `packet_seq` (or `input`) | float32 | (B, 32, 7) | 32 packets × 7 channels |
| Output | `output` | float32 | (B, 1) | Sigmoid probability of botnet |

### 7 Channels (strict order)
| Ch | Name | Computation |
|----|------|-------------|
| 0 | log1p_pkt_size | `log1p(pkt_size_bytes) * 0.0909` |
| 1 | log1p_iat_us | `log1p(clamp(IAT_microseconds, 0, 1e8)) * 0.0543` |
| 2 | padding_mask | `1.0` for real packets, `0.0` for padding |
| 3 | tcp_syn | `1.0` if flags & 0x02 |
| 4 | tcp_fin | `1.0` if flags & 0x01 |
| 5 | tcp_rst | `1.0` if flags & 0x04 |
| 6 | tcp_psh | `1.0` if flags & 0x08 |

### Calibration
- Isotonic regression loaded from `calibrator.pkl`
- Raw Brier: 0.179 → Calibrated Brier: 0.014

### Thresholds (post-calibration)
| Tier | Score | Achieved Recall (test) |
|------|-------|----------------------|
| HIGH | 0.9149 | 85.9% |
| REVIEW | 0.4286 | 97.5% |

### Validation Metrics
| Metric | Value |
|--------|-------|
| Precision | 99.36% |
| Recall | 83.79% |
| F1 | 90.91% |
| ROC-AUC | 93.80% |
| ONNX throughput (batch 256) | 24,917 flows/sec |

---

## Preprocessing Mismatches & Pipeline Notes

| Issue | Resolution |
|-------|-----------|
| Char-CNN `model.py` docstring says "(B, 12)" for feats but actual is 18 | Use 18 features as in `meta.json` and ONNX signature |
| Char-CNN ONNX opset says "14" in verification JSON but export script uses `opset_version=18` | Irrelevant; ONNX Runtime handles both |
| LightGBM `Fwd Segment Size Avg` not in original CIC-IDS2017 column list | Present in the "improved" version; a compatible flow exporter must provide it |
| `d_subflow_bytes_per_pkt` uses `Subflow Fwd Bytes / Subflow Fwd Packets` but sample CSV shows NaN values | Division by zero when packets=0; fill with 0 |
| 1D-CNN ONNX input name may be `input:0` (tf2onnx convention) | Read dynamically via `session.get_inputs()[0].name` |
| 1D-CNN calibrator uses isotonic regression from sklearn | Must load via `pickle` (not joblib); calibrator dict has `{'calibrator': ..., 'type': ...}` |
| Char-CNN `feature_stats.npz` normalisation | Must z-score: `(feat - mean) / std` using the stored arrays |

---

## Artifacts Deployed

```
backend/artifacts/
├── charcnn/
│   ├── model_card.json
│   ├── uniguard_charcnn.onnx
│   ├── uniguard_charcnn.onnx.data
│   ├── feature_stats.npz
│   ├── thresholds.json
│   └── meta.json
├── lgbm_iforest/
│   ├── model_card.json
│   ├── lgbm_binary.txt
│   ├── lgbm_multi.txt
│   ├── iforest.joblib
│   ├── calibrator_binary.joblib
│   ├── calibrator_multi.joblib
│   └── meta.json
└── beacon_cnn/
    ├── model_card.json
    ├── model.onnx
    ├── calibrator.pkl
    ├── meta.json
    ├── calibration_results.json
    ├── training_results.json
    ├── sample_inputs.npy
    └── sample_outputs.npy
```
