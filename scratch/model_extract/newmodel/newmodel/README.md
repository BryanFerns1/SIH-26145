# UniGuard — Smart India Hackathon 2026 (SIH26145, Team CeaserX)

## L2 Supervised Detector (LightGBM) + L3 Unsupervised Anomaly Detector (Isolation Forest)

**Design constraint:** Unidirectional traffic from a receive-only TAP / data diode.
The sensor sees ONLY the forward direction (src→dst) of each conversation.

### Project Structure

```
newmodel/
├── README.md                  # This file
├── config.py                  # Paths, constants, hyperparameters
├── meta.json                  # Model metadata, feature list, thresholds
│
├── uniguard/                  # Core library
│   ├── __init__.py
│   ├── features.py            # Forward-only feature computation
│   ├── host_features.py       # HLL/Space-Saving host-level features
│   ├── lgbm_wrapper.py        # Scikit-learn compatible LGBMWrapper
│   └── detector.py            # Detector class with predict(batch)
│
├── training/                  # Training pipeline
│   ├── prepare_data.py        # Time-blocked split, dedup, forward features
│   ├── train_lgbm.py          # LightGBM binary + multiclass
│   ├── train_iforest.py       # Isolation Forest on benign flows
│   ├── calibrate.py           # Isotonic/Platt calibration + thresholds
│   └── refit_final.py         # Final refit on all data (excl. calibration)
│
├── evaluation/                # Evaluation scripts
│   ├── eval_leave_days.py     # E2: Time-blocked split evaluation
│   ├── run_evals.py           # E6: Evasion + E8: Input matrix
│   └── eval_e7.py             # E7: Benign periodic FP
│
├── ops/                       # Operational components
│   ├── psi.py                 # PSI drift detection
│   └── benchmark.py           # CPU throughput benchmark (pinned core)
│
├── models/                    # Trained model artifacts
│   ├── lgbm_binary.txt        # LightGBM native text format
│   ├── lgbm_multi.txt         # LightGBM native text format
│   ├── iforest.joblib         # Isolation Forest (sklearn)
│   ├── calibrator_binary.joblib
│   ├── calibrator_multi.joblib
│   └── psi_baseline.json
│
├── tests/                     # pytest test suite (13 tests)
│   ├── test_forward_only.py   # Verify no backward features
│   ├── test_split.py          # Verify time-blocked split ordering
│   ├── test_model.py          # Verify model output shapes/bounds
│   └── test_alert.py          # Verify HMAC tamper evidence
│
├── reports/
│   ├── REPORT.md              # Full evaluation report
│   └── reliability_binary.png # Calibration reliability diagram
│
└── logs/                      # Training and evaluation logs
```

### Quick Start

```bash
# Install dependencies
pip install pandas numpy scikit-learn lightgbm pytest psutil joblib matplotlib

# Stage 1: Prepare data (time-blocked split, dedup, forward features)
python -m training.prepare_data

# Stage 2: Train models
python -m training.train_lgbm
python -m training.train_iforest

# Stage 3: Calibrate + set thresholds
python -m training.calibrate

# Stage 4: Evaluate
python -m evaluation.eval_leave_days    # E2: Time-blocked
python -m evaluation.run_evals          # E6: Evasion + E8: Input matrix
python -m evaluation.eval_e7            # E7: Benign periodic FP

# Stage 5: Ops
python -m ops.benchmark                 # Throughput + latency
python -m ops.psi                       # Drift detection

# Stage 6: Final refit (production)
python -m training.refit_final

# Run all tests
pytest tests/ -v
```

### Key Design Decisions

1. **Forward-only features:** No backward packet counts, bytes, IAT, or any
   bidirectional derived features. All features computed from src→dst packets only.
2. **No raw IP/port as features:** IPs/ports used only for flow keying, host-level
   counters, and alert reporting.
3. **Time-blocked splitting:** Strict contiguous time blocks per (day, class) with
   a 5% gap dropped between validation and calibration to prevent temporal leakage.
4. **HMAC-SHA256 tamper evidence:** Each alert carries an HMAC signature over the
   canonical model input, ensuring forensic integrity.
5. **CPU-only:** Target 4-core, 8GB RAM. LightGBM native text format for portability.

### Performance Summary

| Metric | Value |
| :--- | :--- |
| Binary Recall (HIGH) | 99.56% |
| Binary FPR (HIGH) | 0.31% |
| Throughput (1 core) | 13,209 flows/sec |
| P99 Latency | 15.6 ms |
| Tests Passing | 13/13 |
