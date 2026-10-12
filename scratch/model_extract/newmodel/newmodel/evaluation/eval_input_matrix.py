"""
UniGuard E8: Detector-vs-Input Matrix Evaluation.

Evaluates detectors across different input types:
- Full PCAP uniflow (all features available)
- Truncated flows (no timing features, only packet counts)
- NetFlow/IPFIX (no packet data/lengths, only timing and counts)
"""
import json
import logging
import sys
from pathlib import Path

import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import recall_score, precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import prepare, iso_prep

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def simulate_truncated_flow(df: pd.DataFrame) -> pd.DataFrame:
    """Simulate truncated flow: no accurate timing, only packet/byte counts."""
    df_trunc = df.copy()
    
    # Nullify timing features
    timing_cols = [
        "Flow Duration", "Fwd IAT Total", "Fwd IAT Mean", 
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Fwd Packets/s", "Fwd Bytes/Bulk Avg"
    ]
    
    for col in timing_cols:
        if col in df_trunc.columns:
            df_trunc[col] = 0.0
            
    return df_trunc


def simulate_netflow(df: pd.DataFrame) -> pd.DataFrame:
    """Simulate NetFlow: no packet lengths/flags, only timing and totals."""
    df_netflow = df.copy()
    
    # Nullify packet-level details and flags
    pkt_cols = [
        "Fwd Packet Length Max", "Fwd Packet Length Min", 
        "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Fwd PSH Flags", "Fwd URG Flags", "Fwd RST Flags",
        "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        "Fwd Header Length", "Fwd Seg Size Min", "Fwd Segment Size Avg"
    ]
    
    for col in pkt_cols:
        if col in df_netflow.columns:
            df_netflow[col] = 0.0
            
    return df_netflow


def evaluate_input_type(X_base, y_true, bin_cal, iso, thresholds, input_type_name: str):
    """Evaluate models on a specific simulated input type."""
    
    # Re-prepare features from the simulated base
    X = prepare(X_base, config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=False)
    
    # Binary predictions
    bin_probs = bin_cal.predict_proba(X)[:, 1]
    t_rev = thresholds["binary_review"]["value"]
    y_pred_bin = (bin_probs >= t_rev).astype(int)
    
    # Isolation Forest predictions
    X_iso = iso_prep(X, config.ALL_FEATURES)
    iso_scores = -iso.decision_function(X_iso)
    t_iso = thresholds["iforest_review"]["value"]
    y_pred_iso = (iso_scores >= t_iso).astype(int)
    
    # Calculate metrics
    y_true_bin = (y_true != "BENIGN").astype(int)
    
    if y_true_bin.sum() > 0:
        bin_recall = recall_score(y_true_bin, y_pred_bin)
        iso_recall = recall_score(y_true_bin, y_pred_iso)
    else:
        bin_recall = 0.0
        iso_recall = 0.0
        
    log.info(f"{input_type_name:25s} | {bin_recall:14.1%} | {iso_recall:14.1%}")


def main():
    log.info("E8: Detector-vs-Input Matrix")
    log.info("============================")
    
    # Load test data
    dfs = []
    processed_dir = config.PROJECT_ROOT / "data_processed"
    for day in config.TEST_DAYS:
        path = processed_dir / f"{day}.parquet"
        dfs.append(pd.read_parquet(path))
    df_test = pd.concat(dfs, ignore_index=True)
    y_test = df_test["Label"]
    
    # Load models
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    thresh = meta["thresholds"]
    
    log.info(f"{'Input Type':25s} | {'Binary Recall':14s} | {'IForest Recall':14s}")
    log.info("-" * 60)
    
    # 1. Full PCAP Uniflow (Baseline)
    evaluate_input_type(df_test, y_test, bin_cal, iso, thresh, "Full PCAP uniflow")
    
    # 2. Truncated Flows
    df_trunc = simulate_truncated_flow(df_test)
    evaluate_input_type(df_trunc, y_test, bin_cal, iso, thresh, "Truncated flows")
    
    # 3. NetFlow/IPFIX
    df_netflow = simulate_netflow(df_test)
    evaluate_input_type(df_netflow, y_test, bin_cal, iso, thresh, "NetFlow/IPFIX")


if __name__ == "__main__":
    main()
