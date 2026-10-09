import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.lgbm_wrapper import LGBMWrapper
from uniguard.features import iso_prep

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

def load_data():
    path = config.PROJECT_ROOT / "data_processed" / "test.parquet"
    df = pd.read_parquet(path)
    y = df.pop("Label")
    for c in ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']:
        if c in df.columns:
            df.drop(columns=[c], inplace=True)
    return df, y

def apply_padding(X):
    X = X.copy()
    pad = 50
    X['Total Length of Fwd Packet'] += X['Total Fwd Packet'] * pad
    X['Fwd Packet Length Mean'] += pad
    X['Fwd Packet Length Max'] += pad
    return X

def apply_jitter(X):
    X = X.copy()
    jitter = 50000 # 50ms in microsec
    X['Fwd IAT Total'] += X['Total Fwd Packet'] * jitter
    X['Fwd IAT Mean'] += jitter
    X['Fwd IAT Max'] += jitter
    return X

def apply_low_slow(X):
    X = X.copy()
    X['Fwd IAT Total'] *= 10
    X['Fwd IAT Mean'] *= 10
    X['Fwd IAT Max'] *= 10
    X['Flow Duration'] *= 10
    return X

def evaluate_perturbation(X, y_bin, bin_cal, iso, thresh, name):
    # Binary
    bin_probs = bin_cal.predict_proba(X)[:, 1]
    r_high = (bin_probs[y_bin == 1] >= thresh["binary_high"]["value"]).mean()
    r_rev = (bin_probs[y_bin == 1] >= thresh["binary_review"]["value"]).mean()
    
    # IForest
    iso_scores = -iso.decision_function(iso_prep(X, config.ALL_FEATURES))
    r_iso = (iso_scores[y_bin == 1] >= thresh["iforest_review"]["value"]).mean()
    fpr_iso = (iso_scores[y_bin == 0] >= thresh["iforest_review"]["value"]).mean()
    
    log.info(f"{name:25s}: Binary(HIGH)={r_high:.1%} | Binary(REVIEW)={r_rev:.1%} | IForest Recall={r_iso:.1%} | IForest Benign FPR={fpr_iso:.1%}")

def main():
    log.info("Loading models...")
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
    
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    thresh = meta["thresholds"]
    
    log.info("Loading test data...")
    X, y = load_data()
    y_bin = (y != "BENIGN").astype(int)
    
    log.info("\n=== E6: Evasion Robustness ===")
    evaluate_perturbation(X, y_bin, bin_cal, iso, thresh, "Baseline (No Evasion)")
    evaluate_perturbation(apply_padding(X), y_bin, bin_cal, iso, thresh, "Padding (50B/pkt)")
    evaluate_perturbation(apply_jitter(X), y_bin, bin_cal, iso, thresh, "Timing Jitter (50ms)")
    evaluate_perturbation(apply_low_slow(X), y_bin, bin_cal, iso, thresh, "Low and Slow (10x)")
    
    log.info("\n=== E8: Input Matrix (Truncation/NetFlow) ===")
    # NetFlow: Zero out length max/min/std, keep only total/mean
    X_nf = X.copy()
    for c in X_nf.columns:
        if "Max" in c or "Min" in c or "Std" in c or "Flags" in c:
            X_nf[c] = 0
    evaluate_perturbation(X_nf, y_bin, bin_cal, iso, thresh, "NetFlow-like (No variance)")

if __name__ == "__main__":
    main()
