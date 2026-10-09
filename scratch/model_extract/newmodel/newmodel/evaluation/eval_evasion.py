"""
UniGuard E6: Evasion Robustness Evaluation.

Tests feature-level robustness to evasion techniques:
a) Padding packet sizes (adding dummy bytes)
b) Timing jitter (modifying IAT)
c) Both
d) Low-and-slow (slowing down the attack rate)

Reports recall degradation for each detector.
"""
import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import prepare, iso_prep

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def apply_padding(df: pd.DataFrame, max_pad: int = 100) -> pd.DataFrame:
    """Simulate evasion: add random padding to forward packet lengths."""
    df_ev = df.copy()
    # Number of forward packets
    n_pkts = df_ev["Total Fwd Packet"]
    
    # We add between 0 and max_pad bytes per packet on average
    pad_total = n_pkts * np.random.randint(10, max_pad, size=len(df))
    
    # Update base features
    if "Total Length of Fwd Packet" in df_ev.columns:
        df_ev["Total Length of Fwd Packet"] += pad_total
        
    if "Fwd Packet Length Mean" in df_ev.columns:
        df_ev["Fwd Packet Length Mean"] += (pad_total / np.maximum(1, n_pkts))
        
    if "Fwd Packet Length Max" in df_ev.columns:
        df_ev["Fwd Packet Length Max"] = np.maximum(df_ev["Fwd Packet Length Max"], 
                                                  df_ev["Fwd Packet Length Max"] + np.random.randint(0, max_pad, size=len(df)))
        
    return df_ev


def apply_jitter(df: pd.DataFrame, max_jitter_ms: int = 50) -> pd.DataFrame:
    """Simulate evasion: add timing jitter to forward IATs."""
    df_ev = df.copy()
    
    # IAT features are typically in microseconds in this dataset
    # We add random noise up to max_jitter_ms (in ms, so max_jitter_ms * 1000 in us)
    jitter_us = np.random.randint(0, max_jitter_ms * 1000, size=len(df))
    
    if "Fwd IAT Mean" in df_ev.columns:
        df_ev["Fwd IAT Mean"] += jitter_us
        
    if "Fwd IAT Max" in df_ev.columns:
        df_ev["Fwd IAT Max"] += jitter_us
        
    if "Fwd IAT Total" in df_ev.columns:
        # Add jitter to total (proportional to packet count roughly)
        n_pkts = df_ev["Total Fwd Packet"]
        df_ev["Fwd IAT Total"] += (jitter_us * np.maximum(1, n_pkts - 1))
        
    return df_ev


def apply_low_and_slow(df: pd.DataFrame, slowdown_factor: float = 10.0) -> pd.DataFrame:
    """Simulate evasion: stretch the flow duration significantly."""
    df_ev = df.copy()
    
    # Increase flow duration and IATs by the slowdown factor
    cols_to_scale = [
        "Flow Duration", "Fwd IAT Total", "Fwd IAT Mean", 
        "Fwd IAT Max", "Fwd IAT Min"
    ]
    
    for col in cols_to_scale:
        if col in df_ev.columns:
            df_ev[col] *= slowdown_factor
            
    # Packets/s will be recomputed by the prepare() function via derived features
    
    return df_ev


def evaluate_evasion(bin_cal, iso_model, thresholds, df_base: pd.DataFrame, evasion_func, evasion_name: str):
    """Evaluate models on the evaded dataset and report recall."""
    
    # Only evaluate on actual attacks
    df_attacks = df_base[df_base["Label"] != "BENIGN"].copy()
    if len(df_attacks) == 0:
        log.warning("No attacks found in the dataset for evasion testing.")
        return
        
    # Apply evasion perturbation to base features
    df_evaded_base = evasion_func(df_attacks)
    
    # Re-extract ALL features (including derived) from the perturbed base features
    X_evaded = prepare(df_evaded_base, config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=False)
    
    # 1. Binary evaluation
    bin_probs = bin_cal.predict_proba(X_evaded)[:, 1]
    
    t_high = thresholds["binary_high"]["value"]
    t_rev = thresholds["binary_review"]["value"]
    
    recall_high = (bin_probs >= t_high).mean()
    recall_rev = (bin_probs >= t_rev).mean()
    
    # 2. Isolation Forest evaluation
    X_iso = iso_prep(X_evaded, config.ALL_FEATURES)
    iso_scores = -iso_model.decision_function(X_iso)
    t_iso = thresholds["iforest_review"]["value"]
    recall_iso = (iso_scores >= t_iso).mean()
    
    log.info(f"  {evasion_name:25s}: Binary(HIGH)={recall_high:.1%} | Binary(REVIEW)={recall_rev:.1%} | IForest={recall_iso:.1%}")


def main():
    log.info("E6: Feature-Level Evasion Robustness")
    log.info("====================================")
    
    # Load test data (we perturb the base features before derived feature computation)
    # Actually, we need the raw base features. Let's load the parquet, which has base + derived.
    # We will perturb the base features in the parquet, then recompute derived features.
    dfs = []
    processed_dir = config.PROJECT_ROOT / "data_processed"
    for day in config.TEST_DAYS:
        path = processed_dir / f"{day}.parquet"
        df = pd.read_parquet(path)
        dfs.append(df)
    df_test = pd.concat(dfs, ignore_index=True)
    
    # Load models
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    thresh = meta["thresholds"]
    
    log.info(f"Test Set Attacks: {(df_test['Label'] != 'BENIGN').sum():,}")
    log.info("\nRecall on Perturbed Attacks (Degradation):")
    
    # Baseline (no evasion)
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: x, "Baseline (No Evasion)")
    
    # a) Padding
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_padding(x, max_pad=100), "Padding (avg 50B/pkt)")
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_padding(x, max_pad=500), "Padding (avg 250B/pkt)")
    
    # b) Timing Jitter
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_jitter(x, max_jitter_ms=50), "Timing Jitter (max 50ms)")
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_jitter(x, max_jitter_ms=200), "Timing Jitter (max 200ms)")
    
    # c) Both
    def padding_and_jitter(df):
        return apply_jitter(apply_padding(df, 100), 50)
    evaluate_evasion(bin_cal, iso, thresh, df_test, padding_and_jitter, "Padding + Jitter")
    
    # d) Low-and-slow
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_low_and_slow(x, 10.0), "Low and Slow (10x)")
    evaluate_evasion(bin_cal, iso, thresh, df_test, lambda x: apply_low_and_slow(x, 100.0), "Low and Slow (100x)")


if __name__ == "__main__":
    main()
