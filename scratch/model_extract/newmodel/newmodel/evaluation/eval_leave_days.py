"""
UniGuard E2: Leave-days-out Evaluation.

Tests the calibrated models on the held-out TEST days.
Reports precision, recall, F1, PR-AUC, ROC-AUC, confusion matrix,
and handles statistical weakness warning (< 50 samples).
"""
import json
import logging
from pathlib import Path
import sys

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import iso_prep

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def load_test_data():
    path = config.PROJECT_ROOT / "data_processed" / "test.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Missing test data: {path}")
    df = pd.read_parquet(path)
    y = df.pop("Label")
    # drop meta columns if present
    meta_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
    for c in meta_cols:
        if c in df.columns:
            df.drop(columns=[c], inplace=True)
    return df, y


def load_models_and_thresholds():
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    mc_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_multi_file"])
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    
    thresh = meta["thresholds"]
    return bin_cal, mc_cal, iso, thresh, meta


def print_metrics(y_true, y_pred, y_prob, name):
    log.info(f"\n--- {name} Metrics ---")
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    
    # Binary
    if len(np.unique(y_true)) == 2:
        roc = roc_auc_score(y_true, y_prob)
        pr = average_precision_score(y_true, y_prob)
        log.info(f"ROC-AUC: {roc:.4f}")
        log.info(f"PR-AUC:  {pr:.4f}")
        
    # Print per-class metrics, marking weak classes
    log.info("\nPer-class metrics:")
    for cls_name, metrics in report.items():
        if cls_name in ["accuracy", "macro avg", "weighted avg"]:
            continue
        support = metrics["support"]
        weak_flag = "[WEAK < 50 samples]" if support < 50 else ""
        log.info(f"  {cls_name:20s}: P={metrics['precision']:.3f} R={metrics['recall']:.3f} F1={metrics['f1-score']:.3f} (N={int(support)}) {weak_flag}")
        
    cm = confusion_matrix(y_true, y_pred)
    log.info("\nConfusion Matrix:")
    log.info(str(cm))


def main():
    X_test, y_test = load_test_data()
    bin_cal, mc_cal, iso, thresholds, meta = load_models_and_thresholds()
    
    log.info("Evaluating on TEST days: " + ", ".join(config.TEST_DAYS))
    log.info(f"Total test rows: {len(X_test):,}")
    
    # 1. Binary Evaluation
    y_test_bin = (y_test != "BENIGN").astype(int)
    bin_probs = bin_cal.predict_proba(X_test)[:, 1]
    
    # High tier
    t_high = thresholds["binary_high"]["value"]
    y_pred_high = (bin_probs >= t_high).astype(int)
    print_metrics(y_test_bin, y_pred_high, bin_probs, "Binary (HIGH Tier)")
    
    # Review tier
    t_rev = thresholds["binary_review"]["value"]
    y_pred_rev = (bin_probs >= t_rev).astype(int)
    print_metrics(y_test_bin, y_pred_rev, bin_probs, "Binary (REVIEW Tier)")
    
    # 2. Multiclass Evaluation (for predicted attacks only)
    # Actually evaluate on all traffic
    # Filter out rare classes as multiclass doesn't know them
    mask = ~y_test.isin(config.RARE_CLASSES)
    X_mc = X_test[mask]
    y_mc = y_test[mask]
    
    class_to_idx = {c: i for i, c in enumerate(config.CLASSES)}
    idx_to_class = {i: c for i, c in enumerate(config.CLASSES)}
    y_idx = y_mc.map(class_to_idx).values
    
    mc_probs = mc_cal.predict_proba(X_mc)
    y_pred_idx = np.argmax(mc_probs, axis=1)
    
    print_metrics(y_idx, y_pred_idx, mc_probs, "Multiclass Classification")
    
    # Map back to names for CM
    log.info("\nMulticlass Label Mapping:")
    for i, c in idx_to_class.items():
        log.info(f"  {i}: {c}")
        
    # 3. Isolation Forest Evaluation
    # Higher decision_function = more normal. We use -decision_function for anomaly score.
    X_iso = iso_prep(X_test, config.ALL_FEATURES)
    iso_scores = -iso.decision_function(X_iso)
    
    t_iso = thresholds["iforest_review"]["value"]
    y_pred_iso = (iso_scores >= t_iso).astype(int)
    
    print_metrics(y_test_bin, y_pred_iso, iso_scores, "Isolation Forest (Anomaly)")
    
    # Show how Isolation Forest performs specifically on rare classes vs other attacks
    log.info("\n--- Isolation Forest Anomaly Detection Rates ---")
    for cls in np.unique(y_test):
        mask = (y_test == cls)
        rate = y_pred_iso[mask].mean()
        count = mask.sum()
        log.info(f"  {cls:20s}: {rate:.1%} flagged as anomalous (N={count})")


if __name__ == "__main__":
    main()
