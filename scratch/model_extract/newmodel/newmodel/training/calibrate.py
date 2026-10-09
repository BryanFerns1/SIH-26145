"""
UniGuard Stage 3: Calibration + Thresholds.

Calibrates the trained models and sets operational thresholds on
the distinct CALIBRATION split. Also reports actual FPR and Recall on the TEST split.

Sets thresholds:
  - HIGH: 0.2% False Positive Rate (Benign)
  - REVIEW: 1.0% False Positive Rate (Benign)
  - IFOREST: 1.0% False Positive Rate (Benign)
"""
import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss, roc_curve
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.lgbm_wrapper import LGBMWrapper
from uniguard.features import iso_prep

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOGS_DIR / "calibrate.log", mode="w"),
    ],
)
log = logging.getLogger(__name__)


def load_split(split_name: str) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """Load pre-processed parquet for a split."""
    path = config.PROJECT_ROOT / "data_processed" / f"{split_name}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Missing prepared data for {split_name}: {path}")
    df = pd.read_parquet(path)
    log.info(f"Loaded {split_name}: {len(df):,} rows")
    y = df.pop("Label")
    
    # Extract metadata columns if present
    meta_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
    meta = {}
    for c in meta_cols:
        if c in df.columns:
            meta[c] = df.pop(c)
    meta_df = pd.DataFrame(meta)
    
    return df, y, meta_df


def plot_reliability_diagram(y_true, probs_dict, title, save_name):
    plt.figure(figsize=(8, 6))
    plt.plot([0, 1], [0, 1], "k:", label="Perfectly calibrated")
    
    for name, probs in probs_dict.items():
        fraction_of_positives, mean_predicted_value = calibration_curve(y_true, probs, n_bins=10)
        plt.plot(mean_predicted_value, fraction_of_positives, "s-", label=name)
        
    plt.ylabel("Fraction of positives")
    plt.xlabel("Mean predicted value")
    plt.title(title)
    plt.legend(loc="lower right")
    
    save_path = config.PROJECT_ROOT / "reports" / f"{save_name}.png"
    save_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(save_path)
    plt.close()
    log.info(f"Saved reliability diagram to {save_path}")


def calibrate_binary(X_cal, y_cal, X_test, y_test):
    log.info("\n=== Binary Calibration ===")
    
    y_cal_bin = (y_cal != "BENIGN").astype(int)
    y_test_bin = (y_test != "BENIGN").astype(int)
    
    wrapper = LGBMWrapper(config.MODELS_DIR / "lgbm_binary.txt", objective="binary")
    
    # Base probabilities (uncalibrated)
    base_probs_cal = wrapper.predict_proba(X_cal)[:, 1]
    base_brier = brier_score_loss(y_cal_bin, base_probs_cal)
    log.info(f"Base Brier Score: {base_brier:.5f}")
    
    # Try Platt Scaling (sigmoid)
    dummy_cv = [(np.arange(len(X_cal)), np.arange(len(X_cal)))]
    cal_sigmoid = CalibratedClassifierCV(wrapper, method="sigmoid", cv=dummy_cv)
    cal_sigmoid.fit(X_cal, y_cal_bin)
    sig_probs_cal = cal_sigmoid.predict_proba(X_cal)[:, 1]
    sig_brier = brier_score_loss(y_cal_bin, sig_probs_cal)
    log.info(f"Platt (Sigmoid) Brier Score: {sig_brier:.5f}")
    
    # Try Isotonic Regression
    cal_isotonic = CalibratedClassifierCV(wrapper, method="isotonic", cv=dummy_cv)
    cal_isotonic.fit(X_cal, y_cal_bin)
    iso_probs_cal = cal_isotonic.predict_proba(X_cal)[:, 1]
    iso_brier = brier_score_loss(y_cal_bin, iso_probs_cal)
    log.info(f"Isotonic Brier Score: {iso_brier:.5f}")
    
    # Select best
    if iso_brier < sig_brier:
        best_cal = cal_isotonic
        best_probs_cal = iso_probs_cal
        log.info("Selected Method: Isotonic")
    else:
        best_cal = cal_sigmoid
        best_probs_cal = sig_probs_cal
        log.info("Selected Method: Sigmoid")
        
    save_path = config.MODELS_DIR / "calibrator_binary.joblib"
    joblib.dump(best_cal, save_path)
    log.info(f"Saved binary calibrator to {save_path}")
    
    # Plot reliability
    plot_reliability_diagram(
        y_cal_bin, 
        {"Uncalibrated": base_probs_cal, "Sigmoid": sig_probs_cal, "Isotonic": iso_probs_cal}, 
        "Reliability Diagram (Binary)", 
        "reliability_binary"
    )
    
    # Set thresholds on CALIBRATION set (Benign flows only)
    benign_cal_probs = best_probs_cal[y_cal == "BENIGN"]
    # 0.2% FPR High, 1.0% FPR Review
    thresh_high = np.percentile(benign_cal_probs, 100 - 0.2)
    thresh_review = np.percentile(benign_cal_probs, 100 - 1.0)
    
    # Test on TEST set
    test_probs = best_cal.predict_proba(X_test)[:, 1]
    
    for name, thresh, target_fpr in [("HIGH", thresh_high, 0.002), ("REVIEW", thresh_review, 0.01)]:
        log.info(f"  {name} Threshold (Target FPR {target_fpr:.4f}):")
        log.info(f"    Value:       {thresh:.6f}")
        
        # Measure actual FPR on TEST benign
        benign_test_probs = test_probs[y_test == "BENIGN"]
        fp = (benign_test_probs >= thresh).sum()
        actual_fpr = fp / len(benign_test_probs) if len(benign_test_probs) > 0 else 0
        log.info(f"    Actual Test FPR:  {actual_fpr:.6f} ({fp} / {len(benign_test_probs)} benigns)")
        
        # Measure Recall on TEST attacks
        attack_test_probs = test_probs[y_test != "BENIGN"]
        tp = (attack_test_probs >= thresh).sum()
        recall = tp / len(attack_test_probs) if len(attack_test_probs) > 0 else 0
        log.info(f"    Test Recall:      {recall:.4f} ({tp} / {len(attack_test_probs)} attacks)")
        
        if name == "HIGH" and recall < 0.1:
            log.warning("    --> Recall at HIGH is very low on Test set. (Expected due to unidirectional constraints)")

    return best_cal, {"binary_high": {"value": thresh_high, "target_fpr": 0.002}, "binary_review": {"value": thresh_review, "target_fpr": 0.01}}


def calibrate_multiclass(X_cal, y_cal):
    log.info("\n=== Multiclass Calibration ===")
    
    wrapper = LGBMWrapper(config.MODELS_DIR / "lgbm_multi.txt", objective="multiclass")
    
    # Using dummy_cv doesn't work if some classes are missing in Cal block.
    # LightGBM output is mostly calibrated already. We will bypass scikit-learn CalibratedClassifierCV
    # to avoid the "missing class in validation" error, and just use the raw LightGBM output.
    # The requirement didn't strictly mandate isotonic for multiclass if it crashes, 
    # but let's try to fit sigmoid if all classes are present.
    
    # Check if all 10 classes are in y_cal
    class_to_idx = {c: i for i, c in enumerate(config.CLASSES)}
    y_idx = y_cal.map(class_to_idx).fillna(-1).astype(int)
    
    present_classes = set(np.unique(y_idx))
    required_classes = set(range(len(config.CLASSES)))
    
    if required_classes.issubset(present_classes):
        dummy_cv = [(np.arange(len(X_cal)), np.arange(len(X_cal)))]
        cal_mc = CalibratedClassifierCV(wrapper, method="sigmoid", cv=dummy_cv)
        cal_mc.fit(X_cal, y_idx)
        log.info("Fitted Sigmoid calibration for Multiclass.")
    else:
        missing = required_classes - present_classes
        log.warning(f"Classes missing from CAL split (indices {missing}). Bypassing scikit-learn calibration for multiclass.")
        cal_mc = wrapper
    
    save_path = config.MODELS_DIR / "calibrator_multi.joblib"
    joblib.dump(cal_mc, save_path)
    log.info(f"Saved multiclass calibrator to {save_path}")
    
    return cal_mc


def threshold_iforest(X_cal, y_cal, X_test, y_test):
    log.info("\n=== Isolation Forest Thresholds ===")
    
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    
    X_iso_cal = iso_prep(X_cal, config.ALL_FEATURES)
    iso_scores_cal = -iso.decision_function(X_iso_cal)
    
    # Set threshold on CALIBRATION set (Benign only)
    benign_scores_cal = iso_scores_cal[y_cal == "BENIGN"]
    thresh = np.percentile(benign_scores_cal, 100 - 1.0)
    
    log.info(f"  Anomaly Threshold (Target FPR 0.0100):")
    log.info(f"    Value:       {thresh:.6f}")
    
    # Test on TEST set
    X_iso_test = iso_prep(X_test, config.ALL_FEATURES)
    iso_scores_test = -iso.decision_function(X_iso_test)
    benign_scores_test = iso_scores_test[y_test == "BENIGN"]
    
    fp = (benign_scores_test >= thresh).sum()
    actual_fpr = fp / len(benign_scores_test) if len(benign_scores_test) > 0 else 0
    log.info(f"    Actual Test FPR:  {actual_fpr:.6f} ({fp} / {len(benign_scores_test)} benigns)")
    
    return {"iforest_review": {"value": thresh, "target_fpr": 0.01}}


def main():
    log.info("Loading calibration split...")
    X_cal, y_cal, _ = load_split("cal")
    
    log.info("Loading test split for immediate FPR/Recall reporting...")
    X_test, y_test, _ = load_split("test")
    
    cal_bin, bin_thresholds = calibrate_binary(X_cal, y_cal, X_test, y_test)
    
    cal_mc = calibrate_multiclass(X_cal, y_cal)
    
    iso_thresholds = threshold_iforest(X_cal, y_cal, X_test, y_test)
    
    # Update meta.json
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    meta["thresholds"] = {**bin_thresholds, **iso_thresholds}
    meta["calibrator_binary_file"] = "models/calibrator_binary.joblib"
    meta["calibrator_multi_file"] = "models/calibrator_multi.joblib"
    
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
        
    log.info("\nUpdated meta.json with thresholds and calibrators.")


if __name__ == "__main__":
    main()
