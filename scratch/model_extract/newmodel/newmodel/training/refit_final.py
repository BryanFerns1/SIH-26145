"""
UniGuard Stage 6: Final Refit.

Refits the LightGBM models and Isolation Forest on all available
data EXCEPT the calibration blocks (train + val + test).
Does not re-calibrate; we trust the thresholds found in Stage 3.
"""
import json
import logging
import time
from pathlib import Path
import sys

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_class_weight
import joblib
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import iso_prep

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

def load_all_except_cal():
    dfs = []
    for split in ["train", "val", "test"]:
        path = config.PROJECT_ROOT / "data_processed" / f"{split}.parquet"
        df = pd.read_parquet(path)
        dfs.append(df)
        log.info(f"Loaded {split}: {len(df):,} rows")
        
    combined = pd.concat(dfs, ignore_index=True)
    y = combined.pop("Label")
    
    # Drop meta
    meta_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
    for c in meta_cols:
        if c in combined.columns:
            combined.drop(columns=[c], inplace=True)
            
    return combined, y

def downweight_benign(y: pd.Series, base_weight: np.ndarray) -> np.ndarray:
    weights = base_weight.copy()
    is_benign = y == "BENIGN"
    weights[is_benign] *= 0.5
    return weights

def refit_binary(X, y):
    log.info("\n=== Refitting Binary ===")
    y_bin = (y != "BENIGN").astype(int)
    
    classes = np.array([0, 1])
    weights = compute_class_weight("balanced", classes=classes, y=y_bin)
    sample_weights = np.where(y_bin == 1, weights[1], weights[0])
    sample_weights = downweight_benign(y, sample_weights)
    
    train_data = lgb.Dataset(X, label=y_bin, weight=sample_weights, feature_name=config.ALL_FEATURES)
    
    params = config.LGBM_DEFAULTS.copy()
    params.update({
        "objective": "binary",
    })
    
    # We will train for the best_iteration found during validation, or a safe default like 150
    # The previous best was 175. We'll use 175.
    model = lgb.train(params, train_data, num_boost_round=175)
    
    save_path = config.MODELS_DIR / "lgbm_binary.txt"
    model.save_model(save_path)
    log.info(f"Saved final binary model to {save_path}")

def refit_multiclass(X, y):
    log.info("\n=== Refitting Multiclass ===")
    mask = ~y.isin(config.RARE_CLASSES)
    X_mc = X[mask].copy()
    y_mc = y[mask].copy()
    
    class_to_idx = {c: i for i, c in enumerate(config.CLASSES)}
    y_idx = y_mc.map(class_to_idx)
    
    present_classes = np.unique(y_idx.values)
    weights = compute_class_weight("balanced", classes=present_classes, y=y_idx.values)
    weight_dict = {c: w for c, w in zip(present_classes, weights)}
    
    sample_weights = np.array([weight_dict[val] for val in y_idx.values])
    sample_weights = downweight_benign(y_mc, sample_weights)
    
    train_data = lgb.Dataset(X_mc, label=y_idx, weight=sample_weights, feature_name=config.ALL_FEATURES)
    
    params = config.LGBM_DEFAULTS.copy()
    params.update({
        "objective": "multiclass",
        "num_class": len(config.CLASSES),
    })
    
    # The previous best iteration was 109. We'll use 110.
    model = lgb.train(params, train_data, num_boost_round=110)
    
    save_path = config.MODELS_DIR / "lgbm_multi.txt"
    model.save_model(save_path)
    log.info(f"Saved final multiclass model to {save_path}")

def refit_iforest(X, y):
    log.info("\n=== Refitting Isolation Forest ===")
    benign_df = X[y == "BENIGN"].copy()
    
    sample_size = 200_000
    if len(benign_df) > sample_size:
        benign_df = benign_df.sample(n=sample_size, random_state=42)
        
    X_iso = iso_prep(benign_df, config.ALL_FEATURES)
    
    params = config.IFOREST_DEFAULTS.copy()
    model = IsolationForest(**params)
    model.fit(X_iso)
    
    save_path = config.MODELS_DIR / "iforest.joblib"
    joblib.dump(model, save_path)
    log.info(f"Saved final iforest model to {save_path}")

def main():
    X, y = load_all_except_cal()
    refit_binary(X, y)
    refit_multiclass(X, y)
    refit_iforest(X, y)
    log.info("Refit complete.")

if __name__ == "__main__":
    main()
