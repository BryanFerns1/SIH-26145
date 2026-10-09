"""
UniGuard Stage 3: Train LightGBM L2 models (Binary and Multiclass).

Loads prepared parquet data, trains models with early stopping on
validation days, and saves to LightGBM native text format.
Handles class imbalance via class weights.
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_class_weight

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOGS_DIR / "train_lgbm.log", mode="w"),
    ],
)
log = logging.getLogger(__name__)


def load_split(split_name: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load pre-processed parquet for a split."""
    path = config.PROJECT_ROOT / "data_processed" / f"{split_name}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Missing prepared data for {split_name}: {path}")
    df = pd.read_parquet(path)
    log.info(f"Loaded {split_name}: {len(df):,} rows")
    y = df.pop("Label")
    # Also pop metadata columns if present so they don't get used as features
    meta_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
    for c in meta_cols:
        if c in df.columns:
            df.pop(c)
    return df, y


def downweight_benign(y: pd.Series, base_weight: np.ndarray) -> np.ndarray:
    """
    Prevalence down-weighting for benign traffic.
    Since benign traffic (especially periodic checks like NTP) dominates,
    we reduce its weight relative to attacks to improve recall.
    """
    weights = base_weight.copy()
    is_benign = y == "BENIGN"
    # Halve the weight of benign traffic
    weights[is_benign] *= 0.5
    return weights


def train_binary(X_train, y_train, X_val, y_val):
    """Train binary Attack vs Benign LightGBM model."""
    log.info("\n=== Training Binary Model ===")
    
    # 0 = Benign, 1 = Attack
    y_train_bin = (y_train != "BENIGN").astype(int)
    y_val_bin = (y_val != "BENIGN").astype(int)
    
    log.info(f"Train split: {len(y_train_bin):,} rows ({y_train_bin.sum():,} attacks, {len(y_train_bin) - y_train_bin.sum():,} benign)")
    log.info(f"Val split:   {len(y_val_bin):,} rows ({y_val_bin.sum():,} attacks, {len(y_val_bin) - y_val_bin.sum():,} benign)")
    
    # Class weights to handle imbalance
    classes = np.array([0, 1])
    weights = compute_class_weight("balanced", classes=classes, y=y_train_bin)
    sample_weights = np.where(y_train_bin == 1, weights[1], weights[0])
    sample_weights = downweight_benign(y_train, sample_weights)
    
    train_data = lgb.Dataset(X_train, label=y_train_bin, weight=sample_weights, feature_name=config.ALL_FEATURES)
    val_data = lgb.Dataset(X_val, label=y_val_bin, reference=train_data, feature_name=config.ALL_FEATURES)
    
    params = config.LGBM_DEFAULTS.copy()
    params.update({
        "objective": "binary",
        "metric": ["auc", "binary_logloss"],
    })
    
    t0 = time.time()
    callbacks = [
        lgb.early_stopping(stopping_rounds=50, verbose=True),
        lgb.log_evaluation(period=50)
    ]
    
    model = lgb.train(
        params,
        train_data,
        valid_sets=[train_data, val_data],
        valid_names=["train", "val"],
        callbacks=callbacks
    )
    
    log.info(f"Binary model trained in {time.time() - t0:.1f}s")
    log.info(f"Best iteration: {model.best_iteration}")
    
    if model.best_iteration < 50:
        log.error("Binary model best iteration < 50. Possible underfitting or early stopping too soon.")
        # We don't strictly crash here but we log an error for investigation
    
    save_path = config.MODELS_DIR / "lgbm_binary.txt"
    model.save_model(save_path)
    log.info(f"Saved binary model to {save_path}")
    
    return model


def train_multiclass(X_train, y_train, X_val, y_val):
    """Train multiclass Attack Type LightGBM model."""
    log.info("\n=== Training Multiclass Model ===")
    
    # Filter out rare classes if any remain in train/val
    train_mask = ~y_train.isin(config.RARE_CLASSES)
    val_mask = ~y_val.isin(config.RARE_CLASSES)
    
    X_train_mc = X_train[train_mask].copy()
    y_train_mc = y_train[train_mask].copy()
    X_val_mc = X_val[val_mask].copy()
    y_val_mc = y_val[val_mask].copy()
    
    # Map classes to integers 0..N-1
    # Ensure config.CLASSES order is strictly followed
    class_to_idx = {c: i for i, c in enumerate(config.CLASSES)}
    y_train_idx = y_train_mc.map(class_to_idx)
    y_val_idx = y_val_mc.map(class_to_idx)
    
    log.info(f"Train split: {len(y_train_idx):,} rows, {len(config.CLASSES)} classes")
    
    # Compute balanced class weights for classes actually present in training
    present_classes = np.unique(y_train_idx.values)
    weights = compute_class_weight("balanced", classes=present_classes, y=y_train_idx.values)
    weight_dict = {c: w for c, w in zip(present_classes, weights)}
    
    # Map back to array format
    sample_weights = np.array([weight_dict[y] for y in y_train_idx.values])
    sample_weights = downweight_benign(y_train_mc, sample_weights)
    
    train_data = lgb.Dataset(X_train_mc, label=y_train_idx, weight=sample_weights, feature_name=config.ALL_FEATURES)
    val_data = lgb.Dataset(X_val_mc, label=y_val_idx, reference=train_data, feature_name=config.ALL_FEATURES)
    
    params = config.LGBM_DEFAULTS.copy()
    params.update({
        "objective": "multiclass",
        "num_class": len(config.CLASSES),
        "metric": ["multi_logloss", "multi_error"],
    })
    
    t0 = time.time()
    callbacks = [
        lgb.early_stopping(stopping_rounds=50, verbose=True),
        lgb.log_evaluation(period=50)
    ]
    
    model = lgb.train(
        params,
        train_data,
        valid_sets=[train_data, val_data],
        valid_names=["train", "val"],
        callbacks=callbacks
    )
    
    log.info(f"Multiclass model trained in {time.time() - t0:.1f}s")
    log.info(f"Best iteration: {model.best_iteration}")
    
    if model.best_iteration < 50:
        log.error("Multiclass model best iteration < 50. Possible underfitting or early stopping too soon.")
    
    save_path = config.MODELS_DIR / "lgbm_multi.txt"
    model.save_model(save_path)
    log.info(f"Saved multiclass model to {save_path}")
    
    return model


def update_meta():
    """Create or update meta.json with model info."""
    meta_path = config.PROJECT_ROOT / "meta.json"
    
    if meta_path.exists():
        with open(meta_path, "r") as f:
            meta = json.load(f)
    else:
        meta = {}
        
    meta.update({
        "base_features": config.BASE_FEATURES,
        "features": config.ALL_FEATURES,
        "classes": config.CLASSES,
        "rare_classes": config.RARE_CLASSES,
        "benign_value": "BENIGN",
        "merge": config.LABEL_MERGE,
        "lgbm_binary_file": "models/lgbm_binary.txt",
        "lgbm_multi_file": "models/lgbm_multi.txt",
        "trained_on_days": config.TRAIN_DAYS,
        "val_on_days": config.VAL_DAYS,
    })
    
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    log.info(f"Updated meta.json")


def main():
    log.info("Loading training split...")
    X_train, y_train = load_split("train")
    
    log.info("Loading validation split...")
    X_val, y_val = load_split("val")
    
    # Train Binary Model
    train_binary(X_train, y_train, X_val, y_val)
    
    # Train Multiclass Model
    train_multiclass(X_train, y_train, X_val, y_val)
    
    # Update Metadata
    update_meta()
    
    log.info("LightGBM training complete.")


if __name__ == "__main__":
    main()
