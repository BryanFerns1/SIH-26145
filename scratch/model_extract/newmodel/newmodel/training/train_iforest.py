"""
UniGuard Stage 3: Train Isolation Forest L3 model (Unsupervised Anomaly).

Trains ONLY on BENIGN flows drawn from multiple capture days.
Used to flag unusual traffic that matches no known trained class.
"""
import json
import logging
import time
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import iso_prep

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOGS_DIR / "train_iforest.log", mode="w"),
    ],
)
log = logging.getLogger(__name__)


def load_benign_sample(split_name: str, sample_size: int = 150_000) -> pd.DataFrame:
    """Load a random sample of strictly BENIGN flows from the given split."""
    path = config.PROJECT_ROOT / "data_processed" / f"{split_name}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Missing prepared data for {split_name}: {path}")
        
    df = pd.read_parquet(path)
    benign_df = df[df["Label"] == "BENIGN"].copy()
    
    # Drop label and metadata columns
    meta_cols = ['Label', 'Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
    for c in meta_cols:
        if c in benign_df.columns:
            benign_df.drop(columns=[c], inplace=True)
            
    log.info(f"Loaded {len(benign_df):,} benign flows from {split_name}")
    
    if len(benign_df) > sample_size:
        log.info(f"Sampling down to {sample_size:,} flows...")
        benign_df = benign_df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    
    return benign_df


def main():
    log.info("Loading BENIGN training data for Isolation Forest...")
    # Train only on benign flows from training split
    X_train_raw = load_benign_sample("train", sample_size=150_000)
    
    log.info("Applying log1p transform (iso_prep)...")
    X_train = iso_prep(X_train_raw, config.ALL_FEATURES)
    
    params = config.IFOREST_DEFAULTS.copy()
    log.info(f"Training Isolation Forest with params: {params}")
    
    model = IsolationForest(**params)
    
    t0 = time.time()
    model.fit(X_train)
    log.info(f"Isolation Forest trained in {time.time() - t0:.1f}s")
    
    save_path = config.MODELS_DIR / "iforest.joblib"
    joblib.dump(model, save_path)
    log.info(f"Saved model to {save_path} (joblib ver: {joblib.__version__})")
    log.warning("WARNING: joblib files must only be loaded from trusted sources.")
    
    # Update meta.json
    meta_path = config.PROJECT_ROOT / "meta.json"
    if meta_path.exists():
        with open(meta_path, "r") as f:
            meta = json.load(f)
    else:
        meta = {}
    
    meta["iforest_file"] = "models/iforest.joblib"
    
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)


if __name__ == "__main__":
    main()
