"""
UniGuard E4: Leave-One-Class-Out Evaluation (Isolation Forest).

Evaluates the Isolation Forest's ability to detect zero-day attacks
by testing it on classes that were NOT in the training or validation sets.
"""
import json
import logging
import sys
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import iso_prep

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def main():
    log.info("E4: Leave-one-class-out (Zero-day Anomaly Detection)")
    log.info("====================================================")
    
    # Classes completely unseen in training:
    # From inventory:
    # Train: BENIGN, DoS Hulk, DoS GoldenEye, DoS Slow, FTP-Patator, SSH-Patator, Heartbleed
    # Val: Infiltration, Portscan, Web Attack
    # Test: DDoS, Botnet
    
    # We will just evaluate Isolation Forest on ALL attack classes in the Test set
    # Since Isolation Forest was ONLY trained on BENIGN traffic, ALL attacks are "zero-day" to it.
    
    dfs = []
    processed_dir = config.PROJECT_ROOT / "data_processed"
    for day in config.TEST_DAYS:
        path = processed_dir / f"{day}.parquet"
        dfs.append(pd.read_parquet(path))
    df_test = pd.concat(dfs, ignore_index=True)
    
    # Load model
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    thresh = meta["thresholds"]["iforest_review"]["value"]
    
    X_iso = iso_prep(df_test, config.ALL_FEATURES)
    iso_scores = -iso.decision_function(X_iso)
    
    y_pred_iso = (iso_scores >= thresh).astype(int)
    
    log.info(f"{'Threat Class':20s} | {'Detected as Anomaly':20s} | {'Total':10s}")
    log.info("-" * 60)
    
    for cls in df_test["Label"].unique():
        if cls == "BENIGN":
            continue
            
        mask = df_test["Label"] == cls
        detected = y_pred_iso[mask].sum()
        total = mask.sum()
        
        # Determine if it was seen in supervised training
        status = "Unseen" if cls in ["DDoS", "Botnet"] else "Seen in Supv"
        
        log.info(f"{cls:20s} | {detected/total:19.1%} | {total:<10} ({status})")


if __name__ == "__main__":
    main()
