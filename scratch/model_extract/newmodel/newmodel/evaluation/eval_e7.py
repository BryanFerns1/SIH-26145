import json
import logging
import sys
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

def main():
    path = config.PROJECT_ROOT / "data_processed" / "test.parquet"
    df = pd.read_parquet(path)
    
    # Identify periodic benign traffic
    mask_periodic = (df['Dst Port'].isin([123, 53])) & (df['Label'] == 'BENIGN')
    df_periodic = df[mask_periodic].copy()
    
    log.info(f"Identified {len(df_periodic)} benign periodic flows (ports 53, 123).")
    if len(df_periodic) == 0:
        log.warning("No periodic flows found.")
        return
        
    y = df_periodic.pop("Label")
    for c in ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']:
        if c in df_periodic.columns:
            df_periodic.drop(columns=[c], inplace=True)
            
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
    
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    thresh = meta["thresholds"]
    
    bin_probs = bin_cal.predict_proba(df_periodic)[:, 1]
    
    fpr_high = (bin_probs >= thresh["binary_high"]["value"]).mean()
    fpr_rev = (bin_probs >= thresh["binary_review"]["value"]).mean()
    
    log.info(f"FPR on Periodic Benign Traffic (High):   {fpr_high:.2%}")
    log.info(f"FPR on Periodic Benign Traffic (Review): {fpr_rev:.2%}")

if __name__ == "__main__":
    main()
