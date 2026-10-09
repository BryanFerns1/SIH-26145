import pytest
import pandas as pd
import numpy as np
import sys
from pathlib import Path
import joblib
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.lgbm_wrapper import LGBMWrapper

def test_model_shapes():
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    mc_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_multi_file"])
    
    # Create dummy input of correct shape
    X = np.zeros((5, len(config.ALL_FEATURES)))
    
    bin_probs = bin_cal.predict_proba(X)
    assert bin_probs.shape == (5, 2)
    assert np.all(bin_probs >= 0) and np.all(bin_probs <= 1)
    
    mc_probs = mc_cal.predict_proba(X)
    assert mc_probs.shape == (5, len(config.CLASSES))
    assert np.all(mc_probs >= 0) and np.all(mc_probs <= 1)
