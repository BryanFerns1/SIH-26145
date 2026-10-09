"""
UniGuard Stage 7: Population Stability Index (PSI).

Computes PSI for model features and output scores to detect drift.
- Baseline is saved from training data.
- PSI < 0.1: Stable
- 0.1 <= PSI < 0.25: Watch
- PSI >= 0.25: Significant Drift
"""
import json
import logging
from pathlib import Path
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def calculate_psi(expected, actual, bins=10):
    """
    Calculate the PSI for a single continuous feature.
    """
    # Create bins using expected data (deciles)
    # Adding a tiny amount of noise to avoid duplicate edges
    expected_noise = expected + np.random.normal(0, 1e-6, size=len(expected))
    
    # Try to calculate quantiles. If it fails due to many identical values, use uniform bins.
    try:
        breakpoints = np.unique(np.quantile(expected_noise, np.linspace(0, 1, bins + 1)))
        if len(breakpoints) < 2:
            breakpoints = np.linspace(expected.min(), expected.max(), bins + 1)
    except:
        breakpoints = np.linspace(expected.min(), expected.max(), bins + 1)
        
    # Ensure min and max cover everything
    breakpoints[0] = -np.inf
    breakpoints[-1] = np.inf
    
    # Calculate frequencies
    expected_percents = np.histogram(expected, breakpoints)[0] / len(expected)
    actual_percents = np.histogram(actual, breakpoints)[0] / len(actual)
    
    # Avoid zero division
    expected_percents = np.maximum(expected_percents, 1e-4)
    actual_percents = np.maximum(actual_percents, 1e-4)
    
    # Normalize again
    expected_percents /= expected_percents.sum()
    actual_percents /= actual_percents.sum()
    
    # Compute PSI
    psi_values = (actual_percents - expected_percents) * np.log(actual_percents / expected_percents)
    psi = np.sum(psi_values)
    
    return float(psi), breakpoints.tolist(), expected_percents.tolist()


def save_baseline(X_train: pd.DataFrame, y_train_scores: np.ndarray):
    """Compute and save baseline distributions for PSI."""
    log.info("Computing PSI baseline distributions...")
    baseline = {"features": {}, "score": {}}
    
    # Feature distributions
    for col in config.ALL_FEATURES:
        if col in X_train.columns:
            # Drop NaNs for PSI computation
            data = X_train[col].dropna().values
            if len(data) > 0:
                _, breakpoints, percents = calculate_psi(data, data)
                baseline["features"][col] = {
                    "breakpoints": breakpoints,
                    "percents": percents
                }
                
    # Score distribution
    _, breakpoints, percents = calculate_psi(y_train_scores, y_train_scores)
    baseline["score"] = {
        "breakpoints": breakpoints,
        "percents": percents
    }
    
    save_path = config.MODELS_DIR / "psi_baseline.json"
    with open(save_path, "w") as f:
        json.dump(baseline, f, indent=2)
    log.info(f"Saved PSI baseline to {save_path}")


def evaluate_drift(X_new: pd.DataFrame, y_new_scores: np.ndarray, baseline_path: str = None) -> dict:
    """Evaluate drift on new data against the saved baseline."""
    if baseline_path is None:
        baseline_path = config.MODELS_DIR / "psi_baseline.json"
        
    with open(baseline_path, "r") as f:
        baseline = json.load(f)
        
    results = {"features": {}, "score_psi": 0.0, "drift_level": "Stable"}
    
    def calc_new_psi(actual, expected_percents, breakpoints):
        actual_percents = np.histogram(actual, breakpoints)[0] / len(actual)
        actual_percents = np.maximum(actual_percents, 1e-4)
        actual_percents /= actual_percents.sum()
        
        expected_percents = np.array(expected_percents)
        psi_values = (actual_percents - expected_percents) * np.log(actual_percents / expected_percents)
        return float(np.sum(psi_values))
        
    # Feature PSI
    drifted_features = 0
    for col, base_data in baseline["features"].items():
        if col in X_new.columns:
            data = X_new[col].dropna().values
            if len(data) > 0:
                psi = calc_new_psi(data, base_data["percents"], base_data["breakpoints"])
                results["features"][col] = psi
                if psi >= 0.25:
                    drifted_features += 1
                    
    # Score PSI
    score_psi = calc_new_psi(y_new_scores, baseline["score"]["percents"], baseline["score"]["breakpoints"])
    results["score_psi"] = score_psi
    
    # Determine level
    if score_psi >= 0.25 or drifted_features > len(baseline["features"]) * 0.2:
        results["drift_level"] = "Significant Drift"
    elif score_psi >= 0.1 or drifted_features > 0:
        results["drift_level"] = "Watch"
        
    return results


def main():
    # Only run if models exist
    if not (config.MODELS_DIR / "lgbm_binary.txt").exists():
        log.info("Models not found, skipping PSI baseline computation.")
        return
        
    log.info("Loading training data for baseline...")
    processed_dir = config.PROJECT_ROOT / "data_processed"
    X_train = pd.read_parquet(processed_dir / "train.parquet")
    
    # Load model and get scores
    import joblib
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
    
    if "calibrator_binary_file" in meta:
        cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
        log.info("Predicting on training set...")
        # Sample to avoid memory issues and speed up
        sample_X = X_train.sample(min(200_000, len(X_train)), random_state=42)
        
        # Drop Label and meta before prediction
        meta_cols = ['Label', 'Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'day']
        for c in meta_cols:
            if c in sample_X.columns:
                sample_X = sample_X.drop(columns=[c])
        
        scores = cal.predict_proba(sample_X)[:, 1]
        save_baseline(sample_X, scores)
        
        # Test drift on a test day
        log.info("\nEvaluating drift on Test set...")
        df_test = pd.read_parquet(processed_dir / "test.parquet")
        df_test_X = df_test.copy()
        for c in meta_cols:
            if c in df_test_X.columns:
                df_test_X = df_test_X.drop(columns=[c])
                
        test_scores = cal.predict_proba(df_test_X)[:, 1]
        
        results = evaluate_drift(df_test, test_scores)
        log.info(f"Score PSI: {results['score_psi']:.4f}")
        log.info(f"Drift Level: {results['drift_level']}")
        
        high_drift_feats = {k: v for k, v in results["features"].items() if v >= 0.25}
        if high_drift_feats:
            log.info(f"Features with significant drift (>0.25): {len(high_drift_feats)}")
            for k, v in list(high_drift_feats.items())[:5]:
                log.info(f"  {k}: {v:.4f}")
    else:
        log.info("Binary calibrator not found in meta.json. Cannot compute score PSI.")


if __name__ == "__main__":
    main()
