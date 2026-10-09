"""
UniGuard Stage 7: CPU Benchmark.

Benchmarks feature computation and model inference on a single core.
Reports max throughput (flows/s) using large batches, and alert latency using batch=1.
Target: >= 5,000 flows/s on 1 core, latency < 1 ms.
"""
import json
import logging
import time
from pathlib import Path
import sys
import psutil
import os

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import prepare, iso_prep

# Pin to single core for benchmark
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

def pin_to_single_core():
    p = psutil.Process()
    try:
        p.cpu_affinity([0])
        log.info(f"Pinned process to CPU core: {p.cpu_affinity()}")
    except AttributeError:
        log.warning("CPU affinity not supported on this OS. Make sure OMP_NUM_THREADS=1 is sufficient.")


def measure_throughput(df, bin_cal, mc_cal, iso, batch_size=10000, n_iterations=10):
    log.info(f"\n--- Benchmarking Throughput (Batch Size: {batch_size}) ---")
    
    feat_times = []
    bin_times = []
    mc_times = []
    iso_times = []
    
    for i in range(n_iterations):
        batch = df.iloc[i * batch_size: (i + 1) * batch_size].copy()
        
        # 1. Feature computation
        t0 = time.time()
        X = prepare(batch, config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=False)
        t_feat = time.time() - t0
        
        # 2. Binary Model
        t0 = time.time()
        bin_probs = bin_cal.predict_proba(X)[:, 1]
        t_bin = time.time() - t0
        
        # 3. Multiclass Model
        t0 = time.time()
        mc_probs = mc_cal.predict_proba(X)
        t_mc = time.time() - t0
        
        # 4. Isolation Forest
        t0 = time.time()
        X_iso = iso_prep(X, config.ALL_FEATURES)
        iso_scores = iso.decision_function(X_iso)
        t_iso = time.time() - t0
        
        feat_times.append(t_feat)
        bin_times.append(t_bin)
        mc_times.append(t_mc)
        iso_times.append(t_iso)
        
    avg_feat = np.mean(feat_times)
    avg_bin = np.mean(bin_times)
    avg_mc = np.mean(mc_times)
    avg_iso = np.mean(iso_times)
    
    avg_total_time = avg_feat + avg_bin + avg_mc + avg_iso
    throughput = batch_size / avg_total_time
    
    log.info(f"Feature Prep Time (per batch): {avg_feat*1000:.1f} ms")
    log.info(f"Binary Eval Time (per batch):  {avg_bin*1000:.1f} ms")
    log.info(f"Multi Eval Time (per batch):   {avg_mc*1000:.1f} ms")
    log.info(f"IForest Eval Time (per batch): {avg_iso*1000:.1f} ms")
    log.info(f"Total Throughput:              {throughput:,.0f} flows / sec")
    
    return throughput


def measure_latency(df, bin_cal, mc_cal, iso, n_iterations=1000):
    log.info(f"\n--- Benchmarking Latency (Batch Size: 1, {n_iterations} iters) ---")
    
    # Pre-compute features to remove Pandas overhead from inference loop measurement
    X_full = prepare(df.head(n_iterations).copy(), config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=False)
    X_iso_full = iso_prep(X_full, config.ALL_FEATURES)
    
    # Convert to numpy to avoid pandas loc/iloc overhead in the loop
    X_np = X_full.values
    X_iso_np = X_iso_full
    
    latencies = []
    
    for i in range(n_iterations):
        # We simulate receiving an already extracted feature vector
        x_row = X_np[[i]]
        x_iso_row = X_iso_np[[i]]
        
        t0 = time.perf_counter()
        
        bin_probs = bin_cal.predict_proba(x_row)[:, 1]
        if bin_probs[0] >= 0.005:  # simulate trigger threshold
            mc_probs = mc_cal.predict_proba(x_row)
            
        iso_scores = iso.decision_function(x_iso_row)
        
        t_total = time.perf_counter() - t0
        latencies.append(t_total * 1000) # ms
        
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    
    log.info(f"P50 Latency: {p50:.3f} ms")
    log.info(f"P95 Latency: {p95:.3f} ms")
    log.info(f"P99 Latency: {p99:.3f} ms")


def main():
    pin_to_single_core()
    
    test_file = config.PROJECT_ROOT / "data_processed" / "test.parquet"
    df = pd.read_parquet(test_file).sample(10000 * 10, replace=True)
    
    meta_path = config.PROJECT_ROOT / "meta.json"
    with open(meta_path, "r") as f:
        meta = json.load(f)
        
    bin_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_binary_file"])
    mc_cal = joblib.load(config.PROJECT_ROOT / meta["calibrator_multi_file"])
    iso = joblib.load(config.PROJECT_ROOT / meta["iforest_file"])
    
    measure_throughput(df, bin_cal, mc_cal, iso)
    measure_latency(df, bin_cal, mc_cal, iso)


if __name__ == "__main__":
    main()
