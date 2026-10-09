"""
Char-CNN v4 — Evaluation & Benchmarking
=========================================
Provides:
  1. Full classification report and confusion matrix heatmap.
  2. 2D grid search for optimal DGA / Tunnel decision thresholds.
  3. Inference latency / throughput benchmarking (QPS, p50/p95/p99).
"""

import time
from typing import Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import torch
import torch.nn.functional as F
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)
from torch.utils.data import DataLoader

from config import IDX2LABEL


# ──────────────────────────────────────────────
# 1. Metrics & Confusion Matrix
# ──────────────────────────────────────────────

def evaluate_model(
    model: torch.nn.Module,
    test_loader: DataLoader,
    device: torch.device,
    scaler=None,
    output_dir: str = "outputs",
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Run inference on test set, print classification report,
    and save confusion matrix heatmap.

    Returns
    -------
    all_labels, all_preds, all_probs
    """
    model.eval()
    all_preds, all_labels, all_probs = [], [], []

    with torch.no_grad():
        for tokens, feats, labels in test_loader:
            tokens, feats = tokens.to(device), feats.to(device)
            logits = model(tokens, feats)
            if scaler is not None:
                logits = scaler(logits)
            probs = F.softmax(logits, dim=1)
            preds = probs.argmax(dim=1)

            all_preds.append(preds.cpu().numpy())
            all_labels.append(labels.numpy())
            all_probs.append(probs.cpu().numpy())

    all_preds = np.concatenate(all_preds)
    all_labels = np.concatenate(all_labels)
    all_probs = np.concatenate(all_probs)

    # Classification report
    target_names = [IDX2LABEL[i] for i in range(3)]
    all_class_labels = list(range(3))
    report = classification_report(
        all_labels, all_preds, target_names=target_names,
        labels=all_class_labels, digits=4, zero_division=0,
    )
    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT (Test Set)")
    print("=" * 60)
    print(report)

    # Confusion matrix heatmap
    cm = confusion_matrix(all_labels, all_preds, labels=all_class_labels)
    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=target_names,
        yticklabels=target_names,
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Char-CNN v4 - Confusion Matrix")
    plt.tight_layout()
    cm_path = f"{output_dir}/confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"[EVAL] Confusion matrix saved -> {cm_path}")

    return all_labels, all_preds, all_probs


# ──────────────────────────────────────────────
# 2. Threshold Optimisation (2D Grid Search)
# ──────────────────────────────────────────────

def optimise_thresholds(
    all_labels: np.ndarray,
    all_probs: np.ndarray,
    grid_steps: int = 50,
) -> Dict[str, float]:
    """
    Joint 2D grid search over DGA and DNS-tunnel probability thresholds
    to maximise Macro-F1 on the validation/test set.

    Falls back to argmax if no threshold pair beats it.

    Returns
    -------
    dict with keys: 'dga_threshold', 'tunnel_threshold', 'macro_f1',
                    'use_thresholds' (bool).
    """
    # Argmax baseline
    argmax_preds = all_probs.argmax(axis=1)
    baseline_f1 = f1_score(all_labels, argmax_preds, average="macro")

    best_f1 = baseline_f1
    best_dga_th = None
    best_tun_th = None

    thresholds = np.linspace(0.1, 0.95, grid_steps)

    for dga_th in thresholds:
        for tun_th in thresholds:
            preds = np.full(len(all_probs), 0, dtype=int)  # default benign
            # DGA fires if dga_prob ≥ threshold AND dga_prob > tunnel_prob
            dga_mask = (all_probs[:, 1] >= dga_th) & (all_probs[:, 1] >= all_probs[:, 2])
            tun_mask = (all_probs[:, 2] >= tun_th) & (all_probs[:, 2] > all_probs[:, 1])
            preds[dga_mask] = 1
            preds[tun_mask] = 2
            f1 = f1_score(all_labels, preds, average="macro")
            if f1 > best_f1:
                best_f1 = f1
                best_dga_th = dga_th
                best_tun_th = tun_th

    use_thresholds = best_dga_th is not None
    result = {
        "dga_threshold": float(best_dga_th) if best_dga_th else None,
        "tunnel_threshold": float(best_tun_th) if best_tun_th else None,
        "macro_f1": float(best_f1),
        "baseline_argmax_f1": float(baseline_f1),
        "use_thresholds": use_thresholds,
    }

    if use_thresholds:
        print(
            f"[THRESH] Optimised thresholds: DGA={best_dga_th:.3f}, "
            f"Tunnel={best_tun_th:.3f}  ->  Macro-F1={best_f1:.4f} "
            f"(baseline argmax: {baseline_f1:.4f})"
        )
    else:
        print(
            f"[THRESH] Argmax is already optimal  ->  Macro-F1={baseline_f1:.4f}"
        )

    return result


# ──────────────────────────────────────────────
# 3. Inference Benchmarking
# ──────────────────────────────────────────────

def benchmark_inference(
    model: torch.nn.Module,
    device: torch.device,
    max_len: int = 64,
    num_lexical_feats: int = 12,
    batch_sizes: List[int] = [1, 64, 512],
    warmup_iters: int = 20,
    bench_iters: int = 200,
    scaler=None,
) -> List[Dict]:
    """
    Measure sustained inference throughput and latency percentiles.

    Returns list of dicts with keys:
      batch_size, total_queries, qps, p50_ms, p95_ms, p99_ms
    """
    model.eval()
    results = []

    for bs in batch_sizes:
        dummy_tokens = torch.randint(0, 40, (bs, max_len), device=device)
        dummy_feats = torch.randn(bs, num_lexical_feats, device=device)

        # Warmup
        with torch.no_grad():
            for _ in range(warmup_iters):
                logits = model(dummy_tokens, dummy_feats)
                if scaler is not None:
                    logits = scaler(logits)

        # Synchronise before timing
        if device.type == "cuda":
            torch.cuda.synchronize()

        latencies = []
        with torch.no_grad():
            for _ in range(bench_iters):
                t0 = time.perf_counter()
                logits = model(dummy_tokens, dummy_feats)
                if scaler is not None:
                    logits = scaler(logits)
                if device.type == "cuda":
                    torch.cuda.synchronize()
                t1 = time.perf_counter()
                latencies.append((t1 - t0) * 1000)  # ms

        lat = np.array(latencies)
        total_queries = bs * bench_iters
        total_time_s = lat.sum() / 1000
        qps = total_queries / total_time_s

        row = {
            "batch_size": bs,
            "total_queries": total_queries,
            "qps": round(qps, 1),
            "p50_ms": round(float(np.percentile(lat, 50)), 3),
            "p95_ms": round(float(np.percentile(lat, 95)), 3),
            "p99_ms": round(float(np.percentile(lat, 99)), 3),
        }
        results.append(row)

        print(
            f"[BENCH] BS={bs:>4d}  |  QPS={qps:>10,.1f}  |  "
            f"p50={row['p50_ms']:.3f}ms  p95={row['p95_ms']:.3f}ms  "
            f"p99={row['p99_ms']:.3f}ms"
        )

    return results
