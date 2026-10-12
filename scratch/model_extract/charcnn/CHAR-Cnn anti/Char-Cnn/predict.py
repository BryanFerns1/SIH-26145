"""
Char-CNN v4 -- Model Prediction & Accuracy Evaluation
=====================================================
Interactive and batch evaluation for testing domain classifications
against the trained HybridNet_v4 model with calibrated probabilities.

Usage:
  python predict.py "example.com"
  python predict.py --test-suite
"""

import argparse
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.getcwd() != SCRIPT_DIR:
    os.chdir(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from typing import Dict, List, Tuple

import numpy as np
import torch

from alert import generate_sih_alert
from calibration import TemperatureScaler
from config import IDX2LABEL, LABEL2IDX, TrainingConfig
from evidence_features import extract_features_vector
from preprocess import clean_query_name, tokenize_domain
from model import HybridNet_v4


def load_model_and_artifacts(
    model_path: str = "outputs/hybridnet_v4_best.pt",
    calibrated_path: str = "outputs/hybridnet_v4_calibrated.pt",
    stats_path: str = "outputs/feature_stats.npz",
    device: torch.device = None,
) -> Tuple[HybridNet_v4, TemperatureScaler, np.ndarray, np.ndarray, TrainingConfig]:
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if not os.path.isfile(model_path):
        raise FileNotFoundError(f"Model checkpoint not found: {model_path}")
    if not os.path.isfile(stats_path):
        raise FileNotFoundError(f"Feature statistics not found: {stats_path}")

    # Load stats
    stats = np.load(stats_path)
    feat_mean = stats["mean"]
    feat_std = stats["std"]

    # Load model
    ckpt = torch.load(model_path, map_location=device, weights_only=False)
    cfg_dict = ckpt.get("config", {})
    cfg = TrainingConfig(**{k: v for k, v in cfg_dict.items() if hasattr(TrainingConfig, k)})

    model = HybridNet_v4(cfg).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    # Load scaler
    temp_scaler = TemperatureScaler().to(device)
    if os.path.isfile(calibrated_path):
        cal_ckpt = torch.load(calibrated_path, map_location=device, weights_only=False)
        temp_scaler.temperature.data.fill_(cal_ckpt.get("temperature", 1.0))
    temp_scaler.eval()

    return model, temp_scaler, feat_mean, feat_std, cfg


import json

def load_thresholds(thresh_path: str = "outputs/thresholds.json") -> Dict:
    if os.path.isfile(thresh_path):
        try:
            with open(thresh_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"use_thresholds": False, "dga_threshold": 0.50, "tunnel_threshold": 0.50}


def predict_domain(
    domain: str,
    model: HybridNet_v4,
    temp_scaler: TemperatureScaler,
    feat_mean: np.ndarray,
    feat_std: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
    thresholds: Optional[Dict] = None,
) -> Dict:
    cleaned = clean_query_name(domain)
    tokens = torch.from_numpy(
        tokenize_domain(cleaned, cfg.max_len)
    ).unsqueeze(0).to(device)

    raw_feats = extract_features_vector(cleaned)
    safe_std = np.where(feat_std < 1e-8, 1.0, feat_std)
    normed_feats = (raw_feats - feat_mean) / safe_std
    feats_t = torch.from_numpy(normed_feats).float().unsqueeze(0).to(device)

    t0 = time.perf_counter()
    with torch.no_grad():
        logits = model(tokens, feats_t)
        scaled_logits = temp_scaler(logits)
        probs = torch.softmax(scaled_logits, dim=1).cpu().numpy()[0]
    latency_ms = (time.perf_counter() - t0) * 1000.0

    if thresholds and thresholds.get("use_thresholds"):
        tun_th = thresholds.get("tunnel_threshold", 0.50)
        dga_th = thresholds.get("dga_threshold", 0.50)
        if probs[2] >= tun_th and probs[2] >= probs[1]:
            pred_label = "dns_tunnel"
            confidence = float(probs[2])
        elif probs[1] >= dga_th:
            pred_label = "dga"
            confidence = float(probs[1])
        else:
            pred_label = "benign"
            confidence = float(probs[0])
    else:
        pred_idx = int(np.argmax(probs))
        pred_label = IDX2LABEL[pred_idx]
        confidence = float(probs[pred_idx])

    return {
        "domain": domain,
        "predicted_label": pred_label,
        "confidence": confidence,
        "probabilities": {
            "benign": float(probs[0]),
            "dga": float(probs[1]),
            "dns_tunnel": float(probs[2]),
        },
        "latency_ms": latency_ms,
        "entropy": float(raw_feats[2]),
        "subdomain_depth": int(raw_feats[10]),
    }


def run_test_suite(
    model: HybridNet_v4,
    temp_scaler: TemperatureScaler,
    feat_mean: np.ndarray,
    feat_std: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
    thresholds: Optional[Dict] = None,
):
    test_cases = [
        # Benign
        ("www.google.com", "benign"),
        ("api.github.com", "benign"),
        ("cdn.cloudflare.net", "benign"),
        ("login.microsoftonline.com", "benign"),
        ("en.wikipedia.org", "benign"),
        ("updates.zoom.us", "benign"),
        ("static.xx.fbcdn.net", "benign"),
        ("mail.google.com", "benign"),
        # DGA
        ("aj83kd91lz04.biz", "dga"),
        ("x8201jf98a2.org", "dga"),
        ("pkqjdhfa8273.info", "dga"),
        ("9182374619283.xyz", "dga"),
        ("a8f3kd92mxp1.xyz", "dga"),
        ("zkqp1048fna7.top", "dga"),
        ("mxbq73kdla01.net", "dga"),
        ("pw92ks01la93.com", "dga"),
        # DNS Tunnel
        ("01af8c2b.93de41fa.exfil.net", "dns_tunnel"),
        ("4f2a.b8c1.d9e3.f0a2.7b6c.exfil.net", "dns_tunnel"),
        ("8a1f.c3b9.d2e4.f1a0.tunnel.org", "dns_tunnel"),
        ("deadbeef.cafebabe.01234567.dnstun.xyz", "dns_tunnel"),
        ("a1b2c3d4.e5f6a7b8.c9d0e1f2.c2server.com", "dns_tunnel"),
        ("payload01.stage02.exfiltration03.covertch.info", "dns_tunnel"),
        ("7f8a9b0c.1d2e3f4a.5b6c7d8e.exfil.net", "dns_tunnel"),
        ("aa11bb22.cc33dd44.ee55ff66.dnstun.xyz", "dns_tunnel"),
    ]

    print("\n" + "=" * 90)
    print("HYBRIDNET_V4 ACCURACY TEST SUITE (24 Representative Security Domains)")
    print("=" * 90)
    print(
        f"{'Domain':<42} | {'True':<10} | {'Pred':<10} | {'Conf':<6} | "
        f"{'Benign':<6} | {'DGA':<6} | {'Tunnel':<6} | {'Status'}"
    )
    print("-" * 90)

    correct = 0
    total = len(test_cases)
    per_class_correct = {"benign": 0, "dga": 0, "dns_tunnel": 0}
    per_class_total = {"benign": 0, "dga": 0, "dns_tunnel": 0}
    latencies = []

    for domain, true_label in test_cases:
        res = predict_domain(domain, model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)
        pred_label = res["predicted_label"]
        conf = res["confidence"]
        p = res["probabilities"]
        latencies.append(res["latency_ms"])

        is_match = (pred_label == true_label)
        if is_match:
            correct += 1
            per_class_correct[true_label] += 1
            status_str = "[PASS]"
        else:
            status_str = "[FAIL]"
        per_class_total[true_label] += 1

        disp_domain = domain if len(domain) <= 40 else domain[:37] + "..."
        print(
            f"{disp_domain:<42} | {true_label:<10} | {pred_label:<10} | "
            f"{conf*100:>5.1f}% | {p['benign']*100:>5.1f}% | {p['dga']*100:>5.1f}% | "
            f"{p['dns_tunnel']*100:>5.1f}% | {status_str}"
        )

    print("-" * 90)
    accuracy = (correct / total) * 100.0
    avg_latency = float(np.mean(latencies))

    print(f"\nOverall Test Suite Accuracy: {correct}/{total} ({accuracy:.2f}%)")
    print(f"Average Single-Query Latency: {avg_latency:.3f} ms (~{1000.0/avg_latency:.0f} QPS)")
    print("\nPer-Class Breakdown:")
    for cls_name in ["benign", "dga", "dns_tunnel"]:
        c_corr = per_class_correct[cls_name]
        c_tot = per_class_total[cls_name]
        c_acc = (c_corr / c_tot) * 100.0 if c_tot > 0 else 0.0
        print(f"  - {cls_name:<11}: {c_corr}/{c_tot} ({c_acc:.1f}% accuracy)")
    print("=" * 90)


def run_holdout_eval(
    model: HybridNet_v4,
    temp_scaler: TemperatureScaler,
    feat_mean: np.ndarray,
    feat_std: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
    n_samples: int = 1000,
    thresholds: Optional[Dict] = None,
    test_path: str = "data/test.csv",
):
    import pandas as pd
    from sklearn.metrics import classification_report, confusion_matrix

    if not os.path.isfile(test_path):
        print(f"[ERROR] Test dataset not found at {test_path}")
        return

    print(f"\n[PREDICT] Loading holdout test dataset: {test_path}...")
    df = pd.read_csv(test_path)
    if n_samples > 0 and n_samples < len(df):
        df = df.sample(n=n_samples, random_state=42).reset_index(drop=True)
    
    print(f"[PREDICT] Evaluating on {len(df):,} holdout domains...")
    print(f"[PREDICT] Class distribution in sample:\n{df['label'].value_counts().to_string()}\n")

    domains = df["domain"].astype(str).tolist()
    true_labels = df["label"].astype(str).tolist()
    pred_labels = []
    t0 = time.perf_counter()

    for d in domains:
        res = predict_domain(d, model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)
        pred_labels.append(res["predicted_label"])

    elapsed = time.perf_counter() - t0
    qps = len(domains) / elapsed

    print("=" * 70)
    print(f"  HOLDOUT EVALUATION REPORT ({len(domains):,} domains)")
    print("=" * 70)
    print(classification_report(true_labels, pred_labels, digits=4))
    print(f"Total Time: {elapsed:.2f}s | Throughput: {qps:.1f} QPS")

    cm = confusion_matrix(true_labels, pred_labels, labels=["benign", "dga", "dns_tunnel"])
    print("\nConfusion Matrix:")
    print("                  Pred Benign   Pred DGA   Pred Tunnel")
    print(f"True Benign    :  {cm[0,0]:>11d}  {cm[0,1]:>9d}  {cm[0,2]:>12d}")
    print(f"True DGA       :  {cm[1,0]:>11d}  {cm[1,1]:>9d}  {cm[1,2]:>12d}")
    print(f"True Tunnel    :  {cm[2,0]:>11d}  {cm[2,1]:>9d}  {cm[2,2]:>12d}")
    print("=" * 70)


def interactive_loop(model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=None):
    print("\n" + "=" * 70)
    print("  UniGuard Interactive DNS Threat Detector (SIH26145)")
    print("  Model: HybridNet_v4 (943k params) with Calibrated Scaling")
    print("=" * 70)
    print("Enter any domain to inspect threat class & probabilities.")
    print("Commands:")
    print("  - Type any domain name (e.g. google.com, aj83kd91lz04.biz)")
    print("  - 'alert <domain>' to see the full SIH26145 JSON Security Alert")
    print("  - 'test' to run the 24-domain security benchmark suite")
    print("  - 'exit' or 'quit' to exit\n")

    while True:
        try:
            user_input = input("UniGuard > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting UniGuard CLI.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            print("Exiting UniGuard.")
            break
        if user_input.lower() == "test":
            run_test_suite(model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)
            continue

        show_alert = False
        domain = user_input
        if user_input.lower().startswith("alert "):
            show_alert = True
            domain = user_input[6:].strip()

        res = predict_domain(domain, model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)
        threat = res["predicted_label"].upper()
        conf = res["confidence"] * 100.0
        p = res["probabilities"]

        print(f"\n--> Result: [{threat:<10}] | Confidence: {conf:>5.1f}% | Latency: {res['latency_ms']:.2f}ms")
        print(f"    Probabilities : Benign={p['benign']*100:.1f}% | DGA={p['dga']*100:.1f}% | Tunnel={p['dns_tunnel']*100:.1f}%")
        print(f"    Features      : Entropy={res['entropy']:.2f} | Subdomain Depth={res['subdomain_depth']}")

        if show_alert:
            probs_arr = np.array([p["benign"], p["dga"], p["dns_tunnel"]])
            alert_json = generate_sih_alert(res["domain"], probs_arr)
            print("\n--- SIH26145 Security Alert ---")
            print(alert_json)
        print()


def main():
    parser = argparse.ArgumentParser(description="Char-CNN v4 Prediction & Accuracy Checker")
    parser.add_argument("domain", nargs="?", default=None, help="Domain name to evaluate")
    parser.add_argument("-i", "--interactive", action="store_true", help="Start interactive CLI session")
    parser.add_argument("--test-suite", action="store_true", help="Run full evaluation test suite")
    parser.add_argument("--holdout", type=int, nargs="?", const=1000, default=None,
                        help="Evaluate N random holdout domains from data/test.csv (default: 1000, pass 0 for all)")
    parser.add_argument("--alert", action="store_true", help="Also print the SIH26145 JSON alert")
    parser.add_argument("--argmax", action="store_true", help="Force raw argmax classification instead of calibrated thresholds")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[PREDICT] Loading model onto device: {device}...")
    model, temp_scaler, feat_mean, feat_std, cfg = load_model_and_artifacts(device=device)

    thresholds = None
    if not args.argmax:
        thresholds = load_thresholds("outputs/thresholds.json")
        if thresholds.get("use_thresholds"):
            print(f"[PREDICT] Using calibrated thresholds: DGA={thresholds['dga_threshold']:.3f}, Tunnel={thresholds['tunnel_threshold']:.3f}")

    if args.domain:
        res = predict_domain(args.domain, model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)
        print("\n" + "=" * 60)
        print(f"INFERENCE RESULT: {res['domain']}")
        print("=" * 60)
        print(f"Predicted Threat Class : {res['predicted_label'].upper()}")
        print(f"Confidence Level       : {res['confidence']*100:.2f}%")
        print(f"Probability [Benign]   : {res['probabilities']['benign']*100:.2f}%")
        print(f"Probability [DGA]      : {res['probabilities']['dga']*100:.2f}%")
        print(f"Probability [Tunnel]   : {res['probabilities']['dns_tunnel']*100:.2f}%")
        print(f"Shannon Entropy        : {res['entropy']:.4f}")
        print(f"Subdomain Depth        : {res['subdomain_depth']}")
        print(f"Inference Latency      : {res['latency_ms']:.3f} ms")

        if args.alert:
            probs_arr = np.array([
                res["probabilities"]["benign"],
                res["probabilities"]["dga"],
                res["probabilities"]["dns_tunnel"]
            ])
            alert_json = generate_sih_alert(res["domain"], probs_arr)
            print("\n--- SIH26145 Compliant JSON Alert ---")
            print(alert_json)
        print("=" * 60)

    elif args.test_suite:
        run_test_suite(model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)

    elif args.holdout is not None:
        run_holdout_eval(model, temp_scaler, feat_mean, feat_std, cfg, device, n_samples=args.holdout, thresholds=thresholds)

    else:
        interactive_loop(model, temp_scaler, feat_mean, feat_std, cfg, device, thresholds=thresholds)


if __name__ == "__main__":
    main()
