"""
Char-CNN v4 — Main Entry Point
=================================
Orchestrates the full pipeline:
  1. Load & validate data
  2. Group-aware leak-free splitting
  3. Feature standardisation & dataset creation
  4. Model instantiation
  5. Training with Focal Loss + AMP + OneCycleLR + early stopping
  6. Temperature scaling calibration
  7. Test evaluation + confusion matrix
  8. 2D threshold optimisation
  9. Inference benchmarking
  10. SIH alert generation demo

Usage:
  python main.py                          # default config
  python main.py --data data/dataset.csv  # custom data path
  python main.py --demo                   # run with synthetic data
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from alert import generate_sih_alert
from calibration import TemperatureScaler
from config import LABEL2IDX, IDX2LABEL, TrainingConfig, VOCAB_CHARS, CHAR2IDX
from dataset import DNSDomainDataset, compute_feature_stats, load_csv
from evaluate import benchmark_inference, evaluate_model, optimise_thresholds
from model import HybridNet_v4
from splitter import split_data
from train import run_training


# ──────────────────────────────────────────────
# Synthetic demo data generator
# ──────────────────────────────────────────────

def generate_synthetic_data(n_per_class: int = 2000, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic domain data for demonstration / smoke testing.

    Creates three distinct distribution patterns:
      - benign:     natural-looking domains (short, low entropy)
      - dga:        random alphanumeric strings (high entropy)
      - dns_tunnel: long subdomain chains with hex-encoded payloads
    """
    rng = np.random.default_rng(seed)
    rows = []

    # ── Benign domains ────────────────────────
    tlds = ["com", "org", "net", "io", "co.uk", "edu"]
    words = [
        "google", "amazon", "github", "stackoverflow", "wikipedia",
        "microsoft", "apple", "netflix", "spotify", "reddit",
        "facebook", "twitter", "linkedin", "medium", "dropbox",
        "slack", "zoom", "notion", "figma", "canva",
        "cloudflare", "fastly", "akamai", "vercel", "netlify",
        "shopify", "stripe", "paypal", "square", "plaid",
    ]
    for _ in range(n_per_class):
        word = rng.choice(words)
        tld = rng.choice(tlds)
        sub = ""
        if rng.random() < 0.3:
            sub = rng.choice(["www.", "mail.", "api.", "cdn.", "blog."])
        rows.append({"domain": f"{sub}{word}.{tld}", "label": "benign"})

    # ── DGA domains ───────────────────────────
    for _ in range(n_per_class):
        length = rng.integers(8, 32)
        charset = list("abcdefghijklmnopqrstuvwxyz0123456789")
        name = "".join(rng.choice(charset, size=length))
        tld = rng.choice(["com", "net", "org", "xyz", "top", "info", "biz"])
        rows.append({"domain": f"{name}.{tld}", "label": "dga"})

    # ── DNS Tunnel domains ────────────────────
    for _ in range(n_per_class):
        # Simulate hex-encoded payload subdomains
        n_subs = rng.integers(3, 8)
        subs = []
        for _ in range(n_subs):
            sub_len = rng.integers(4, 16)
            sub = "".join(rng.choice(list("0123456789abcdef"), size=sub_len))
            subs.append(sub)
        base = rng.choice(["c2server.com", "exfil.net", "tunnel.org",
                           "dnstun.xyz", "covertch.info"])
        domain = ".".join(subs) + "." + base
        rows.append({"domain": domain, "label": "dns_tunnel"})

    df = pd.DataFrame(rows)
    print(f"[SYNTH] Generated {len(df):,} synthetic samples")
    return df


# ──────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Char-CNN v4 — DNS Threat Detection Engine (SIH26145)"
    )
    parser.add_argument(
        "--data", type=str, default=None,
        help="Path to CSV dataset (columns: domain, label)."
    )
    parser.add_argument(
        "--domain-col", type=str, default="domain",
        help="Name of the domain column in the CSV."
    )
    parser.add_argument(
        "--label-col", type=str, default="label",
        help="Name of the label column in the CSV."
    )
    parser.add_argument(
        "--group-col", type=str, default=None,
        help="Optional grouping column for leak-free splits."
    )
    parser.add_argument(
        "--epochs", type=int, default=30,
        help="Number of training epochs."
    )
    parser.add_argument(
        "--batch-size", type=int, default=512,
        help="Training batch size."
    )
    parser.add_argument(
        "--lr", type=float, default=3e-3,
        help="Peak learning rate."
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run with synthetic data for smoke testing."
    )
    parser.add_argument(
        "--output-dir", type=str, default="outputs",
        help="Directory for model checkpoints and plots."
    )
    parser.add_argument(
        "--resume", type=str, nargs="?", const="auto",
        help="Resume training from a checkpoint. Pass a path, or just "
             "--resume to auto-detect from output-dir."
    )
    parser.add_argument(
        "--eval-only", action="store_true",
        help="Skip training and run evaluation/benchmarking directly from checkpoint."
    )
    args = parser.parse_args()

    # ── Config ────────────────────────────────
    cfg = TrainingConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        output_dir=args.output_dir,
        model_save_path=os.path.join(args.output_dir, "hybridnet_v4_best.pt"),
        calibrated_model_path=os.path.join(args.output_dir, "hybridnet_v4_calibrated.pt"),
    )
    if args.group_col:
        cfg.group_col = args.group_col

    # ── Device ────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[MAIN] Device: {device}")
    if device.type == "cuda":
        print(f"[MAIN] GPU: {torch.cuda.get_device_name(0)}")

    # ── Vocabulary sanity check (v4 fix) ─────
    assert "." in CHAR2IDX, "CRITICAL: Dot (.) missing from vocabulary!"
    print(f"[MAIN] Vocabulary size: {len(CHAR2IDX)+2} (incl. PAD, UNK)")
    print(f"[MAIN] Dot token ID: {CHAR2IDX['.']}")

    # ── Load data ─────────────────────────────
    cal_loader = None
    if args.demo:
        df = generate_synthetic_data()
        df["label_id"] = df["label"].map(LABEL2IDX)
        train_df, val_df, test_df = split_data(
            df,
            domain_col=args.domain_col,
            label_col="label_id",
            group_col=args.group_col or cfg.group_col,
            test_size=cfg.test_size,
            val_size=cfg.val_size,
            random_seed=cfg.random_seed,
        )
        feat_mean, feat_std = compute_feature_stats(train_df[args.domain_col].values)
    elif args.data is not None and not os.path.isfile("data/train.csv"):
        df = load_csv(
            args.data,
            domain_col=args.domain_col,
            label_col=args.label_col,
            group_col=args.group_col,
        )
        train_df, val_df, test_df = split_data(
            df,
            domain_col=args.domain_col,
            label_col="label_id",
            group_col=args.group_col or cfg.group_col,
            test_size=cfg.test_size,
            val_size=cfg.val_size,
            random_seed=cfg.random_seed,
        )
        feat_mean, feat_std = compute_feature_stats(train_df[args.domain_col].values)
    else:
        print("[MAIN] Loading pre-split leak-free datasets from data/...")
        train_df = load_csv("data/train.csv", domain_col="domain", label_col="label")
        val_df = load_csv("data/val.csv", domain_col="domain", label_col="label")
        cal_df = load_csv("data/calibration.csv", domain_col="domain", label_col="label")
        test_df = load_csv("data/test.csv", domain_col="domain", label_col="label")

        if os.path.isfile("outputs/feature_stats.npz"):
            stats = np.load("outputs/feature_stats.npz")
            feat_mean, feat_std = stats["mean"], stats["std"]
        else:
            feat_mean, feat_std = compute_feature_stats(train_df["domain"].values)

        cal_ds = DNSDomainDataset(
            cal_df["domain"].values,
            cal_df["label_id"].values,
            max_len=cfg.max_len,
            feat_mean=feat_mean,
            feat_std=feat_std,
        )
        cal_loader = DataLoader(
            cal_ds, batch_size=cfg.batch_size, shuffle=False,
            num_workers=0, pin_memory=False,
        )

    print(f"[MAIN] Feature means (18-feat): {np.round(feat_mean[:6], 3)}...")
    print(f"[MAIN] Feature stds  (18-feat): {np.round(feat_std[:6], 3)}...")

    from evidence_features import FEATURE_NAMES_EXTENDED
    label_feature_indices = [10, 11, 12]  # n_labels, max_label_len, mean_label_len
    for idx in label_feature_indices:
        if feat_std[idx] < 1e-8:
            print(
                f"[WARNING] Feature '{FEATURE_NAMES_EXTENDED[idx]}' has zero variance!"
            )
        else:
            print(
                f"[MAIN] [OK] Feature '{FEATURE_NAMES_EXTENDED[idx]}' is ALIVE "
                f"(std={feat_std[idx]:.4f})"
            )

    # ── Datasets & loaders ───────────────────
    train_domain_col = args.domain_col if args.domain_col in train_df.columns else "domain"
    val_domain_col = args.domain_col if args.domain_col in val_df.columns else "domain"
    test_domain_col = args.domain_col if args.domain_col in test_df.columns else "domain"

    train_ds = DNSDomainDataset(
        train_df[train_domain_col].values,
        train_df["label_id"].values,
        max_len=cfg.max_len,
        feat_mean=feat_mean,
        feat_std=feat_std,
    )
    val_ds = DNSDomainDataset(
        val_df[val_domain_col].values,
        val_df["label_id"].values,
        max_len=cfg.max_len,
        feat_mean=feat_mean,
        feat_std=feat_std,
    )
    test_ds = DNSDomainDataset(
        test_df[test_domain_col].values,
        test_df["label_id"].values,
        max_len=cfg.max_len,
        feat_mean=feat_mean,
        feat_std=feat_std,
    )

    train_loader = DataLoader(
        train_ds, batch_size=cfg.batch_size, shuffle=True,
        num_workers=0, pin_memory=False, drop_last=False,
    )
    val_loader = DataLoader(
        val_ds, batch_size=cfg.batch_size, shuffle=False,
        num_workers=0, pin_memory=False,
    )
    test_loader = DataLoader(
        test_ds, batch_size=cfg.batch_size, shuffle=False,
        num_workers=0, pin_memory=False,
    )

    # ── Model ─────────────────────────────────
    model = HybridNet_v4(cfg)
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"[MAIN] HybridNet_v4 -- {n_params:,} trainable parameters")

    # ── Resolve resume checkpoint path ──────
    resume_path = None
    if args.resume:
        if args.resume == "auto":
            resume_path = cfg.model_save_path
        else:
            resume_path = args.resume
        if os.path.isfile(resume_path):
            print(f"[MAIN] Will resume from: {resume_path}")
        else:
            print(f"[MAIN] WARNING: Resume checkpoint not found at {resume_path}")
            resume_path = None

    # ── Train or Eval-Only ────────────────────
    if args.eval_only:
        ckpt_path = resume_path or cfg.model_save_path
        if not os.path.isfile(ckpt_path):
            raise FileNotFoundError(f"Checkpoint not found at {ckpt_path}")
        print(f"[MAIN] Skipping training (--eval-only). Loading: {ckpt_path}")
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()

        temp_scaler = TemperatureScaler().to(device)
        if os.path.isfile(cfg.calibrated_model_path):
            print(f"[MAIN] Loading calibrated scaler from {cfg.calibrated_model_path}")
            cal_ckpt = torch.load(cfg.calibrated_model_path, map_location=device, weights_only=False)
            temp_scaler.temperature.data.fill_(cal_ckpt.get("temperature", 1.0))
        else:
            temp_scaler.calibrate(model, val_loader, device)
        history = ckpt.get("history", {})
    else:
        model, temp_scaler, history = run_training(
            model, train_loader, val_loader,
            train_labels=train_df["label_id"].values,
            cfg=cfg, device=device,
            resume_checkpoint=resume_path,
            cal_loader=cal_loader,
        )

    # ── Test evaluation ──────────────────────
    print("\n" + "=" * 60)
    print("TEST SET EVALUATION")
    print("=" * 60)
    all_labels, all_preds, all_probs = evaluate_model(
        model, test_loader, device,
        scaler=temp_scaler,
        output_dir=cfg.output_dir,
    )

    # ── Threshold optimisation ───────────────
    print("\n" + "=" * 60)
    print("THRESHOLD OPTIMISATION (2D Grid Search)")
    print("=" * 60)
    thresh_result = optimise_thresholds(all_labels, all_probs)

    # Save threshold config
    thresh_path = os.path.join(cfg.output_dir, "thresholds.json")
    with open(thresh_path, "w") as f:
        json.dump(thresh_result, f, indent=2)
    print(f"[MAIN] Thresholds saved -> {thresh_path}")

    # ── Inference benchmarking ───────────────
    print("\n" + "=" * 60)
    print("INFERENCE BENCHMARKING")
    print("=" * 60)
    bench_results = benchmark_inference(
        model, device,
        max_len=cfg.max_len,
        num_lexical_feats=cfg.num_lexical_features,
        scaler=temp_scaler,
    )

    bench_path = os.path.join(cfg.output_dir, "benchmark_results.json")
    with open(bench_path, "w") as f:
        json.dump(bench_results, f, indent=2)
    print(f"[MAIN] Benchmark results saved -> {bench_path}")

    # ── SIH Alert demo ──────────────────────
    print("\n" + "=" * 60)
    print("SIH ALERT SERIALIZATION DEMO")
    print("=" * 60)

    demo_domains = [
        "www.google.com",
        "a8f3kd92mxp1.xyz",
        "4f2a.b8c1.d9e3.f0a2.7b6c.exfil.net",
    ]

    for domain in demo_domains:
        from preprocess import tokenize_domain, clean_query_name
        from evidence_features import extract_features_vector as elf

        cleaned = clean_query_name(domain)
        tokens = torch.from_numpy(
            tokenize_domain(cleaned, cfg.max_len)
        ).unsqueeze(0).to(device)

        raw_feats = elf(cleaned)
        safe_std = np.where(feat_std < 1e-8, 1.0, feat_std)
        normed_feats = (raw_feats - feat_mean) / safe_std
        feats_t = torch.from_numpy(normed_feats).float().unsqueeze(0).to(device)

        model.eval()
        temp_scaler.eval()
        with torch.no_grad():
            logits = model(tokens, feats_t)
            scaled_logits = temp_scaler(logits)
            probs = torch.softmax(scaled_logits, dim=1).cpu().numpy()[0]

        alert_json = generate_sih_alert(domain, probs)
        print(f"\n--- Alert for: {domain} ---")
        print(alert_json)

    # ── Save feature statistics ──────────────
    np.savez(
        os.path.join(cfg.output_dir, "feature_stats.npz"),
        mean=feat_mean,
        std=feat_std,
    )

    print("\n" + "=" * 60)
    print("[DONE] PIPELINE COMPLETE -- Char-CNN v4 (SIH26145)")
    print("=" * 60)


if __name__ == "__main__":
    main()
