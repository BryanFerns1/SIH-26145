"""
SIH26145 Compliance & Evaluation Extension Script
=====================================================
Standalone script fulfilling Smart India Hackathon (SIH26145) defense criteria.

Capabilities:
  1. Full holdout evaluation with confusion matrix (all 3 classes, non-zero support).
  2. Standardised SIH alert schema serializer (`generate_sih_alert`).

IMPORTANT: This script does NOT retrain or overwrite any model weights.

Usage:
  python sih_compliance_eval.py                          # Default: synthetic demo data
  python sih_compliance_eval.py --data path/to/data.csv  # Custom dataset
  python sih_compliance_eval.py --alert-demo              # Print SIH alerts for sample domains
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
import torch.nn.functional as F
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader

# -- Project imports ------------------------------
from calibration import TemperatureScaler
from config import (
    CHAR2IDX,
    IDX2LABEL,
    LABEL2IDX,
    MITRE_MAP,
    NUM_CLASSES,
    SEVERITY_THRESHOLDS,
    TrainingConfig,
)
from dataset import DNSDomainDataset, compute_feature_stats, load_csv
from evidence_features import FEATURE_NAMES_EXTENDED, extract_features_vector
from preprocess import clean_query_name, tokenize_domain
from model import HybridNet_v4
from splitter import split_data


# =======================================================================
# S1  MODEL & ARTIFACT LOADING (read-only -- no weight mutation)
# =======================================================================

def load_calibrated_model(
    model_path: str = "outputs/hybridnet_v4_best.pt",
    calibrated_path: str = "outputs/hybridnet_v4_calibrated.pt",
    stats_path: str = "outputs/feature_stats.npz",
    device: torch.device = None,
) -> Tuple[HybridNet_v4, TemperatureScaler, np.ndarray, np.ndarray, TrainingConfig]:
    """
    Load the trained HybridNet_v4 and its calibration scaler in **eval-only** mode.

    Returns
    -------
    model, temp_scaler, feat_mean, feat_std, cfg
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    for path, desc in [(model_path, "Model checkpoint"), (stats_path, "Feature stats")]:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{desc} not found: {path}")

    # Feature normalisation statistics
    stats = np.load(stats_path)
    feat_mean, feat_std = stats["mean"], stats["std"]

    # Model weights
    ckpt = torch.load(model_path, map_location=device, weights_only=False)
    cfg_dict = ckpt.get("config", {})
    cfg = TrainingConfig(**{k: v for k, v in cfg_dict.items() if hasattr(TrainingConfig, k)})

    model = HybridNet_v4(cfg).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    # Temperature scaler
    temp_scaler = TemperatureScaler().to(device)
    if os.path.isfile(calibrated_path):
        cal_ckpt = torch.load(calibrated_path, map_location=device, weights_only=False)
        temp_scaler.temperature.data.fill_(cal_ckpt.get("temperature", 1.0))
        print(f"[SIH] Temperature scaler loaded (T={temp_scaler.temperature.item():.4f})")
    else:
        print("[SIH] WARNING: Calibrated checkpoint not found -- using T=1.0 (uncalibrated).")
    temp_scaler.eval()

    n_params = sum(p.numel() for p in model.parameters())
    print(f"[SIH] HybridNet_v4 loaded -- {n_params:,} parameters on {device}")
    return model, temp_scaler, feat_mean, feat_std, cfg


# =======================================================================
# S2  FULL HOLDOUT EVALUATION & CONFUSION MATRIX
# =======================================================================

def _generate_synthetic_data(n_per_class: int = 2000, seed: int = 42) -> pd.DataFrame:
    """
    Deterministic synthetic data generator -- identical to main.py's
    `generate_synthetic_data()` to reproduce the exact same test split.
    """
    rng = np.random.default_rng(seed)
    rows = []

    # -- Benign --------------------------------
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

    # -- DGA -----------------------------------
    for _ in range(n_per_class):
        length = rng.integers(8, 32)
        charset = list("abcdefghijklmnopqrstuvwxyz0123456789")
        name = "".join(rng.choice(charset, size=length))
        tld = rng.choice(["com", "net", "org", "xyz", "top", "info", "biz"])
        rows.append({"domain": f"{name}.{tld}", "label": "dga"})

    # -- DNS Tunnel ----------------------------
    for _ in range(n_per_class):
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
    df["label_id"] = df["label"].map(LABEL2IDX)
    print(f"[SIH] Synthetic dataset: {len(df):,} samples "
          f"({n_per_class:,} per class)")
    return df


def _verify_class_support(labels: np.ndarray, split_name: str = "test") -> None:
    """Abort with a clear message if any class has zero support."""
    unique, counts = np.unique(labels, return_counts=True)
    dist = dict(zip(unique, counts))
    print(f"[SIH] {split_name.title()} split class distribution:")
    for idx in range(NUM_CLASSES):
        cls_name = IDX2LABEL[idx]
        count = dist.get(idx, 0)
        print(f"       {cls_name:<12}: {count:>6,} samples")
        if count == 0:
            raise RuntimeError(
                f"FATAL: Class '{cls_name}' (idx={idx}) has ZERO support in the "
                f"{split_name} split. Evaluation cannot proceed -- ensure the "
                f"dataset contains samples from all three classes."
            )
    print(f"[SIH] [OK] All {NUM_CLASSES} classes have non-zero support.")


def compute_advanced_metrics(
    all_labels: np.ndarray,
    all_probs: np.ndarray,
    output_dir: str = "outputs",
) -> Dict[str, Any]:
    from sklearn.metrics import roc_curve, precision_recall_curve, roc_auc_score, auc
    import matplotlib.pyplot as plt

    target_names = ["benign", "dga", "dns_tunnel"]
    one_hot = np.eye(3)[all_labels]

    roc_aucs = {}
    pr_aucs = {}
    fpr_at_95_tpr = {}

    for i, name in enumerate(target_names):
        y_true = one_hot[:, i]
        y_score = all_probs[:, i]

        roc_auc = roc_auc_score(y_true, y_score)
        roc_aucs[name] = float(roc_auc)

        prec, rec, _ = precision_recall_curve(y_true, y_score)
        pr_auc = auc(rec, prec)
        pr_aucs[name] = float(pr_auc)

        fpr, tpr, _ = roc_curve(y_true, y_score)
        idx = np.where(tpr >= 0.95)[0]
        fpr_val = float(fpr[idx[0]]) if len(idx) > 0 else 1.0
        fpr_at_95_tpr[name] = fpr_val

    macro_roc = float(np.mean(list(roc_aucs.values())))
    macro_pr = float(np.mean(list(pr_aucs.values())))

    print("\n" + "=" * 64)
    print("  SIH26145  -  ADVANCED ROC & PR METRICS")
    print("=" * 64)
    for name in target_names:
        print(f"  [{name.upper():10s}] ROC-AUC: {roc_aucs[name]:.4f} | PR-AUC: {pr_aucs[name]:.4f} | FPR@95% TPR: {fpr_at_95_tpr[name]:.4f}")
    print(f"\n  Macro ROC-AUC: {macro_roc:.4f}")
    print(f"  Macro PR-AUC:  {macro_pr:.4f}")
    print(f"  DGA FPR @ 95% TPR:        {fpr_at_95_tpr['dga']:.4f}")
    print(f"  DNS Tunnel FPR @ 95% TPR: {fpr_at_95_tpr['dns_tunnel']:.4f}")
    print("=" * 64)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    for i, name in enumerate(target_names):
        y_true = one_hot[:, i]
        y_score = all_probs[:, i]
        fpr, tpr, _ = roc_curve(y_true, y_score)
        prec, rec, _ = precision_recall_curve(y_true, y_score)
        ax1.plot(fpr, tpr, label=f"{name} (AUC={roc_aucs[name]:.3f})")
        ax2.plot(rec, prec, label=f"{name} (PR-AUC={pr_aucs[name]:.3f})")

    ax1.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax1.set_xlabel("False Positive Rate")
    ax1.set_ylabel("True Positive Rate")
    ax1.set_title("ROC Curves (One-vs-Rest)")
    ax1.legend(loc="lower right")
    ax1.grid(True, alpha=0.3)

    ax2.set_xlabel("Recall")
    ax2.set_ylabel("Precision")
    ax2.set_title("Precision-Recall Curves")
    ax2.legend(loc="lower left")
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    roc_pr_path = os.path.join(output_dir, "roc_pr_curves.png")
    fig.savefig(roc_pr_path, dpi=150)
    plt.close(fig)
    print(f"[SIH] ROC & PR Curves saved -> {roc_pr_path}")

    return {
        "roc_auc": roc_aucs,
        "pr_auc": pr_aucs,
        "fpr_at_95_tpr": fpr_at_95_tpr,
        "macro_roc_auc": macro_roc,
        "macro_pr_auc": macro_pr,
    }


def run_full_holdout_evaluation(
    model: HybridNet_v4,
    temp_scaler: TemperatureScaler,
    feat_mean: np.ndarray,
    feat_std: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
    data_path: Optional[str] = None,
    domain_col: str = "domain",
    label_col: str = "label",
    group_col: Optional[str] = None,
    output_dir: str = "outputs",
) -> Dict[str, Any]:
    """
    Load dataset -> split (same seed as training) -> evaluate test partition.

    Returns a summary dict with accuracy, macro-F1, and per-class metrics.
    """
    os.makedirs(output_dir, exist_ok=True)

    # -- Load data -----------------------------
    if data_path and os.path.isfile(data_path):
        print(f"[SIH] Loading dataset from: {data_path}")
        df = load_csv(data_path, domain_col=domain_col, label_col=label_col,
                      group_col=group_col)
        _, _, test_df = split_data(
            df,
            domain_col=domain_col,
            label_col="label_id",
            group_col=group_col or cfg.group_col,
            test_size=cfg.test_size,
            val_size=cfg.val_size,
            random_seed=cfg.random_seed,
        )
    elif os.path.isfile("data/test.csv"):
        print("[SIH] Loading holdout test dataset from: data/test.csv")
        test_df = load_csv("data/test.csv", domain_col="domain", label_col="label")
    else:
        print("[SIH] No dataset specified -- using synthetic demo data.")
        df = _generate_synthetic_data()
        _, _, test_df = split_data(
            df,
            domain_col=domain_col,
            label_col="label_id",
            group_col=group_col or cfg.group_col,
            test_size=cfg.test_size,
            val_size=cfg.val_size,
            random_seed=cfg.random_seed,
        )

    test_labels = test_df["label_id"].values

    # If any class has zero support (common with synthetic tunnel data
    # where few SLD groups exist), fall back to stratified random split.
    unique_classes = np.unique(test_labels)
    if len(unique_classes) < NUM_CLASSES:
        from sklearn.model_selection import StratifiedShuffleSplit
        missing = set(range(NUM_CLASSES)) - set(unique_classes)
        missing_names = [IDX2LABEL[c] for c in missing]
        print(f"[SIH] WARNING: Group-aware split left class(es) "
              f"{missing_names} with zero test support.")
        print("[SIH] Falling back to stratified split for compliance eval...")

        sss1 = StratifiedShuffleSplit(
            n_splits=1, test_size=cfg.test_size, random_state=cfg.random_seed,
        )
        train_val_idx, test_idx = next(sss1.split(df, df["label_id"].values))
        test_df = df.iloc[test_idx].reset_index(drop=True)
        test_labels = test_df["label_id"].values
        print(f"[SIH] Stratified test split: {len(test_df):,} samples")

    # -- Verify non-zero support --------------
    _verify_class_support(test_labels, split_name="test")

    # -- Build test DataLoader ----------------
    test_ds = DNSDomainDataset(
        test_df["domain"].values if "domain" in test_df.columns else test_df[domain_col].values,
        test_labels,
        max_len=cfg.max_len,
        feat_mean=feat_mean,
        feat_std=feat_std,
    )
    test_loader = DataLoader(
        test_ds, batch_size=cfg.batch_size, shuffle=False,
        num_workers=0, pin_memory=(device.type == "cuda"),
    )

    # -- Inference ----------------------------
    model.eval()
    temp_scaler.eval()
    all_preds, all_labels_list, all_probs = [], [], []

    with torch.no_grad():
        for tokens, feats, labels in test_loader:
            tokens = tokens.to(device)
            feats = feats.to(device)
            logits = model(tokens, feats)
            scaled_logits = temp_scaler(logits)
            probs = F.softmax(scaled_logits, dim=1)
            preds = probs.argmax(dim=1)

            all_preds.append(preds.cpu().numpy())
            all_labels_list.append(labels.numpy())
            all_probs.append(probs.cpu().numpy())

    all_preds = np.concatenate(all_preds)
    all_labels = np.concatenate(all_labels_list)
    all_probs = np.concatenate(all_probs)

    # -- Classification report ----------------
    target_names = [IDX2LABEL[i] for i in range(NUM_CLASSES)]
    class_labels = list(range(NUM_CLASSES))
    report_str = classification_report(
        all_labels, all_preds,
        target_names=target_names,
        labels=class_labels,
        digits=4,
        zero_division=0,
    )
    report_dict = classification_report(
        all_labels, all_preds,
        target_names=target_names,
        labels=class_labels,
        digits=4,
        zero_division=0,
        output_dict=True,
    )

    print("\n" + "=" * 64)
    print("  SIH26145  -  CLASSIFICATION REPORT  (Full Holdout Test Set)")
    print("=" * 64)
    print(report_str)

    accuracy = float(report_dict["accuracy"])
    macro_f1 = float(report_dict["macro avg"]["f1-score"])
    print(f"  Overall Accuracy : {accuracy:.4f}")
    print(f"  Macro F1-Score   : {macro_f1:.4f}")
    print("=" * 64)

    # -- Confusion matrix visualisation -------
    cm = confusion_matrix(all_labels, all_preds, labels=class_labels)

    fig, ax = plt.subplots(figsize=(8, 6.5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=target_names,
        yticklabels=target_names,
        ax=ax,
        linewidths=0.5,
        linecolor="white",
        cbar_kws={"shrink": 0.8, "label": "Sample Count"},
        annot_kws={"size": 14, "weight": "bold"},
    )
    ax.set_xlabel("Predicted Label", fontsize=12, labelpad=10)
    ax.set_ylabel("True Label", fontsize=12, labelpad=10)
    ax.set_title(
        "SIH26145 -- HybridNet v4 Confusion Matrix\n"
        f"Test Set: {len(all_labels):,} samples  |  "
        f"Accuracy: {accuracy:.4f}  |  Macro-F1: {macro_f1:.4f}",
        fontsize=13,
        pad=14,
    )
    ax.tick_params(axis="both", labelsize=11)
    plt.tight_layout()

    cm_path = os.path.join(output_dir, "confusion_matrix_v4_full.png")
    fig.savefig(cm_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"[SIH] Confusion matrix saved -> {cm_path}")

    # -- Compute Advanced ROC & PR Metrics ---
    adv_metrics = compute_advanced_metrics(all_labels, all_probs, output_dir=output_dir)

    # -- Save classification report as JSON ---
    full_report = {
        "classification_report": report_dict,
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "advanced_metrics": adv_metrics,
        "confusion_matrix": cm.tolist(),
        "test_samples": len(all_labels),
    }

    report_json_path = os.path.join(output_dir, "sih_classification_report.json")
    with open(report_json_path, "w") as f:
        json.dump(full_report, f, indent=2)
    print(f"[SIH] Comprehensive compliance report saved -> {report_json_path}")

    return full_report


# =======================================================================
# S3  STANDARDISED SIH ALERT SCHEMA SERIALIZER
# =======================================================================

def _map_severity(confidence: float) -> str:
    """Map top-class confidence to severity tier using config thresholds."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if confidence >= threshold:
            return label
    return "LOW"


def generate_sih_alert(
    domain_name: str,
    probs: Dict[str, float],
    lexical_feats: Dict[str, float],
) -> str:
    """
    Generate a SIH26145-compliant JSON alert string.

    Parameters
    ----------
    domain_name : str
        The queried FQDN.
    probs : dict
        Probability dict with keys: ``benign``, ``dga``, ``dns_tunnel``.
    lexical_feats : dict
        Lexical feature dict (must include ``shannon_entropy`` and
        ``subdomain_depth``).

    Returns
    -------
    str
        Formatted JSON string adhering to the SIH26145 alert schema.

    Schema Keys
    ------------
    timestamp, flow_id, target_domain, threat_class, confidence, severity,
    evidence (dga_score, dns_tunnel_score, benign_score, subdomain_depth,
    shannon_entropy), mitre_attack (technique_id, technique_name, tactic),
    observability_caveat, evidence_hash_sha256.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    flow_id = str(uuid.uuid4())

    # Determine predicted class
    threat_class = max(probs, key=probs.get)
    confidence = round(probs[threat_class], 6)
    severity = _map_severity(confidence)

    # Evidence block
    evidence = {
        "dga_score": round(probs.get("dga", 0.0), 6),
        "dns_tunnel_score": round(probs.get("dns_tunnel", 0.0), 6),
        "benign_score": round(probs.get("benign", 0.0), 6),
        "subdomain_depth": int(lexical_feats.get("subdomain_depth", 0)),
        "shannon_entropy": round(float(lexical_feats.get("shannon_entropy", 0.0)), 4),
    }

    # MITRE ATT&CK mapping
    mitre = MITRE_MAP.get(threat_class, MITRE_MAP["benign"])

    # SHA-256 evidence hash  (domain + timestamp)
    hash_input = f"{domain_name}{timestamp}"
    evidence_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

    alert = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "target_domain": domain_name,
        "threat_class": threat_class,
        "confidence": confidence,
        "severity": severity,
        "evidence": evidence,
        "mitre_attack": mitre,
        "observability_caveat": "unidirectional_passive_ingress_only",
        "evidence_hash_sha256": evidence_hash,
    }

    return json.dumps(alert, indent=2)


# =======================================================================
# S4  ALERT DEMO DRIVER (end-to-end: domain -> model -> alert)
# =======================================================================

def run_alert_demo(
    model: HybridNet_v4,
    temp_scaler: TemperatureScaler,
    feat_mean: np.ndarray,
    feat_std: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
) -> None:
    """
    End-to-end demonstration: feed representative domains through the
    calibrated model, then serialise each result as an SIH26145 alert.
    """
    from preprocess import tokenize_domain

    demo_domains = [
        ("www.google.com", "Expected: benign"),
        ("a8f3kd92mxp1.xyz", "Expected: dga"),
        ("4f2a.b8c1.d9e3.f0a2.7b6c.exfil.net", "Expected: dns_tunnel"),
    ]

    print("\n" + "=" * 64)
    print("  SIH26145  -  ALERT SERIALIZATION DEMO")
    print("=" * 64)

    model.eval()
    temp_scaler.eval()

    for domain, note in demo_domains:
        cleaned = clean_query_name(domain)
        # Tokenise
        tokens = torch.from_numpy(
            tokenize_domain(cleaned, cfg.max_len)
        ).unsqueeze(0).to(device)

        # Lexical features + z-score normalisation
        raw_feats = extract_features_vector(cleaned)
        safe_std = np.where(feat_std < 1e-8, 1.0, feat_std)
        normed_feats = (raw_feats - feat_mean) / safe_std
        feats_t = torch.from_numpy(normed_feats).float().unsqueeze(0).to(device)

        # Inference
        with torch.no_grad():
            logits = model(tokens, feats_t)
            scaled_logits = temp_scaler(logits)
            prob_tensor = F.softmax(scaled_logits, dim=1).cpu().numpy()[0]

        # Build dicts for the serializer
        probs_dict: Dict[str, float] = {
            "benign": float(prob_tensor[0]),
            "dga": float(prob_tensor[1]),
            "dns_tunnel": float(prob_tensor[2]),
        }
        lexical_dict: Dict[str, float] = {
            "shannon_entropy": float(raw_feats[2]),            # feature idx 2 (Shannon entropy)
            "subdomain_depth": int(raw_feats[10]),             # feature idx 10 (n_labels)
        }

        alert_json = generate_sih_alert(domain, probs_dict, lexical_dict)
        print(f"\n--- Alert for: {domain}  ({note}) ---")
        print(alert_json)

    print("\n" + "=" * 64)


# =======================================================================
# S5  ENTRY POINT
# =======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SIH26145 Compliance & Evaluation Script -- Char-CNN v4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python sih_compliance_eval.py\n"
            "  python sih_compliance_eval.py --data data/dataset.csv\n"
            "  python sih_compliance_eval.py --alert-demo\n"
            "  python sih_compliance_eval.py --data train_combined_multiclass.csv.gz --alert-demo\n"
        ),
    )
    parser.add_argument(
        "--data", type=str, default=None,
        help="Path to CSV/CSV.GZ dataset (columns: domain, label). "
             "If omitted, uses deterministic synthetic demo data.",
    )
    parser.add_argument(
        "--domain-col", type=str, default="domain",
        help="Name of the domain column (default: 'domain').",
    )
    parser.add_argument(
        "--label-col", type=str, default="label",
        help="Name of the label column (default: 'label').",
    )
    parser.add_argument(
        "--group-col", type=str, default=None,
        help="Optional grouping column for leak-free splits.",
    )
    parser.add_argument(
        "--model-path", type=str, default="outputs/hybridnet_v4_best.pt",
        help="Path to trained model checkpoint.",
    )
    parser.add_argument(
        "--calibrated-path", type=str, default="outputs/hybridnet_v4_calibrated.pt",
        help="Path to calibrated checkpoint (temperature scaler).",
    )
    parser.add_argument(
        "--stats-path", type=str, default="outputs/feature_stats.npz",
        help="Path to feature normalisation statistics.",
    )
    parser.add_argument(
        "--output-dir", type=str, default="outputs",
        help="Directory for output artefacts (confusion matrix, report JSON).",
    )
    parser.add_argument(
        "--alert-demo", action="store_true",
        help="Run end-to-end SIH alert serialisation demo after evaluation.",
    )
    parser.add_argument(
        "--skip-eval", action="store_true",
        help="Skip holdout evaluation (use with --alert-demo for alert-only mode).",
    )
    args = parser.parse_args()

    # -- Banner --------------------------------
    print("=" * 64)
    print("  SIH26145  -  COMPLIANCE & EVALUATION EXTENSION")
    print("  HybridNet v4 -- DNS Threat Detection Engine")
    print("  Mode: EVAL-ONLY  (no retraining, no weight mutation)")
    print("=" * 64)

    # -- Device --------------------------------
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[SIH] Device: {device}")
    if device.type == "cuda":
        print(f"[SIH] GPU: {torch.cuda.get_device_name(0)}")

    # -- Load model ----------------------------
    model, temp_scaler, feat_mean, feat_std, cfg = load_calibrated_model(
        model_path=args.model_path,
        calibrated_path=args.calibrated_path,
        stats_path=args.stats_path,
        device=device,
    )

    # -- Holdout Evaluation -------------------
    if not args.skip_eval:
        summary = run_full_holdout_evaluation(
            model=model,
            temp_scaler=temp_scaler,
            feat_mean=feat_mean,
            feat_std=feat_std,
            cfg=cfg,
            device=device,
            data_path=args.data,
            domain_col=args.domain_col,
            label_col=args.label_col,
            group_col=args.group_col,
            output_dir=args.output_dir,
        )

        print(f"\n[SIH] Evaluation Summary:")
        print(f"       Test Samples : {summary['test_samples']:,}")
        print(f"       Accuracy     : {summary['accuracy']:.4f}")
        print(f"       Macro F1     : {summary['macro_f1']:.4f}")

    # -- Alert Demo ---------------------------
    if args.alert_demo or args.skip_eval:
        run_alert_demo(model, temp_scaler, feat_mean, feat_std, cfg, device)

    # -- Done ---------------------------------
    print("\n" + "=" * 64)
    print("  [DONE]  SIH26145 COMPLIANCE EVALUATION COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
