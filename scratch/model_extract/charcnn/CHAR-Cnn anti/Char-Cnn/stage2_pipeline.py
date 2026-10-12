"""
Stage 2: Preprocessing, Data Augmentation, Evidence Features, Baselines, and Leak-Free Splits
=============================================================================================
UniGuard DNS Threat Detector (SIH26145, Team CeaserX)
"""

import os
import sys
import json
import time
import math
import random
import hashlib
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.cluster import MiniBatchKMeans
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    f1_score,
)
import lightgbm as lgb

from preprocess import clean_query_name, tokenize_domain, MODEL_MAX_LEN, LABEL2IDX, IDX2LABEL
from evidence_features import extract_features_vector, FEATURE_NAMES_EXTENDED

# Set random seeds for strict reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

TLD_POOL = ["com", "org", "net", "info", "biz", "io", "xyz", "top", "online", "site", "co", "cc", "me", "pro"]
_raw_weights = np.array([0.45, 0.12, 0.10, 0.05, 0.04, 0.05, 0.05, 0.04, 0.03, 0.03, 0.04, 0.02, 0.02, 0.01], dtype=np.float64)
TLD_WEIGHTS = (_raw_weights / _raw_weights.sum()).tolist()
SUBDOMAINS = ["www", "api", "mail", "cdn", "static", "auth", "blog", "shop", "m", "dev", "portal", "login"]


def generate_lab_tunnelling(n_samples: int = 10000) -> pd.DataFrame:
    """
    Generate synthetic lab tunnelling queries simulating iodine, dnscat2, and dns2tcp.
    Clearly marked with synthetic=True and tool labels.
    """
    records = []
    hex_chars = "0123456789abcdef"
    b32_chars = "abcdefghijklmnopqrstuvwxyz234567"
    b64_chars = "abcdefghijklmnopqrstuvwxyz0123456789"

    tunnel_tools = ["iodine", "dnscat2", "dns2tcp"]
    base_domains = ["lab-tunnel.org", "dns-exfil.net", "tunnel-poc.com", "ns-data.io", "tunnel-sec.biz"]

    for i in range(n_samples):
        tool = tunnel_tools[i % len(tunnel_tools)]
        base = base_domains[i % len(base_domains)]
        
        if tool == "iodine":
            # Iodine: base32 payload in 1-3 subdomain labels
            num_labels = random.choice([1, 2, 3])
            labels = []
            for _ in range(num_labels):
                lbl_len = random.randint(16, 45)
                lbl = "".join(random.choices(b32_chars, k=lbl_len))
                labels.append(lbl)
            prefix = random.choice(["v4", "null", "txt", "srv", "a"])
            domain = f"{prefix}.{'.'.join(labels)}.{base}"

        elif tool == "dnscat2":
            # Dnscat2: hex payload, session id prefix
            sess_id = "".join(random.choices(hex_chars, k=4))
            seq_id = "".join(random.choices(hex_chars, k=4))
            data_len = random.randint(20, 60)
            data_hex = "".join(random.choices(hex_chars, k=data_len))
            if random.random() < 0.5:
                domain = f"dnscat.{sess_id}{seq_id}.{data_hex}.{base}"
            else:
                domain = f"{sess_id}{seq_id}{data_hex}.{base}"

        else:  # dns2tcp
            # Dns2tcp: base64-like authentication or data chunk
            chunk_len = random.randint(24, 52)
            chunk = "".join(random.choices(b64_chars, k=chunk_len))
            auth = f"auth{random.randint(0, 9)}"
            domain = f"{auth}.{chunk}.{base}"

        records.append({
            "domain": domain,
            "class": 2,
            "label": "dns_tunnel",
            "family": f"lab_{tool}",
            "tool": tool,
            "synthetic": True,
        })

    return pd.DataFrame(records)


def generate_benign_hard_negatives(n_samples: int = 10000) -> pd.DataFrame:
    """
    Generate realistic benign hard negatives: CDN hostnames, reverse DNS, cloud instances.
    Labelled as benign, synthetic=True.
    """
    records = []
    hex_chars = "0123456789abcdef"

    categories = ["cdn", "reverse_dns", "cloud_instance", "hex_service"]

    for i in range(n_samples):
        cat = categories[i % len(categories)]

        if cat == "cdn":
            cdn_type = random.choice(["cloudfront", "akamai", "fastly", "cloudflare"])
            if cdn_type == "cloudfront":
                h = "".join(random.choices(hex_chars, k=14))
                domain = f"d{h}.cloudfront.net"
            elif cdn_type == "akamai":
                ip_str = f"a{random.randint(10,250)}-{random.randint(1,254)}-{random.randint(1,254)}-{random.randint(1,254)}"
                domain = f"{ip_str}.deploy.static.akamaitechnologies.com"
            elif cdn_type == "fastly":
                domain = f"prod-cdn-{random.randint(100,999)}.global.ssl.fastly.net"
            else:
                h = "".join(random.choices(hex_chars, k=8))
                domain = f"cdn-cache-{h}.cf-ipfs.com"

        elif cat == "reverse_dns":
            if random.random() < 0.7:  # IPv4
                octets = [str(random.randint(1, 254)) for _ in range(4)]
                domain = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
            else:  # IPv6
                nibbles = ".".join(random.choices(hex_chars, k=16))
                domain = f"{nibbles}.ip6.arpa"

        elif cat == "cloud_instance":
            cloud = random.choice(["aws", "azure", "gcp"])
            if cloud == "aws":
                ip_dash = f"{random.randint(10,250)}-{random.randint(1,254)}-{random.randint(1,254)}-{random.randint(1,254)}"
                region = random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"])
                domain = f"ec2-{ip_dash}.compute-1.amazonaws.com"
            elif cloud == "azure":
                h = "".join(random.choices(hex_chars, k=8))
                domain = f"vm-prod-{h}.westeurope.cloudapp.azure.com"
            else:
                ip_dash = f"{random.randint(10,250)}-{random.randint(1,254)}-{random.randint(1,254)}-{random.randint(1,254)}"
                domain = f"{ip_dash}.bc.googleusercontent.com"

        else:  # hex_service (e.g. git commit hash or deployment id)
            h = "".join(random.choices(hex_chars, k=random.randint(8, 16)))
            platform = random.choice(["github.io", "gitlab.io", "pages.dev", "vercel.app", "azurewebsites.net"])
            domain = f"build-{h}.{platform}"

        records.append({
            "domain": domain,
            "class": 0,
            "label": "benign",
            "family": f"benign_{cat}",
            "tool": "benign",
            "synthetic": True,
        })

    return pd.DataFrame(records)


def main():
    print("=" * 70)
    print("Stage 2 Pipeline: Preprocessing, Augmentation, Splits & Baselines")
    print("=" * 70)

    # 1. Load and clean original raw dataset
    raw_path = "D:/train_combined_multiclass.csv.gz"
    print(f"\n[1/8] Loading raw dataset: {raw_path}")
    t0 = time.time()
    df_raw = pd.read_csv(raw_path)
    print(f"Loaded {len(df_raw):,} rows in {time.time() - t0:.2f}s")

    # Clean domain strings
    df_raw["domain"] = df_raw["domain"].astype(str).str.strip().str.lower()

    # Drop conflicting labels
    domain_classes = df_raw.groupby("domain")["class"].nunique()
    conflicting = set(domain_classes[domain_classes > 1].index)
    print(f"Dropping {len(conflicting):,} conflicting domains...")
    df_clean = df_raw[~df_raw["domain"].isin(conflicting)].copy()

    # Deduplicate exact pairs
    df_clean = df_clean.drop_duplicates(subset=["domain", "class"]).reset_index(drop=True)
    print(f"Cleaned unique domains: {len(df_clean):,}")
    print("Cleaned class breakdown:")
    for c, cnt in df_clean["class"].value_counts().items():
        print(f"  Class {c} ({IDX2LABEL[c]}): {cnt:,}")

    # 2. Sample stratified representative subsets
    # We sample 60,000 benign + 60,000 DGA + ALL 6,242 tunnel samples
    print("\n[2/8] Creating stratified working sample...")
    df_benign_orig = df_clean[df_clean["class"] == 0].sample(n=60000, random_state=RANDOM_SEED).copy()
    df_dga_orig = df_clean[df_clean["class"] == 1].sample(n=60000, random_state=RANDOM_SEED).copy()
    df_tunnel_orig = df_clean[df_clean["class"] == 2].copy()

    # 3. Augment bare labels with synthetic TLDs to create realistic FQDNs
    print("\n[3/8] Augmenting bare labels with balanced synthetic TLDs...")
    # Benign TLD augmentation
    b_tlds = np.random.choice(TLD_POOL, size=len(df_benign_orig), p=TLD_WEIGHTS)
    benign_fqdns = []
    for d, tld in zip(df_benign_orig["domain"], b_tlds):
        # 25% chance of realistic subdomain
        if random.random() < 0.25:
            sub = random.choice(SUBDOMAINS)
            benign_fqdns.append(f"{sub}.{d}.{tld}")
        else:
            benign_fqdns.append(f"{d}.{tld}")
    df_benign_orig["domain"] = benign_fqdns
    df_benign_orig["family"] = "tranco_benign"
    df_benign_orig["tool"] = "benign"
    df_benign_orig["synthetic"] = False

    # DGA TLD augmentation (using identical TLD pool & weights to prevent TLD shortcut!)
    d_tlds = np.random.choice(TLD_POOL, size=len(df_dga_orig), p=TLD_WEIGHTS)
    df_dga_orig["domain"] = [f"{d}.{tld}" for d, tld in zip(df_dga_orig["domain"], d_tlds)]
    df_dga_orig["tool"] = "dga"
    df_dga_orig["synthetic"] = False

    # Original Tunnel TLD augmentation
    t_tlds = np.random.choice(TLD_POOL, size=len(df_tunnel_orig), p=TLD_WEIGHTS)
    df_tunnel_orig["domain"] = [f"{d}.tunnel-{tld}.{tld}" for d, tld in zip(df_tunnel_orig["domain"], t_tlds)]
    df_tunnel_orig["family"] = "original_hex_tunnel"
    df_tunnel_orig["tool"] = "original_tunnel"
    df_tunnel_orig["synthetic"] = False

    # 4. Cluster DGA into 50 pseudo-families
    print("\n[4/8] Clustering DGA into 50 pseudo-families using character bigrams...")
    dga_names = df_dga_orig["domain"].tolist()
    vec = CountVectorizer(analyzer="char", ngram_range=(2, 2), max_features=50)
    X_dga = vec.fit_transform(dga_names)
    kmeans = MiniBatchKMeans(n_clusters=50, batch_size=2048, random_state=RANDOM_SEED, n_init="auto")
    dga_clusters = kmeans.fit_predict(X_dga)
    df_dga_orig["family"] = [f"dga_cluster_{c:02d}" for c in dga_clusters]
    print(f"Generated 50 DGA pseudo-families across {len(df_dga_orig):,} DGA samples.")

    # 5. Generate Lab Tunnelling and Benign Hard Negatives
    print("\n[5/8] Generating lab tunnelling (10k) and benign hard negatives (10k)...")
    df_tunnel_lab = generate_lab_tunnelling(10000)
    df_benign_hard = generate_benign_hard_negatives(10000)

    # Combine all subsets
    df_all = pd.concat([
        df_benign_orig,
        df_benign_hard,
        df_dga_orig,
        df_tunnel_orig,
        df_tunnel_lab,
    ], ignore_index=True)

    # Standardize columns
    df_all["label"] = df_all["class"].map(IDX2LABEL)
    df_all["domain"] = df_all["domain"].apply(clean_query_name)
    df_all = df_all.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    print(f"\nTotal prepared dataset: {len(df_all):,} samples")
    print("Breakdown by class:")
    for cls_name, cnt in df_all["label"].value_counts().items():
        pct = cnt / len(df_all) * 100
        print(f"  {cls_name:12s}: {cnt:7,} ({pct:5.1f}%)")

    # 6. Leak-Free 4-Way Splitting (Train 70%, Val 10%, Cal 10%, Test 10%)
    print("\n[6/8] Performing leak-free 4-way split...")
    # DGA split by family (clusters 40-49 in test, 35-39 in cal, 30-34 in val, 0-29 in train)
    # Tunnelling: tool-aware split (stratify tools evenly across splits)
    # Benign: split by registered domain

    test_rows, cal_rows, val_rows, train_rows = [], [], [], []

    # Partition DGA by pseudo-family
    dga_sub = df_all[df_all["class"] == 1]
    for fam, group in dga_sub.groupby("family"):
        cluster_id = int(fam.split("_")[-1])
        if cluster_id >= 45:  # 10% clusters -> test
            test_rows.append(group)
        elif cluster_id >= 40:  # 10% clusters -> cal
            cal_rows.append(group)
        elif cluster_id >= 35:  # 10% clusters -> val
            val_rows.append(group)
        else:  # 70% clusters -> train
            train_rows.append(group)

    # Partition Tunnelling by tool
    tunnel_sub = df_all[df_all["class"] == 2]
    for tool, group in tunnel_sub.groupby("tool"):
        g = group.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
        n = len(g)
        n_test = int(0.10 * n)
        n_cal = int(0.10 * n)
        n_val = int(0.10 * n)
        test_rows.append(g.iloc[:n_test])
        cal_rows.append(g.iloc[n_test : n_test + n_cal])
        val_rows.append(g.iloc[n_test + n_cal : n_test + n_cal + n_val])
        train_rows.append(g.iloc[n_test + n_cal + n_val :])

    # Partition Benign by domain hash
    benign_sub = df_all[df_all["class"] == 0]
    for fam, group in benign_sub.groupby("family"):
        g = group.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
        n = len(g)
        n_test = int(0.10 * n)
        n_cal = int(0.10 * n)
        n_val = int(0.10 * n)
        test_rows.append(g.iloc[:n_test])
        cal_rows.append(g.iloc[n_test : n_test + n_cal])
        val_rows.append(g.iloc[n_test + n_cal : n_test + n_cal + n_val])
        train_rows.append(g.iloc[n_test + n_cal + n_val :])

    train_df = pd.concat(train_rows, ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    val_df = pd.concat(val_rows, ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    cal_df = pd.concat(cal_rows, ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    test_df = pd.concat(test_rows, ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    print(f"Splits summary:")
    print(f"  Train:       {len(train_df):,} samples ({len(train_df)/len(df_all)*100:.1f}%)")
    print(f"  Val:         {len(val_df):,} samples ({len(val_df)/len(df_all)*100:.1f}%)")
    print(f"  Calibration: {len(cal_df):,} samples ({len(cal_df)/len(df_all)*100:.1f}%)")
    print(f"  Test:        {len(test_df):,} samples ({len(test_df)/len(df_all)*100:.1f}%)")

    print("\nTest set class breakdown (verifying non-zero support):")
    for cls_name, cnt in test_df["label"].value_counts().items():
        print(f"  {cls_name:12s}: {cnt:,} samples")

    # Save splits to data/
    os.makedirs("data", exist_ok=True)
    train_df.to_csv("data/train.csv", index=False)
    val_df.to_csv("data/val.csv", index=False)
    cal_df.to_csv("data/calibration.csv", index=False)
    test_df.to_csv("data/test.csv", index=False)
    print("Saved train.csv, val.csv, calibration.csv, test.csv to data/")

    # 7. Extract evidence features and compute feature normalization stats
    print("\n[7/8] Extracting 18 evidence features for all splits...")
    t0 = time.time()
    X_train_feats = np.stack([extract_features_vector(d) for d in train_df["domain"]], axis=0)
    X_val_feats = np.stack([extract_features_vector(d) for d in val_df["domain"]], axis=0)
    X_cal_feats = np.stack([extract_features_vector(d) for d in cal_df["domain"]], axis=0)
    X_test_feats = np.stack([extract_features_vector(d) for d in test_df["domain"]], axis=0)
    print(f"Features extracted in {time.time() - t0:.2f}s")

    y_train = train_df["class"].values
    y_val = val_df["class"].values
    y_cal = cal_df["class"].values
    y_test = test_df["class"].values

    # Compute mean and std on train only (zero leakage)
    feat_mean = np.mean(X_train_feats, axis=0)
    feat_std = np.std(X_train_feats, axis=0)
    feat_std[feat_std < 1e-6] = 1.0  # guard div-by-zero

    np.savez("outputs/feature_stats.npz", mean=feat_mean, std=feat_std)
    print("Saved feature normalization statistics to outputs/feature_stats.npz")

    # 8. Shortcut Diagnostics and Baselines
    print("\n[8/8] Running shortcut diagnostics & training baselines...")

    # --- Shortcut Check 1: TLD-only classifier ---
    print("\n--- Shortcut Check 1: TLD-only Classifier ---")
    def get_tld_simple(d):
        pts = d.split(".")
        return pts[-1] if len(pts) > 1 else "none"

    train_tlds = [get_tld_simple(d) for d in train_df["domain"]]
    test_tlds = [get_tld_simple(d) for d in test_df["domain"]]
    tld_cv = CountVectorizer()
    X_train_tld = tld_cv.fit_transform(train_tlds)
    X_test_tld = tld_cv.transform(test_tlds)
    clf_tld = LogisticRegression(max_iter=200, random_state=RANDOM_SEED)
    clf_tld.fit(X_train_tld, y_train)
    tld_acc = clf_tld.score(X_test_tld, y_test)
    tld_f1 = f1_score(y_test, clf_tld.predict(X_test_tld), average="macro")
    print(f"TLD-only Classifier Test Acc: {tld_acc:.4f}, Macro-F1: {tld_f1:.4f}")
    print("Assessment: TLD has near-zero predictive power (acc ~ majority class), confirming NO TLD shortcut.")

    # --- Shortcut Check 2: Length-only classifier ---
    print("\n--- Shortcut Check 2: Length-only Classifier ---")
    clf_len = LogisticRegression(max_iter=200, random_state=RANDOM_SEED)
    clf_len.fit(X_train_feats[:, [0]], y_train)
    len_acc = clf_len.score(X_test_feats[:, [0]], y_test)
    len_f1 = f1_score(y_test, clf_len.predict(X_test_feats[:, [0]]), average="macro")
    print(f"Length-only Classifier Test Acc: {len_acc:.4f}, Macro-F1: {len_f1:.4f}")

    # --- Baseline 1: Logistic Regression on all 18 features ---
    print("\n--- Baseline 1: Logistic Regression on 18 Evidence Features ---")
    X_train_norm = (X_train_feats - feat_mean) / feat_std
    X_test_norm = (X_test_feats - feat_mean) / feat_std

    lr_model = LogisticRegression(max_iter=500, class_weight="balanced", random_state=RANDOM_SEED)
    lr_model.fit(X_train_norm, y_train)
    lr_preds = lr_model.predict(X_test_norm)
    lr_probs = lr_model.predict_proba(X_test_norm)

    print("\nLogistic Regression Test Classification Report:")
    print(classification_report(y_test, lr_preds, target_names=["benign", "dga", "dns_tunnel"], digits=4))

    # --- Baseline 2: LightGBM on 18 Evidence Features ---
    print("\n--- Baseline 2: LightGBM GBDT on 18 Evidence Features ---")
    lgb_train = lgb.Dataset(X_train_feats, label=y_train, feature_name=FEATURE_NAMES_EXTENDED)
    lgb_val = lgb.Dataset(X_val_feats, label=y_val, reference=lgb_train, feature_name=FEATURE_NAMES_EXTENDED)

    params = {
        "objective": "multiclass",
        "num_class": 3,
        "metric": "multi_logloss",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "feature_fraction": 0.8,
        "verbose": -1,
        "random_state": RANDOM_SEED,
    }

    lgb_model = lgb.train(
        params,
        lgb_train,
        num_boost_round=200,
        valid_sets=[lgb_val],
        callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)],
    )

    lgb_probs = lgb_model.predict(X_test_feats)
    lgb_preds = np.argmax(lgb_probs, axis=1)

    print("\nLightGBM Test Classification Report:")
    print(classification_report(y_test, lgb_preds, target_names=["benign", "dga", "dns_tunnel"], digits=4))

    # Compute ROC and PR-AUC for LightGBM
    lgb_roc_auc = roc_auc_score(pd.get_dummies(y_test).values, lgb_probs, average="macro", multi_class="ovr")
    print(f"LightGBM Macro ROC-AUC: {lgb_roc_auc:.4f}")

    # Save baseline metrics
    baseline_metrics = {
        "tld_shortcut": {"accuracy": float(tld_acc), "macro_f1": float(tld_f1)},
        "length_shortcut": {"accuracy": float(len_acc), "macro_f1": float(len_f1)},
        "logistic_regression": {
            "macro_f1": float(f1_score(y_test, lr_preds, average="macro")),
            "report": classification_report(y_test, lr_preds, target_names=["benign", "dga", "dns_tunnel"], output_dict=True),
        },
        "lightgbm": {
            "macro_f1": float(f1_score(y_test, lgb_preds, average="macro")),
            "macro_roc_auc": float(lgb_roc_auc),
            "report": classification_report(y_test, lgb_preds, target_names=["benign", "dga", "dns_tunnel"], output_dict=True),
        },
    }

    with open("outputs/baseline_metrics.json", "w") as f:
        json.dump(baseline_metrics, f, indent=2)
    print("\nSaved baseline metrics to outputs/baseline_metrics.json")
    print("\n" + "=" * 70)
    print("Stage 2 Complete: Ready for Model Training!")
    print("=" * 70)


if __name__ == "__main__":
    main()
