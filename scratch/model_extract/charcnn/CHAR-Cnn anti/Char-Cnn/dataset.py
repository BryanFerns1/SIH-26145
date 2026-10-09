"""
Char-CNN v5 — Dataset & Tokeniser
===================================
PyTorch Dataset that:
  * Preserves dots in FQDNs (RFC 1035 compliant).
  * Cleans domains via preprocess.clean_query_name.
  * Tokenises domains into padded integer tensors (max_len = 128).
  * Extracts 18 lexical and structural evidence features per domain.
  * Applies z-score standardisation on features using training statistics.
"""

from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

from config import CHAR2IDX, LABEL2IDX, PAD_TOKEN, UNK_TOKEN
from evidence_features import extract_features_vector, FEATURE_NAMES_EXTENDED
from preprocess import clean_query_name, tokenize_domain, MODEL_MAX_LEN


# ──────────────────────────────────────────────
# Dataset
# ──────────────────────────────────────────────

class DNSDomainDataset(Dataset):
    """
    Parameters
    ----------
    domains : array-like of str
        Raw FQDN strings.
    labels : array-like of int
        Integer class labels (0=benign, 1=dga, 2=dns_tunnel).
    max_len : int
        Maximum character-token sequence length (default: 128).
    feat_mean : np.ndarray or None
        If provided, used to z-score standardise lexical features.
    feat_std : np.ndarray or None
        If provided, used to z-score standardise lexical features.
    """

    def __init__(
        self,
        domains,
        labels,
        max_len: int = MODEL_MAX_LEN,
        feat_mean: Optional[np.ndarray] = None,
        feat_std: Optional[np.ndarray] = None,
    ):
        self.domains = [clean_query_name(str(d)) for d in domains]
        self.labels = np.asarray(labels, dtype=np.int64)
        self.max_len = max_len
        self.feat_mean = feat_mean
        self.feat_std = feat_std

        # Pre-compute token arrays and lexical features for maximum training speed
        self.token_ids = np.stack(
            [tokenize_domain(d, max_len=max_len) for d in self.domains]
        )
        self.features = np.stack(
            [extract_features_vector(d) for d in self.domains]
        )

        # Apply standardisation if statistics are provided
        if self.feat_mean is not None and self.feat_std is not None:
            safe_std = np.where(self.feat_std < 1e-8, 1.0, self.feat_std)
            self.features = (self.features - self.feat_mean) / safe_std

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        tokens = torch.from_numpy(self.token_ids[idx])           # (max_len,) int64
        feats = torch.from_numpy(self.features[idx]).float()     # (18,) float32
        label = torch.tensor(self.labels[idx], dtype=torch.long) # scalar int64
        return tokens, feats, label


# ──────────────────────────────────────────────
# Utility: compute feature statistics from training split
# ──────────────────────────────────────────────

def compute_feature_stats(
    domains,
) -> Tuple[np.ndarray, np.ndarray]:
    """Return (mean, std) arrays of shape (18,) for z-score standardisation."""
    cleaned = [clean_query_name(str(d)) for d in domains]
    feats = np.stack([extract_features_vector(d) for d in cleaned])
    mean = feats.mean(axis=0)
    std = feats.std(axis=0)
    std[std < 1e-6] = 1.0
    return mean, std


# ──────────────────────────────────────────────
# Utility: load and validate CSV
# ──────────────────────────────────────────────

def load_csv(
    path: str,
    domain_col: str = "domain",
    label_col: str = "label",
    group_col: Optional[str] = None,
) -> pd.DataFrame:
    """
    Load a dataset CSV, lowercase labels, and map to integer IDs.
    """
    df = pd.read_csv(path)
    if "class" in df.columns and label_col not in df.columns:
        df["label_id"] = df["class"].astype(int)
        inv_map = {0: "benign", 1: "dga", 2: "dns_tunnel"}
        df["label"] = df["class"].map(inv_map)
    else:
        required = {domain_col, label_col}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        df[label_col] = df[label_col].str.strip().str.lower()
        df["label_id"] = df[label_col].map(LABEL2IDX)

        unmapped = df["label_id"].isna().sum()
        if unmapped:
            bad = df.loc[df["label_id"].isna(), label_col].unique()
            raise ValueError(
                f"{unmapped} rows have unknown labels: {bad}. "
                f"Expected one of {list(LABEL2IDX.keys())}"
            )
        df["label_id"] = df["label_id"].astype(int)

    print(f"[DATA] Loaded {len(df):,} rows from {path}")
    print(f"[DATA] Class distribution:\n{df['label_id'].value_counts().to_string()}")
    return df
