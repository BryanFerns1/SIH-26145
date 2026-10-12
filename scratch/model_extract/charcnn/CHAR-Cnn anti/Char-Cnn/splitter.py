"""
Char-CNN v4 — Leak-Free Data Splitting
========================================
Implements group-aware stratified splitting to prevent data leakage.

FIX (v4): Previous versions used random splitting which leaked DGA family
patterns across train/test.  This module groups domains by their registered
second-level domain (SLD) so that all variants of the same SLD stay in a
single split.
"""

from typing import Optional, Tuple

import numpy as np
import pandas as pd

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit


# ──────────────────────────────────────────────
# Group extraction
# ──────────────────────────────────────────────

def _extract_sld_fallback(domain: str) -> str:
    """
    Fallback SLD extraction when tldextract is unavailable.
    Takes the last two dot-separated labels (e.g., 'example.com').
    """
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return parts[0]


def _extract_sld_tldextract(domain: str) -> str:
    """Extract registered domain via tldextract."""
    ext = tldextract.extract(domain)
    rd = ext.registered_domain
    return rd if rd else ext.domain


def extract_groups(
    domains: pd.Series,
    group_col_values: Optional[pd.Series] = None,
) -> np.ndarray:
    """
    Return a group array suitable for GroupShuffleSplit.

    Priority:
      1. If an explicit group column is supplied, use it.
      2. Else, extract SLD with tldextract (if installed).
      3. Else, fall back to naive last-two-label extraction.
    """
    if group_col_values is not None:
        return group_col_values.values

    extractor = _extract_sld_tldextract if _HAS_TLDEXTRACT else _extract_sld_fallback
    return np.array([extractor(d) for d in domains])


# ──────────────────────────────────────────────
# Splitting logic
# ──────────────────────────────────────────────

def split_data(
    df: pd.DataFrame,
    domain_col: str = "domain",
    label_col: str = "label_id",
    group_col: Optional[str] = None,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split DataFrame into train / val / test with group-aware stratification.

    Returns
    -------
    train_df, val_df, test_df
    """
    labels = df[label_col].values
    group_vals = df[group_col] if (group_col and group_col in df.columns) else None
    groups = extract_groups(df[domain_col], group_vals)

    # ── First split: train+val  vs  test ──────
    n_groups = len(np.unique(groups))
    if n_groups > 1 and n_groups >= int(1.0 / test_size) + 1:
        # Enough unique groups for group-based split
        gss = GroupShuffleSplit(
            n_splits=1, test_size=test_size, random_state=random_seed
        )
        train_val_idx, test_idx = next(gss.split(df, labels, groups))
    else:
        # Fallback: stratified random split (rare edge case)
        sss = StratifiedShuffleSplit(
            n_splits=1, test_size=test_size, random_state=random_seed
        )
        train_val_idx, test_idx = next(sss.split(df, labels))

    train_val_df = df.iloc[train_val_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    # ── Second split: train  vs  val ──────────
    tv_labels = train_val_df[label_col].values
    tv_groups = extract_groups(
        train_val_df[domain_col],
        train_val_df[group_col] if (group_col and group_col in train_val_df.columns) else None,
    )

    relative_val = val_size / (1.0 - test_size)
    n_tv_groups = len(np.unique(tv_groups))

    if n_tv_groups > 1 and n_tv_groups >= int(1.0 / relative_val) + 1:
        gss2 = GroupShuffleSplit(
            n_splits=1, test_size=relative_val, random_state=random_seed
        )
        train_idx, val_idx = next(gss2.split(train_val_df, tv_labels, tv_groups))
    else:
        sss2 = StratifiedShuffleSplit(
            n_splits=1, test_size=relative_val, random_state=random_seed
        )
        train_idx, val_idx = next(sss2.split(train_val_df, tv_labels))

    train_df = train_val_df.iloc[train_idx].reset_index(drop=True)
    val_df = train_val_df.iloc[val_idx].reset_index(drop=True)

    print(f"[SPLIT] Train: {len(train_df):,}  Val: {len(val_df):,}  Test: {len(test_df):,}")
    return train_df, val_df, test_df
