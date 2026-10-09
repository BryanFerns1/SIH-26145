"""
UniGuard forward-only feature computation.

SINGLE SOURCE OF TRUTH: this module is used by both training and inference.
All features are derived from forward-direction (src→dst) packet headers only.

FORBIDDEN inputs (enforced by ALLOWED_COLUMNS):
  - Any column with "Bwd" or "Backward" in the name
  - "Down/Up Ratio"
  - Bidirectional "Flow IAT" (Mean/Std/Max/Min) — we use Fwd IAT only
  - Bidirectional "Packet Length" (Min/Max/Mean/Std/Variance)
  - "Bwd Init Win Bytes"
  - Raw IP addresses or port numbers

This module provides:
  - add_derived(df)   : compute derived ratio/diff features from base columns
  - prepare(df, ...)  : full pipeline: validate → select base → derive → reorder
  - iso_prep(X, ...)  : log1p transform for Isolation Forest input
"""
import numpy as np
import pandas as pd
from typing import List, Optional

# ─── Forward-only allowed columns ───────────────────────────────────────
# These are the ONLY columns from the dataset that may be used as model inputs.
# Every column here is either:
#   (a) forward-direction only (Fwd prefix, SYN/FIN/RST/PSH/ACK/URG/CWR/ECE flag counts
#       which in CIC-IDS2017 count flags in all packets but are not direction-biased), or
#   (b) duration/timing that doesn't require reverse traffic (Flow Duration, Fwd IAT).

# Substring patterns that are ALWAYS forbidden (clearly backward/identity)
FORBIDDEN_SUBSTRINGS = [
    "Bwd ",    # note trailing space to avoid matching "Fwd" words
    "Backward",
    "Down/Up",
    "Src IP", "Dst IP", "Src Port", "Dst Port",
    "Flow ID", "Timestamp", "Label", "Attempted",
    "ICMP Code", "ICMP Type", "Total TCP Flow Time",
    "Total Bwd", "Total Length of Bwd",
    "Subflow Bwd",
]

# Exact column names that are forbidden (bidirectional aggregates).
# These are NOT prefixed with "Fwd" but include backward traffic.
FORBIDDEN_EXACT_COLUMNS = {
    "Packet Length Min", "Packet Length Max", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "Average Packet Size",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Flow Bytes/s", "Flow Packets/s",
    "Avg Bwd Segment Size",
    "Bwd Init Win Bytes",
}


def is_forbidden(col_name: str) -> bool:
    """Check if a column name is forbidden (reverse-direction or identity)."""
    cn = col_name.strip()
    # Check exact forbidden columns
    if cn in FORBIDDEN_EXACT_COLUMNS:
        return True
    # Check substring patterns
    cn_lower = cn.lower()
    for sub in FORBIDDEN_SUBSTRINGS:
        if sub.lower() in cn_lower:
            return True
    return False


# ─── Derived feature definitions ────────────────────────────────────────
# Each tuple: (output_name, numerator_col, denominator_col)
# For DIFF features: (output_name, col_a, col_b) → a - b
RATIOS = [
    ("d_fwd_bytes_per_pkt",     "Total Length of Fwd Packet", "Total Fwd Packet"),
    ("d_fwd_hdr_per_pkt",       "Fwd Header Length",          "Total Fwd Packet"),
    ("d_fwd_iat_cv",            "Fwd IAT Std",                "Fwd IAT Mean"),
    ("d_fwd_len_cv",            "Fwd Packet Length Std",      "Fwd Packet Length Mean"),
    ("d_subflow_bytes_per_pkt", "Subflow Fwd Bytes",          "Subflow Fwd Packets"),
    ("d_fwd_hdr_ratio",         "Fwd Header Length",          "Total Length of Fwd Packet"),
    ("d_fwd_active_ratio",      "Fwd Act Data Pkts",          "Total Fwd Packet"),
]

# Duration-based ratios (Flow Duration is in microseconds in CIC-IDS2017)
DURATION_RATIOS = [
    ("d_fwd_pkts_per_s",  "Total Fwd Packet",           "Flow Duration"),
    ("d_fwd_bytes_per_s", "Total Length of Fwd Packet",  "Flow Duration"),
]

DIFFS = [
    ("d_fwd_len_range", "Fwd Packet Length Max", "Fwd Packet Length Min"),
]


def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived ratio/diff features from forward-only base columns.
    Inputs that are missing are silently skipped.
    Division by zero → NaN. Inf → NaN.
    """
    new = {}

    for name, num, den in RATIOS:
        if num in df.columns and den in df.columns:
            denominator = df[den].astype("float64")
            new[name] = df[num].astype("float64") / denominator.where(denominator > 0)

    for name, num, den in DURATION_RATIOS:
        if num in df.columns and den in df.columns:
            # Flow Duration is in microseconds → convert to seconds
            dur_s = df[den].astype("float64") / 1e6
            new[name] = df[num].astype("float64") / dur_s.where(dur_s > 0)

    for name, a, b in DIFFS:
        if a in df.columns and b in df.columns:
            new[name] = df[a].astype("float64") - df[b].astype("float64")

    if not new:
        return df

    extra = (pd.DataFrame(new, index=df.index)
             .replace([np.inf, -np.inf], np.nan)
             .astype("float32"))
    return pd.concat([df, extra], axis=1)


def validate_columns(columns: List[str]) -> None:
    """
    Validate that no forbidden (reverse-direction or identity) columns are present.
    Raises ValueError if any forbidden column is found.
    """
    violations = [c for c in columns if is_forbidden(c)]
    if violations:
        raise ValueError(
            f"FORBIDDEN columns detected in feature list "
            f"(reverse-direction or raw identity): {violations}"
        )


def prepare(
    df: pd.DataFrame,
    base_features: List[str],
    all_features: List[str],
    derived: bool = True,
    validate: bool = True,
) -> pd.DataFrame:
    """
    Full feature preparation pipeline.

    1. Strip column names
    2. Validate no forbidden columns
    3. Select base features
    4. Convert to float32, replace inf with NaN
    5. Compute derived features
    6. Return in exact feature order

    Parameters
    ----------
    df : raw flow DataFrame (from CSV or flow extractor)
    base_features : list of base column names to select
    all_features : final ordered feature list (base + derived)
    derived : whether to compute derived features
    validate : whether to validate column names against forbidden list

    Returns
    -------
    pd.DataFrame with exactly len(all_features) columns in the specified order
    """
    t = df.copy()
    t.columns = t.columns.str.strip()

    if validate:
        validate_columns(base_features)
        validate_columns(all_features)

    missing = [c for c in base_features if c not in t.columns]
    if missing:
        raise ValueError(
            f"Missing {len(missing)} required base columns: {missing[:5]}"
        )

    X = (t[base_features]
         .apply(pd.to_numeric, errors="coerce")
         .replace([np.inf, -np.inf], np.nan)
         .astype("float32"))

    if derived:
        X = add_derived(X)

    # Ensure exact column order, fill missing derived columns with NaN
    for col in all_features:
        if col not in X.columns:
            X[col] = np.float32(np.nan)

    return X[all_features]


def iso_prep(X: pd.DataFrame, features: List[str]) -> np.ndarray:
    """
    Prepare features for Isolation Forest: select, fill NaN, log1p transform.
    log1p tames the huge value ranges of flow features.
    """
    Xs = X[features].fillna(0)
    return np.log1p(Xs.clip(lower=0).values).astype("float32")


def get_feature_names(
    base_features: Optional[List[str]] = None,
) -> List[str]:
    """Return the complete ordered feature list (base + derived)."""
    if base_features is None:
        from config import BASE_FEATURES, ALL_FEATURES
        return ALL_FEATURES

    derived_names = (
        [name for name, _, _ in RATIOS] +
        [name for name, _, _ in DURATION_RATIOS] +
        [name for name, _, _ in DIFFS]
    )
    return list(base_features) + derived_names
