"""
Char-CNN v4 — Lexical Feature Extraction
==========================================
Computes 12 handcrafted lexical features from raw FQDNs.

CRITICAL FIX (v4):  Features that depend on label boundaries (n_labels,
max_label_len, mean_label_len) are computed on the dot-preserved domain
string, so they no longer collapse to constants.
"""

import math
import re
from collections import Counter
from typing import List

import numpy as np


# ──────────────────────────────────────────────
# Vowel / consonant sets
# ──────────────────────────────────────────────
_VOWELS = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _entropy(s: str) -> float:
    """Shannon entropy over character distribution."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _max_consonant_run(s: str) -> int:
    """Longest contiguous run of consonants."""
    max_run = 0
    cur = 0
    for ch in s:
        if ch in _CONSONANTS:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


def extract_lexical_features(domain: str) -> np.ndarray:
    """
    Extract 12 lexical features from a single FQDN.

    Parameters
    ----------
    domain : str
        Raw FQDN string (dots preserved, trailing root dot stripped).

    Returns
    -------
    np.ndarray of shape (12,) with dtype float32.
    """
    # Normalise: lowercase, strip trailing root dot only
    d = domain.lower().rstrip(".")
    alpha_only = re.sub(r"[^a-z]", "", d)

    length = len(d) if d else 1  # guard div-by-zero

    # 1. Log length
    log_len = math.log1p(length)

    # 2. Shannon entropy
    entropy = _entropy(d)

    # 3. Digit ratio
    digit_count = sum(ch.isdigit() for ch in d)
    digit_ratio = digit_count / length

    # 4. Alpha ratio
    alpha_count = sum(ch.isalpha() for ch in d)
    alpha_ratio = alpha_count / length

    # 5. Vowel ratio (over alpha chars)
    vowel_count = sum(ch in _VOWELS for ch in d)
    vowel_ratio = vowel_count / max(alpha_count, 1)

    # 6. Max consonant run
    max_cons = _max_consonant_run(d)

    # 7. Separator ratio (dots + hyphens + underscores)
    sep_count = sum(ch in ".-_" for ch in d)
    sep_ratio = sep_count / length

    # 8. Unique character ratio
    unique_chars = len(set(d))
    unique_char_ratio = unique_chars / length

    # 9. Normalised entropy (entropy / log2(unique_chars))
    norm_entropy = entropy / math.log2(max(unique_chars, 2))

    # 10–12. Label-level features (FIXED in v4: dots are preserved)
    labels = d.split(".")
    n_labels = len(labels)
    label_lens = [len(lbl) for lbl in labels]
    max_label_len = max(label_lens) if label_lens else 0
    mean_label_len = float(np.mean(label_lens)) if label_lens else 0.0

    return np.array(
        [
            log_len,           # 0
            entropy,           # 1
            digit_ratio,       # 2
            alpha_ratio,       # 3
            vowel_ratio,       # 4
            max_cons,          # 5
            sep_ratio,         # 6
            unique_char_ratio, # 7
            norm_entropy,      # 8
            n_labels,          # 9
            max_label_len,     # 10
            mean_label_len,    # 11
        ],
        dtype=np.float32,
    )


FEATURE_NAMES: List[str] = [
    "log_len",
    "entropy",
    "digit_ratio",
    "alpha_ratio",
    "vowel_ratio",
    "max_consonant_run",
    "sep_ratio",
    "unique_char_ratio",
    "norm_entropy",
    "n_labels",
    "max_label_len",
    "mean_label_len",
]
