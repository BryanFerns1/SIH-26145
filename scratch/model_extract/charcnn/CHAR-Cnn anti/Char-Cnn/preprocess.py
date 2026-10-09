"""
UniGuard DNS Query Preprocessing Pipeline
=========================================
Strict query-side preprocessing compliant with RFC 1035 and SIH26145 constraints.
Zero response-side leakage (no RCODE, no TTL, no answer records, no RTT).
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple, Union
import numpy as np

# Load meta.json
_META_PATH = os.path.join(os.path.dirname(__file__), "meta.json")
with open(_META_PATH, "r", encoding="utf-8") as f:
    META = json.load(f)

PAD_TOKEN = META["vocab"]["pad_token"]
UNK_TOKEN = META["vocab"]["unk_token"]
VOCAB_CHARS = META["vocab"]["chars"]
CHAR2IDX = {ch: idx + 2 for idx, ch in enumerate(VOCAB_CHARS)}
IDX2CHAR = {idx + 2: ch for idx, ch in enumerate(VOCAB_CHARS)}
IDX2CHAR[PAD_TOKEN] = "<PAD>"
IDX2CHAR[UNK_TOKEN] = "<UNK>"
VOCAB_SIZE = META["vocab"]["vocab_size"]

MODEL_MAX_LEN = META["constraints"]["model_max_len"]
LABEL2IDX = META["classes"]
IDX2LABEL = {int(k): v for k, v in META["inverse_classes"].items()}


def clean_query_name(raw_name: str) -> str:
    """
    RFC 1035 query name cleaner and normalizer.
    Eliminates casing and whitespace artifacts.
    Handles IDN / punycode.
    Preserves all internal hierarchy dots while stripping trailing root dot.
    """
    if not isinstance(raw_name, str):
        raw_name = str(raw_name) if raw_name is not None else ""

    s = raw_name.strip()

    # 1. Strip protocol or ports if raw input is from packet log
    s = re.sub(r"^[a-zA-Z]+://", "", s)
    s = s.split("/")[0]
    s = re.sub(r":\d+$", "", s)

    # 2. Convert to lowercase (CRITICAL: eliminates the uppercase tunnelling shortcut)
    s = s.lower()

    # 3. Handle IDN / Punycode: if non-ASCII, encode to punycode
    try:
        if any(ord(c) > 127 for c in s):
            s = s.encode("idna").decode("ascii")
    except Exception:
        # Fallback: remove non-ascii characters
        s = re.sub(r"[^\x00-\x7f]", "", s)

    # 4. Strip trailing root dot (RFC 1035 allows trailing dot for root zone)
    s = s.rstrip(".")

    # 5. Collapse consecutive dots (malformed queries)
    s = re.sub(r"\.{2,}", ".", s)

    # 6. Clip RFC 1035 maximum length (253 characters)
    if len(s) > 253:
        s = s[:253]

    return s


def tokenize_domain(
    cleaned_domain: str,
    max_len: int = MODEL_MAX_LEN,
) -> np.ndarray:
    """
    Tokenize a cleaned FQDN into integer token IDs padded/truncated to max_len.
    Returns:
      np.ndarray of shape (max_len,) dtype int64
    """
    tokens = [CHAR2IDX.get(ch, UNK_TOKEN) for ch in cleaned_domain[:max_len]]
    if len(tokens) < max_len:
        tokens.extend([PAD_TOKEN] * (max_len - len(tokens)))
    return np.array(tokens, dtype=np.int64)


def preprocess_batch(
    domain_list: List[str],
    max_len: int = MODEL_MAX_LEN,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Vectorized preprocessing for a batch of raw query names.
    Returns:
      token_tensor: np.ndarray (B, max_len) int64
      features_tensor: np.ndarray (B, num_features) float32
      cleaned_names: List[str] of normalized FQDNs
    """
    from evidence_features import extract_features_vector

    cleaned = [clean_query_name(d) for d in domain_list]
    tokens = np.stack([tokenize_domain(d, max_len=max_len) for d in cleaned], axis=0)
    feats = np.stack([extract_features_vector(d) for d in cleaned], axis=0)

    return tokens, feats, cleaned
