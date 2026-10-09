"""
Char-CNN v4 — Configuration Module
===================================
Centralised hyperparameters, paths, and constants for the DNS Threat
Detection Engine (SIH26145).
"""

from dataclasses import dataclass, field
from typing import List, Optional
import os


# ──────────────────────────────────────────────
# Character Vocabulary
# ──────────────────────────────────────────────
# CRITICAL FIX (v4): Dots (`.`) are INCLUDED in the vocabulary to preserve
# hierarchical label boundaries.  Only the trailing root dot (if present) is
# stripped during preprocessing — all internal dots remain intact.
PAD_TOKEN = 0
UNK_TOKEN = 1
VOCAB_CHARS = list("abcdefghijklmnopqrstuvwxyz0123456789-_.")
CHAR2IDX = {ch: idx + 2 for idx, ch in enumerate(VOCAB_CHARS)}  # 0=PAD, 1=UNK
IDX2CHAR = {v: k for k, v in CHAR2IDX.items()}
IDX2CHAR[PAD_TOKEN] = "<PAD>"
IDX2CHAR[UNK_TOKEN] = "<UNK>"
VOCAB_SIZE = len(VOCAB_CHARS) + 2  # +PAD +UNK  → 41


# ──────────────────────────────────────────────
# Label Mapping
# ──────────────────────────────────────────────
LABEL2IDX = {"benign": 0, "dga": 1, "dns_tunnel": 2}
IDX2LABEL = {v: k for k, v in LABEL2IDX.items()}
NUM_CLASSES = len(LABEL2IDX)


@dataclass
class TrainingConfig:
    """All training-related hyperparameters."""

    # ── Data ──────────────────────────────────
    max_len: int = 128
    group_col: Optional[str] = None          # Column for group-aware splitting
    test_size: float = 0.10
    val_size: float = 0.10
    random_seed: int = 42

    # ── Model ─────────────────────────────────
    emb_dim: int = 48
    conv_filters: int = 128
    kernel_sizes: List[int] = field(default_factory=lambda: [3, 5, 7, 9])
    gru_hidden: int = 160
    num_lexical_features: int = 18
    lexical_proj_dim: int = 64
    classifier_hidden: int = 128
    dropout: float = 0.25

    # ── Training ──────────────────────────────
    batch_size: int = 512
    epochs: int = 5
    lr: float = 2.5e-3
    weight_decay: float = 1e-4
    focal_gamma: float = 2.0
    warmup_pct: float = 0.15
    grad_clip_norm: float = 1.0
    patience: int = 3                        # Early stopping patience
    use_amp: bool = False                    # False for CPU execution

    # ── Paths ─────────────────────────────────
    data_path: str = "data/train.csv"
    val_data_path: str = "data/val.csv"
    cal_data_path: str = "data/calibration.csv"
    test_data_path: str = "data/test.csv"
    output_dir: str = "outputs"
    model_save_path: str = "outputs/hybridnet_v4_best.pt"
    calibrated_model_path: str = "outputs/hybridnet_v4_calibrated.pt"

    def __post_init__(self):
        os.makedirs(self.output_dir, exist_ok=True)


# ──────────────────────────────────────────────
# MITRE ATT&CK Mappings
# ──────────────────────────────────────────────
MITRE_MAP = {
    "dga": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
    },
    "dns_tunnel": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control / Exfiltration",
    },
    "benign": {
        "technique_id": "N/A",
        "technique_name": "N/A",
        "tactic": "N/A",
    },
}

# ──────────────────────────────────────────────
# Severity Mapping (confidence → severity)
# ──────────────────────────────────────────────
SEVERITY_THRESHOLDS = [
    (0.95, "CRITICAL"),
    (0.85, "HIGH"),
    (0.65, "MEDIUM"),
    (0.0, "LOW"),
]
