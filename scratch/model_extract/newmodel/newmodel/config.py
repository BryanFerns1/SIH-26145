"""
UniGuard configuration — paths, constants, hyperparameters.
All paths are relative to the project root.
"""
import os
from pathlib import Path

# ─── Project root ───────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent

# ─── Data paths ─────────────────────────────────────────────────────────
# CIC-IDS2017 improved (corrected labels by Engelen, Rimmer, Joosen)
CICIDS2017_DIR = Path(r"C:\Users\soura\Downloads\CICIDS2017_improved")
CICIDS2017_FILES = {
    "monday":    CICIDS2017_DIR / "monday.csv",
    "tuesday":   CICIDS2017_DIR / "tuesday.csv",
    "wednesday": CICIDS2017_DIR / "wednesday.csv",
    "thursday":  CICIDS2017_DIR / "thursday.csv",
    "friday":    CICIDS2017_DIR / "friday.csv",
}

# Cross-dataset: CIC-DDoS2019 / CSE-CIC-IDS2018 (via cic-collection parquet)
CIC_COLLECTION_PARQUET = Path(r"C:\Users\soura\Downloads\archive\cic-collection.parquet")
BOTNET_2018_PARQUET = Path(r"C:\Users\soura\Downloads\Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet\Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet")

# ICS/OT: 4SICS and HAI — NOT AVAILABLE on this machine
ICS_4SICS_DIR = None   # Set when available
HAI_DIR = None         # Set when available

# ─── Model output paths ────────────────────────────────────────────────
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
REPORTS_DIR = PROJECT_ROOT / "reports"

# ─── Day/Capture split assignments ─────────────────────────────────────
# CIC-IDS2017 days and their attack content (for capture-level splits):
#   Monday:    BENIGN only
#   Tuesday:   FTP-Patator, SSH-Patator
#   Wednesday: DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), Heartbleed
#   Thursday:  Web Attack (Brute Force, XSS, SQL Injection), Infiltration
#   Friday:    Portscan, DDoS, Botnet

# Capture-level train/val/test split:
# Train: Monday (benign), Tuesday (patators), Wednesday (DoS)
# Validation: Thursday (web attack, infiltration)  — used for early stopping / Optuna
# Test: Friday (portscan, DDoS, botnet)
TRAIN_DAYS = ["monday", "tuesday", "wednesday"]
VAL_DAYS = ["thursday"]
TEST_DAYS = ["friday"]

# Alternative split for leave-days-out experiments:
# Multiple rotations tested in eval_leave_days.py

# ─── Attempted rows handling ────────────────────────────────────────────
# Decision: DROP attempted attack rows (rows where Attempted Category != -1
# and label contains "- Attempted"). Rationale: these are flows where the
# attack was attempted but not necessarily successful, and the corrected
# labels distinguish them. Keeping them as a separate class would create
# too many tiny classes. They are documented here as dropped.
DROP_ATTEMPTED = True

# ─── Label merge map ────────────────────────────────────────────────────
# Merging tiny sub-classes for practical multiclass classification.
LABEL_MERGE = {
    "DoS Slowhttptest": "DoS Slow",
    "DoS Slowloris": "DoS Slow",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - SQL Injection": "Web Attack",
    "Infiltration - Portscan": "Portscan",
}

# Rare classes — evaluated via Isolation Forest only, not LightGBM multiclass
RARE_CLASSES = ["Heartbleed", "Infiltration"]

# Final class list (after merging, excluding rare):
CLASSES = [
    "BENIGN",
    "Botnet",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slow",
    "FTP-Patator",
    "Portscan",
    "SSH-Patator",
    "Web Attack",
]

# ─── Forward-only base features ─────────────────────────────────────────
# These are the columns from the CIC-IDS2017-improved CSV that we use.
# ALL are forward-direction only or direction-neutral.
# FORBIDDEN: any column with "Bwd", "Backward", "Down/Up Ratio",
#            bidirectional Flow IAT, bidirectional Packet Length stats.
BASE_FEATURES = [
    "Flow Duration",
    "Total Fwd Packet",
    "Total Length of Fwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd RST Flags",
    "Fwd Header Length",
    "Fwd Packets/s",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "FWD Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Fwd Segment Size Avg",
]

# Derived ratio/diff features (computed from base features only)
DERIVED_FEATURES = [
    "d_fwd_bytes_per_pkt",       # Total Length of Fwd Packet / Total Fwd Packet
    "d_fwd_hdr_per_pkt",         # Fwd Header Length / Total Fwd Packet
    "d_fwd_pkts_per_s",          # Total Fwd Packet / (Flow Duration / 1e6)
    "d_fwd_bytes_per_s",         # Total Length of Fwd Packet / (Flow Duration / 1e6)
    "d_fwd_iat_cv",              # Fwd IAT Std / Fwd IAT Mean
    "d_fwd_len_cv",              # Fwd Packet Length Std / Fwd Packet Length Mean
    "d_fwd_len_range",           # Fwd Packet Length Max - Fwd Packet Length Min
    "d_subflow_bytes_per_pkt",   # Subflow Fwd Bytes / Subflow Fwd Packets
    "d_fwd_hdr_ratio",           # Fwd Header Length / Total Length of Fwd Packet
    "d_fwd_active_ratio",        # Fwd Act Data Pkts / Total Fwd Packet
]

# Full feature list (base + derived) — this is the model input order
ALL_FEATURES = BASE_FEATURES + DERIVED_FEATURES

# ─── Snapshot times (seconds) for sub-second alert training ──────────────
SNAPSHOT_TIMES_SEC = [0.5, 1.0, 5.0, 30.0, None]  # None = flow end

# ─── Host-level feature config ──────────────────────────────────────────
HOST_ROLLING_WINDOWS_SEC = [10.0, 60.0]
HOST_MAX_TRACKED_KEYS = 100_000   # bounded state
HLL_PRECISION = 10                # HyperLogLog precision (2^10 = 1024 registers)

# ─── LightGBM hyperparameter defaults ───────────────────────────────────
LGBM_DEFAULTS = {
    "num_leaves": 63,
    "max_depth": -1,
    "min_child_samples": 50,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,
    "learning_rate": 0.05,
    "n_estimators": 2000,
    "reg_alpha": 0.1,
    "reg_lambda": 1.0,
    "random_state": 42,
    "n_jobs": 1,           # CPU-only, single core for reproducibility
    "verbose": -1,
}

# ─── Isolation Forest defaults ───────────────────────────────────────────
IFOREST_DEFAULTS = {
    "n_estimators": 300,
    "max_samples": 0.1,     # 10% of training data per tree
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": 1,
}

# ─── Operating tiers ────────────────────────────────────────────────────
# Set on benign calibration data only
TARGET_FPR_HIGH = 0.002     # 0.2% FPR
TARGET_FPR_REVIEW = 0.01    # 1.0% FPR

# ─── Seeds for reproducibility ──────────────────────────────────────────
SEEDS = [42, 123, 2024]     # 3 seeds for mean ± std reporting

# ─── MITRE ATT&CK mappings ──────────────────────────────────────────────
# Looked up from MITRE's official ATT&CK data
MITRE_MAPPING = {
    "DoS Hulk":       {"enterprise": "T1498.001", "ics": "T0814", "confidence": "high"},
    "DoS GoldenEye":  {"enterprise": "T1498.001", "ics": "T0814", "confidence": "high"},
    "DoS Slow":       {"enterprise": "T1499.002", "ics": "T0814", "confidence": "high"},
    "DDoS":           {"enterprise": "T1498",     "ics": "T0814", "confidence": "high"},
    "Portscan":       {"enterprise": "T1046",     "ics": "T0846", "confidence": "high"},
    "FTP-Patator":    {"enterprise": "T1110.001", "ics": None,    "confidence": "high"},
    "SSH-Patator":    {"enterprise": "T1110.001", "ics": None,    "confidence": "high"},
    "Web Attack":     {"enterprise": "T1190",     "ics": None,    "confidence": "approximate, needs review"},
    "Botnet":         {"enterprise": "T1071.001", "ics": "T0884", "confidence": "approximate, needs review"},
    "Heartbleed":     {"enterprise": "T1190",     "ics": None,    "confidence": "high"},
    "Infiltration":   {"enterprise": "T1071",     "ics": None,    "confidence": "approximate, needs review"},
}

# ─── Threat classes NOT MET ─────────────────────────────────────────────
# These are required but no labelled data exists in CIC-IDS2017:
NOT_MET_CLASSES = {
    "Data Exfiltration": "No labelled captures available in CIC-IDS2017",
    "DNS Tunnelling":    "No labelled captures available in CIC-IDS2017",
}

# ─── Flow extractor timeouts ────────────────────────────────────────────
IDLE_TIMEOUT_SEC = 120
ACTIVE_TIMEOUT_SEC = 300
