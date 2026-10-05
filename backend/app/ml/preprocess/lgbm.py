"""UniGuard Preprocessing: LightGBM (CIC-IDS2017 feature engineering)"""

import numpy as np
import pandas as pd

# The 28 base features that the pipeline will receive from the flow exporter
BASE_FEATURES = [
    "Flow Duration", "Total Fwd Packet", "Total Length of Fwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags",
    "Fwd RST Flags", "Fwd Header Length", "Fwd Packets/s",
    "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "FWD Init Win Bytes",
    "Fwd Act Data Pkts", "Fwd Seg Size Min", "Fwd Segment Size Avg"
]

ALL_FEATURES = BASE_FEATURES + [
    "d_fwd_bytes_per_pkt", "d_fwd_hdr_per_pkt", "d_fwd_pkts_per_s",
    "d_fwd_bytes_per_s", "d_fwd_iat_cv", "d_fwd_len_cv",
    "d_fwd_len_range", "d_subflow_bytes_per_pkt", "d_fwd_hdr_ratio",
    "d_fwd_active_ratio"
]

def preprocess_lgbm(flows: list[dict]) -> pd.DataFrame:
    """Preprocess a batch of raw flow dicts into the 38-feature LightGBM DataFrame."""
    if not flows:
        return pd.DataFrame(columns=ALL_FEATURES)
        
    df = pd.DataFrame(flows)
    
    # Ensure all base features exist, fill missing with 0
    for col in BASE_FEATURES:
        if col not in df.columns:
            df[col] = 0.0
            
    # Convert to float32
    X = df[BASE_FEATURES].astype(np.float32)
    
    # Compute derived features (safe division)
    # Total Length of Fwd Packet / Total Fwd Packet
    X["d_fwd_bytes_per_pkt"] = np.where(X["Total Fwd Packet"] > 0, 
                                        X["Total Length of Fwd Packet"] / X["Total Fwd Packet"], 0.0)
    
    # Fwd Header Length / Total Fwd Packet
    X["d_fwd_hdr_per_pkt"] = np.where(X["Total Fwd Packet"] > 0,
                                      X["Fwd Header Length"] / X["Total Fwd Packet"], 0.0)
                                      
    # Duration in seconds (Flow Duration is in microseconds)
    dur_s = X["Flow Duration"] / 1e6
    X["d_fwd_pkts_per_s"] = np.where(dur_s > 0, X["Total Fwd Packet"] / dur_s, 0.0)
    X["d_fwd_bytes_per_s"] = np.where(dur_s > 0, X["Total Length of Fwd Packet"] / dur_s, 0.0)
    
    # Fwd IAT Std / Fwd IAT Mean
    X["d_fwd_iat_cv"] = np.where(X["Fwd IAT Mean"] > 0, X["Fwd IAT Std"] / X["Fwd IAT Mean"], 0.0)
    
    # Fwd Packet Length Std / Fwd Packet Length Mean
    X["d_fwd_len_cv"] = np.where(X["Fwd Packet Length Mean"] > 0, 
                                 X["Fwd Packet Length Std"] / X["Fwd Packet Length Mean"], 0.0)
                                 
    # Fwd Packet Length Max - Fwd Packet Length Min
    X["d_fwd_len_range"] = X["Fwd Packet Length Max"] - X["Fwd Packet Length Min"]
    
    # Subflow Fwd Bytes / Subflow Fwd Packets
    X["d_subflow_bytes_per_pkt"] = np.where(X["Subflow Fwd Packets"] > 0,
                                            X["Subflow Fwd Bytes"] / X["Subflow Fwd Packets"], 0.0)
                                            
    # Fwd Header Length / Total Length of Fwd Packet
    X["d_fwd_hdr_ratio"] = np.where(X["Total Length of Fwd Packet"] > 0,
                                    X["Fwd Header Length"] / X["Total Length of Fwd Packet"], 0.0)
                                    
    # Fwd Act Data Pkts / Total Fwd Packet
    X["d_fwd_active_ratio"] = np.where(X["Total Fwd Packet"] > 0,
                                       X["Fwd Act Data Pkts"] / X["Total Fwd Packet"], 0.0)
                                       
    # Replace any infinity or NaN from edge cases with 0
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0.0, inplace=True)
    
    # Return in EXACT column order
    return X[ALL_FEATURES].astype(np.float32)

def preprocess_iforest(X: pd.DataFrame) -> np.ndarray:
    """Prepare features for Isolation Forest (log1p transform)."""
    return np.log1p(X.clip(lower=0).values).astype(np.float32)
