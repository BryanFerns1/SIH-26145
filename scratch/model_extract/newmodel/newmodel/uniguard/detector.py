"""
UniGuard Stage 8: Main Detector Class.

Provides `predict(batch)` that:
- Never raises on empty or malformed input
- Returns structured results with Calibrated Confidence and Tier (HIGH/REVIEW)
- Handles Observability State mapping to available detectors.
"""
import hashlib
import json
import logging
from typing import Dict, List, Any
from pathlib import Path
import sys

import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import prepare, iso_prep

log = logging.getLogger(__name__)


class UniGuardDetector:
    def __init__(self, models_dir: str = None):
        if models_dir is None:
            models_dir = config.MODELS_DIR
        else:
            models_dir = Path(models_dir)
            
        # Load meta
        with open(config.PROJECT_ROOT / "meta.json", "r") as f:
            self.meta = json.load(f)
            
        self.classes = self.meta["classes"]
        self.thresholds = self.meta["thresholds"]
        
        # Load models
        try:
            self.bin_cal = joblib.load(config.PROJECT_ROOT / self.meta["calibrator_binary_file"])
            self.mc_cal = joblib.load(config.PROJECT_ROOT / self.meta["calibrator_multi_file"])
            self.iso = joblib.load(config.PROJECT_ROOT / self.meta["iforest_file"])
            self.models_loaded = True
        except Exception as e:
            log.error(f"Failed to load models: {e}")
            self.models_loaded = False

    def get_observability_state(self, df: pd.DataFrame) -> str:
        """Determine what data is actually present."""
        has_pkts = "Total Length of Fwd Packet" in df.columns and df["Total Length of Fwd Packet"].sum() > 0
        has_flags = "SYN Flag Count" in df.columns
        has_timing = "Fwd IAT Mean" in df.columns
        
        if has_pkts and has_flags and has_timing:
            return "uniflow_fwd_only"
        elif not has_pkts and has_timing:
            return "netflow_no_packet_data"
        else:
            return "truncated_flow"

    def compute_evidence_hash(self, row: pd.Series) -> str:
        """HMAC-SHA256 of canonical exact model input for tamper evidence."""
        import hmac
        import hashlib
        # Use only base features used by the model
        input_data = {}
        for f in config.BASE_FEATURES:
            val = row.get(f)
            # Handle pandas NA/NaN
            input_data[f] = float(val) if pd.notnull(val) else None
            
        canonical = json.dumps(input_data, sort_keys=True)
        # Use a hardcoded key for the hackathon prototype, normally from env vars
        secret_key = b"UniGuard_SIH2026_Secret_Key_v1"
        h = hmac.new(secret_key, canonical.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()

    def predict(self, batch: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Run inference on a batch of flows.
        Never raises exceptions, returns empty list on bad input.
        """
        results = []
        
        if not self.models_loaded:
            log.error("Models not loaded.")
            return results
            
        if batch is None or len(batch) == 0:
            return results
            
        try:
            obs_state = self.get_observability_state(batch)
            
            # Prepare features
            X = prepare(batch, config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=False)
            X_iso = iso_prep(X, config.ALL_FEATURES)
            
            # 1. Binary Predictions
            bin_probs = self.bin_cal.predict_proba(X)[:, 1]
            
            # 2. Multiclass Predictions
            mc_probs = self.mc_cal.predict_proba(X)
            mc_preds = np.argmax(mc_probs, axis=1)
            mc_confs = np.max(mc_probs, axis=1)
            
            # 3. Isolation Forest
            iso_scores = -self.iso.decision_function(X_iso)
            
            # Thresholds
            t_high = self.thresholds["binary_high"]["value"]
            t_rev = self.thresholds["binary_review"]["value"]
            t_iso = self.thresholds["iforest_review"]["value"]
            
            # Generate alerts for flagged flows
            for i in range(len(batch)):
                p_bin = bin_probs[i]
                s_iso = iso_scores[i]
                
                is_attack = p_bin >= t_rev
                is_anomaly = s_iso >= t_iso
                
                if not is_attack and not is_anomaly:
                    continue  # Benign
                    
                row = batch.iloc[i]
                evidence_hash = self.compute_evidence_hash(row)
                
                alert = {
                    "timestamp": row.get("Timestamp", time.time()),
                    "src_ip": row.get("Src IP", "unknown"),
                    "dst_ip": row.get("Dst IP", "unknown"),
                    "dst_port": row.get("Dst Port", 0),
                    "protocol": row.get("Protocol", 0),
                    "observability_state": obs_state,
                    "evidence_hash": evidence_hash,
                }
                
                if is_attack:
                    # Known attack detected by supervised model
                    tier = "HIGH" if p_bin >= t_high else "REVIEW"
                    pred_class = self.classes[mc_preds[i]]
                    conf = mc_confs[i]
                    
                    # Get MITRE mapping
                    mitre = config.MITRE_MAPPING.get(pred_class, {})
                    
                    alert.update({
                        "threat_class": pred_class,
                        "confidence": float(conf),
                        "severity": "CRITICAL" if tier == "HIGH" else "HIGH",
                        "mitre_id_enterprise": mitre.get("enterprise"),
                        "mitre_id_ics": mitre.get("ics"),
                        "detector": "multiclass",
                        "tier": tier,
                    })
                else:
                    # Only flagged by isolation forest (unknown anomaly)
                    alert.update({
                        "threat_class": "Anomaly_Unknown",
                        "confidence": float(s_iso), # Raw score for anomaly
                        "severity": "MEDIUM",
                        "mitre_id_enterprise": None,
                        "mitre_id_ics": None,
                        "detector": "iforest",
                        "tier": "REVIEW",
                    })
                    
                results.append(alert)
                
        except Exception as e:
            log.error(f"Error during predict: {e}")
            # Never raise, just return what we have (or empty)
            
        return results
