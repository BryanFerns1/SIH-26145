"""UniGuard Ensemble Pipeline (Phase 3)."""

import logging
from typing import List, Dict, Any
import numpy as np

from app.schemas import Alert, ThreatClass, Severity, FiveTuple, ModelScore
from app.ml.registry import ModelRegistry
from app.ml.preprocess.lgbm import preprocess_lgbm, preprocess_iforest, BASE_FEATURES
from app.ml.preprocess.beacon import preprocess_beacon_cnn
from app.ml.preprocess.charcnn import preprocess_charcnn

log = logging.getLogger("uniguard.pipeline")

class Pipeline:
    def __init__(self, registry: ModelRegistry):
        self.registry = registry

    async def process_batch(self, flows: List[Dict[str, Any]]) -> List[Alert]:
        """Runs the ensemble of models on a batch of flows and produces alerts."""
        if not flows:
            return []
            
        alerts = []
        
        # Different models need different observed inputs. Never run a model against
        # zero-filled or absent data just to produce a prediction.
        lgbm_preds: Dict[int, Dict[str, Any]] = {}
        beacon_preds: Dict[int, float] = {}
        charcnn_preds: Dict[int, List[float]] = {}

        obs_state = "uniflow_fwd_only" if all(
            "Total Length of Fwd Packet" in flow and "SYN Flag Count" in flow
            and "Fwd IAT Mean" in flow for flow in flows
        ) else "packet_features_partial"

        # LightGBM/IForest require the complete feature vector. Packet sensor
        # flows missing an initial TCP SYN are withheld from these models.
        lgbm_indices = [
            i for i, flow in enumerate(flows)
            if all(flow.get(name) is not None for name in BASE_FEATURES)
            and (flow.get("sensor_metadata") or {}).get(
                "lgbm_inputs_complete", (flow.get("sensor_metadata") or {}).get("lgbm_ready", True)
            )
        ]
        if "lgbm_iforest" in self.registry.models and lgbm_indices:
            lgbm_models = self.registry.models["lgbm_iforest"]
            try:
                lgbm_flows = [flows[i] for i in lgbm_indices]
                df_lgbm = preprocess_lgbm(lgbm_flows)
                X_iso = preprocess_iforest(df_lgbm)
                iso_scores_raw = -lgbm_models["iforest"].decision_function(X_iso)
                bin_probs = lgbm_models["cal_bin"].predict_proba(df_lgbm)[:, 1]
                mc_probs = lgbm_models["cal_multi"].predict_proba(df_lgbm)
                mc_preds_idx = np.argmax(mc_probs, axis=1)
                mc_confs = np.max(mc_probs, axis=1)
                for row, flow_index in enumerate(lgbm_indices):
                    lgbm_preds[flow_index] = {
                        "bin_prob": bin_probs[row],
                        "mc_idx": mc_preds_idx[row],
                        "mc_conf": mc_confs[row],
                        "iso_score": iso_scores_raw[row],
                    }
            except Exception as e:
                log.error(f"LGBM inference error: {e}")

        # Beacon needs a captured packet sequence with aligned timestamps/flags.
        beacon_indices = [
            i for i, flow in enumerate(flows)
            if flow.get("pkt_sizes") and len(flow.get("pkt_iats", [])) >= len(flow["pkt_sizes"])
            and len(flow.get("pkt_flags", [])) >= len(flow["pkt_sizes"])
        ]
        if "beacon_cnn" in self.registry.models and beacon_indices:
            beacon = self.registry.models["beacon_cnn"]
            try:
                beacon_flows = [flows[i] for i in beacon_indices]
                X_beacon = preprocess_beacon_cnn(beacon_flows)
                raw_scores = []
                for row in range(len(beacon_flows)):
                    x_i = X_beacon[row:row + 1]
                    raw = beacon["session"].run(None, {beacon["input_name"]: x_i})[0].flatten()
                    raw_scores.extend(beacon["calibrator"].predict(raw).tolist())
                beacon_preds.update(dict(zip(beacon_indices, raw_scores)))
            except Exception as e:
                log.error(f"Beacon CNN inference error: {e}")

        # Char-CNN consumes actual DNS query names only; no empty-name prediction.
        charcnn_indices = [
            i for i, flow in enumerate(flows)
            if isinstance(flow.get("domain"), str) and flow["domain"].strip()
        ]
        if "charcnn_dns" in self.registry.models and charcnn_indices:
            charcnn = self.registry.models["charcnn_dns"]
            try:
                domains = [flows[i]["domain"] for i in charcnn_indices]
                stats_path = str(self.registry.artifacts_dir / "charcnn" / "feature_stats.npz")
                token_ids, feats = preprocess_charcnn(domains, stats_path)
                for row, flow_index in enumerate(charcnn_indices):
                    prob = charcnn["session"].run(None, {
                        charcnn["input_names"][0]: token_ids[row:row + 1],
                        charcnn["input_names"][1]: feats[row:row + 1],
                    })[0][0]
                    charcnn_preds[flow_index] = prob.tolist()
            except Exception as e:
                log.error(f"CharCNN inference error: {e}")

        # --- Ensemble & Alert Generation ---
        for i, flow in enumerate(flows):
            model_scores: List[ModelScore] = []
            final_threat = None
            final_conf = 0.0
            severity = Severity.LOW
            
            # Helper to add model score
            def add_score(name, score, label, ver):
                model_scores.append(ModelScore(name=name, score=score, label=label, version=ver))
            
            # Check LightGBM
            if i in lgbm_preds:
                p = lgbm_preds[i]
                t_high = 0.1452
                t_rev = 0.0056
                t_iso = 0.0847
                
                if p["bin_prob"] >= t_rev:
                    # Attack detected
                    is_high = p["bin_prob"] >= t_high
                    add_score("lgbm_binary", p["bin_prob"], "ATTACK", "1.0.0")
                    
                    # Get multiclass class
                    # mapping classes from index to string
                    lgbm_classes = ["BENIGN", "Botnet", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slow", "FTP-Patator", "Portscan", "SSH-Patator", "Web Attack"]
                    pred_class_str = lgbm_classes[p["mc_idx"]]
                    add_score("lgbm_multi", p["mc_conf"], pred_class_str, "1.0.0")
                    
                    final_threat = ThreatClass.DDOS if "DoS" in pred_class_str else ThreatClass.SCAN
                    final_conf = p["bin_prob"]
                    severity = Severity.CRITICAL if is_high else Severity.HIGH
                elif p["iso_score"] >= t_iso:
                    # Anomaly detected
                    add_score("iforest", p["iso_score"], "ANOMALY", "1.0.0")
                    final_threat = ThreatClass.ANOMALY
                    final_conf = p["iso_score"]
                    severity = Severity.MEDIUM
                    
            # Check Beacon
            if i in beacon_preds:
                score = beacon_preds[i]
                if score >= 0.4286: # REVIEW threshold
                    is_high = score >= 0.9149
                    add_score("beacon_cnn", score, "C2_BEACON", "1.0.0")
                    if score > final_conf:
                        final_threat = ThreatClass.C2_BEACON
                        final_conf = score
                        severity = Severity.CRITICAL if is_high else Severity.HIGH
                        
            # Check CharCNN
            if i in charcnn_preds:
                probs = charcnn_preds[i]
                dga_score = probs[1]
                tunnel_score = probs[2]
                
                if dga_score >= 0.655:
                    add_score("charcnn_dns", dga_score, "DGA", "5.0.0")
                    if dga_score > final_conf:
                        final_threat = ThreatClass.DGA
                        final_conf = dga_score
                        severity = Severity.CRITICAL
                elif tunnel_score >= 0.100:
                    add_score("charcnn_dns", tunnel_score, "DNS_TUNNEL", "5.0.0")
                    if tunnel_score > final_conf:
                        final_threat = ThreatClass.DNS_TUNNEL
                        final_conf = tunnel_score
                        severity = Severity.CRITICAL
                        
            # Generate Alert if threat found
            if final_threat:
                # Build FiveTuple
                ft = FiveTuple(
                    src_ip=flow.get("Src IP", "0.0.0.0"),
                    src_port=int(flow.get("Src Port", 0)),
                    dst_ip=flow.get("Dst IP", "0.0.0.0"),
                    dst_port=int(flow.get("Dst Port", 0)),
                    proto={"6": "TCP", "17": "UDP"}.get(str(flow.get("Protocol", "0")), str(flow.get("Protocol", "0")))
                )
                
                from datetime import datetime
                alert = Alert(
                    timestamp=datetime.utcnow(),
                    five_tuple=ft,
                    threat_class=final_threat,
                    severity=severity,
                    confidence=float(final_conf),
                    models=model_scores,
                    evidence={
                        "observability": obs_state,
                        **({"sensor": flow["sensor_metadata"]} if flow.get("sensor_metadata") else {}),
                        **({"dns_query_observed": True} if flow.get("domain") else {}),
                    }
                )
                alerts.append(alert.seal())

        return alerts
