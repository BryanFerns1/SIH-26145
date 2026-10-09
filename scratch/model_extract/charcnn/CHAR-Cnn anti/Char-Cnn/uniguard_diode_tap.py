"""
UniGuard Unidirectional Data Diode / TAP Integration Wrapper
============================================================
Smart India Hackathon 2026 (SIH26145) - Team CeaserX

Purpose:
  Monitors UNIDIRECTIONAL traffic from a receive-only TAP / data diode.
  The sensor sees client->server direction ONLY.
  Server DNS responses (RCODE, NXDOMAIN, answer records, TTL, response size)
  are physically NEVER visible.

Capabilities:
  1. Passive ingress query packet parser (Ethernet/IP/UDP/DNS port 53).
  2. Strict query-side-only constraint validation (rejects response attributes).
  3. High-throughput batched inference using ONNX Runtime or PyTorch.
  4. SIH26145 JSON alert generator with MITRE ATT&CK and SHA-256 evidence hashing.
"""

import hashlib
import json
import os
import sys
import time
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.getcwd() != SCRIPT_DIR:
    os.chdir(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import numpy as np

try:
    import dpkt
    _HAS_DPKT = True
except ImportError:
    _HAS_DPKT = False

try:
    import onnxruntime as ort
    _HAS_ORT = True
except ImportError:
    _HAS_ORT = False

import torch
from config import IDX2LABEL, LABEL2IDX, MITRE_MAP, SEVERITY_THRESHOLDS
from evidence_features import extract_features_vector
from preprocess import clean_query_name, tokenize_domain, MODEL_MAX_LEN


class UniGuardDiodeEngine:
    """
    Production-grade passive DNS threat detector for unidirectional taps.
    """
    def __init__(
        self,
        onnx_model_path: str = "outputs/uniguard_charcnn.onnx",
        stats_path: str = "outputs/feature_stats.npz",
        thresholds_path: Optional[str] = "outputs/thresholds.json",
        use_onnx: bool = True,
    ):
        self.use_onnx = use_onnx and _HAS_ORT and os.path.isfile(onnx_model_path)
        
        # Load feature normalization stats
        if not os.path.isfile(stats_path):
            raise FileNotFoundError(f"Feature statistics not found at {stats_path}")
        stats = np.load(stats_path)
        self.feat_mean = stats["mean"]
        self.feat_std = np.where(stats["std"] < 1e-8, 1.0, stats["std"])

        # Load thresholds if available
        self.dga_threshold = 0.50
        self.tunnel_threshold = 0.50
        if thresholds_path and os.path.isfile(thresholds_path):
            try:
                with open(thresholds_path, "r") as f:
                    th = json.load(f)
                    if th.get("dga_threshold"):
                        self.dga_threshold = float(th["dga_threshold"])
                    if th.get("tunnel_threshold"):
                        self.tunnel_threshold = float(th["tunnel_threshold"])
            except Exception:
                pass

        # Initialize inference engine
        if self.use_onnx:
            print(f"[UniGuard TAP] Initializing ONNX Runtime engine: {onnx_model_path}")
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = 4
            self.session = ort.InferenceSession(onnx_model_path, opts, providers=["CPUExecutionProvider"])
        else:
            print(f"[UniGuard TAP] Initializing PyTorch fallback engine")
            from predict import load_model_and_artifacts
            self.model, self.temp_scaler, _, _, self.cfg = load_model_and_artifacts()
            self.session = None

    def classify_queries(self, raw_queries: List[str]) -> List[Dict[str, Any]]:
        """
        Batch-classify raw query names (QNAME).
        Returns list of classification dicts with threat_class, confidence, and probabilities.
        """
        if not raw_queries:
            return []

        cleaned_domains = [clean_query_name(q) for q in raw_queries]

        # Extract tokens and normalized features
        tokens = np.stack([tokenize_domain(d, max_len=MODEL_MAX_LEN) for d in cleaned_domains], axis=0)
        raw_feats = np.stack([extract_features_vector(d) for d in cleaned_domains], axis=0)
        norm_feats = (raw_feats - self.feat_mean) / self.feat_std

        if self.use_onnx:
            ort_inputs = {
                "token_ids": tokens.astype(np.int64),
                "lexical_features": norm_feats.astype(np.float32),
            }
            probs = self.session.run(["probabilities"], ort_inputs)[0]
        else:
            with torch.no_grad():
                t_tokens = torch.from_numpy(tokens).long()
                t_feats = torch.from_numpy(norm_feats).float()
                logits = self.model(t_tokens, t_feats)
                scaled_logits = self.temp_scaler(logits)
                probs = torch.softmax(scaled_logits, dim=-1).cpu().numpy()

        results = []
        for i, domain in enumerate(cleaned_domains):
            p = probs[i]
            # Decision threshold logic
            if p[2] >= self.tunnel_threshold and p[2] >= p[1]:
                threat = "dns_tunnel"
                conf = float(p[2])
            elif p[1] >= self.dga_threshold:
                threat = "dga"
                conf = float(p[1])
            else:
                threat = "benign"
                conf = float(p[0])

            results.append({
                "domain": domain,
                "threat_class": threat,
                "confidence": conf,
                "probabilities": {
                    "benign": round(float(p[0]), 6),
                    "dga": round(float(p[1]), 6),
                    "dns_tunnel": round(float(p[2]), 6),
                },
                "raw_feats": raw_feats[i],
            })

        return results

    def generate_alert(
        self,
        domain: str,
        probs: Dict[str, float],
        threat_class: str,
        confidence: float,
        raw_feats: np.ndarray,
        packet_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Format a single threat detection into the standardized SIH26145 alert schema.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        flow_id = str(uuid.uuid4())

        severity = "LOW"
        for thresh, label in SEVERITY_THRESHOLDS:
            if confidence >= thresh:
                severity = label
                break

        evidence = {
            "dga_score": probs["dga"],
            "dns_tunnel_score": probs["dns_tunnel"],
            "benign_score": probs["benign"],
            "subdomain_depth": int(raw_feats[10]),      # n_labels
            "shannon_entropy": round(float(raw_feats[2]), 4),
            "max_consonant_run": int(raw_feats[7]),
            "digit_ratio": round(float(raw_feats[4]), 4),
            "hex_fraction": round(float(raw_feats[13]), 4),
        }

        mitre = MITRE_MAP.get(threat_class, MITRE_MAP["benign"])
        hash_input = f"{domain}{timestamp}{json.dumps(evidence, sort_keys=True)}"
        evidence_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        alert = {
            "timestamp": timestamp,
            "flow_id": flow_id,
            "target_domain": domain,
            "threat_class": threat_class,
            "confidence": round(confidence, 6),
            "severity": severity,
            "evidence": evidence,
            "mitre_attack": mitre,
            "observability_caveat": "unidirectional_passive_ingress_only",
            "evidence_hash_sha256": evidence_hash,
        }
        if packet_metadata:
            alert["diode_metadata"] = packet_metadata

        return alert

    def process_pcap_stream(
        self,
        pcap_path: str,
        batch_size: int = 256,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Process a PCAP file captured on the unidirectional TAP interface.
        Extracts only query-side DNS packets.
        """
        if not _HAS_DPKT:
            raise RuntimeError("dpkt package required for pcap processing")

        queries = []
        metadata_list = []

        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.udp.UDP):
                        continue
                    udp = ip.data
                    if udp.dport != 53 and udp.sport != 53:
                        continue

                    dns = dpkt.dns.DNS(udp.data)
                    # HARD CONSTRAINT: Only inspect client queries (qr == 0)
                    # Server responses (qr == 1) must NEVER be processed
                    if dns.qr != 0 or len(dns.qd) == 0:
                        continue

                    qname = dns.qd[0].name
                    queries.append(qname)
                    metadata_list.append({
                        "src_ip": f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}",
                        "dst_ip": f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}",
                        "qtype": int(dns.qd[0].type),
                        "pkt_timestamp": ts,
                    })

                    if len(queries) >= batch_size:
                        batch_res = self.classify_queries(queries)
                        for r, meta in zip(batch_res, metadata_list):
                            if r["threat_class"] != "benign":
                                yield self.generate_alert(
                                    domain=r["domain"],
                                    probs=r["probabilities"],
                                    threat_class=r["threat_class"],
                                    confidence=r["confidence"],
                                    raw_feats=r["raw_feats"],
                                    packet_metadata=meta,
                                )
                        queries.clear()
                        metadata_list.clear()

                except Exception:
                    continue

            # Process remaining
            if queries:
                batch_res = self.classify_queries(queries)
                for r, meta in zip(batch_res, metadata_list):
                    if r["threat_class"] != "benign":
                        yield self.generate_alert(
                            domain=r["domain"],
                            probs=r["probabilities"],
                            threat_class=r["threat_class"],
                            confidence=r["confidence"],
                            raw_feats=r["raw_feats"],
                            packet_metadata=meta,
                        )


def simulate_stream_demo():
    print("=" * 64)
    print("UniGuard Data Diode / TAP Stream Simulation")
    print("=" * 64)
    engine = UniGuardDiodeEngine()

    test_stream = [
        "www.google.com",
        "api.github.com",
        "v4ml7xko7pcz1dpiso31xwi4lm.org",
        "0100abcd1234567890abcdef.tunnel-exfil.net",
        "r5r5sp3et32.biz",
        "d111111abcdef8.cloudfront.net",
        "4f2ab8c1d9e3.dns-exfil.net",
        "ec2-54-123-45-67.compute-1.amazonaws.com",
    ]

    print(f"\nProcessing stream of {len(test_stream)} DNS queries...")
    results = engine.classify_queries(test_stream)

    alerts = []
    for r in results:
        print(f"\n[{r['threat_class'].upper():10s}] {r['domain'][:35]:35s} | Conf: {r['confidence']:.4f} | P: {r['probabilities']}")
        if r["threat_class"] != "benign":
            alert = engine.generate_alert(
                domain=r["domain"],
                probs=r["probabilities"],
                threat_class=r["threat_class"],
                confidence=r["confidence"],
                raw_feats=r["raw_feats"],
                packet_metadata={"interface": "tap0", "direction": "ingress_only"},
            )
            alerts.append(alert)

    print(f"\nGenerated {len(alerts)} SIH Security Alerts:")
    for a in alerts[:2]:
        print("\n--- SIH ALERT SAMPLE ---")
        print(json.dumps(a, indent=2))


if __name__ == "__main__":
    simulate_stream_demo()
