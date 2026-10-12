"""
Char-CNN v4 — SIH Alert Schema Serializer
===========================================
Generates JSON alerts compliant with the SIH26145 specification,
including decoupled threat scores, MITRE ATT&CK mapping,
SHA-256 evidence hashing, and observability caveats.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import numpy as np

from config import IDX2LABEL, MITRE_MAP, SEVERITY_THRESHOLDS
from evidence_features import extract_features_vector


def _severity(confidence: float) -> str:
    """Map confidence score to severity label."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if confidence >= threshold:
            return label
    return "LOW"


def generate_sih_alert(
    domain_name: str,
    probabilities: np.ndarray,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a SIH26145-compliant JSON alert string.

    Parameters
    ----------
    domain_name : str
        The queried FQDN.
    probabilities : np.ndarray
        Calibrated probability array of shape (3,) — [benign, dga, dns_tunnel].
    metadata : dict, optional
        Additional metadata to merge into the alert.

    Returns
    -------
    str : Serialised JSON alert.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    flow_id = str(uuid.uuid4())

    # Predicted class
    pred_idx = int(np.argmax(probabilities))
    threat_class = IDX2LABEL[pred_idx]
    confidence = float(probabilities[pred_idx])
    severity = _severity(confidence)

    # Lexical features for evidence enrichment
    feats = extract_features_vector(domain_name)

    evidence = {
        "dga_score": round(float(probabilities[1]), 6),
        "dns_tunnel_score": round(float(probabilities[2]), 6),
        "benign_score": round(float(probabilities[0]), 6),
        "subdomain_depth": int(feats[10]),      # n_labels
        "entropy": round(float(feats[2]), 4),   # Shannon entropy
    }

    # MITRE ATT&CK mapping
    mitre = MITRE_MAP.get(threat_class, MITRE_MAP["benign"])

    # SHA-256 evidence hash
    hash_input = f"{domain_name}{timestamp}{json.dumps(evidence, sort_keys=True)}"
    evidence_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

    alert = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "target_domain": domain_name,
        "threat_class": threat_class,
        "confidence": round(confidence, 6),
        "severity": severity,
        "evidence": evidence,
        "mitre_attack": mitre,
        "observability_caveat": "unidirectional_passive_ingress_only",
        "evidence_hash_sha256": evidence_hash,
    }

    # Merge optional metadata
    if metadata:
        alert["metadata"] = metadata

    return json.dumps(alert, indent=2)
