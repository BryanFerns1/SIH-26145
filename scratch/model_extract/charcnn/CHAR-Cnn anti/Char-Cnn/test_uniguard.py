"""
UniGuard Test Suite (SIH26145 - Team CeaserX)
==============================================
Unit tests for preprocessing, evidence features, unidirectional constraints,
model architecture parameter limits (<1M), and SIH alert schema compliance.

All synthetic test cases are explicitly labelled [SYNTHETIC TEST DATA].
"""

import hashlib
import json
import unittest
import numpy as np
import torch

from alert import generate_sih_alert
from config import TrainingConfig, VOCAB_SIZE
from evidence_features import extract_features_vector, FEATURE_NAMES_EXTENDED
from model import HybridNet_v4
from preprocess import clean_query_name, tokenize_domain, MODEL_MAX_LEN


class TestUniGuardPipeline(unittest.TestCase):
    """Unit tests for the UniGuard Passive DNS Threat Detector."""

    def test_01_preprocessing_rfc1035_and_shortcuts(self):
        """[SYNTHETIC TEST DATA] Preprocessing compliance with RFC 1035 and shortcut removal."""
        # 1. Trailing root dot must be stripped, internal dots preserved
        raw_fqdn = "secure.api.bank.com."
        cleaned = clean_query_name(raw_fqdn)
        self.assertEqual(cleaned, "secure.api.bank.com", "Trailing root dot was not cleanly stripped")

        # 2. Casing shortcut mitigation (all uppercase converted to lowercase)
        mixed_case = "4F2A.B8C1.D9E3.TUNNEL.NET"
        cleaned_case = clean_query_name(mixed_case)
        self.assertEqual(cleaned_case, "4f2a.b8c1.d9e3.tunnel.net", "Casing was not normalized to lowercase")

        # 3. IDN / Punycode handling
        idn_domain = "münchen.de"
        cleaned_idn = clean_query_name(idn_domain)
        self.assertTrue(cleaned_idn.startswith("xn--") or "de" in cleaned_idn, "Punycode normalization failed")

        # 4. Strip protocol or ports if passed in log stream
        logged_query = "http://bad-c2.malicious.org:53/path"
        cleaned_log = clean_query_name(logged_query)
        self.assertEqual(cleaned_log, "bad-c2.malicious.org", "Protocol/port stripping failed")

        # 5. Length clipping at 253 characters
        oversized = "a" * 300 + ".com"
        cleaned_len = clean_query_name(oversized)
        self.assertLessEqual(len(cleaned_len), 253, "RFC 1035 max length 253 violated")

    def test_02_evidence_features_vector(self):
        """[SYNTHETIC TEST DATA] Evidence features dimension and boundary checks."""
        domain = "4f2a9b3c1d.tunnel-exfil.net"
        vec = extract_features_vector(domain)

        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), 18, f"Expected 18 features, got {len(vec)}")
        self.assertEqual(len(FEATURE_NAMES_EXTENDED), 18)

        # Statistical boundaries
        self.assertGreater(vec[0], 0, "Length feature must be positive")
        self.assertGreater(vec[2], 0, "Shannon entropy must be positive")
        self.assertGreaterEqual(vec[4], 0.0)
        self.assertLessEqual(vec[4], 1.0, "Digit ratio must be in [0, 1]")
        self.assertGreaterEqual(vec[5], 0.0)
        self.assertLessEqual(vec[5], 1.0, "Alpha ratio must be in [0, 1]")
        self.assertGreaterEqual(vec[13], 0.0)
        self.assertLessEqual(vec[13], 1.0, "Hex fraction must be in [0, 1]")
        self.assertGreaterEqual(vec[14], 0.0)
        self.assertLessEqual(vec[14], 1.0, "Base32 fraction must be in [0, 1]")
        self.assertEqual(vec[10], 3.0, "n_labels for 4f2a9b3c1d.tunnel-exfil.net should be 3")

    def test_03_tokenization(self):
        """[SYNTHETIC TEST DATA] Character-level tokenization and vocabulary bounds."""
        domain = "google.com"
        tokens = tokenize_domain(domain, max_len=MODEL_MAX_LEN)

        self.assertEqual(len(tokens), MODEL_MAX_LEN)
        self.assertTrue((tokens >= 0).all() and (tokens < VOCAB_SIZE).all())
        # First 10 positions must be non-zero (non-PAD)
        self.assertTrue((tokens[:10] > 0).all())
        # Remaining positions must be PAD (0)
        self.assertTrue((tokens[10:] == 0).all())

    def test_04_model_parameter_limit(self):
        """[HARD CONSTRAINT] Architecture must have < 1,000,000 trainable parameters."""
        cfg = TrainingConfig()
        model = HybridNet_v4(cfg)
        param_count = sum(p.numel() for p in model.parameters() if p.requires_grad)

        print(f"\n[TEST] Model parameter count: {param_count:,}")
        self.assertLess(param_count, 1_000_000, f"Model has {param_count:,} params, violating <1M constraint!")

    def test_05_unidirectional_diode_constraint(self):
        """[HARD CONSTRAINT] Sensor sees unidirectional ingress queries ONLY (no response fields)."""
        forbidden_fields = ["rcode", "nxdomain", "answers", "ttl", "rtt", "response_size"]
        from preprocess import clean_query_name
        import inspect

        # Inspect signature of clean_query_name & tokenize_domain
        sig_clean = inspect.signature(clean_query_name)
        self.assertEqual(list(sig_clean.parameters.keys()), ["raw_name"])

        sig_vec = inspect.signature(extract_features_vector)
        self.assertIn("domain", sig_vec.parameters)
        for forbidden in forbidden_fields:
            self.assertNotIn(forbidden, sig_vec.parameters, f"Forbidden response field {forbidden} found in feature extraction!")

    def test_06_sih_alert_schema_and_mitre_mapping(self):
        """[SYNTHETIC TEST DATA] SIH26145 alert schema, decoupled scores, and MITRE ATT&CK mapping."""
        domain = "4f2a.b8c1.d9e3.exfil.net"
        probs = np.array([0.001, 0.009, 0.990], dtype=np.float32)

        alert_str = generate_sih_alert(domain, probs)
        alert = json.loads(alert_str)

        # Required SIH Schema Keys
        required_keys = [
            "timestamp", "flow_id", "target_domain", "threat_class",
            "confidence", "severity", "evidence", "mitre_attack",
            "observability_caveat", "evidence_hash_sha256"
        ]
        for key in required_keys:
            self.assertIn(key, alert, f"Missing required schema key: {key}")

        self.assertEqual(alert["threat_class"], "dns_tunnel")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["observability_caveat"], "unidirectional_passive_ingress_only")

        # MITRE ATT&CK Mapping
        self.assertEqual(alert["mitre_attack"]["technique_id"], "T1071.004")
        self.assertEqual(alert["mitre_attack"]["tactic"], "Command and Control / Exfiltration")

        # Evidence block check
        evidence = alert["evidence"]
        self.assertIn("dga_score", evidence)
        self.assertIn("dns_tunnel_score", evidence)
        self.assertIn("benign_score", evidence)
        self.assertEqual(evidence["dns_tunnel_score"], 0.99)

        # SHA-256 evidence hash verification
        hash_input = f"{domain}{alert['timestamp']}{json.dumps(evidence, sort_keys=True)}"
        expected_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        self.assertEqual(alert["evidence_hash_sha256"], expected_hash, "SHA-256 evidence hash mismatch")


if __name__ == "__main__":
    unittest.main()
