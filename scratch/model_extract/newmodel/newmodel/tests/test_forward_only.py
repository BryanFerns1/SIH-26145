"""
Test: Forward-only guarantee.

Verifies that NO reverse-direction field is ever read or used as a model input.
"""
import sys
from pathlib import Path
import pytest
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import (
    is_forbidden, validate_columns, prepare, FORBIDDEN_SUBSTRINGS,
    FORBIDDEN_EXACT_COLUMNS,
)


class TestForwardOnlyGuarantee:
    """Ensure model inputs contain ONLY forward-direction fields."""

    def test_base_features_have_no_forbidden(self):
        """Every base feature must pass the forbidden check."""
        for feat in config.BASE_FEATURES:
            assert not is_forbidden(feat), f"Base feature '{feat}' is forbidden!"

    def test_all_features_have_no_forbidden(self):
        """Every feature (base + derived) must pass the forbidden check."""
        for feat in config.ALL_FEATURES:
            assert not is_forbidden(feat), f"Feature '{feat}' is forbidden!"

    def test_forbidden_columns_are_actually_forbidden(self):
        """Known backward/bidirectional columns MUST be detected as forbidden."""
        known_forbidden = [
            "Total Bwd packets",
            "Total Length of Bwd Packet",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Bwd PSH Flags",
            "Bwd URG Flags",
            "Bwd RST Flags",
            "Bwd Header Length",
            "Bwd Packets/s",
            "Bwd Segment Size Avg",
            "Bwd Bytes/Bulk Avg",
            "Bwd Packet/Bulk Avg",
            "Bwd Bulk Rate Avg",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "Bwd Init Win Bytes",
            "Down/Up Ratio",
            "Packet Length Min",      # bidirectional aggregate
            "Packet Length Max",      # bidirectional aggregate
            "Packet Length Mean",     # bidirectional aggregate
            "Packet Length Std",      # bidirectional aggregate
            "Packet Length Variance", # bidirectional aggregate
            "Average Packet Size",   # bidirectional aggregate
            "Flow IAT Mean",         # bidirectional aggregate
            "Flow IAT Std",          # bidirectional aggregate
            "Flow IAT Max",          # bidirectional aggregate
            "Flow IAT Min",          # bidirectional aggregate
            "Flow Bytes/s",          # includes backward in computation
            "Flow Packets/s",        # includes backward in computation
        ]
        for col in known_forbidden:
            assert is_forbidden(col), f"Column '{col}' SHOULD be forbidden but is NOT!"

    def test_no_raw_ip_or_port_in_features(self):
        """Raw IPs and ports must never appear as model input features."""
        forbidden_identity = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Flow ID"]
        for feat in config.ALL_FEATURES:
            for identity in forbidden_identity:
                assert identity.lower() not in feat.lower(), \
                    f"Feature '{feat}' contains raw identity '{identity}'!"

    def test_validate_columns_raises_on_backward(self):
        """validate_columns() must raise ValueError for backward columns."""
        with pytest.raises(ValueError, match="FORBIDDEN"):
            validate_columns(["Total Fwd Packet", "Total Bwd packets"])

    def test_validate_columns_passes_forward(self):
        """validate_columns() should NOT raise for forward-only columns."""
        validate_columns(config.BASE_FEATURES)  # should not raise
        validate_columns(config.ALL_FEATURES)   # should not raise

    def test_prepare_rejects_forbidden_base_features(self):
        """prepare() must refuse to use forbidden base features."""
        # SYNTHETIC test data
        df = pd.DataFrame({
            "Total Fwd Packet": [10, 20],
            "Total Bwd packets": [5, 10],  # FORBIDDEN
        })
        with pytest.raises(ValueError):
            prepare(
                df,
                base_features=["Total Fwd Packet", "Total Bwd packets"],
                all_features=["Total Fwd Packet", "Total Bwd packets"],
                derived=False,
                validate=True,
            )

    def test_forward_only_features_are_all_fwd_prefixed_or_neutral(self):
        """
        Each base feature should either:
        - Start with 'Fwd' or 'FWD'
        - Be a known direction-neutral field (flag counts, Flow Duration)
        - Be a derived feature (starts with 'd_')
        """
        neutral_fields = {
            "Flow Duration",
            "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
            "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        }
        for feat in config.BASE_FEATURES:
            feat_lower = feat.lower()
            is_fwd = (
                feat_lower.startswith("fwd") or
                feat_lower.startswith("total fwd") or
                feat_lower.startswith("total length of fwd") or
                feat_lower.startswith("subflow fwd")
            )
            is_neutral = feat in neutral_fields
            assert is_fwd or is_neutral, \
                f"Base feature '{feat}' is neither Fwd-prefixed nor neutral!"

    def test_derived_features_all_start_with_d_prefix(self):
        """All derived features must start with 'd_' prefix."""
        for feat in config.DERIVED_FEATURES:
            assert feat.startswith("d_"), \
                f"Derived feature '{feat}' doesn't start with 'd_'!"
