"""
Unit tests for UniGuard 1D CNN Beacon Detector.

Tests:
1. Forward-only guarantee: no reverse-direction fields are ever read
2. Preprocessing determinism
3. Padding/mask correctness
4. Detector wrapper on empty input
5. ONNX parity (if model exists)
"""

import os
import sys
import json
import numpy as np
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from preprocessing import (
    preprocess_variant_a, preprocess_variant_b, build_beacon_series,
    compute_evidence_hash, compute_lomb_scargle_score,
    DEFAULT_META, perturb_packet_sizes, perturb_timing,
)
from uniflow_extractor import UniFlow, _FlowState


# ---------------------------------------------------------------------------
# Test Data Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_flows():
    """Create sample flow dicts for testing."""
    return [
        {
            'src_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'proto': 6,
            'start_time': 1000.0,
            'end_time': 1001.0,
            'duration': 1.0,
            'fwd_packets': 5,
            'fwd_bytes': 500,
            'pkt_sizes': [100, 200, 150, 50, 100],
            'pkt_timestamps': [1000.0, 1000.1, 1000.3, 1000.5, 1001.0],
            'pkt_tcp_flags': [0x02, 0x18, 0x18, 0x18, 0x01],  # SYN, PSH+ACK, ..., FIN
            'label': 1,
            'scenario_id': 1,
        },
        {
            'src_ip': '10.0.0.2',
            'src_port': 54321,
            'dst_ip': '192.168.1.2',
            'dst_port': 443,
            'proto': 6,
            'start_time': 2000.0,
            'end_time': 2000.5,
            'duration': 0.5,
            'fwd_packets': 3,
            'fwd_bytes': 300,
            'pkt_sizes': [100, 100, 100],
            'pkt_timestamps': [2000.0, 2000.2, 2000.5],
            'pkt_tcp_flags': [0x02, 0x18, 0x01],
            'label': 0,
            'scenario_id': 1,
        },
    ]


@pytest.fixture
def empty_flow():
    """A flow with no packets."""
    return {
        'src_ip': '10.0.0.3',
        'src_port': 0,
        'dst_ip': '10.0.0.4',
        'dst_port': 0,
        'proto': 17,
        'start_time': 3000.0,
        'end_time': 3000.0,
        'duration': 0.0,
        'fwd_packets': 0,
        'fwd_bytes': 0,
        'pkt_sizes': [],
        'pkt_timestamps': [],
        'pkt_tcp_flags': [],
        'label': 0,
        'scenario_id': 1,
    }


@pytest.fixture
def short_flow():
    """A flow with only 1 packet."""
    return {
        'src_ip': '10.0.0.5',
        'src_port': 1111,
        'dst_ip': '10.0.0.6',
        'dst_port': 53,
        'proto': 17,
        'start_time': 4000.0,
        'end_time': 4000.0,
        'duration': 0.0,
        'fwd_packets': 1,
        'fwd_bytes': 64,
        'pkt_sizes': [64],
        'pkt_timestamps': [4000.0],
        'pkt_tcp_flags': [0],
        'label': 0,
        'scenario_id': 1,
    }


# ---------------------------------------------------------------------------
# Test 1: Forward-only guarantee
# ---------------------------------------------------------------------------

class TestForwardOnlyGuarantee:
    """Assert no reverse-direction field is ever read."""

    FORBIDDEN_FIELDS = [
        'dst_bytes', 'dst_packets', 'reverse_bytes', 'reverse_packets',
        'rev_bytes', 'rev_packets', 'resp_bytes', 'resp_packets',
        'dTos', 'reply_flags', 'Dir', 'direction',
        'State', 'tcp_state', 'SrcRatio', 'src_ratio',
        'DstBytes', 'DstPkts', 'rev_pkt_sizes', 'rev_timestamps',
        'backward_packets', 'backward_bytes', 'bwd_packets', 'bwd_bytes',
    ]

    def test_uniflow_has_no_reverse_fields(self):
        """UniFlow dataclass must not have reverse-direction fields."""
        flow = UniFlow(
            src_ip='10.0.0.1', src_port=1234,
            dst_ip='10.0.0.2', dst_port=80, proto=6,
        )
        for field in self.FORBIDDEN_FIELDS:
            assert not hasattr(flow, field), \
                f"UniFlow has forbidden field: {field}"

    def test_flow_state_has_no_reverse_fields(self):
        """_FlowState must not have reverse-direction fields."""
        state = _FlowState('10.0.0.1', 1234, '10.0.0.2', 80, 6,
                            1000.0, 100, 0)
        for field in self.FORBIDDEN_FIELDS:
            assert not hasattr(state, field), \
                f"_FlowState has forbidden field: {field}"

    def test_preprocessing_uses_only_forward_fields(self, sample_flows):
        """Preprocessing must only access forward-direction fields."""
        # Create a flow dict with ONLY forward fields
        forward_only = {
            'pkt_sizes': [100, 200],
            'pkt_timestamps': [1000.0, 1000.1],
            'pkt_tcp_flags': [0x02, 0x18],
            'fwd_bytes': 300,
            'fwd_packets': 2,
            'start_time': 1000.0,
            'label': 0,
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'dst_port': 80,
            'proto': 6,
        }
        # This should work without errors
        X = preprocess_variant_a([forward_only], DEFAULT_META, True)
        assert X.shape == (1, 32, 7)

    def test_no_ip_port_in_model_input(self, sample_flows):
        """Model input must not contain raw IPs or ports."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        # Check that no channel contains IP-like values (>65535 would be sus)
        # Actually, IPs are strings so can't be in numpy array.
        # Ports would be integers up to 65535.
        # The preprocessing should only have log-scaled values and flags.
        assert X.max() <= 2.0, "Input values suspiciously large (possible raw port/IP)"
        assert X.min() >= 0.0, "Input values should be non-negative"

    def test_source_code_no_forbidden_imports(self):
        """Check that preprocessing.py doesn't reference forbidden fields."""
        import inspect
        from preprocessing import preprocess_variant_a, preprocess_variant_b

        source_a = inspect.getsource(preprocess_variant_a)
        source_b = inspect.getsource(preprocess_variant_b)

        for field in ['dst_bytes', 'reverse_bytes', 'backward_bytes',
                      'rev_bytes', 'Dir_', 'State_', 'SrcRatio',
                      'dTos', 'reply_flag']:
            assert field not in source_a, \
                f"preprocess_variant_a references forbidden field: {field}"
            assert field not in source_b, \
                f"preprocess_variant_b references forbidden field: {field}"


# ---------------------------------------------------------------------------
# Test 2: Preprocessing determinism
# ---------------------------------------------------------------------------

class TestPreprocessingDeterminism:
    """Preprocessing must be deterministic (same input -> same output)."""

    def test_variant_a_deterministic(self, sample_flows):
        """Running preprocessing twice gives identical results."""
        X1 = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        X2 = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        np.testing.assert_array_equal(X1, X2)

    def test_variant_a_no_tcp_flags_deterministic(self, sample_flows):
        """Same test without TCP flags."""
        X1 = preprocess_variant_a(sample_flows, DEFAULT_META, False)
        X2 = preprocess_variant_a(sample_flows, DEFAULT_META, False)
        np.testing.assert_array_equal(X1, X2)

    def test_evidence_hash_deterministic(self, sample_flows):
        """Evidence hash must be reproducible."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        h1 = compute_evidence_hash(X[0])
        h2 = compute_evidence_hash(X[0])
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# Test 3: Padding and mask correctness
# ---------------------------------------------------------------------------

class TestPaddingMask:
    """Test zero-padding and mask channel correctness."""

    def test_short_flow_padding(self, short_flow):
        """Short flows should be zero-padded with mask=0."""
        X = preprocess_variant_a([short_flow], DEFAULT_META, True)
        # Only position 0 should have mask=1
        assert X[0, 0, 2] == 1.0, "First packet should have mask=1"
        for j in range(1, 32):
            assert X[0, j, 2] == 0.0, f"Position {j} should have mask=0 (padded)"
            assert X[0, j, 0] == 0.0, f"Position {j} should have size=0 (padded)"
            assert X[0, j, 1] == 0.0, f"Position {j} should have IAT=0 (padded)"

    def test_empty_flow_all_padded(self, empty_flow):
        """Empty flows should be all zeros."""
        X = preprocess_variant_a([empty_flow], DEFAULT_META, True)
        assert np.allclose(X[0], 0.0), "Empty flow should be all zeros"

    def test_full_flow_no_padding(self):
        """Flow with exactly 32 packets should have no padding."""
        flow = {
            'pkt_sizes': [100] * 32,
            'pkt_timestamps': [1000.0 + i * 0.1 for i in range(32)],
            'pkt_tcp_flags': [0x18] * 32,
            'label': 0,
        }
        X = preprocess_variant_a([flow], DEFAULT_META, True)
        # All mask positions should be 1
        for j in range(32):
            assert X[0, j, 2] == 1.0, f"Position {j} should have mask=1"

    def test_overflow_flow_truncated(self):
        """Flow with > 32 packets should be truncated to 32."""
        flow = {
            'pkt_sizes': [100] * 50,
            'pkt_timestamps': [1000.0 + i * 0.1 for i in range(50)],
            'pkt_tcp_flags': [0x18] * 50,
            'label': 0,
        }
        X = preprocess_variant_a([flow], DEFAULT_META, True)
        assert X.shape == (1, 32, 7)
        # All positions should have mask=1 (first 32 of 50)
        for j in range(32):
            assert X[0, j, 2] == 1.0

    def test_packet_size_scaling(self, sample_flows):
        """Packet sizes should be log1p-scaled with fixed constant."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        scale = DEFAULT_META['pkt_size_log_scale']
        expected = np.log1p(100) * scale  # first packet of first flow is 100 bytes
        np.testing.assert_almost_equal(X[0, 0, 0], expected, decimal=5)

    def test_iat_first_packet_zero(self, sample_flows):
        """IAT for the first packet should always be 0."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        for i in range(len(sample_flows)):
            assert X[i, 0, 1] == 0.0, "First packet IAT should be 0"

    def test_tcp_flags_extraction(self, sample_flows):
        """TCP flags should be correctly extracted."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        # First flow, first packet has SYN (0x02)
        assert X[0, 0, 3] == 1.0, "SYN flag should be 1"
        assert X[0, 0, 4] == 0.0, "FIN flag should be 0"
        assert X[0, 0, 5] == 0.0, "RST flag should be 0"
        assert X[0, 0, 6] == 0.0, "PSH flag should be 0"

        # First flow, last packet has FIN (0x01)
        assert X[0, 4, 3] == 0.0, "SYN should be 0"
        assert X[0, 4, 4] == 1.0, "FIN should be 1"


# ---------------------------------------------------------------------------
# Test 4: Detector wrapper on empty input
# ---------------------------------------------------------------------------

class TestDetectorWrapper:
    """Test BeaconCNNDetector handles edge cases."""

    def test_empty_input_returns_empty(self):
        """predict([]) should return []."""
        from stage6_export import BeaconCNNDetector
        # Create with non-existent model dir (will have no ONNX)
        detector = BeaconCNNDetector("nonexistent_model_dir")
        result = detector.predict([])
        assert result == []

    def test_malformed_input_no_crash(self):
        """Malformed input should not raise, return empty detections."""
        from stage6_export import BeaconCNNDetector
        detector = BeaconCNNDetector("nonexistent_model_dir")
        result = detector.predict([{"garbage": True}])
        assert len(result) == 1
        assert result[0].score == 0.0
        assert result[0].tier is None

    def test_detection_fields(self):
        """Detection dataclass should have all required fields."""
        from stage6_export import Detection
        d = Detection(
            threat_class="Botnet C2 beaconing",
            score=0.95,
            tier="HIGH",
            detector="cnn1d_beacon",
            observability="uniflow_fwd_only",
            evidence_hash="abc123",
        )
        assert d.threat_class == "Botnet C2 beaconing"
        assert d.mitre_id == "T1071"
        assert d.detector == "cnn1d_beacon"
        assert d.observability == "uniflow_fwd_only"


# ---------------------------------------------------------------------------
# Test 5: ONNX parity (conditional on model existence)
# ---------------------------------------------------------------------------

class TestONNXParity:
    """Test ONNX model parity with Keras (skipped if no model)."""

    @pytest.fixture
    def model_dir(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "model_bundle")

    def test_onnx_parity(self, model_dir):
        """ONNX and Keras outputs must match within 1e-4."""
        onnx_path = os.path.join(model_dir, "model.onnx")
        keras_path = os.path.join(model_dir, "model.keras")

        if not os.path.exists(onnx_path) or not os.path.exists(keras_path):
            pytest.skip("Model files not found")

        sample_path = os.path.join(model_dir, "sample_inputs.npy")
        if not os.path.exists(sample_path):
            pytest.skip("Sample inputs not found")

        from stage6_export import onnx_parity_test
        sample_inputs = np.load(sample_path)
        result = onnx_parity_test(keras_path, onnx_path, sample_inputs)
        assert result['passed'], \
            f"ONNX parity failed: max_diff={result['max_abs_diff']}"


# ---------------------------------------------------------------------------
# Test: Lomb-Scargle
# ---------------------------------------------------------------------------

class TestLombScargle:
    def test_periodic_signal_high_score(self):
        """A perfectly periodic series of flows should have high LS score."""
        flows = []
        import random
        for i in range(20):
            flows.append({'start_time': 1000.0 + i * 60.0 + random.uniform(-0.1, 0.1)})  # every 60 seconds with noise
        score = compute_lomb_scargle_score(flows)
        assert score > 0.3, f"Periodic signal should have high LS score, got {score}"

    def test_too_few_flows(self):
        """Less than 4 flows should return 0."""
        flows = [{'start_time': 1000.0}, {'start_time': 1001.0}]
        score = compute_lomb_scargle_score(flows)
        assert score == 0.0


# ---------------------------------------------------------------------------
# Test: Perturbation functions
# ---------------------------------------------------------------------------

class TestPerturbation:
    def test_perturb_sizes_changes_values(self, sample_flows):
        """Packet size perturbation should change values."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        X_pert = perturb_packet_sizes(X, random_pad_range=(100, 200))
        # Original and perturbed should differ where mask=1
        mask = X[:, :, 2] > 0
        assert not np.allclose(X[mask, 0], X_pert[mask, 0])

    def test_perturb_timing_changes_values(self, sample_flows):
        """Timing perturbation should change IAT values."""
        X = preprocess_variant_a(sample_flows, DEFAULT_META, True)
        X_pert = perturb_timing(X, jitter_magnitude_us=1e5)
        # Check that some IAT values changed (not all, since j=0 is always 0)
        assert not np.allclose(X[:, 1:, 1], X_pert[:, 1:, 1])


# ---------------------------------------------------------------------------
# Test: Alert formatting
# ---------------------------------------------------------------------------

class TestAlertFormat:
    def test_format_alert_has_all_fields(self):
        """format_alert should produce all required fields."""
        from stage6_export import Detection, format_alert
        d = Detection(
            threat_class="Botnet C2 beaconing",
            score=0.9,
            tier="HIGH",
            detector="cnn1d_beacon",
            observability="uniflow_fwd_only",
            evidence_hash="abc",
        )
        flow = {
            'src_ip': '10.0.0.1', 'src_port': 1234,
            'dst_ip': '10.0.0.2', 'dst_port': 80,
            'proto': 6,
        }
        alert = format_alert(d, flow, timestamp="2024-01-01T00:00:00Z")

        required_fields = [
            'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
            'protocol', 'threat_class', 'confidence', 'severity',
            'mitre_id', 'observability', 'detector', 'top_features',
            'evidence_hash',
        ]
        for field in required_fields:
            assert field in alert, f"Missing field: {field}"


class TestVariantAB:
    def test_layer_connectivity(self):
        """b_conv2 must receive input from b_relu1, not inp_b."""
        from model import build_model_ab
        model = build_model_ab()
        cfg = model.get_config()
        # Find b_conv2 in the config and check its inbound node
        for layer_cfg in cfg['layers']:
            if layer_cfg['name'] == 'b_conv2':
                # In Keras 3 config, inbound_nodes lists the source layers
                inbound = layer_cfg.get('inbound_nodes', [])
                # Flatten to find source layer names
                src_names = []
                def _collect(obj):
                    if isinstance(obj, dict):
                        if 'name' in obj:
                            src_names.append(obj['name'])
                        if 'keras_history' in obj and isinstance(obj['keras_history'], (list, tuple)) and len(obj['keras_history']) > 0:
                            src_names.append(obj['keras_history'][0])
                        for k, v in obj.items():
                            _collect(v)
                    elif isinstance(obj, (list, tuple)):
                        for item in obj:
                            _collect(item)
                _collect(inbound)
                # The source should be b_relu1, NOT beacon_seq (inp_b)
                assert any('b_relu1' in n or 'b_bn1' in n for n in src_names), \
                    f"b_conv2 inbound sources are {src_names}, expected b_relu1"
                assert not any('beacon_seq' in n for n in src_names), \
                    f"b_conv2 is connected directly to inp_b (beacon_seq)!"
                break
        else:
            # If config format doesn't expose inbound_nodes, verify via shapes
            # b_conv2 input shape should be (None, 32, 32) after conv1+bn+relu,
            # NOT (None, 32, 3) which is inp_b
            b_conv2 = model.get_layer('b_conv2')
            in_shape = b_conv2.input.shape
            assert in_shape[-1] == 32, \
                f"b_conv2 input has {in_shape[-1]} channels; expected 32 (from b_conv1), got {in_shape}"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
