"""
Stage 6: ONNX Export, Benchmark, PSI, and Detector Wrapper.

- Export Keras model to ONNX via tf2onnx
- ONNX parity test (Keras vs ONNX)
- CPU benchmark (feature extraction, CNN-only, end-to-end)
- PSI baseline computation
- BeaconCNNDetector wrapper class
"""

import os
import sys
import json
import time
import pickle
import hashlib
import argparse
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple
from collections import Counter

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


# ---------------------------------------------------------------------------
# ONNX Export
# ---------------------------------------------------------------------------

def export_to_onnx(keras_model_path: str, onnx_path: str, input_shape: tuple):
    """Export Keras model to ONNX format using tf2onnx."""
    import tensorflow as tf
    import tf2onnx

    model = tf.keras.models.load_model(keras_model_path, compile=False)
    spec = (tf.TensorSpec(input_shape, tf.float32, name="input"),)

    model_proto, _ = tf2onnx.convert.from_keras(
        model, input_signature=spec,
        opset=13,
        output_path=onnx_path,
    )

    print(f"ONNX model saved to {onnx_path}")
    return onnx_path


def onnx_parity_test(keras_model_path: str, onnx_path: str,
                      sample_inputs: np.ndarray, tolerance: float = 1e-4):
    """
    Test parity between Keras and ONNX model outputs.

    Returns max absolute difference and pass/fail status.
    """
    import tensorflow as tf
    import onnxruntime as ort

    # Keras predictions
    model = tf.keras.models.load_model(keras_model_path, compile=False)
    keras_out = model.predict(sample_inputs, batch_size=len(sample_inputs),
                               verbose=0).flatten()

    # ONNX predictions
    sess = ort.InferenceSession(onnx_path,
                                 providers=['CPUExecutionProvider'])
    input_name = sess.get_inputs()[0].name
    onnx_out = sess.run(None, {input_name: sample_inputs.astype(np.float32)})[0].flatten()

    max_diff = float(np.max(np.abs(keras_out - onnx_out)))
    passed = max_diff < tolerance

    print(f"ONNX parity test:")
    print(f"  Max absolute difference: {max_diff:.2e}")
    print(f"  Tolerance: {tolerance:.2e}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")

    return {
        'max_abs_diff': max_diff,
        'tolerance': tolerance,
        'passed': passed,
        'n_samples': len(sample_inputs),
    }


# ---------------------------------------------------------------------------
# CPU Benchmark
# ---------------------------------------------------------------------------

def benchmark_inference(onnx_path: str, keras_model_path: str,
                         input_shape: tuple, batch_sizes: list = [1, 100, 1000],
                         n_warmup: int = 5, n_runs: int = 20):
    """
    Benchmark CNN inference speed on CPU.

    Reports flows/s for ONNX Runtime and Keras at various batch sizes.
    """
    import tensorflow as tf
    import onnxruntime as ort
    import platform

    results = {
        'cpu': platform.processor(),
        'cores': os.cpu_count(),
        'batch_sizes': {},
    }

    # Setup ONNX
    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 1
    sess_opts.inter_op_num_threads = 1
    ort_sess = ort.InferenceSession(onnx_path, sess_opts,
                                     providers=['CPUExecutionProvider'])
    input_name = ort_sess.get_inputs()[0].name

    # Setup Keras
    keras_model = tf.keras.models.load_model(keras_model_path, compile=False)

    for bs in batch_sizes:
        print(f"\n  Batch size: {bs}")
        X = np.random.randn(bs, *input_shape[1:]).astype(np.float32)

        # --- ONNX Runtime ---
        # Warmup
        for _ in range(n_warmup):
            ort_sess.run(None, {input_name: X})
        # Benchmark
        ort_times = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            ort_sess.run(None, {input_name: X})
            ort_times.append(time.perf_counter() - t0)

        ort_mean = np.mean(ort_times)
        ort_flows_per_sec = bs / ort_mean

        # --- Keras ---
        # Warmup
        for _ in range(n_warmup):
            keras_model.predict(X, batch_size=bs, verbose=0)
        # Benchmark
        keras_times = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            keras_model.predict(X, batch_size=bs, verbose=0)
            keras_times.append(time.perf_counter() - t0)

        keras_mean = np.mean(keras_times)
        keras_flows_per_sec = bs / keras_mean

        results['batch_sizes'][str(bs)] = {
            'onnx_mean_ms': float(ort_mean * 1000),
            'onnx_flows_per_sec': float(ort_flows_per_sec),
            'keras_mean_ms': float(keras_mean * 1000),
            'keras_flows_per_sec': float(keras_flows_per_sec),
        }

        print(f"    ONNX:  {ort_mean*1000:.2f} ms, {ort_flows_per_sec:,.0f} flows/s")
        print(f"    Keras: {keras_mean*1000:.2f} ms, {keras_flows_per_sec:,.0f} flows/s")

    # Check 5000 flows/s target
    onnx_1000 = results['batch_sizes'].get('1000', {}).get('onnx_flows_per_sec', 0)
    target_met = onnx_1000 >= 5000
    results['target_5000_met'] = target_met
    results['onnx_best_flows_per_sec'] = onnx_1000

    print(f"\n  5,000 flows/s target: {'MET' if target_met else 'NOT MET'} "
          f"(ONNX at bs=1000: {onnx_1000:,.0f} flows/s)")

    return results


# ---------------------------------------------------------------------------
# PSI (Population Stability Index)
# ---------------------------------------------------------------------------

def compute_psi_baseline(X: np.ndarray, y_scores: np.ndarray,
                          n_bins: int = 10) -> dict:
    """
    Compute PSI baseline from training data.

    Saves binned distributions for each input channel summary and output scores.
    """
    baseline = {'n_bins': n_bins, 'channels': {}, 'output': {}}

    # Input channel summaries (mean per flow)
    for c in range(X.shape[-1]):
        channel_means = X[:, :, c].mean(axis=1)
        hist, edges = np.histogram(channel_means, bins=n_bins)
        baseline['channels'][f'channel_{c}_mean'] = {
            'edges': edges.tolist(),
            'counts': hist.tolist(),
            'proportions': (hist / hist.sum()).tolist(),
        }

    # Output score distribution
    hist, edges = np.histogram(y_scores, bins=n_bins, range=(0, 1))
    baseline['output'] = {
        'edges': edges.tolist(),
        'counts': hist.tolist(),
        'proportions': (hist / hist.sum()).tolist(),
    }

    return baseline


def compute_psi(baseline: dict, X_new: np.ndarray = None,
                 y_scores_new: np.ndarray = None) -> dict:
    """
    Compute Population Stability Index between baseline and new data.

    PSI > 0.1: some shift; PSI > 0.25: significant shift
    """
    psi_results = {}
    eps = 1e-8

    if X_new is not None:
        for key, base_dist in baseline['channels'].items():
            c_idx = int(key.split('_')[1])
            channel_means = X_new[:, :, c_idx].mean(axis=1)
            hist, _ = np.histogram(channel_means, bins=base_dist['edges'])
            new_prop = hist / max(hist.sum(), 1)
            base_prop = np.array(base_dist['proportions'])

            psi = float(np.sum(
                (new_prop - base_prop) * np.log((new_prop + eps) / (base_prop + eps))
            ))
            psi_results[key] = psi

    if y_scores_new is not None:
        base_dist = baseline['output']
        hist, _ = np.histogram(y_scores_new, bins=base_dist['edges'])
        new_prop = hist / max(hist.sum(), 1)
        base_prop = np.array(base_dist['proportions'])

        psi = float(np.sum(
            (new_prop - base_prop) * np.log((new_prop + eps) / (base_prop + eps))
        ))
        psi_results['output_score'] = psi

    return psi_results


# ---------------------------------------------------------------------------
# BeaconCNNDetector wrapper
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    """Single detection result."""
    threat_class: str
    score: float
    tier: Optional[str]      # "HIGH", "REVIEW", or None
    detector: str
    observability: str
    evidence_hash: str
    mitre_id: str = "T1071"
    mitre_name: str = "Application Layer Protocol"


class BeaconCNNDetector:
    """
    UniGuard 1D CNN Beacon Detector.

    Loads ONNX model + meta.json, applies shared preprocessing,
    calibration, and thresholds. Never raises on empty or malformed input.

    Usage:
        detector = BeaconCNNDetector("model_bundle/")
        detections = detector.predict(batch_of_flows)
    """

    def __init__(self, model_dir: str):
        import onnxruntime as ort
        from preprocessing import DEFAULT_META

        self.model_dir = model_dir

        # Load meta.json
        meta_path = os.path.join(model_dir, "meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                self.meta = json.load(f)
        else:
            self.meta = DEFAULT_META.copy()

        # Load ONNX model
        onnx_path = os.path.join(model_dir, "model.onnx")
        if os.path.exists(onnx_path):
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = os.cpu_count() or 4
            self.session = ort.InferenceSession(
                onnx_path, sess_opts,
                providers=['CPUExecutionProvider']
            )
            self.input_name = self.session.get_inputs()[0].name
        else:
            self.session = None

        # Load calibrator
        cal_path = os.path.join(model_dir, "calibrator.pkl")
        if os.path.exists(cal_path):
            with open(cal_path, 'rb') as f:
                cal_data = pickle.load(f)
            self.calibrator = cal_data['calibrator']
            self.cal_type = cal_data['type']
        else:
            self.calibrator = None
            self.cal_type = None

        # Load thresholds
        self.thresholds = self.meta.get('thresholds', {
            'HIGH': {'score': 0.5, 'target_fpr': 0.002},
            'REVIEW': {'score': 0.3, 'target_fpr': 0.01},
        })

    def predict(self, batch: list) -> List[Detection]:
        """
        Run inference on a batch of flow dicts.

        Args:
            batch: list of flow dicts with keys:
                pkt_sizes, pkt_timestamps, pkt_tcp_flags

        Returns:
            list of Detection objects (one per flow)
        """
        if not batch:
            return []

        try:
            return self._predict_internal(batch)
        except Exception as e:
            # Never raise on malformed input
            print(f"BeaconCNNDetector warning: {e}")
            return [self._empty_detection() for _ in batch]

    def _predict_internal(self, batch: list) -> List[Detection]:
        from preprocessing import preprocess_variant_a, compute_evidence_hash

        # Preprocess
        X = preprocess_variant_a(batch, self.meta, include_tcp_flags=True)

        if self.session is None:
            return [self._empty_detection() for _ in batch]

        # ONNX inference
        raw_scores = self.session.run(
            None, {self.input_name: X.astype(np.float32)}
        )[0].flatten()

        # Calibrate
        if self.calibrator is not None:
            if self.cal_type == 'isotonic':
                scores = self.calibrator.predict(raw_scores)
            else:
                scores = self.calibrator.predict_proba(
                    raw_scores.reshape(-1, 1)
                )[:, 1]
        else:
            scores = raw_scores

        # Build detections
        detections = []
        high_thresh = self.thresholds.get('HIGH', {}).get('score', 0.5)
        review_thresh = self.thresholds.get('REVIEW', {}).get('score', 0.3)

        for i, score in enumerate(scores):
            score = float(score)

            if score >= high_thresh:
                tier = "HIGH"
            elif score >= review_thresh:
                tier = "REVIEW"
            else:
                tier = None

            evidence_hash = compute_evidence_hash(X[i])

            detections.append(Detection(
                threat_class="Botnet C2 beaconing",
                score=score,
                tier=tier,
                detector="cnn1d_beacon",
                observability="uniflow_fwd_only",
                evidence_hash=evidence_hash,
            ))

        return detections

    def _empty_detection(self) -> Detection:
        return Detection(
            threat_class="Botnet C2 beaconing",
            score=0.0,
            tier=None,
            detector="cnn1d_beacon",
            observability="uniflow_fwd_only",
            evidence_hash="",
        )


# ---------------------------------------------------------------------------
# Alert Formatter (UniGuard integration adapter)
# ---------------------------------------------------------------------------

def format_alert(detection: Detection, flow: dict, timestamp: str = None) -> dict:
    """
    Format a Detection into the UniGuard alert format.

    Fields: timestamp, src/dst ip+port, protocol, threat_class,
    confidence, severity, mitre_id, observability, detector,
    top_features, evidence_hash
    """
    import datetime

    if timestamp is None:
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # Map tier to severity
    severity_map = {"HIGH": "critical", "REVIEW": "medium", None: "low"}

    # ICS reporting note
    ics_note = ("MITRE ATT&CK T1071: Application Layer Protocol. "
                "Mapped for ICS/OT reporting context. Note: this model "
                "is trained on IT botnet traffic, NOT ICS/OT traffic.")

    return {
        "timestamp": timestamp,
        "src_ip": flow.get("src_ip", ""),
        "src_port": flow.get("src_port", 0),
        "dst_ip": flow.get("dst_ip", ""),
        "dst_port": flow.get("dst_port", 0),
        "protocol": flow.get("proto", 0),
        "threat_class": detection.threat_class,
        "confidence": detection.score,
        "severity": severity_map.get(detection.tier, "low"),
        "mitre_id": detection.mitre_id,
        "mitre_name": detection.mitre_name,
        "observability": detection.observability,
        "detector": detection.detector,
        "top_features": "fwd_pkt_sizes,fwd_iats,fwd_tcp_flags",
        "evidence_hash": detection.evidence_hash,
        "tier": detection.tier,
        "ics_mapping_note": ics_note,
    }


# ---------------------------------------------------------------------------
# Main (export + benchmark + save samples)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Stage 6: Export + Benchmark")
    parser.add_argument("--model-dir", default="model_bundle")
    parser.add_argument("--flows", default="extracted_flows/all_flows.pkl")
    parser.add_argument("--skip-benchmark", action="store_true")
    args = parser.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base, args.model_dir)
    keras_path = os.path.join(model_dir, "model.keras")
    onnx_path = os.path.join(model_dir, "model.onnx")

    print("="*60)
    print("UniGuard 1D CNN - Stage 6: Export + Benchmark")
    print("="*60)

    # --- Load meta for input shape ---
    meta_path = os.path.join(model_dir, "meta.json")
    with open(meta_path, 'r') as f:
        meta = json.load(f)

    input_shape = tuple([None] + (meta.get('input_shape_A') or [32, 7]))
    print(f"\nInput shape: {input_shape}")

    # --- Export to ONNX ---
    print("\n--- ONNX Export ---")
    export_to_onnx(keras_path, onnx_path, input_shape)

    # --- Generate sample inputs/outputs ---
    print("\n--- Generating sample inputs/outputs ---")
    flows_path = os.path.join(base, args.flows)
    if os.path.exists(flows_path):
        from stage3_train import load_flows, prepare_data
        from preprocessing import DEFAULT_META
        flows = load_flows(flows_path)
        labelled = [f for f in flows if f['label'] >= 0][:50]
        from preprocessing import preprocess_variant_a
        sample_inputs = preprocess_variant_a(labelled, meta, include_tcp_flags=True)
    else:
        sample_inputs = np.random.randn(50, *input_shape[1:]).astype(np.float32)

    np.save(os.path.join(model_dir, "sample_inputs.npy"), sample_inputs)

    import onnxruntime as ort
    sess = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
    input_name = sess.get_inputs()[0].name
    sample_outputs = sess.run(None, {input_name: sample_inputs.astype(np.float32)})[0]
    np.save(os.path.join(model_dir, "sample_outputs.npy"), sample_outputs)
    print(f"  Saved {len(sample_inputs)} sample inputs/outputs")

    # --- ONNX Parity Test ---
    print("\n--- ONNX Parity Test (50 samples) ---")
    parity_50 = onnx_parity_test(keras_path, onnx_path, sample_inputs)

    # Test on 1000+ real inputs if available
    if os.path.exists(flows_path):
        labelled_1000 = [f for f in flows if f['label'] >= 0][:1000]
        X_1000 = preprocess_variant_a(labelled_1000, meta, include_tcp_flags=True)
        print("\n--- ONNX Parity Test (1000 real inputs) ---")
        parity_1000 = onnx_parity_test(keras_path, onnx_path, X_1000)
    else:
        parity_1000 = None

    # --- PSI Baseline ---
    print("\n--- PSI Baseline ---")
    if os.path.exists(flows_path):
        from splits import TRAIN_SCENARIOS
        train_flows = [f for f in flows if f['label'] >= 0
                        and f['scenario_id'] in TRAIN_SCENARIOS]
        X_train = preprocess_variant_a(train_flows[:10000], meta, include_tcp_flags=True)

        import tensorflow as tf
        keras_model = tf.keras.models.load_model(keras_path, compile=False)
        train_scores = keras_model.predict(X_train, batch_size=1024, verbose=0).flatten()

        psi_baseline = compute_psi_baseline(X_train, train_scores)
        psi_path = os.path.join(model_dir, "psi_baseline.json")
        with open(psi_path, 'w') as f:
            json.dump(psi_baseline, f, indent=2)
        print(f"  PSI baseline saved to {psi_path}")

    # --- Benchmark ---
    if not args.skip_benchmark:
        print("\n--- CPU Benchmark ---")
        bench_results = benchmark_inference(
            onnx_path, keras_path, input_shape,
            batch_sizes=[1, 256, 1024],
        )

        bench_path = os.path.join(model_dir, "benchmark_results.json")
        with open(bench_path, 'w') as f:
            json.dump(bench_results, f, indent=2)
        print(f"  Benchmark results saved to {bench_path}")

    # --- Save parity results ---
    parity_results = {
        'sample_50': parity_50,
        'real_1000': parity_1000,
    }
    with open(os.path.join(model_dir, "parity_results.json"), 'w') as f:
        json.dump(parity_results, f, indent=2)

    print("\nStage 6 complete!")


if __name__ == "__main__":
    main()
