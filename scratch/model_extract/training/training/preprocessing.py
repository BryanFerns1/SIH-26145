"""
Shared preprocessing for UniGuard 1D CNN Beacon Detector.

This module defines THE SINGLE preprocessing function used by both
training and inference. It uses FIXED constants (not fitted scalers)
stored in meta.json.

Two input representations:
  A) Packet-sequence: (N=32, C) per flow
  B) Beacon-series:   (K=32, 3) per host-pair series

All features are derived from FORWARD-DIRECTION ONLY:
  - packet sizes (forward)
  - inter-arrival times (forward)
  - forward TCP flags (SYN, FIN, RST, PSH)

FORBIDDEN: destination bytes, destination packets, direction columns,
           TCP state strings, reply flags, raw IPs, raw ports.
"""

import json
import hashlib
import numpy as np
from typing import List, Dict, Tuple, Optional
from scipy.signal import lombscargle

# ---------------------------------------------------------------------------
# Fixed preprocessing constants (stored in meta.json)
# ---------------------------------------------------------------------------
DEFAULT_META = {
    "N": 32,                          # max packets per flow
    "K": 32,                          # max flows per beacon series
    "channels_A": [
        "log1p_pkt_size",
        "log1p_iat_us",
        "padding_mask",
        "tcp_syn",
        "tcp_fin",
        "tcp_rst",
        "tcp_psh",
    ],
    "channels_B": [
        "log1p_gap_seconds",
        "log1p_fwd_bytes",
        "log1p_fwd_packets",
    ],
    "pkt_size_log_scale": 1.0 / 11.0, # log1p(65535) ≈ 11.09
    "iat_log_scale": 1.0 / 18.42,     # log1p(1e8 us = 100s) ≈ 18.42
    "iat_clip_us": 1e8,                # 100 seconds max IAT
    "gap_log_scale": 1.0 / 14.0,      # log1p(1.2e6 s ≈ 2 weeks) ≈ 14.0
    "gap_clip_s": 1.2e6,               # ~2 weeks max gap
    "bytes_log_scale": 1.0 / 23.0,     # log1p(~10 GB) ≈ 23
    "packets_log_scale": 1.0 / 16.0,   # log1p(~10M pkts) ≈ 16
    "class_names": ["benign", "botnet"],
    "thresholds": {
        "HIGH": {"score": 0.5, "target_fpr": 0.002},
        "REVIEW": {"score": 0.3, "target_fpr": 0.01},
    },
}


def load_meta(meta_path: str) -> dict:
    """Load preprocessing constants from meta.json."""
    with open(meta_path, 'r') as f:
        return json.load(f)


def save_meta(meta: dict, meta_path: str):
    """Save preprocessing constants to meta.json."""
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)


# ---------------------------------------------------------------------------
# Variant A: Packet-sequence preprocessing
# ---------------------------------------------------------------------------

def preprocess_variant_a(flows: list, meta: dict = None,
                          include_tcp_flags: bool = True) -> np.ndarray:
    """
    Convert a list of flow dicts/objects to Variant A input arrays.

    Input: list of flows, each with:
      - pkt_sizes: list of int (forward packet sizes)
      - pkt_timestamps: list of float (forward packet timestamps)
      - pkt_tcp_flags: list of int (forward TCP flag bytes)

    Output: np.ndarray of shape (len(flows), N, C)
      C = 3 (size, iat, mask) or 7 (+ SYN, FIN, RST, PSH)

    Uses FIXED constants, not fitted scalers.
    """
    if meta is None:
        meta = DEFAULT_META

    N = meta["N"]
    C = 7 if include_tcp_flags else 3

    result = np.zeros((len(flows), N, C), dtype=np.float32)

    pkt_size_scale = meta["pkt_size_log_scale"]
    iat_scale = meta["iat_log_scale"]
    iat_clip = meta["iat_clip_us"]

    for i, flow in enumerate(flows):
        # Get packet data from flow (dict or object)
        if isinstance(flow, dict):
            sizes = flow.get('pkt_sizes', [])
            timestamps = flow.get('pkt_timestamps', [])
            tcp_flags = flow.get('pkt_tcp_flags', [])
        else:
            sizes = getattr(flow, 'fwd_pkt_sizes', [])
            timestamps = getattr(flow, 'fwd_timestamps', [])
            tcp_flags = getattr(flow, 'fwd_tcp_flags', [])

        n_pkts = min(len(sizes), N)

        for j in range(n_pkts):
            # Channel 0: log1p(packet size), scaled
            result[i, j, 0] = np.log1p(sizes[j]) * pkt_size_scale

            # Channel 1: log1p(IAT in microseconds), scaled
            if j == 0:
                iat_us = 0.0
            else:
                iat_us = max(0.0, (timestamps[j] - timestamps[j-1]) * 1e6)
                iat_us = min(iat_us, iat_clip)
            result[i, j, 1] = np.log1p(iat_us) * iat_scale

            # Channel 2: padding mask (1 = real packet)
            result[i, j, 2] = 1.0

            # Channels 3-6: TCP flags (SYN, FIN, RST, PSH)
            if include_tcp_flags and j < len(tcp_flags):
                flags = tcp_flags[j]
                result[i, j, 3] = 1.0 if (flags & 0x02) else 0.0  # SYN
                result[i, j, 4] = 1.0 if (flags & 0x01) else 0.0  # FIN
                result[i, j, 5] = 1.0 if (flags & 0x04) else 0.0  # RST
                result[i, j, 6] = 1.0 if (flags & 0x08) else 0.0  # PSH

    return result


# ---------------------------------------------------------------------------
# Variant B: Beacon-series preprocessing
# ---------------------------------------------------------------------------

def build_beacon_series(flows: list, meta: dict = None) -> Dict[tuple, list]:
    """
    Group flows by (src_ip, dst_ip, dst_port, proto) and sort by start_time.

    Returns dict mapping host-pair key -> sorted list of flows.
    Keys are used ONLY for grouping, never as model inputs.
    """
    groups = {}
    for flow in flows:
        if isinstance(flow, dict):
            key = (flow['src_ip'], flow['dst_ip'], flow['dst_port'], flow['proto'])
            t = flow['start_time']
        else:
            key = flow.host_pair_key()
            t = flow.start_time

        if key not in groups:
            groups[key] = []
        groups[key].append(flow)

    # Sort each group by start time
    for key in groups:
        groups[key].sort(key=lambda f: f['start_time'] if isinstance(f, dict) else f.start_time)

    return groups


def preprocess_variant_b(beacon_groups: Dict[tuple, list],
                          meta: dict = None) -> Tuple[np.ndarray, list]:
    """
    Convert beacon series (grouped flows) to Variant B input arrays.

    For each host-pair group, take the last K flows and create:
      Channel 0: log1p(gap between flow start times in seconds), scaled
      Channel 1: log1p(forward bytes), scaled
      Channel 2: log1p(forward packets), scaled

    Output:
      - np.ndarray of shape (n_groups, K, 3)
      - list of keys corresponding to each row

    Label: majority vote from the flows in the group.
    """
    if meta is None:
        meta = DEFAULT_META

    K = meta["K"]
    gap_scale = meta["gap_log_scale"]
    gap_clip = meta["gap_clip_s"]
    bytes_scale = meta["bytes_log_scale"]
    pkts_scale = meta["packets_log_scale"]

    keys = list(beacon_groups.keys())
    result = np.zeros((len(keys), K, 3), dtype=np.float32)
    labels = []

    for idx, key in enumerate(keys):
        group = beacon_groups[key]
        # Take last K flows
        group = group[-K:]
        n_flows = len(group)

        flow_labels = []
        for j, flow in enumerate(group):
            if isinstance(flow, dict):
                start_time = flow['start_time']
                fwd_bytes = flow['fwd_bytes']
                fwd_packets = flow['fwd_packets']
                lbl = flow.get('label', -1)
            else:
                start_time = flow.start_time
                fwd_bytes = flow.fwd_bytes
                fwd_packets = flow.fwd_packets
                lbl = flow.label

            flow_labels.append(lbl)

            # Channel 0: log1p(gap in seconds)
            if j == 0:
                gap_s = 0.0
            else:
                prev_flow = group[j-1]
                prev_start = prev_flow['start_time'] if isinstance(prev_flow, dict) else prev_flow.start_time
                gap_s = max(0.0, start_time - prev_start)
                gap_s = min(gap_s, gap_clip)
            result[idx, K - n_flows + j, 0] = np.log1p(gap_s) * gap_scale

            # Channel 1: log1p(forward bytes)
            result[idx, K - n_flows + j, 1] = np.log1p(fwd_bytes) * bytes_scale

            # Channel 2: log1p(forward packets)
            result[idx, K - n_flows + j, 2] = np.log1p(fwd_packets) * pkts_scale

        # Label: 1 if any flow in group is botnet (conservative)
        valid_labels = [l for l in flow_labels if l >= 0]
        if valid_labels:
            labels.append(1 if any(l == 1 for l in valid_labels) else 0)
        else:
            labels.append(-1)

    return result, keys, labels


# ---------------------------------------------------------------------------
# Lomb-Scargle periodicity score
# ---------------------------------------------------------------------------

def compute_lomb_scargle_score(flows: list) -> float:
    """
    Compute Lomb-Scargle periodicity score for a series of flows.

    Uses flow start times as the time series.
    Higher score = more periodic (beaconing-like) behaviour.

    Returns a float in [0, 1] range (normalised power).
    """
    if len(flows) < 4:
        return 0.0

    # Extract timestamps
    times = []
    for f in flows:
        t = f['start_time'] if isinstance(f, dict) else f.start_time
        times.append(t)

    times = np.array(times, dtype=np.float64)
    times = times - times[0]  # normalise to start at 0

    if times[-1] - times[0] < 1.0:  # less than 1 second span
        return 0.0

    # Create a uniform signal (1 at each flow time)
    # and compute Lomb-Scargle periodogram
    n = len(times)
    # Add tiny noise to avoid zero-variance division-by-zero in scipy's lombscargle
    # when subtracting the mean from a constant signal.
    signal = np.ones(n) + np.random.uniform(-1e-4, 1e-4, n)

    # Frequency range: from 1/(total_duration) to n/(2*total_duration) (Nyquist-ish)
    duration = times[-1] - times[0]
    if duration <= 0:
        return 0.0

    min_freq = 1.0 / duration
    max_freq = n / (2.0 * duration)

    if max_freq <= min_freq:
        return 0.0

    # Test 100 angular frequencies
    freqs = np.linspace(min_freq, max_freq, min(100, n * 5))
    angular_freqs = 2 * np.pi * freqs

    try:
        power = lombscargle(times, signal - signal.mean(), angular_freqs, normalize=True)
        # Return max normalised power as the periodicity score
        max_power = float(np.max(power))
        # Clip to [0, 1]
        return min(1.0, max(0.0, max_power))
    except (ValueError, ZeroDivisionError):
        return 0.0


def compute_beacon_scores(beacon_groups: Dict[tuple, list]) -> Dict[tuple, float]:
    """Compute Lomb-Scargle scores for all beacon groups."""
    scores = {}
    for key, flows in beacon_groups.items():
        scores[key] = compute_lomb_scargle_score(flows)
    return scores


# ---------------------------------------------------------------------------
# Evidence hash
# ---------------------------------------------------------------------------

def compute_evidence_hash(input_array: np.ndarray) -> str:
    """
    Compute SHA-256 hash of the model input array for evidence tracking.
    Uses canonical serialisation (C-contiguous float32 bytes).
    """
    arr = np.ascontiguousarray(input_array, dtype=np.float32)
    return hashlib.sha256(arr.tobytes()).hexdigest()


# ---------------------------------------------------------------------------
# Feature-level perturbation for evasion tests (E5)
# ---------------------------------------------------------------------------

def perturb_packet_sizes(X: np.ndarray, pad_to: int = None,
                          random_pad_range: Tuple[int, int] = (0, 200),
                          meta: dict = None, seed: int = 42) -> np.ndarray:
    """
    Evasion test: add padding to packet sizes.
    Operates on Variant A arrays (channel 0 = log1p(pkt_size) * scale).
    """
    if meta is None:
        meta = DEFAULT_META
    rng = np.random.RandomState(seed)
    X_pert = X.copy()
    scale = meta["pkt_size_log_scale"]
    mask = X_pert[:, :, 2] > 0  # only real packets

    for i in range(X_pert.shape[0]):
        for j in range(X_pert.shape[1]):
            if mask[i, j]:
                # Reverse the transform to get original size
                orig_log = X_pert[i, j, 0] / scale
                orig_size = np.expm1(orig_log)
                # Add random padding
                pad = rng.randint(random_pad_range[0], random_pad_range[1] + 1)
                new_size = orig_size + pad
                X_pert[i, j, 0] = np.log1p(new_size) * scale

    return X_pert


def perturb_timing(X: np.ndarray, jitter_magnitude_us: float = 1e4,
                    meta: dict = None, seed: int = 42) -> np.ndarray:
    """
    Evasion test: add random jitter to inter-arrival times.
    Operates on Variant A arrays (channel 1 = log1p(IAT_us) * scale).
    """
    if meta is None:
        meta = DEFAULT_META
    rng = np.random.RandomState(seed)
    X_pert = X.copy()
    scale = meta["iat_log_scale"]
    clip = meta["iat_clip_us"]
    mask = X_pert[:, :, 2] > 0

    for i in range(X_pert.shape[0]):
        for j in range(1, X_pert.shape[1]):  # skip j=0 (always 0 IAT)
            if mask[i, j]:
                orig_log = X_pert[i, j, 1] / scale
                orig_iat = np.expm1(orig_log)
                jitter = rng.uniform(-jitter_magnitude_us, jitter_magnitude_us)
                new_iat = max(0.0, orig_iat + jitter)
                new_iat = min(new_iat, clip)
                X_pert[i, j, 1] = np.log1p(new_iat) * scale

    return X_pert
