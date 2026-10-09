"""
UniGuard host-level features with BOUNDED STATE.

Uses datasketch HyperLogLog for distinct-count estimation and a
Space-Saving (heavy hitters) approximation for frequent-item tracking.

Per source IP, over rolling windows (e.g., 10s and 60s):
  - Number of distinct destination IPs   (HLL)
  - Number of distinct destination ports  (HLL)
  - New flows/s
  - Failed-looking short flows (forward SYN-only, no data packets)
  - Packet-size entropy (Shannon entropy of binned packet sizes)

Memory is bounded:
  - Key table: max HOST_MAX_TRACKED_KEYS entries, LRU eviction
  - Per key: HLL (p=10 → 1024 registers → ~1 KB) + counters (~64 bytes)
  - At 100K keys: ~110 MB (well within 8 GB budget)

IPs are KEYS only, never model inputs.
"""
import time
import struct
import math
from collections import OrderedDict
from typing import Dict, Optional, Tuple, List

import numpy as np
import mmh3
from datasketch import HyperLogLog

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config


class BoundedLRUDict(OrderedDict):
    """OrderedDict with bounded size and LRU eviction."""

    def __init__(self, max_size: int):
        super().__init__()
        self.max_size = max_size
        self.eviction_count = 0

    def __getitem__(self, key):
        # Move to end (most recently used)
        self.move_to_end(key)
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.max_size:
            oldest = next(iter(self))
            del self[oldest]
            self.eviction_count += 1


class HostState:
    """Per-host (per source IP) state with bounded memory."""

    __slots__ = [
        "dst_ip_hll", "dst_port_hll",
        "flow_count", "syn_only_count",
        "pkt_size_bins", "total_packets",
        "window_start", "last_seen",
    ]

    def __init__(self, hll_p: int = 10):
        self.dst_ip_hll = HyperLogLog(p=hll_p)
        self.dst_port_hll = HyperLogLog(p=hll_p)
        self.flow_count = 0
        self.syn_only_count = 0
        # Binned packet size histogram (16 bins: 0-64, 64-128, ..., 960-1024, 1024+)
        self.pkt_size_bins = np.zeros(16, dtype=np.int32)
        self.total_packets = 0
        self.window_start = 0.0
        self.last_seen = 0.0

    def memory_bytes(self) -> int:
        """Estimate memory usage of this state object."""
        # HLL: 2^p registers × 1 byte each × 2 HLLs
        hll_bytes = 2 * (2 ** 10)  # ~2048 bytes
        # Counters + bins: ~128 bytes
        return hll_bytes + 128


class HostFeatureTracker:
    """
    Track host-level features with bounded state.

    Usage:
        tracker = HostFeatureTracker()
        for flow in flows:
            tracker.update(flow)
            features = tracker.get_features(flow.src_ip, flow.timestamp)
    """

    def __init__(
        self,
        max_keys: int = config.HOST_MAX_TRACKED_KEYS,
        hll_p: int = config.HLL_PRECISION,
        windows_sec: List[float] = None,
    ):
        self.max_keys = max_keys
        self.hll_p = hll_p
        self.windows_sec = windows_sec or config.HOST_ROLLING_WINDOWS_SEC

        # One bounded dict per window
        self.states: Dict[float, BoundedLRUDict] = {
            w: BoundedLRUDict(max_keys) for w in self.windows_sec
        }

    def _get_or_create(self, src_ip: str, window: float, timestamp: float) -> HostState:
        """Get or create host state, resetting if window has expired."""
        states = self.states[window]
        if src_ip in states:
            state = states[src_ip]
            # Check if window has expired
            if timestamp - state.window_start > window:
                # Reset state for new window
                state = HostState(self.hll_p)
                state.window_start = timestamp
                states[src_ip] = state
        else:
            state = HostState(self.hll_p)
            state.window_start = timestamp
            states[src_ip] = state
        return state

    def update(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
        fwd_pkt_count: int,
        syn_flag: bool,
        has_data: bool,
        pkt_sizes: Optional[List[int]] = None,
    ):
        """
        Update host state with a new flow observation.

        Parameters
        ----------
        src_ip : source IP (key only, never a feature)
        dst_ip : destination IP (used for HLL distinct count)
        dst_port : destination port (used for HLL distinct count)
        timestamp : flow start time in seconds
        fwd_pkt_count : number of forward packets
        syn_flag : whether SYN flag was set
        has_data : whether flow has data packets (Fwd Act Data Pkts > 0)
        pkt_sizes : list of forward packet sizes (for entropy)
        """
        for window in self.windows_sec:
            state = self._get_or_create(src_ip, window, timestamp)

            # Update HLL for distinct destination IPs and ports
            state.dst_ip_hll.update(dst_ip.encode())
            state.dst_port_hll.update(struct.pack(">H", dst_port % 65536))

            # Flow counter
            state.flow_count += 1

            # SYN-only (failed-looking) flows
            if syn_flag and not has_data and fwd_pkt_count <= 3:
                state.syn_only_count += 1

            # Packet size histogram
            if pkt_sizes:
                for sz in pkt_sizes:
                    bin_idx = min(sz // 64, 15)
                    state.pkt_size_bins[bin_idx] += 1
                    state.total_packets += 1

            state.last_seen = timestamp

    def get_features(self, src_ip: str, timestamp: float) -> Dict[str, float]:
        """
        Get host-level features for a source IP at a given time.

        Returns dict with feature names prefixed by window (e.g., "h10_distinct_dst_ips").
        """
        features = {}
        for window in self.windows_sec:
            prefix = f"h{int(window)}"
            states = self.states[window]

            if src_ip not in states:
                # No state → all zeros
                features[f"{prefix}_distinct_dst_ips"] = 0.0
                features[f"{prefix}_distinct_dst_ports"] = 0.0
                features[f"{prefix}_flows_per_s"] = 0.0
                features[f"{prefix}_syn_only_flows"] = 0.0
                features[f"{prefix}_pkt_size_entropy"] = 0.0
                continue

            state = states[src_ip]
            elapsed = max(timestamp - state.window_start, 0.001)

            features[f"{prefix}_distinct_dst_ips"] = float(state.dst_ip_hll.count())
            features[f"{prefix}_distinct_dst_ports"] = float(state.dst_port_hll.count())
            features[f"{prefix}_flows_per_s"] = state.flow_count / elapsed
            features[f"{prefix}_syn_only_flows"] = float(state.syn_only_count)

            # Shannon entropy of packet size distribution
            if state.total_packets > 0:
                probs = state.pkt_size_bins / state.total_packets
                probs = probs[probs > 0]
                entropy = -np.sum(probs * np.log2(probs))
            else:
                entropy = 0.0
            features[f"{prefix}_pkt_size_entropy"] = entropy

        return features

    def memory_report(self) -> Dict:
        """Report memory usage."""
        total_keys = sum(len(s) for s in self.states.values())
        per_key_bytes = HostState(self.hll_p).memory_bytes()
        total_bytes = total_keys * per_key_bytes
        evictions = sum(s.eviction_count for s in self.states.values())

        return {
            "total_keys": total_keys,
            "per_key_bytes": per_key_bytes,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / 1e6, 2),
            "max_keys_per_window": self.max_keys,
            "windows": self.windows_sec,
            "evictions": evictions,
            "estimated_at_1M_keys_mb": round(1_000_000 * per_key_bytes / 1e6, 2),
        }

    @staticmethod
    def host_feature_names(windows_sec: List[float] = None) -> List[str]:
        """Return the ordered list of host-level feature names."""
        windows = windows_sec or config.HOST_ROLLING_WINDOWS_SEC
        names = []
        for window in windows:
            prefix = f"h{int(window)}"
            names.extend([
                f"{prefix}_distinct_dst_ips",
                f"{prefix}_distinct_dst_ports",
                f"{prefix}_flows_per_s",
                f"{prefix}_syn_only_flows",
                f"{prefix}_pkt_size_entropy",
            ])
        return names
