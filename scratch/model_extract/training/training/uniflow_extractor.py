"""
UniFlowExtractor: Unidirectional flow extraction from PCAP files.

Strict 5-tuple (src_ip, src_port, dst_ip, dst_port, proto) keying.
Forward packets only (as seen from the sensor on a receive-only TAP).
No reverse-direction information is ever stored or returned.

Timeouts:
  - Idle timeout: 120 seconds (no forward packet seen)
  - Active timeout: 300 seconds (flow forcibly closed)
  - FIN/RST closes flow immediately

Each emitted flow carries:
  - Flow-level summary stats (forward only)
  - First N forward packets as a sequence for the CNN
  - Forward TCP flags observed per packet
"""

import dpkt
import socket
import struct
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Iterator
import numpy as np


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IDLE_TIMEOUT = 120.0        # seconds
ACTIVE_TIMEOUT = 300.0      # seconds
MAX_PACKETS_PER_FLOW = 32   # N: first N forward packets stored
MAX_BEACON_FLOWS = 32       # K: last K flows per host-pair for beacon series


@dataclass
class UniFlow:
    """A unidirectional flow record. Contains ONLY forward-direction data."""
    # 5-tuple (used for grouping/reporting, NOT as model input)
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: int                     # 6=TCP, 17=UDP, 1=ICMP, ...

    # Timing
    start_time: float = 0.0        # epoch seconds of first packet
    end_time: float = 0.0          # epoch seconds of last packet
    duration: float = 0.0          # end_time - start_time

    # Forward-only aggregates
    fwd_packets: int = 0
    fwd_bytes: int = 0
    fwd_pkt_sizes: List[int] = field(default_factory=list)   # first N sizes
    fwd_timestamps: List[float] = field(default_factory=list) # first N timestamps
    fwd_tcp_flags: List[int] = field(default_factory=list)    # first N TCP flag bytes

    # Flow termination reason
    terminated_by: str = ""         # "idle", "active", "fin", "rst", "eof"

    # Scenario / label metadata (set externally)
    scenario_id: int = -1
    label: int = -1                 # 0=benign, 1=botnet, -1=unknown

    def flow_key(self) -> Tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto)

    def host_pair_key(self) -> Tuple:
        """Key for beacon series: (src_ip, dst_ip, dst_port, proto).
        Used ONLY for grouping, never as model input."""
        return (self.src_ip, self.dst_ip, self.dst_port, self.proto)


def _ip_to_str(ip_bytes: bytes) -> str:
    """Convert raw IP bytes to dotted string."""
    if len(ip_bytes) == 4:
        return socket.inet_ntoa(ip_bytes)
    elif len(ip_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return ""


def _get_tcp_flags(tcp_pkt) -> int:
    """Extract TCP flags byte from a dpkt TCP packet."""
    # dpkt stores flags in tcp.flags as an int
    return tcp_pkt.flags if hasattr(tcp_pkt, 'flags') else 0


class _FlowState:
    """Internal mutable state for an active flow being assembled."""
    __slots__ = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto',
        'start_time', 'last_time', 'fwd_packets', 'fwd_bytes',
        'pkt_sizes', 'timestamps', 'tcp_flags', 'fin_seen', 'rst_seen',
    ]

    def __init__(self, src_ip, src_port, dst_ip, dst_port, proto, ts, pkt_len, tcp_flag):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.proto = proto
        self.start_time = ts
        self.last_time = ts
        self.fwd_packets = 1
        self.fwd_bytes = pkt_len
        self.pkt_sizes = [pkt_len]
        self.timestamps = [ts]
        self.tcp_flags = [tcp_flag]
        self.fin_seen = bool(tcp_flag & dpkt.tcp.TH_FIN) if proto == 6 else False
        self.rst_seen = bool(tcp_flag & dpkt.tcp.TH_RST) if proto == 6 else False

    def add_packet(self, ts, pkt_len, tcp_flag):
        self.last_time = ts
        self.fwd_packets += 1
        self.fwd_bytes += pkt_len
        if len(self.pkt_sizes) < MAX_PACKETS_PER_FLOW:
            self.pkt_sizes.append(pkt_len)
            self.timestamps.append(ts)
            self.tcp_flags.append(tcp_flag)
        if self.proto == 6:
            if tcp_flag & dpkt.tcp.TH_FIN:
                self.fin_seen = True
            if tcp_flag & dpkt.tcp.TH_RST:
                self.rst_seen = True

    def to_uniflow(self, terminated_by: str) -> UniFlow:
        return UniFlow(
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            proto=self.proto,
            start_time=self.start_time,
            end_time=self.last_time,
            duration=self.last_time - self.start_time,
            fwd_packets=self.fwd_packets,
            fwd_bytes=self.fwd_bytes,
            fwd_pkt_sizes=list(self.pkt_sizes),
            fwd_timestamps=list(self.timestamps),
            fwd_tcp_flags=list(self.tcp_flags),
            terminated_by=terminated_by,
        )


def extract_flows_from_pcap(pcap_path: str, scenario_id: int = -1,
                             infected_ips: set = None,
                             max_packets: int = None,
                             progress_callback=None) -> List[UniFlow]:
    """
    Extract unidirectional flows from a PCAP file.

    Labelling rule:
      - If infected_ips is provided and src_ip is in infected_ips -> label=1 (botnet)
      - If infected_ips is provided and src_ip is NOT in infected_ips -> label=0 (benign)
      - If infected_ips is None -> label=-1 (unknown)

    NOTE: We label based on src_ip because we see only the forward direction.
    Traffic FROM an infected host is botnet C2/beaconing.
    Traffic TO an infected host (replies) would be in the reverse direction
    which we cannot see on a unidirectional TAP.

    Args:
        pcap_path: Path to PCAP file
        scenario_id: CTU-13 scenario number
        infected_ips: Set of known infected IP addresses
        max_packets: Maximum packets to read (None = all)
        progress_callback: Optional callback(packets_read) for progress

    Returns:
        List of UniFlow objects
    """
    active_flows: Dict[tuple, _FlowState] = {}
    completed_flows: List[UniFlow] = []
    packets_read = 0

    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            # Try pcapng
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        for ts, buf in pcap:
            packets_read += 1
            if max_packets and packets_read > max_packets:
                break

            if progress_callback and packets_read % 100000 == 0:
                progress_callback(packets_read)

            # Parse Ethernet -> IP
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # Handle VLAN tags
            if isinstance(eth.data, dpkt.ip.IP):
                ip_pkt = eth.data
            elif hasattr(eth, 'tag') and isinstance(getattr(eth, 'data', None), dpkt.ip.IP):
                ip_pkt = eth.data
            else:
                # Try raw IP (Linux cooked capture, etc.)
                try:
                    ip_pkt = dpkt.ip.IP(buf[14:])  # skip ethernet header
                    if ip_pkt.v != 4:
                        continue
                except:
                    continue

            if not isinstance(ip_pkt, dpkt.ip.IP):
                continue

            src_ip = _ip_to_str(ip_pkt.src)
            dst_ip = _ip_to_str(ip_pkt.dst)
            proto = ip_pkt.p
            pkt_len = ip_pkt.len if hasattr(ip_pkt, 'len') and ip_pkt.len else len(ip_pkt)

            # Extract ports and TCP flags
            src_port = 0
            dst_port = 0
            tcp_flags = 0

            if proto == 6 and isinstance(ip_pkt.data, dpkt.tcp.TCP):
                tcp = ip_pkt.data
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = _get_tcp_flags(tcp)
            elif proto == 17 and isinstance(ip_pkt.data, dpkt.udp.UDP):
                udp = ip_pkt.data
                src_port = udp.sport
                dst_port = udp.dport
            elif proto == 1:  # ICMP
                src_port = 0
                dst_port = 0

            flow_key = (src_ip, src_port, dst_ip, dst_port, proto)

            # Check timeouts on existing flow
            if flow_key in active_flows:
                state = active_flows[flow_key]
                idle_gap = ts - state.last_time
                active_dur = ts - state.start_time

                if idle_gap > IDLE_TIMEOUT:
                    completed_flows.append(state.to_uniflow("idle"))
                    del active_flows[flow_key]
                elif active_dur > ACTIVE_TIMEOUT:
                    completed_flows.append(state.to_uniflow("active"))
                    del active_flows[flow_key]

            # Add packet to flow or create new flow
            if flow_key in active_flows:
                state = active_flows[flow_key]
                state.add_packet(ts, pkt_len, tcp_flags)

                # Check FIN/RST termination
                if proto == 6 and (state.fin_seen or state.rst_seen):
                    reason = "fin" if state.fin_seen else "rst"
                    completed_flows.append(state.to_uniflow(reason))
                    del active_flows[flow_key]
            else:
                active_flows[flow_key] = _FlowState(
                    src_ip, src_port, dst_ip, dst_port, proto,
                    ts, pkt_len, tcp_flags
                )

    # Flush remaining active flows
    for state in active_flows.values():
        completed_flows.append(state.to_uniflow("eof"))

    # Apply labels
    for flow in completed_flows:
        flow.scenario_id = scenario_id
        if infected_ips is not None:
            flow.label = 1 if flow.src_ip in infected_ips else 0
        else:
            flow.label = -1

    return completed_flows


def flows_to_dict_list(flows: List[UniFlow]) -> List[dict]:
    """Convert flows to list of dicts for DataFrame creation."""
    records = []
    for f in flows:
        records.append({
            'src_ip': f.src_ip,
            'src_port': f.src_port,
            'dst_ip': f.dst_ip,
            'dst_port': f.dst_port,
            'proto': f.proto,
            'start_time': f.start_time,
            'end_time': f.end_time,
            'duration': f.duration,
            'fwd_packets': f.fwd_packets,
            'fwd_bytes': f.fwd_bytes,
            'terminated_by': f.terminated_by,
            'scenario_id': f.scenario_id,
            'label': f.label,
            # Store packet sequences as serialised strings for DataFrame storage
            'pkt_sizes': f.fwd_pkt_sizes,
            'pkt_timestamps': f.fwd_timestamps,
            'pkt_tcp_flags': f.fwd_tcp_flags,
        })
    return records
