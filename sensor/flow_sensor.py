#!/usr/bin/env python3
"""Private-lab packet sensor that exports observed directional flows to UniGuard."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import queue
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, get_if_list, sniff


LOG = logging.getLogger("uniguard.sensor")
MAX_SEQUENCE_PACKETS = 32
EXPORT_BATCH_SIZE = 32
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128",
)))


def private_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use a literal private lab IP address.") from error
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise argparse.ArgumentTypeError("Only RFC1918, IPv6 ULA, or loopback lab addresses are allowed.")
    return address


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and export only traffic to a configured private lab target.")
    parser.add_argument("--interface", required=True, help="Explicit Linux capture interface, for example eth0.")
    parser.add_argument("--mode", choices=("private-lab",), default="private-lab", help="Capture is restricted to private lab targets.")
    parser.add_argument("--target", required=True, type=private_address, help="Private IP address of the controlled lab server.")
    parser.add_argument("--port", required=True, type=int, help="Destination TCP/UDP port on the controlled lab server.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000/api/flows", help="UniGuard POST /api/flows URL.")
    parser.add_argument("--flow-timeout", type=float, default=5.0, help="Idle timeout in seconds before a flow is exported (default: 5).")
    parser.add_argument("--active-timeout", type=float, default=60.0, help="Maximum flow age in seconds (default: 60).")
    parser.add_argument("--source-filter", help="Optional source IP/CIDR filter, restricted to private lab ranges.")
    parser.add_argument("--dry-run", action="store_true", help="Print observed flow JSON without sending it to the backend.")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.flow_timeout <= 0 or args.active_timeout <= 0:
        parser.error("flow timeouts must be positive")
    if args.flow_timeout > args.active_timeout:
        parser.error("--flow-timeout cannot exceed --active-timeout")
    if args.source_filter:
        try:
            args.source_network = ipaddress.ip_network(args.source_filter, strict=False)
        except ValueError as error:
            parser.error(f"invalid --source-filter: {error}")
        if args.source_network.version != args.target.version:
            parser.error("--source-filter address family must match --target")
        if not any(args.source_network.subnet_of(network) for network in PRIVATE_NETWORKS):
            parser.error("--source-filter must stay within a private or loopback lab range")
    else:
        args.source_network = None

    parsed_url = urlparse(args.backend_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname or not parsed_url.path.endswith("/api/flows"):
        parser.error("--backend-url must be an HTTP(S) URL ending in /api/flows")
    if parsed_url.hostname == "localhost":
        pass
    else:
        try:
            private_address(parsed_url.hostname)
        except argparse.ArgumentTypeError as error:
            parser.error(f"--backend-url must point to a private lab IP or localhost: {error}")
    return args


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    first_seen: float
    last_seen: float
    packet_lengths: list[int] = field(default_factory=list)
    payload_lengths: list[int] = field(default_factory=list)
    header_lengths: list[int] = field(default_factory=list)
    iats_us: list[float] = field(default_factory=list)
    packet_times: list[float] = field(default_factory=list)
    tcp_flags: list[int] = field(default_factory=list)
    sequence_sizes: list[int] = field(default_factory=list)
    sequence_iats: list[float] = field(default_factory=list)
    sequence_flags: list[int] = field(default_factory=list)
    first_syn_window: int | None = None
    flag_counts: dict[str, int] = field(default_factory=lambda: {"fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0})
    domain: str | None = None

    @property
    def key(self) -> tuple[str, int, str, int, int]:
        return self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto

    def add(self, timestamp: float, packet_length: int, payload_length: int, header_length: int,
            flags: int, window: int | None, domain: str | None) -> None:
        if self.packet_times:
            iat_us = max(0.0, (timestamp - self.last_seen) * 1_000_000)
            self.iats_us.append(iat_us)
        else:
            iat_us = 0.0
        self.last_seen = timestamp
        self.packet_lengths.append(packet_length)
        self.payload_lengths.append(payload_length)
        self.header_lengths.append(header_length)
        self.tcp_flags.append(flags)
        if len(self.sequence_sizes) < MAX_SEQUENCE_PACKETS:
            self.sequence_sizes.append(packet_length)
            self.sequence_iats.append(iat_us)
            self.sequence_flags.append(flags)
        if flags & 0x02:
            self.flag_counts["syn"] += 1
            if not flags & 0x10 and self.first_syn_window is None and window is not None:
                self.first_syn_window = window
        for bit, name in ((0x01, "fin"), (0x04, "rst"), (0x08, "psh"), (0x10, "ack"), (0x20, "urg")):
            if flags & bit:
                self.flag_counts[name] += 1
        if domain:
            self.domain = domain
        self.packet_times.append(timestamp)

    def to_record(self, reason: str) -> dict[str, Any]:
        lengths = self.packet_lengths
        payloads = self.payload_lengths
        duration_s = max(0.0, self.last_seen - self.first_seen)
        iats = self.iats_us
        # These are packet-derived lab features. The documented feature names mirror
        # the existing CIC IDS model input; details of CICFlowMeter subflow/segment
        # calculations differ, so the metadata below explicitly identifies the adapter.
        record: dict[str, Any] = {
            "Src IP": self.src_ip,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.proto,
            "Flow Duration": duration_s * 1_000_000,
            "Total Fwd Packet": len(lengths),
            "Total Length of Fwd Packet": sum(lengths),
            "Fwd Packet Length Max": max(lengths, default=0),
            "Fwd Packet Length Min": min(lengths, default=0),
            "Fwd Packet Length Mean": statistics.fmean(lengths) if lengths else 0.0,
            "Fwd Packet Length Std": statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
            "Fwd IAT Total": sum(iats),
            "Fwd IAT Mean": statistics.fmean(iats) if iats else 0.0,
            "Fwd IAT Std": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "Fwd IAT Max": max(iats, default=0.0),
            "Fwd IAT Min": min(iats, default=0.0),
            "Fwd PSH Flags": self.flag_counts["psh"],
            "Fwd URG Flags": self.flag_counts["urg"],
            "Fwd RST Flags": self.flag_counts["rst"],
            "Fwd Header Length": sum(self.header_lengths),
            "Fwd Packets/s": len(lengths) / duration_s if duration_s > 0 else 0.0,
            "SYN Flag Count": self.flag_counts["syn"],
            "FIN Flag Count": self.flag_counts["fin"],
            "RST Flag Count": self.flag_counts["rst"],
            "PSH Flag Count": self.flag_counts["psh"],
            "ACK Flag Count": self.flag_counts["ack"],
            "URG Flag Count": self.flag_counts["urg"],
            "Subflow Fwd Packets": len(lengths),
            "Subflow Fwd Bytes": sum(lengths),
            "FWD Init Win Bytes": self.first_syn_window if self.proto == 6 else 0,
            "Fwd Act Data Pkts": sum(size > 0 for size in payloads),
            "Fwd Seg Size Min": min(payloads, default=0),
            "Fwd Segment Size Avg": statistics.fmean(payloads) if payloads else 0.0,
            "pkt_sizes": self.sequence_sizes,
            "pkt_iats": self.sequence_iats,
            "pkt_flags": self.sequence_flags,
            "sensor_metadata": {
                "sensor": "uniguard-private-lab-sensor",
                "feature_profile": "packet-derived-lab-v1",
                "flow_direction": "captured packets to configured destination",
                "termination": reason,
                "lgbm_feature_semantics": "packet-derived lab adapter; not CICFlowMeter parity",
                "field_notes": [
                    "Subflow Fwd Packets/Bytes are observed directional totals, not CICFlowMeter subflow averages.",
                    "Fwd packet-length stats use captured IP packet lengths; segment sizes use captured transport payload lengths.",
                    "CICFlowMeter field semantics are not guaranteed to match this packet-derived adapter.",
                ],
            },
        }
        if self.proto == 6 and self.first_syn_window is None:
            record["FWD Init Win Bytes"] = None
            record["sensor_metadata"]["lgbm_inputs_complete"] = False
            record["sensor_metadata"]["cicflowmeter_compatible"] = False
            record["sensor_metadata"]["missing_features"] = ["FWD Init Win Bytes (TCP SYN was not observed)"]
        else:
            record["sensor_metadata"]["lgbm_inputs_complete"] = True
            record["sensor_metadata"]["cicflowmeter_compatible"] = False
            record["sensor_metadata"]["missing_features"] = []
        if self.domain:
            record["domain"] = self.domain
        return record


class LabFlowSensor:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.flows: dict[tuple[str, int, str, int, int], FlowState] = {}
        self.export_queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10_000)
        self.stop_exporter = threading.Event()
        self.packets_seen = 0
        self.flows_completed = 0
        self.flows_dropped = 0
        self.export_thread = threading.Thread(target=self._export_loop, name="flow-exporter", daemon=True)

    def bpf_filter(self) -> str:
        expression = f"dst host {self.args.target} and dst port {self.args.port}"
        if self.args.source_network:
            expression += f" and src net {self.args.source_network}"
        return expression

    def _packet_fields(self, packet: Any) -> tuple[str, str, int, int, int, int, int, int, int, int | None, str | None] | None:
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is None or str(network.dst) != str(self.args.target):
            return None
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        if transport is None or int(transport.dport) != self.args.port:
            return None
        src_ip = str(network.src)
        try:
            source_address = ipaddress.ip_address(src_ip)
        except ValueError:
            return None
        if not any(source_address in net for net in PRIVATE_NETWORKS):
            return None
        if self.args.source_network and source_address not in self.args.source_network:
            return None

        proto = 6 if isinstance(transport, TCP) else 17
        flags = int(transport.flags) if proto == 6 else 0
        packet_length = len(network)
        payload_length = len(transport.payload)
        header_length = packet_length - payload_length
        window = int(transport.window) if proto == 6 else None
        domain = None
        dns = packet.getlayer(DNS)
        if dns is not None and int(dns.qr) == 0 and dns.qd is not None and packet.dport == 53:
            query = dns.qd.qname
            if isinstance(query, bytes):
                domain = query.decode("idna", errors="replace").rstrip(".")
            else:
                domain = str(query).rstrip(".")
        return src_ip, str(network.dst), int(transport.sport), int(transport.dport), proto, packet_length, payload_length, header_length, flags, window, domain

    def handle_packet(self, packet: Any) -> None:
        try:
            fields = self._packet_fields(packet)
            if fields is None:
                return
            (src_ip, dst_ip, src_port, dst_port, proto, packet_length,
             payload_length, header_length, flags, window, domain) = fields
            timestamp = float(packet.time)
            key = src_ip, src_port, dst_ip, dst_port, proto
            state = self.flows.get(key)
            if state is None:
                state = FlowState(src_ip, dst_ip, src_port, dst_port, proto, timestamp, timestamp)
                self.flows[key] = state
            state.add(timestamp, packet_length, payload_length, header_length, flags, window, domain)
            self.packets_seen += 1
            if self.packets_seen == 1 or self.packets_seen % 100 == 0:
                LOG.info("[SENSOR] captured %d packets for configured lab target", self.packets_seen)

            now = time.time()
            self._expire_flows(now)
            if proto == 6 and flags & (0x01 | 0x04):
                self._complete_flow(key, "fin" if flags & 0x01 else "rst")
        except Exception:
            LOG.warning("[SENSOR] ignored malformed or unsupported packet", exc_info=True)

    def _expire_flows(self, now: float) -> None:
        for key, state in list(self.flows.items()):
            if now - state.last_seen >= self.args.flow_timeout:
                self._complete_flow(key, "idle-timeout")
            elif now - state.first_seen >= self.args.active_timeout:
                self._complete_flow(key, "active-timeout")

    def _complete_flow(self, key: tuple[str, int, str, int, int], reason: str) -> None:
        state = self.flows.pop(key, None)
        if state is None:
            return
        record = state.to_record(reason)
        self.flows_completed += 1
        LOG.info("[FLOW] completed %s:%d -> %s:%d proto=%d packets=%d reason=%s",
                 state.src_ip, state.src_port, state.dst_ip, state.dst_port, state.proto,
                 len(state.packet_lengths), reason)
        try:
            self.export_queue.put_nowait(record)
        except queue.Full:
            self.flows_dropped += 1
            LOG.error("[EXPORT] queue full; dropped completed flow (total=%d)", self.flows_dropped)

    def _export_loop(self) -> None:
        client = None if self.args.dry_run else httpx.Client(timeout=10.0)
        batch: list[dict[str, Any]] = []
        try:
            while not self.stop_exporter.is_set() or not self.export_queue.empty():
                try:
                    record = self.export_queue.get(timeout=0.25)
                except queue.Empty:
                    record = None
                if record is not None:
                    batch.append(record)
                should_send = batch and (len(batch) >= EXPORT_BATCH_SIZE or record is None)
                if record is None and self.stop_exporter.is_set() and not batch:
                    break
                if not should_send:
                    continue
                if self.args.dry_run:
                    print(json.dumps(batch, indent=2, ensure_ascii=False), flush=True)
                    LOG.info("[EXPORT] dry-run printed %d observed flow(s); no backend request made", len(batch))
                else:
                    self._post_batch(client, batch)
                batch = []
        finally:
            if client is not None:
                client.close()

    def _post_batch(self, client: httpx.Client, batch: list[dict[str, Any]]) -> None:
        LOG.info("[EXPORT] POST %s (%d observed flow(s))", self.args.backend_url, len(batch))
        for attempt in range(1, 4):
            try:
                response = client.post(self.args.backend_url, json=batch)
                response.raise_for_status()
                result = response.json()
                LOG.info("[MODEL] backend accepted %s flow(s), returned %s alert(s), processing %.2f ms",
                         result.get("flows_received", "?"), result.get("alerts_generated", "?"),
                         result.get("processing_time_ms", 0.0))
                return
            except httpx.TimeoutException:
                LOG.warning("[EXPORT] backend request timed out (attempt %d/3)", attempt)
            except httpx.HTTPStatusError as error:
                LOG.error("[EXPORT] backend returned HTTP %s: %s", error.response.status_code, error.response.text[:300])
                return
            except httpx.HTTPError as error:
                LOG.warning("[EXPORT] backend unavailable: %s (attempt %d/3)", error, attempt)
            if attempt < 3:
                time.sleep(attempt)
        LOG.error("[EXPORT] unable to deliver batch after 3 attempts; %d flow(s) were not delivered", len(batch))

    def run(self) -> int:
        if sys.platform != "linux":
            LOG.error("Live capture is supported on Linux/Kali only; run the sensor on the Kali VM.")
            return 2
        if self.args.interface not in get_if_list():
            LOG.error("Capture interface '%s' was not found. Available: %s", self.args.interface, ", ".join(get_if_list()))
            return 2

        self.export_thread.start()
        bpf = self.bpf_filter()
        LOG.info("[SENSOR] %s mode target=%s port=%d iface=%s", self.args.mode, self.args.target, self.args.port, self.args.interface)
        LOG.info("[SENSOR] capture filter: %s", bpf)
        LOG.info("[SENSOR] flow idle/active timeouts: %.1fs / %.1fs; dry-run=%s",
                 self.args.flow_timeout, self.args.active_timeout, self.args.dry_run)
        try:
            while True:
                sniff(iface=self.args.interface, filter=bpf, prn=self.handle_packet,
                      store=False, timeout=0.5)
                self._expire_flows(time.time())
        except PermissionError:
            LOG.error("Packet capture permission denied. Run with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN.")
            return 1
        except OSError as error:
            LOG.error("Packet capture failed: %s. Check libpcap, interface, and capture permissions.", error)
            return 1
        except Exception as error:
            LOG.error("Packet capture failed: %s. Check libpcap, interface, and capture permissions.", error)
            return 1
        except KeyboardInterrupt:
            LOG.info("[SENSOR] stopping; flushing remaining observed flows")
        finally:
            for key in list(self.flows):
                self._complete_flow(key, "sensor-shutdown")
            self.stop_exporter.set()
            try:
                self.export_thread.join(timeout=30)
            except RuntimeError:
                pass
            LOG.info("[SENSOR] stopped packets=%d flows=%d dropped=%d", self.packets_seen,
                     self.flows_completed, self.flows_dropped)
        return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    args = parse_args()
    return LabFlowSensor(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
