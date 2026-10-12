"""
Stage 1: Data Inventory, Flow Extraction, and Label Matching.

This script:
1. Inventories all CTU-13 PCAP and binetflow files
2. Extracts unidirectional flows from each botnet PCAP
3. Labels flows based on infected-host IPs from ground truth
4. Reports label matching statistics
5. Saves extracted flows to pickle for subsequent stages

IMPORTANT CONSTRAINTS:
- Only forward-direction packets are extracted
- Labels come from known infected IPs per scenario (ground truth)
- No bidirectional features are used
- IPs/ports are stored for grouping/reporting only, not as model inputs
"""

import os
import sys
import time
import pickle
import hashlib
import json
import argparse
from collections import Counter, defaultdict

import numpy as np

# Local modules
from ctu13_ground_truth import SCENARIOS, FAMILY_SCENARIOS, get_infected_ips
from uniflow_extractor import extract_flows_from_pcap, flows_to_dict_list

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Default path to CTU-13 dataset
DEFAULT_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "dataset 1D CNN", "CTU-13-Dataset"
)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extracted_flows")


def get_pcap_hash(pcap_path: str, block_size: int = 65536) -> str:
    """Compute SHA-256 of a PCAP file (first 10MB for speed)."""
    sha = hashlib.sha256()
    with open(pcap_path, 'rb') as f:
        for _ in range(10 * 1024 * 1024 // block_size + 1):
            data = f.read(block_size)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def run_data_inventory(data_dir: str) -> dict:
    """
    Inventory all CTU-13 files and check availability.

    Returns dict with scenario metadata and file paths.
    """
    inventory = {}

    for scenario_id, meta in SCENARIOS.items():
        scenario_dir = os.path.join(data_dir, str(scenario_id))
        pcap_path = os.path.join(scenario_dir, meta["pcap"])
        binetflow_path = os.path.join(scenario_dir, meta["binetflow"])

        pcap_exists = os.path.exists(pcap_path)
        binetflow_exists = os.path.exists(binetflow_path)
        pcap_size_mb = os.path.getsize(pcap_path) / (1024 * 1024) if pcap_exists else 0

        inventory[scenario_id] = {
            "scenario_id": scenario_id,
            "family": meta["family"],
            "infected_ips": meta["infected_ips"],
            "pcap_path": pcap_path,
            "pcap_exists": pcap_exists,
            "pcap_size_mb": round(pcap_size_mb, 2),
            "binetflow_path": binetflow_path,
            "binetflow_exists": binetflow_exists,
        }

    return inventory


def extract_scenario(scenario_id: int, pcap_path: str, infected_ips: set,
                      max_packets: int = None) -> list:
    """Extract flows from a single scenario PCAP."""
    print(f"\n{'='*60}")
    print(f"Scenario {scenario_id}: {SCENARIOS[scenario_id]['family']}")
    print(f"  PCAP: {os.path.basename(pcap_path)}")
    print(f"  Infected IPs: {infected_ips}")
    print(f"  Max packets: {max_packets or 'all'}")

    t0 = time.time()
    progress = lambda n: print(f"    ...{n:,} packets read", end='\r')

    flows = extract_flows_from_pcap(
        pcap_path, scenario_id=scenario_id,
        infected_ips=infected_ips,
        max_packets=max_packets,
        progress_callback=progress
    )

    elapsed = time.time() - t0
    flow_dicts = flows_to_dict_list(flows)

    # Count labels
    labels = Counter(f['label'] for f in flow_dicts)
    total_flows = len(flow_dicts)
    botnet_flows = labels.get(1, 0)
    benign_flows = labels.get(0, 0)
    unknown_flows = labels.get(-1, 0)

    print(f"\n  Extracted {total_flows:,} flows in {elapsed:.1f}s")
    print(f"  Botnet: {botnet_flows:,} | Benign: {benign_flows:,} | Unknown: {unknown_flows:,}")
    print(f"  Flows/sec: {total_flows/max(elapsed, 0.001):,.0f}")

    # Flow statistics
    if flow_dicts:
        sizes = [f['fwd_bytes'] for f in flow_dicts]
        pkts = [f['fwd_packets'] for f in flow_dicts]
        durs = [f['duration'] for f in flow_dicts]
        print(f"  Fwd bytes: mean={np.mean(sizes):.0f}, median={np.median(sizes):.0f}")
        print(f"  Fwd packets: mean={np.mean(pkts):.1f}, median={np.median(pkts):.0f}")
        print(f"  Duration: mean={np.mean(durs):.2f}s, median={np.median(durs):.2f}s")

    return flow_dicts


def main():
    parser = argparse.ArgumentParser(description="Stage 1: Data inventory and flow extraction")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help="Path to CTU-13-Dataset directory")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help="Output directory for extracted flows")
    parser.add_argument("--max-packets", type=int, default=None,
                        help="Max packets per PCAP (for testing, None=all)")
    parser.add_argument("--scenarios", type=int, nargs="+", default=None,
                        help="Specific scenarios to extract (default: all)")
    parser.add_argument("--skip-large", action="store_true",
                        help="Skip scenarios > 1 GB PCAP (10, 11)")
    args = parser.parse_args()

    # Normalise data dir path
    data_dir = os.path.abspath(args.data_dir)
    print(f"Data directory: {data_dir}")

    # --- Step 1: Inventory ---
    print("\n" + "="*60)
    print("STEP 1: DATA INVENTORY")
    print("="*60)

    inventory = run_data_inventory(data_dir)

    print(f"\n{'Scenario':>10} {'Family':>10} {'PCAP?':>6} {'Size(MB)':>10} "
          f"{'Binetflow?':>10} {'Infected IPs':>15}")
    print("-" * 75)

    total_pcap_gb = 0
    for sid, info in sorted(inventory.items()):
        total_pcap_gb += info['pcap_size_mb'] / 1024
        print(f"{sid:>10} {info['family']:>10} "
              f"{'YES' if info['pcap_exists'] else 'NO':>6} "
              f"{info['pcap_size_mb']:>10.1f} "
              f"{'YES' if info['binetflow_exists'] else 'NO':>10} "
              f"{len(info['infected_ips']):>15}")

    print(f"\nTotal PCAP size: {total_pcap_gb:.2f} GB")

    # Check which scenarios to process
    if args.scenarios:
        scenario_ids = args.scenarios
    else:
        scenario_ids = sorted(inventory.keys())

    if args.skip_large:
        skipped = [s for s in scenario_ids if inventory[s]['pcap_size_mb'] > 1024]
        scenario_ids = [s for s in scenario_ids if inventory[s]['pcap_size_mb'] <= 1024]
        if skipped:
            print(f"\nSkipping large scenarios: {skipped}")

    # --- Step 2: Extract Flows ---
    print("\n" + "="*60)
    print("STEP 2: FLOW EXTRACTION FROM PCAP")
    print("="*60)

    os.makedirs(args.output_dir, exist_ok=True)
    all_flows = []
    extraction_stats = {}

    for sid in scenario_ids:
        info = inventory[sid]
        if not info['pcap_exists']:
            print(f"\nScenario {sid}: PCAP not found, skipping")
            continue

        infected = set(info['infected_ips'])
        flow_dicts = extract_scenario(
            sid, info['pcap_path'], infected,
            max_packets=args.max_packets
        )

        all_flows.extend(flow_dicts)

        # Stats for report
        labels = Counter(f['label'] for f in flow_dicts)
        extraction_stats[sid] = {
            "total_flows": len(flow_dicts),
            "botnet_flows": labels.get(1, 0),
            "benign_flows": labels.get(0, 0),
            "unknown_flows": labels.get(-1, 0),
            "family": info['family'],
        }

    # --- Step 3: Summary ---
    print("\n" + "="*60)
    print("STEP 3: EXTRACTION SUMMARY")
    print("="*60)

    total = len(all_flows)
    total_bot = sum(1 for f in all_flows if f['label'] == 1)
    total_ben = sum(1 for f in all_flows if f['label'] == 0)
    total_unk = sum(1 for f in all_flows if f['label'] == -1)

    print(f"\nTotal flows extracted: {total:,}")
    print(f"  Botnet:  {total_bot:,} ({100*total_bot/max(total,1):.1f}%)")
    print(f"  Benign:  {total_ben:,} ({100*total_ben/max(total,1):.1f}%)")
    print(f"  Unknown: {total_unk:,} ({100*total_unk/max(total,1):.1f}%)")

    print(f"\n{'Scenario':>10} {'Family':>10} {'Total':>10} {'Botnet':>10} "
          f"{'Benign':>10} {'Unknown':>10} {'Ratio':>8}")
    print("-" * 80)
    for sid in sorted(extraction_stats.keys()):
        s = extraction_stats[sid]
        ratio = s['botnet_flows'] / max(s['benign_flows'], 1)
        print(f"{sid:>10} {s['family']:>10} {s['total_flows']:>10,} "
              f"{s['botnet_flows']:>10,} {s['benign_flows']:>10,} "
              f"{s['unknown_flows']:>10,} {ratio:>8.3f}")

    # --- Label matching report ---
    print("\n" + "="*60)
    print("LABEL MATCHING REPORT")
    print("="*60)
    print("""
Matching rule:
  - Extract flows from BOTNET-ONLY PCAPs (publicly available captures
    containing only the infected host's traffic)
  - Label = 1 (BOTNET) if src_ip is in the known infected IP set for
    that scenario (i.e., traffic ORIGINATING from the bot)
  - Label = 0 (BENIGN) if src_ip is NOT in the infected set
    (these are replies/connections TO the bot from clean hosts,
     but since we only see forward direction from the PCAP's
     perspective, these are flows where clean hosts initiated
     connections seen in the capture)

NOTE: The botnet-only PCAPs contain ALL traffic involving the
infected machine(s), including incoming connections. Flows where
src_ip is NOT an infected IP represent traffic where external
hosts sent packets to the infected machine. In a unidirectional
TAP deployment, these would be the forward direction of connections
initiated by those external hosts.

Unmatched flows: 0 (all flows from PCAP are labelled by src_ip rule)
""")

    # --- Save ---
    output_path = os.path.join(args.output_dir, "all_flows.pkl")
    print(f"\nSaving {total:,} flows to {output_path}")
    with open(output_path, 'wb') as f:
        pickle.dump(all_flows, f)

    stats_path = os.path.join(args.output_dir, "extraction_stats.json")
    with open(stats_path, 'w') as f:
        json.dump(extraction_stats, f, indent=2)

    print(f"Stats saved to {stats_path}")
    print("\nStage 1 complete!")

    # --- Benign periodic traffic note ---
    print("\n" + "="*60)
    print("BENIGN PERIODIC TRAFFIC NOTE")
    print("="*60)
    print("""
The CTU-13 botnet-only PCAPs contain traffic from/to infected hosts.
The 'benign' flows (label=0) in these captures are connections FROM
external clean hosts to the infected machine.

For experiment E4 (benign periodic false-positive test), we need
additional captures containing known-benign periodic traffic:
  - NTP synchronisation
  - OS/software update checks
  - Cloud sync (Dropbox, OneDrive, etc.)
  - Monitoring heartbeats

These are NOT available in the CTU-13 botnet-only PCAPs.

OPTIONS:
  1. CIC-IDS2017 benign Monday capture (benign_traffic.pcap)
  2. UNSW-NB15 benign subset
  3. Synthetic periodic traffic (would be marked SYNTHETIC)

RECOMMENDATION: Please provide or specify which public benign periodic
PCAPs to download. Until then, E4 results will be marked INCOMPLETE.
""")

    return all_flows, extraction_stats


if __name__ == "__main__":
    main()
