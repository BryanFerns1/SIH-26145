<div align="center">

# 🛡️ UniGuard

### See every threat. Touch nothing.

**Read-only, encryption-aware network threat detection for critical infrastructure (OT/ICS).**

[![Smart India Hackathon 2026](https://img.shields.io/badge/SIH-2026-orange)](#)
[![Problem Statement](https://img.shields.io/badge/PS-SIH26145-blue)](#)
[![Team](https://img.shields.io/badge/Team-CeaserX-purple)](#)
[![License](https://img.shields.io/badge/License-BSD--3--Clause-green)](LICENSE)
[![CPU only](https://img.shields.io/badge/Runs%20on-CPU%20only-lightgrey)](#)

</div>

---

## 📖 Table of Contents

- [The Problem](#-the-problem)
- [Our Solution](#-our-solution)
- [Why UniGuard](#-why-uniguard)
- [How It Works](#-how-it-works)
- [Threats We Detect](#-threats-we-detect)
- [Alert Format](#-alert-format)
- [Comparison with Existing Tools](#-comparison-with-existing-tools)
- [Getting Started](#-getting-started)
- [Results](#-results)
- [Roadmap](#-roadmap)
- [Regulatory Alignment](#-regulatory-alignment)
- [Team](#-team)
- [License](#-license)

---

## 🚨 The Problem

Power grids, water plants, refineries and railways run on operational technology (OT). Protecting them with network monitoring is hard, because:

| Challenge | What it means |
|---|---|
| **One-way visibility** | The sensor can see all traffic but must never probe, handshake or block. Any packet it sends could disturb a live plant. |
| **Passive data only** | Six threat classes must be found, from DDoS to data exfiltration, using only what is observed. |
| **No decryption** | Encrypted sessions can only be judged from metadata: sizes, timing and handshake fingerprints. |
| **Alert overload** | Isolated alerts hide multi-stage attack chains, and analysts drown in noise. |
| **No proof of read-only** | Operators cannot easily verify that the sensor never transmits. |

## 💡 Our Solution

**UniGuard** is a passive sensor that listens to network traffic through a **receive-only hardware tap**, finds attacks using three layers of detection, and produces **ranked, explained, tamper-evident alerts**, all on an ordinary CPU with no GPU and no licence fees.

In plain words:

1. **It only listens.** The hardware physically cannot send data back into the network.
2. **It never opens private messages.** It studies traffic *patterns* (who talks, how often, how much) to spot danger.
3. **It tells you what matters.** Alerts are ranked by seriousness and joined into one attack story.
4. **It can prove itself.** Evidence is hash-chained, so anyone can check that nothing was altered.

## ✨ Why UniGuard

| Benefit | What you get |
|---|---|
| 🔒 **No inline path, no probing** | Monitoring adds no new door for attackers and no risk of disrupting operations. |
| 🕵️ **Catches hidden and new threats** | Finds attacks inside encrypted traffic and flags unknown behaviour without breaking privacy. |
| 🧰 **One tool, six major threat classes** | No need to stitch together separate tools. |
| ⚡ **Faster, smarter response** | Risk-scored alerts and attack chains let teams fix the worst problem first. |
| 📋 **Audit-ready evidence** | Tamper-evident records make compliance reviews simpler. |
| 💰 **Low cost** | Open source, CPU-only, no special hardware beyond a receive-only tap. |

## 🏗️ How It Works

```
 ┌──────────────┐   ┌────────────────┐   ┌───────────────┐
 │ Receive-only │──▶│  Capture NIC   │──▶│ Flow assembler│
 │ TAP / diode  │   │ (no TX pair)   │   │ uniflow/biflow│
 └──────────────┘   └────────────────┘   └───────┬───────┘
                                                 │ tagged with visibility state
                                                 ▼
                        ┌──────────────────────────────────────┐
                        │         Three detection layers        │
                        │ 1. Statistical extractors             │
                        │ 2. Supervised AI                      │
                        │ 3. Unsupervised anomaly detection     │
                        └───────────────────┬──────────────────┘
                                            ▼
                     ┌───────────────────────────────────────┐
                     │ Risk scoring → Correlation (MITRE ATT&CK)│
                     └───────────────────┬───────────────────┘
                                         ▼
              ┌──────────────────────────────────────────────────┐
              │ Tamper-evident ledger (hash chain) → Dashboard     │
              │ Alerts leave via a second diode or DMZ             │
              └──────────────────────────────────────────────────┘
```

### 1. Read-only by hardware
- A **receive-only TAP or data diode** (no transmit pair) is the primary guarantee.
- Supporting evidence: a no-IP capture NIC, an `nftables` egress drop rule, and **zero-TX counters**.
- Alerts exit through a **second diode or a DMZ**, so the management path is never a route back into the OT zone.

### 2. Streaming flow assembly
- Builds **uniflows or biflows** ([RFC 5103](https://www.rfc-editor.org/rfc/rfc5103)) incrementally with bounded state and fixed time windows.
- Every alert is tagged with what the sensor could actually see:
  `FULL_BIFLOW` · `UNIFLOW_EGRESS` · `UNIFLOW_INGRESS` · `SAMPLED`

### 3. Three detection layers

| Layer | Techniques |
|---|---|
| **Statistical** | Entropy, sketches, beacon periodicity, fan-out analysis |
| **Supervised AI** | LightGBM, 1D-CNN, character-level CNN to classify threat type |
| **Unsupervised** | Isolation Forest to flag unknown or novel behaviour |

Encrypted traffic is judged from the **client JA4 fingerprint** plus **packet size and timing**. No payload is decrypted or inspected.

### 4. Risk scoring and correlation
- Each alert carries a **confidence** and a **severity**, so the worst threats surface first.
- Same-host alerts are linked into **attack chains** and mapped to **MITRE ATT&CK for ICS** techniques (Enterprise only where no ICS equivalent exists).

### 5. Tamper-evident ledger
Alerts and evidence are stored in a **hash chain** (each record includes the hash of the previous one). It is deliberately *not* a blockchain: there is a single trusted sensor and no multi-party writes, so consensus is not needed.

## 🎯 Threats We Detect

The six problem-statement threat classes map to **seven outputs**. DGA and DNS tunnelling are one class, scored separately.

| # | Output | Signal examples |
|---|---|---|
| 1 | DDoS | Volume, sketch anomalies, source fan-in |
| 2 | C2 beaconing | Periodicity, jitter, consistent intervals |
| 3 | DGA | Character-level domain models |
| 4 | DNS tunnelling | Query length, entropy, record patterns |
| 5 | Encrypted malware | JA4 + size/timing behaviour |
| 6 | Port scanning | Fan-out, failed-connection ratios |
| 7 | Data exfiltration | Unusual outbound volume and duration |

**OT protocol coverage** (Modbus, DNP3, IEC 60870-5-104): 🟡 *planned / in progress. Update this line to match what is actually parsed.*

## 📦 Alert Format

Standard JSON with threat class, confidence, severity, MITRE ID, observability state and an evidence hash:

```json
{
  "alert_id": "a-000123",
  "timestamp": "2026-09-30T12:34:56Z",
  "threat_class": "c2_beaconing",
  "confidence": 0.91,
  "severity": "high",
  "mitre_attack_ics": "T0869",
  "observability": "UNIFLOW_INGRESS",
  "src": "10.10.4.21",
  "dst": "203.0.113.7",
  "chain_id": "chain-17",
  "evidence_hash": "sha256:<hash>",
  "prev_hash": "sha256:<hash>"
}
```

> Example values are illustrative. Verify technique IDs against the current MITRE ATT&CK for ICS matrix.

## 🔍 Comparison with Existing Tools

| Capability | Zeek | Suricata | Security Onion | OT monitors* | **UniGuard** |
|---|---|---|---|---|---|
| One-way input only | Partial | Degraded | Partial | Varies | **Native** |
| Encrypted, no decryption | Fingerprints | Fingerprints | Fingerprints | Varies | **JA4 + timing ML** |
| Visibility tag per alert | `conn_state` | Not built in | Not built in | Not published | **Every alert** |
| Tamper-evident evidence | Not built in | Not built in | Not built in | Varies | **Hash-chained** |
| Cost / hardware | Free, CPU | Free, CPU | Free, CPU | Licensed | **Free, CPU-only** |

<sub>*Nozomi, Claroty, Dragos are closed products. "Varies / Not published" means not publicly documented. Verify each cell and add source links before submission.</sub>

## 🚀 Getting Started

> Replace the commands below with your real ones.

### Prerequisites
- Linux host with Python 3.10+
- A receive-only TAP or data diode (or a `tcpreplay`/PCAP file for testing)
- 4-core CPU, 8 GB RAM *(use the spec you actually tested on)*

### Install
```bash
git clone https://github.com/<your-org>/uniguard.git
cd uniguard
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Run on a PCAP (safe demo)
```bash
python -m uniguard.run --pcap samples/demo.pcap --out alerts/
```

### Run live on a receive-only interface
```bash
sudo ./scripts/harden_capture_nic.sh eth1   # no IP, egress drop, zero-TX check
python -m uniguard.run --iface eth1 --out alerts/
```

### Launch the dashboard
```bash
python -m uniguard.dashboard
```

### Verify the evidence chain
```bash
python -m uniguard.verify alerts/ledger.jsonl
```

## 📊 Results

> ⚠️ **Only measured numbers belong in this table. Anything not measured yet must say "target".**

| Metric | Value |
|---|---|
| Throughput | **Target:** ≥ 5,000 flows/s on one CPU core |
| p99 alert latency | **Target:** < 1 s (measured with `tcpreplay`) |
| Precision / Recall / F1 | *TBD per class* |
| False-positive rate | *TBD* |

**Datasets:** CIC-IDS2017, CTU-13, CIC-DDoS2019 (IT traffic), plus at least one ICS capture set *(candidates to verify for availability and licence: 4SICS, SWaT, HAI, CIC Modbus)*.

**Evaluation:** report both **random-split** and **cross-capture** results.

<!-- Add a dashboard screenshot: ![Dashboard](docs/dashboard.png) -->

## 🗺️ Roadmap

| Phase | Goal | Status |
|---|---|---|
| **1. Prototype** | Detection pipeline on IT datasets | 🟡 In progress |
| **2. Validation** | Test on ICS datasets and OT protocols | ⬜ Planned |
| **3. Pilot** | Testbed or utility environment with hardware TAP | ⬜ Planned |

*Add rough durations for each phase.*

## ⚖️ Regulatory Alignment

UniGuard is designed to support (not replace) compliance work:

- **CERT-In directions (April 2022):** 6-hour incident reporting, 180-day log retention. Alerts and the hash-chained evidence store support both.
- **NCIIPC guidelines** and **IEC 62443** for critical infrastructure security
- **DPDP Act 2023:** aligned by design, using metadata only with no payload inspection
- **NIST SP 800-82** for ICS security guidance

## 👥 Team

**Team CeaserX** · Smart India Hackathon 2026 · Problem Statement **SIH26145**

| Name | Role |
|---|---|
| _Your name_ | _Role_ |
| _Your name_ | _Role_ |

## 📚 References

Full reference list is in [`docs/REFERENCES.md`](docs/REFERENCES.md). Key sources: RFC 5103, JA4 (FoxIO), MITRE ATT&CK for ICS, NIST SP 800-82, IEC 62443, RITA.

## 📄 License

Released under the [BSD-3-Clause License](LICENSE).

---

<div align="center">

**UniGuard: see every threat, touch nothing.**

</div>
