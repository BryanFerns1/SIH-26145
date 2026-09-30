# UniGuard

### AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Smart India Hackathon 2026 — SIH26145**

UniGuard is a cybersecurity monitoring system designed for **critical infrastructure and OT/ICS environments** where network traffic must be monitored without creating an inline communication path back into the protected network.

The system analyzes **unidirectional network traffic**, extracts network and protocol-level features, detects suspicious behaviour, and generates security alerts with contextual visibility and tamper-evident evidence.

---

## 🎯 Problem

Critical infrastructure such as:

* Power
* Water
* Oil & Gas
* Transportation

uses Operational Technology (OT) networks to control physical processes.

These environments require strong isolation because introducing an active monitoring system into the production network can itself create additional risk.

Traditional security monitoring can also face limitations when:

* Traffic is encrypted
* Network visibility is incomplete
* Systems must remain isolated
* Monitoring equipment cannot actively probe the OT network
* Security teams need reliable evidence for investigation

UniGuard addresses these challenges through **passive, receive-only monitoring of unidirectional traffic**.

---

## 💡 Our Solution

UniGuard follows a **read-only monitoring architecture**.

Network traffic is copied from the OT environment through a:

* Receive-only Network TAP
* Hardware Data Diode
* SPAN/Mirror interface

The monitoring system receives a copy of the traffic but does not send packets back into the protected OT network.

```text
                    OT / PRODUCTION NETWORK
                             │
                             │
                    Network TAP / SPAN
                             │
                             ▼
                    ┌─────────────────┐
                    │ Hardware Data   │
                    │     Diode       │
                    └────────┬────────┘
                             │
                             │ One-way traffic
                             ▼
                    ┌─────────────────┐
                    │    UniGuard     │
                    │ Monitoring Node │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         Packet/Flow    Feature          Protocol
         Processing    Extraction        Analysis
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Threat Detection│
                    │     Engine      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Alert Generation│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Tamper-Evident  │
                    │ Evidence Store  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    Dashboard    │
                    └─────────────────┘
```

---

## 🔐 Core Security Principle

### No Inline Path. No Probing.

UniGuard is designed around passive monitoring.

The primary protection is provided by the **receive-only TAP / hardware data diode architecture**.

Additional supporting controls can include:

* Zero-TX monitoring
* Network interface restrictions
* Firewall rules
* `nftables`
* Isolated management connectivity

The management side is separated from the OT environment through a **second diode or DMZ**, preventing the monitoring system from becoming a communication path into the production network.

---

## 🔍 Threat Detection

UniGuard is designed to detect the threat classes defined for SIH26145.

The monitored threat categories include:

1. **DDoS**
2. **C2 Beaconing**
3. **Domain Generation Algorithm (DGA)**
4. **DNS Tunnelling**
5. **Encrypted Malware**
6. **Reconnaissance / Exfiltration**

DGA and DNS tunnelling are treated as separate detection/scoring categories.

---

## 🧠 Detection Approach

UniGuard combines network traffic processing, feature extraction, protocol analysis, and machine-learning-based detection.

The general pipeline is:

```text
Network Traffic
       ↓
Packet / Flow Collection
       ↓
Preprocessing
       ↓
Feature Extraction
       ↓
Protocol Analysis
       ↓
Detection Models
       ↓
Threat Classification
       ↓
MITRE ATT&CK for ICS Mapping
       ↓
Alert Generation
       ↓
Evidence Storage
       ↓
Dashboard
```

The system is designed to work with both **visible network information and encrypted traffic metadata**, without requiring payload decryption.

---

## 🔒 Encrypted Traffic Detection

Encrypted communication can hide malicious payloads from traditional deep-packet inspection.

UniGuard focuses on metadata and behavioural characteristics rather than decrypting the communication.

Relevant information can include:

* Flow behaviour
* Connection frequency
* Packet characteristics
* Timing patterns
* TLS-related fingerprints
* JA4 fingerprinting
* Communication relationships
* Behavioural anomalies

This allows suspicious encrypted communication to be investigated without requiring access to the encrypted payload.

---

## 🏭 OT / ICS Protocol Coverage

The architecture is designed to support industrial protocols such as:

* **Modbus**
* **DNP3**
* **IEC 104**

Protocol support can be expanded as additional parsers and datasets become available.

Where protocol parsing is not yet implemented, the protocol is treated as a planned extension rather than a completed capability.

---

## 🧭 MITRE ATT&CK for ICS

Detected activities are mapped to the **MITRE ATT&CK for ICS** framework wherever applicable.

This provides security analysts with additional context about:

* Attack behaviour
* Adversary techniques
* Potential objectives
* OT-specific attack patterns

The system prioritizes ATT&CK for ICS rather than using generic Enterprise ATT&CK terminology where an ICS technique is available.

---

## 🧾 Tamper-Evident Evidence

UniGuard maintains security evidence using a **tamper-evident hash-chained ledger**.

Each recorded event can contain:

* Timestamp
* Source information
* Destination information
* Protocol
* Detection result
* Threat category
* Relevant metadata
* Previous record hash
* Current record hash

Conceptually:

```text
Event 1
   │
   └── Hash 1
          ↓
Event 2 + Hash 1
   │
   └── Hash 2
          ↓
Event 3 + Hash 2
   │
   └── Hash 3
```

If an earlier record is modified, the hash relationship can reveal the alteration.

A blockchain consensus mechanism is not required because the system operates with a trusted monitoring sensor rather than multiple independent writers.

---

## 🚨 Alert Structure

A UniGuard alert can contain information such as:

```json
{
  "timestamp": "2026-09-30T12:00:00Z",
  "source": "192.168.1.10",
  "destination": "192.168.1.20",
  "protocol": "Modbus",
  "threat": "Reconnaissance",
  "severity": "High",
  "visibility": "Encrypted Metadata",
  "ja4": "example_fingerprint",
  "mitre_attack_ics": "Technique",
  "evidence_hash": "example_hash"
}
```

The exact schema may evolve as implementation progresses.

---

## 📊 Visibility State

Every alert can include a visibility state describing what information was available to the detection system.

Examples include:

```text
Cleartext
Encrypted Metadata
Flow Metadata
Protocol Metadata
Limited Visibility
```

This allows analysts to understand **what the system actually observed** instead of treating every detection as having the same level of visibility.

---

## 📈 Performance Targets

The current architecture includes performance targets that will be replaced with measured results as testing progresses.

| Metric        | Target                            |
| ------------- | --------------------------------- |
| Alert latency | p99 < 1 second                    |
| Throughput    | ≥ 5,000 flows/sec on one CPU core |
| Hardware      | CPU-only deployment               |
| GPU           | Not required                      |

**Important:** Performance numbers are labelled as targets until they are experimentally measured.

---

## 🧪 Evaluation

UniGuard can be evaluated using network security datasets and captured traffic.

Potential datasets include:

* CIC-IDS2017
* CTU-13
* CIC-DDoS2019
* ICS/OT-specific datasets and PCAP collections

For OT validation, datasets such as **4SICS, SWaT, HAI, or CIC Modbus** can be evaluated based on availability and licensing.

### Evaluation Metrics

The model will be evaluated using:

* Precision
* Recall
* F1-score
* False-positive rate
* Detection latency
* Network throughput

Where applicable, both:

* Random-split results
* Cross-capture results

will be reported to provide a more realistic evaluation of generalization.

---

## 🖥️ Dashboard

The UniGuard dashboard is intended to provide security analysts with a centralized view of detected activity.

The dashboard can display:

* Active alerts
* Threat categories
* Severity
* Source and destination information
* Protocol
* Visibility state
* JA4 information
* ATT&CK for ICS mapping
* Detection timestamps
* Evidence status
* Traffic statistics

---

## 🏗️ Architecture Components

### 1. Traffic Collection

Receives a one-way copy of network traffic from the protected environment.

### 2. Packet / Flow Processor

Processes packets and groups them into useful network flows.

### 3. Feature Extraction

Extracts network, timing, protocol and metadata features.

### 4. Protocol Analysis

Analyzes supported OT/ICS protocols and network communication patterns.

### 5. Threat Detection Engine

Uses detection logic and machine-learning models to identify suspicious behaviour.

### 6. Threat Classification

Classifies detected behaviour into the supported threat categories.

### 7. ATT&CK for ICS Mapping

Maps relevant detections to OT-specific adversary techniques.

### 8. Evidence Store

Stores security events using a tamper-evident hash chain.

### 9. Alert Management

Generates structured alerts for security analysts.

### 10. Dashboard

Provides visualization and investigation capabilities.

---

## 🛠️ Technology Stack

### Programming

* Python
* JavaScript / TypeScript

### Machine Learning

* Python ML libraries
* Scikit-learn
* TensorFlow / Keras where required

### Network Security

* Wireshark
* Scapy
* Zeek
* Network PCAP analysis
* `nftables`

### Protocol Analysis

* Modbus
* DNP3
* IEC 104

### Frontend

* React

### Backend

* Python-based API

### Security Framework

* MITRE ATT&CK for ICS

### Deployment

* Linux
* Docker
* CPU-only architecture

---

## 📁 Project Structure

```text
UniGuard/
│
├── backend/
│   ├── api/
│   ├── detection/
│   ├── preprocessing/
│   ├── protocols/
│   └── evidence/
│
├── frontend/
│   ├── src/
│   ├── components/
│   └── pages/
│
├── models/
│   └── trained_models/
│
├── datasets/
│   └── README.md
│
├── sample_pcaps/
│
├── scripts/
│
├── tests/
│
├── docs/
│
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/UniGuard.git
cd UniGuard
```

Create a Python virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Activate it on Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the System

The exact commands may change during development.

Typical workflow:

```text
1. Start the backend
2. Load the detection model
3. Provide PCAP / network traffic
4. Process packets and flows
5. Run feature extraction
6. Perform threat detection
7. Generate alerts
8. Store evidence
9. View results on dashboard
```

---

## 🗺️ Development Roadmap

### Phase 1 — Prototype

* Network traffic processing
* IT cybersecurity datasets
* Initial detection models
* Basic alert generation

### Phase 2 — ICS Validation

* ICS datasets
* OT protocol analysis
* ATT&CK for ICS mapping
* Encrypted traffic evaluation
* Cross-capture testing

### Phase 3 — Testbed / Pilot

* OT testbed deployment
* Receive-only hardware architecture
* Performance testing
* Realistic traffic validation
* Dashboard deployment
* Operational evaluation

---

## 🌐 Applications

UniGuard is intended for environments where network visibility and isolation are critical, including:

* Power utilities
* Water treatment
* Oil and gas
* Transportation
* Industrial automation
* Critical infrastructure SOCs
* OT security monitoring environments

---

## 🔮 Future Scope

Future development may include:

* Additional ICS protocol support
* Real-time packet processing
* Improved encrypted-traffic detection
* More advanced anomaly detection
* Automated threat correlation
* Expanded ATT&CK for ICS mapping
* SIEM integration
* Automated incident-response workflows
* Large-scale OT testbed validation
* Additional hardware data-diode integrations

---

## 👥 Team

### Team CeaserX

**Smart India Hackathon 2026**

**Problem Statement:** SIH26145
**Project:** UniGuard
**Domain:** Cybersecurity

---

## 📜 License

This project is developed as part of **Smart India Hackathon 2026** for research, development, and educational purposes.
