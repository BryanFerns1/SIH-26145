# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## SIH26145

### 📌 Problem Statement

Industrial and critical infrastructure networks often use **unidirectional communication** to protect sensitive systems from external threats. While these networks improve security by preventing direct incoming connections, monitoring the traffic flowing through them and identifying malicious activity remains challenging.

The objective of this project is to develop a system capable of **monitoring unidirectional IP traffic and detecting potential cyber threats automatically**.

---

## 💡 Our Solution

We propose a cybersecurity monitoring system that analyzes network traffic flowing through a **unidirectional network architecture**.

The system captures and processes network traffic, extracts important characteristics from packets, and uses a **machine-learning/deep-learning based detection mechanism** to identify suspicious or malicious traffic.

The detected threats can then be displayed through a monitoring dashboard, allowing security teams to understand and respond to potential attacks.

---

## 🏗️ System Overview

```text
        OT / Production Network
                  │
                  │
          Network TAP / SPAN
                  │
                  ▼
       ┌─────────────────────┐
       │ Unidirectional Link │
       │   / Data Diode      │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │ Traffic Collection  │
       │ & Packet Processing │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │ Feature Extraction  │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │ Threat Detection    │
       │      Model          │
       └──────────┬──────────┘
                  │
          ┌───────┴────────┐
          ▼                ▼
      Normal Traffic    Threat Detected
                           │
                           ▼
                    Alert / Dashboard
```

---

## ⚙️ How It Works

### 1. Traffic Collection

Network traffic is collected from the monitored environment using mechanisms such as:

* Network TAP
* SPAN/Mirror Port
* Packet capture interfaces
* PCAP files

### 2. Packet Processing

Captured traffic is processed to extract useful network information such as:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Packet size
* Packet frequency
* Flow information

### 3. Feature Extraction

Relevant features are extracted from the network traffic and converted into a format that can be processed by the detection model.

### 4. Threat Detection

The extracted features are passed to the trained detection model.

The model classifies traffic as:

```text
Normal Traffic
       OR
Suspicious / Malicious Traffic
```

The system can be trained to identify different types of network attacks depending on the dataset used.

### 5. Alert Generation

When suspicious traffic is detected, the system generates an alert containing relevant information about the detected activity.

### 6. Monitoring Dashboard

A dashboard can provide security personnel with information such as:

* Current network activity
* Detected threats
* Threat type
* Source and destination information
* Detection timestamp
* Traffic statistics
* Threat history

---

## 🧠 Machine Learning / Deep Learning

The project can use machine-learning and deep-learning techniques for network traffic classification.

Possible approaches include:

* 1D Convolutional Neural Network (1D-CNN)
* Random Forest
* XGBoost
* Neural Networks
* Anomaly Detection

The model can be trained using publicly available cybersecurity datasets and evaluated using appropriate classification metrics.

---

## 📊 Dataset

The system can be trained and tested using network security datasets containing both normal and malicious traffic.

Example datasets include:

* CTU-13
* CICIDS
* CIC-DDoS
* Other relevant network traffic datasets

The dataset is processed before training to remove unnecessary information and convert network traffic into suitable model features.

---

## 🔍 Threat Detection

The system is designed to detect suspicious network behaviour such as:

* Denial-of-Service attacks
* Distributed Denial-of-Service attacks
* Port scanning
* Network scanning
* Brute-force activity
* Suspicious connection patterns
* Abnormal traffic behaviour

The exact attack categories depend on the dataset and trained model.

---

## 🛠️ Technology Stack

### Programming

* Python

### Machine Learning

* TensorFlow / Keras
* Scikit-learn
* NumPy
* Pandas

### Network Analysis

* Wireshark
* Tshark
* Scapy
* PCAP analysis

### Backend

* Python
* FastAPI / Flask

### Frontend

* React.js
* HTML
* CSS
* JavaScript

### Visualization

* Chart.js / Recharts
* Grafana

### Development Tools

* Git
* GitHub
* VS Code
* Docker

---

## 📁 Project Structure

```text
SIH26145/
│
├── backend/
│   ├── api/
│   ├── models/
│   ├── detection/
│   └── preprocessing/
│
├── frontend/
│   ├── src/
│   ├── components/
│   └── pages/
│
├── dataset/
│   └── README.md
│
├── models/
│   └── trained_models/
│
├── sample_pcaps/
│
├── notebooks/
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

### Clone the Repository

```bash
git clone https://github.com/<your-username>/<your-repository>.git
cd <your-repository>
```

### Create a Virtual Environment

```bash
python -m venv venv
```

### Activate the Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / macOS

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

Start the backend:

```bash
python app.py
```

Start the frontend:

```bash
npm install
npm run dev
```

The dashboard can then be accessed through the local development server.

---

## 🧪 Testing

The system can be tested using:

* Pre-recorded PCAP files
* Simulated network traffic
* Public cybersecurity datasets
* Normal and malicious traffic samples

Example workflow:

```text
PCAP File
   ↓
Packet Extraction
   ↓
Feature Extraction
   ↓
Preprocessing
   ↓
ML/DL Model
   ↓
Traffic Classification
   ↓
Threat Alert
```

---

## 🔐 Security Considerations

The proposed architecture focuses on monitoring traffic without creating a direct communication path back into the protected network.

Important considerations include:

* One-way traffic flow
* Isolation of critical systems
* Secure traffic collection
* Protection of captured network data
* Model integrity
* Secure dashboard access
* Logging and auditing

---

## 📈 Future Scope

Future improvements may include:

* Real-time packet analysis
* Improved anomaly detection
* Support for additional attack types
* Continuous model retraining
* Automated threat correlation
* Real-time dashboards
* Integration with SIEM systems
* Automated incident response
* Deployment using Docker/Kubernetes
* Support for large-scale industrial networks

---

## 🎯 Expected Outcome

The final system aims to provide a **practical network security monitoring solution** capable of:

1. Capturing unidirectional network traffic.
2. Processing network packets.
3. Extracting relevant traffic features.
4. Detecting abnormal or malicious behaviour.
5. Classifying potential cyber threats.
6. Generating security alerts.
7. Presenting useful information through a monitoring dashboard.

---

## 👥 Team

**Smart India Hackathon 2026**

**Problem Statement:** SIH26145
**Domain:** Cybersecurity

---

## 📜 License

This project is developed as part of **Smart India Hackathon 2026** for educational and research purposes.

