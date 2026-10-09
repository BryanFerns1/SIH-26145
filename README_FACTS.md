# UniGuard repository facts (inspection 2026-10-10)

This file records what is present in this checkout. `scratch/model_extract/` contains experiment snapshots and stale source/results; it is not imported by the backend at runtime. Metrics below are labelled as either recorded in checked-in model cards/reports or measured during this inspection. A recorded metric is not a new evaluation performed here.

## 1. Repository overview

### Folder tree (annotated, two to three levels)

```text
Prototype/
├── backend/                         FastAPI backend and deployed model artifacts
│   ├── app/                          API, flow ingestion, schema, storage and ML pipeline
│   │   ├── api/                      Empty API package placeholder; routes are in app/main.py
│   │   ├── core/                     Pydantic settings
│   │   ├── db/                       SQLAlchemy models and async DB connection
│   │   ├── ml/preprocess/             LightGBM, DNS and beacon feature adapters
│   │   └── pipeline/                 Model inference and alert construction
│   ├── artifacts/                    Three deployed model families plus cards/metadata
│   ├── tests/                        Backend ensemble mapping tests (currently stale/failing)
│   └── uniguard/                     LightGBM estimator wrapper
├── data/samples/                     50-row CSV used in the API smoke run
├── docs/                             Model discovery notes
├── frontend/                         React + TypeScript dashboard (Vite)
│   ├── public/                       Static public assets
│   └── src/                           App, page/component sources and state/WebSocket client
├── scratch/                           Logs and archived model/training/evaluation work
│   └── model_extract/                 Extracted snapshots from three model archives
├── sensor/                            Linux/Kali private-lab passive flow sensor
├── docker-compose.yml                 TimescaleDB, Redis, API and nginx stack definition
├── render.yaml                        Render Blueprint for API and static dashboard
├── README.md                          Existing setup and prototype description
``` 

The checked-in application has **no root-level `requirements.txt`, `package.json`, LICENSE, `.github` CI workflow, or Docker Compose version declaration**. `git` is not installed in the inspection environment, so repository status/commit provenance could not be read (`git status --short --branch` → `git: The term 'git' is not recognized`). No public badges are justified by files present. The README's “working prototype” is supported by the local smoke run below, with caveats.

### Entry points and call flow

- Backend: `backend/app/main.py`: FastAPI lifespan initializes the database, `ModelRegistry`, `Pipeline`, and `FlowProcessor`; `POST /api/flows` → `FlowProcessor.process` (`backend/app/ingestion.py`) → `Pipeline.process_batch` (`backend/app/pipeline/ensemble.py`) → artifact-specific preprocessors/models → schema `Alert` (`backend/app/schemas.py`) → SQLite row, in-memory recent-alert deque and WebSocket broadcasts.
- Sensor: `sensor/flow_sensor.py:main` → `parse_args` → `LabFlowSensor.run` → Scapy `sniff(store=False)`/`handle_packet` → per-directional-five-tuple `FlowState` → `to_record` → bounded export queue → POST batch to `/api/flows`.
- Frontend: `frontend/src/main.tsx` mounts `frontend/src/App.tsx` and `WebSocketProvider`; provider fetches alerts/metrics and receives `/ws` messages; app renders Overview, Alerts, Hosts, Models and Settings. `App.jsx` and `src/pages/*.tsx` contain additional/older UI components; they are not the main entry rendered in `main.tsx`.

### Languages and versions

| Component | Evidence/version |
|---|---|
| Python | Host Python `3.13.13`; backend Docker image `python:3.11-slim`; code/dependencies do not state a Python package lock or `requires-python`. Sensor is Linux-only (`sys.platform != 'linux'` exits). |
| Node | Host Node `v24.21.0`; frontend Docker build uses `node:22-alpine`. |
| npm | Host npm `11.19.0`; `frontend/package-lock.json` locks install resolution. |
| Frontend | React `^19.2.8`, TypeScript `~6.0.2`, Vite `^8.3.0`; successful local build reported Vite `8.3.2`. |
| API | FastAPI pinned `0.115.0`, Uvicorn `[standard]` pinned `0.30.0`; temporary clean environment installed from the file and loaded all models. |
| Compose | Docker Compose file has no `version:` key. Docker CLI/Compose are not installed here, so engine/plugin version is NOT FOUND. |

## 2. Requirements and installation

### Hardware, OS, privileges, ports

Observed inspection host: Windows 11 Home Single Language 64-bit, build 26300; Intel Core i5-13420H, 8 physical / 12 logical cores; RAM 15.7 GiB. This is only the inspection host and no throughput claim was measured on it. The live sensor expressly needs Linux/Kali, an interface accessible to Scapy/libpcap, and capture privileges (README says `sudo` or `CAP_NET_RAW` and `CAP_NET_ADMIN`; code only invokes capture and needs packet-capture privilege; it does not install firewall rules). `libpcap-dev` is in the sensor setup. No CAP_NET_RAW, root-only nftables rules, zero-TX counter, or egress-firewall verification is included in this repo.

Ports in configuration/docs: API and WebSocket `8000`; Vite dev dashboard `5173`; nginx dashboard `80`; Compose also publishes PostgreSQL-compatible TimescaleDB `5432` and Redis `6379`. `backend/Dockerfile` defaults to 10000 for Render, whose `PORT` can override. Compose maps API `8000:8000`, frontend `80:80`. PostgreSQL/Redis are declared in Compose, but backend defaults to SQLite and actual runtime code does not use Redis.

### Dependency/config contents

`backend/requirements.txt` (verbatim):

```text
fastapi==0.115.0
uvicorn[standard]==0.30.0
pydantic==2.9.0
pydantic-settings==2.5.0
sqlalchemy[asyncio]==2.0.35
aiosqlite==0.20.0
onnxruntime
lightgbm
joblib
scikit-learn
numpy
pandas
websockets==12.0
python-multipart==0.0.9
orjson==3.10.7
httpx==0.27.2
```

Six ML/runtime dependencies are unpinned; this checkout has no constraints/lockfile for them. `sensor/requirements.txt`:

```text
httpx==0.27.2
scapy==2.6.1
```

`frontend/package.json` (verbatim manifest):

```json
{
  "name": "frontend", "private": true, "version": "0.0.0", "type": "module",
  "scripts": {"dev":"vite","build":"tsc -b && vite build","lint":"oxlint","preview":"vite preview"},
  "dependencies": {
    "@fontsource/inter":"^5.3.0","@fontsource/jetbrains-mono":"^5.3.0",
    "@tanstack/react-query":"^5.104.1","@tanstack/react-table":"^9.2.5","@tanstack/react-virtual":"^3.14.13",
    "@types/three":"^0.186.0","class-variance-authority":"^0.7.1","clsx":"^2.1.1",
    "echarts":"^6.1.0","echarts-for-react":"^3.0.6","framer-motion":"^14.0.0",
    "lucide-react":"^1.52.0","puppeteer":"^25.12.0","radix-ui":"^1.7.0",
    "react":"^19.2.8","react-dom":"^19.2.8","react-force-graph-2d":"^1.29.2",
    "react-hotkeys-hook":"^5.3.3","react-resizable-panels":"^4.14.2","react-router":"^8.4.0",
    "react-router-dom":"^7.18.4","recharts":"^3.10.1","tailwind-merge":"^3.7.0",
    "three":"^0.186.1","tw-animate-css":"^1.4.0","zustand":"^5.0.15"
  },
  "devDependencies": {
    "@tailwindcss/vite":"^4.3.3","@types/node":"^24.19.1","@types/react":"^19.2.18",
    "@types/react-dom":"^19.2.7","@vitejs/plugin-react":"^6.1.1","oxlint":"^1.81.0",
    "tailwindcss":"^4.3.3","typescript":"~6.0.2","vite":"^8.3.0"
  }
}
```

`backend/Dockerfile` (verbatim):

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 10000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
```

`frontend/Dockerfile` (verbatim):

```dockerfile
FROM node:22-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

`docker-compose.yml` service configuration (comments omitted, values preserved):

```yaml
services:
  timescaledb:
    image: timescale/timescaledb:latest-pg16
    container_name: uniguard-tsdb
    environment: {POSTGRES_USER: uniguard, POSTGRES_PASSWORD: uniguard_sih2026, POSTGRES_DB: uniguard}
    ports: ["5432:5432"]
    volumes: ["tsdb_data:/var/lib/postgresql/data"]
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U uniguard"], interval: 5s, timeout: 3s, retries: 10}
  redis:
    image: redis:7-alpine
    container_name: uniguard-redis
    ports: ["6379:6379"]
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck: {test: ["CMD", "redis-cli", "ping"], interval: 5s, timeout: 3s, retries: 10}
  backend:
    build: {context: ./backend, dockerfile: Dockerfile}
    container_name: uniguard-backend
    ports: ["8000:8000"]
    environment:
      REDIS_URL: redis://redis:6379/0
      DATABASE_URL: postgresql+asyncpg://uniguard:uniguard_sih2026@timescaledb:5432/uniguard
      ARTIFACTS_DIR: /app/artifacts
      LOG_LEVEL: INFO
    volumes: ["./backend:/app", "./data:/data"]
    depends_on:
      redis: {condition: service_healthy}
      timescaledb: {condition: service_healthy}
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --log-level info
  frontend:
    build: {context: ./frontend, dockerfile: Dockerfile}
    container_name: uniguard-frontend
    ports: ["80:80"]
    depends_on: [backend]
volumes:
  tsdb_data:
```

`frontend/package.json` declares the scripts (`dev`, `build`, `lint`, `preview`) and dependency ranges; exact resolved packages are in `frontend/package-lock.json`. Frontend Docker uses `npm install` (not `npm ci`), and Python Docker installs the unpinned requirements as currently resolved.

`backend/Dockerfile`: `python:3.11-slim`, installs `build-essential libpq-dev`, copies requirements and app, runs Uvicorn on `${PORT:-10000}`. `frontend/Dockerfile`: `node:22-alpine` build, `npm install`, `npm run build`, then `nginx:alpine` serving port 80. `docker-compose.yml` raw service settings: TimescaleDB `timescale/timescaledb:latest-pg16`, Redis `redis:7-alpine` capped at 256 MB, backend depends on both health checks, frontend port 80. Compose sets a `postgresql+asyncpg://...` URL, but `asyncpg` is missing from backend requirements; Compose startup may fail at DB engine setup and was not executable here. Compose hardcodes demo database credentials; this is not a production-safe secret configuration.

Settings in `backend/app/core/config.py` (environment names are uppercase forms because `env_prefix=""`, case-insensitive): `ARTIFACTS_DIR` defaults to backend artifacts; `DATA_DIR=/data`; `REDIS_URL=redis://localhost:6379/0`; `DATABASE_URL=sqlite+aiosqlite:///./uniguard.db`; target flows/s `5000`; micro batch size `256`; batch timeout `100 ms`; max queue depth `10000`; weights `0.45/0.25/0.30`, signal boost `0.15`; WebSocket interval `250 ms`; `LOG_LEVEL=INFO`; `SENSOR_API_KEY` and `ADMIN_API_KEY` empty. Several settings (target, batching, weights, Redis and WS interval) are not actually applied by this runtime path. The actual flow processor has a 3-second rate window, max 500 recent alerts and API max 4096 flows per batch. Sensor CLI defaults: backend URL `http://127.0.0.1:8000/api/flows`, idle timeout 5 s, active timeout 60 s; `UNIGUARD_SENSOR_API_KEY` optionally supplies request header. Frontend optional `VITE_API_BASE_URL`; Vite proxy uses localhost:8000; telemetry plugin additionally reads `UNIGUARD_BACKEND_URL`, `UNIGUARD_SENSOR_API_KEY`/`SENSOR_API_KEY`.

### Exact install/run attempts

Docker was attempted with `docker --version` and `docker compose version`; both failed because `docker` is not recognized. Thus Compose installation/run was NOT MEASURED. Raw error excerpt:

```text
docker : The term 'docker' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

Frontend clean dependency installation was present already (`frontend/node_modules` existed); `npm run build --prefix frontend` succeeded. Backend clean install was run in temporary `backend/.venv-doc-facts` using Python 3.13 and `pip install -r backend/requirements.txt`; all listed dependencies installed. `pyarrow==23.0.1`, `scapy==2.6.1` and `psutil==7.2.2` were added only to that temporary environment for archive evaluation/tests; they are absent from `backend/requirements.txt`. This directory remains in the workspace because automatic review rejected the recursive cleanup command. The original `backend/venv` launcher is broken because it points to missing `C:\Program Files\Python313\python.exe`.

Manual app start command (from `backend/`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Dashboard, in another terminal from `frontend/`:

```powershell
npm ci
npm run dev -- --host 0.0.0.0
```

For sensor, on Linux/Kali from `sensor/`: `sudo apt install -y python3-venv libpcap-dev`; create/activate venv; `python -m pip install -r requirements.txt`; then run the documented `sudo .venv/bin/python flow_sensor.py --mode private-lab --interface <IFACE> --target <PRIVATE_IP> --port <PORT> --backend-url http://<BACKEND_PRIVATE_IP>:8000/api/flows --flow-timeout 3`. This capture command was not run because the host is Windows and there is no live lab interface/target. Ports/firewall reachability also not tested.

### Quick demo fact

The repo has no attack/traffic generator. A reproducible smoke path is backend + dashboard + POST the checked-in `data/samples/sample_50.csv` converted to flow JSON. In this inspection, the actual API accepted 50 rows and returned `{"flows_received":50,"alerts_generated":50,"processing_time_ms":137.501}`; the model output comprised 40 `SCAN` and 10 `DDOS` alerts. This archived CSV has no flow addresses or packet sequences/domains, so returned tuples show `0.0.0.0:0`, and its generated classifications are model predictions, not a validated realistic alert demo. No elapsed wall time for clone-to-visible-alert was measured. Expected number/classes on another install: NOT GUARANTEED.

## 3. Simulated one-directional input

The active sensor does not use `tcpreplay`, ingest PCAP files, or derive a one-way file from bidirectional data. It sniffs live Linux packets with `store=False`, BPF-filtered to packets whose **destination** is the configured private target and destination port; exported five-tuples retain that direction. It groups only that direction, not a reverse-direction mate. It has no PCAP CLI, NetFlow, IPFIX, sFlow or live socket API beyond Scapy capture. Data conversion scripts live in `scratch/model_extract/` and cannot be described as the running input adapter. No capture files/dataset conversion proof are included.

Actual parser: TCP, UDP, IPv4 and IPv6; DNS query name only when Scapy sees an unencrypted DNS question on destination port 53. TLS, QUIC, Modbus, DNP3 and IEC 104 parsers are NOT FOUND. No TLS fingerprint code. No packet payload bytes are exported; payload *length* is used, and the DNS question name is extracted as metadata from cleartext DNS.

## 4. Per-threat implementation (six problem classes)

| Required threat | What the active backend actually does | Layer/features/threshold/evidence |
|---|---|---|
| Volumetric/protocol DDoS | Partial, indirect: LightGBM attack binary + 10-class model; class labels containing `DoS` map to `DDOS`. No separate SYN flood, UDP reflection/amplification, spoof-source or source-IP entropy/rate detector. The deployed multiclass label `DDoS` can yield DDOS predictions from CIC features, but this is not packet rule validation. | Flow classifier; 38 forward-only CIC-style features. Binary review `0.005563...`, high `0.145161...`; alert branch uses 0.0056 and 0.1452. No explicit rate/entropy window. `backend/app/pipeline/ensemble.py`, `backend/app/ml/preprocess/lgbm.py`. |
| Botnet/C2 beaconing | Partial model: 1D CNN on first ≤32 directional packet size/IAT/TCP flags, isotonic calibrated. No periodicity statistic, jitter-tolerant interval matching, or benign-beacon down-weighting in deployed pipeline. It runs per completed flow, not across repeated flows/host history. | Sequence model; review ≥0.4286, high ≥0.9149. `backend/app/ml/preprocess/beacon.py`; `backend/app/pipeline/ensemble.py`; `backend/artifacts/beacon_cnn/`. |
| DGA/DNS tunnel | Domain-name Char-CNN runs only if the sensor gives a nonempty DNS `domain`. Uses tokens and 18 lexical features including length, entropy and label lengths. Record-type anomalies/query-type counts are not implemented; query-length is present as a lexical domain length feature. | DNS feature/model path; DGA ≥0.655, tunnel ≥0.100. `backend/app/ml/preprocess/charcnn.py`, `backend/app/pipeline/ensemble.py`; artifacts `charcnn`. DNS benchmark caveat says query-side only. |
| Malware in encrypted sessions | NOT IMPLEMENTED in active app. No JA3/JA3S/JA4, TLS metadata model, QUIC support or TLS decryption. | None. Search of active `backend/app`, `sensor`, deployed artifacts finds no JA3/QUIC detector. |
| Recon/port scanning | Partial and mapping is overbroad: LightGBM's `Portscan` maps to `SCAN`, but the active mapping also maps every multiclass label not containing the exact substring `DoS` to `SCAN`, including `BENIGN`. No horizontal/vertical fan-out aggregation over destination ports/hosts in app. | 38 forward-only CIC-style flow features; same binary review/high thresholds. Sensor maintains directional flow keys only. `backend/app/pipeline/ensemble.py`; no host-window counter. |
| Data exfiltration | NOT IMPLEMENTED. No inbound/outbound byte ratio/asymmetry detector; absent reverse direction means the one-way target-bound sensor cannot compute the counterpart flow's inbound/outbound volume. | No ratio threshold/rule or `EXFIL` branch in active pipeline. |

The schema enum names all six required classes plus others, but enum membership is not implementation. Backend may produce `ANOMALY`; `TLS_MALWARE` and `EXFIL` are never assigned by the current `Pipeline`.

## 5. Models and training

### Deployed artifacts

| Model | Algorithm, data and recorded output | Hyperparameters/features | File and size |
|---|---|---|---|
| `lgbm_iforest` binary | LightGBM binary; model card says CIC-IDS2017 Improved with Engelen/Rimmer/Joosen corrected labels. Recorded time-blocked metrics: high tier recall 99.56%, precision 99.9%, FPR 0.31%; review recall 99.64%, precision 99.9%, FPR 1.49%. Output attack probability. | 38 forward-only features; binary params `num_leaves=63`, `max_depth=-1`, `min_child_samples=50`, feature/bagging fractions .8, LR .05, 2000 estimators. | `backend/artifacts/lgbm_iforest/lgbm_binary.txt` 11,652,769 B; calibrator 4,036,006 B. |
| `lgbm_iforest` multi | LightGBM 10-way: BENIGN, Botnet, DDoS, DoS GoldenEye, DoS Hulk, DoS Slow, FTP-Patator, Portscan, SSH-Patator, Web Attack. Per-class P/R/F1/support: NOT FOUND in deployed card. | Same 38 features. Card omits full multiclass hyperparameter record. | `lgbm_multi.txt` 25,702,780 B; calibrator 2,443,235 B. |
| `lgbm_iforest` anomaly | sklearn IsolationForest; benign CIC-IDS2017 only; returns `-decision_function`, threshold 0.0847. Card records 78.7% Portscan, 1.8% DDoS recall; Botnet/Web Attack 0%. | 300 estimators, `max_samples=0.1`, `contamination=auto`; `log1p(clip(x, lower=0))` over 38 fields. | `iforest.joblib` 66,376,349 B. |
| `charcnn_dns` | HybridNet v4 multi-scale CNN + BiGRU/lexical gate, ONNX, benign/DGA/tunnel; 943,923 params. Card-reported 10,769-test accuracy 93.21%, macro F1 91.99%; per-class metrics below. | 128 character tokens + 18 z-score lexical features; embedded temperature scaling T=1.012448. | `uniguard_charcnn.onnx` 102,912 B plus external tensor 3,779,520 B; `feature_stats.npz` 644 B. |
| `beacon_cnn` | 1D CNN on CTU-13; binary benign/botnet. Card-reported P 99.36%, R 83.79%, F1 90.91%, ROC-AUC .938, PR-AUC .9786; 11,255 test rows. | (32,7) sequence; 21,697 parameters; isotonic calibration. | `model.onnx` 92,471 B; calibrator 565 B. |

Current backend imports exactly these three model-card families. There is no standalone TLS, exfil, DDoS heuristic or scan-window model.

### Feature list and windows

- **Flow (38)**, in exact order in `backend/app/ml/preprocess/lgbm.py`: 28 base: Flow Duration; Total Fwd Packet; Total Length of Fwd Packet; Fwd Packet Length Max/Min/Mean/Std; Fwd IAT Total/Mean/Std/Max/Min; Fwd PSH Flags; Fwd URG Flags; Fwd RST Flags; Fwd Header Length; Fwd Packets/s; SYN/FIN/RST/PSH/ACK/URG Flag Count; Subflow Fwd Packets; Subflow Fwd Bytes; FWD Init Win Bytes; Fwd Act Data Pkts; Fwd Seg Size Min; Fwd Segment Size Avg. Derived 10: `d_fwd_bytes_per_pkt`, `d_fwd_hdr_per_pkt`, `d_fwd_pkts_per_s`, `d_fwd_bytes_per_s`, `d_fwd_iat_cv`, `d_fwd_len_cv`, `d_fwd_len_range`, `d_subflow_bytes_per_pkt`, `d_fwd_hdr_ratio`, `d_fwd_active_ratio`.
- **DNS (18)**: length, log_len, entropy, norm_entropy, digit_ratio, alpha_ratio, vowel_ratio, max_consonant_run, sep_ratio, unique_char_ratio, n_labels, max_label_len, mean_label_len, hex_fraction, base32_fraction, base64_fraction, dict_word_ratio, subdomain_entropy. Note implementation sets `dict_word_ratio=0` (documented as simplified/mock) and `subdomain_entropy=whole-domain entropy`; no qtype feature. Token window 128 chars.
- **TLS**: none.
- **First-N packet sequence (7 channels)**: log packet size, log IAT microseconds, real/padding mask, TCP SYN/FIN/RST/PSH. Sensor retains at most first 32 sequence entries per flow; model uses 32x7.
- **OT**: none. Archived flow-training config mentions 10/60-second host windows and a 100,000-key bound, HLL precision 10, and snapshot times .5/1/5/30 seconds/end; those are in `scratch/model_extract/newmodel/newmodel/config.py`, not used by active app/sensor.

### Training facts and datasets

Active README explicitly says this setup does not retrain. Reproducible source scripts for deployed LightGBM are in archived `scratch/model_extract/newmodel/newmodel/training/`; other source in `scratch/model_extract/training/training/` and `scratch/model_extract/charcnn/CHAR-Cnn anti/Char-Cnn/`. They refer to external data directories and are not wired into the app. Flow config describes time-blocked/capture-by-day split: train Mon–Wed, validation Thu, test Fri; another archived report says time-blocked proportions train 60%, val 10%, gap 5%, cal 5%, test 20%. These reflect different archive configurations and must not be conflated. Config drops attempted rows, merges rare labels and uses class weights plus half-weight for benign. Artifact cards say isotonic for beacon, temperature scaling for DNS, `CalibratedClassifierCV` wrappers for LightGBM; random seeds in archived flow config are 42, and beacon training result seed 42. No deployed checksum/retraining recipe pins all data/software/random seeds.

| Dataset | Present evidence | Size/split/source/license |
|---|---|---|
| CIC-IDS2017 Improved | Named in LightGBM card, archived processed parquets include per-day and train/val/cal/test. External raw source path in archived config is `C:\Users\soura\Downloads\CICIDS2017_improved`. | Archived processed row counts: train 963,503; val 173,913; cal 99,946; test 288,796. Per-day rows: Mon 350,579; Tue 296,907; Wed 453,585; Thu 258,745; Fri 345,205. These are parquet rows, not raw dataset size. Raw data absent. Local sample CSV is 50 rows. Dataset license NOT FOUND. |
| CTU-13 | Named in beacon card; card says scenarios 1–5 train, 6–7 val, 13 calibration, 8+12 test. | Raw capture count/bytes and licence NOT FOUND in this repo. |
| DNS Threats multiclass | Named in Char-CNN card (benign/DGA/DNS tunnel); archived train/val/test/calibration CSVs. | Card test support 7,000 benign/2,146 DGA/1,623 tunnel. Dataset canonical URL/licence and total original data size NOT FOUND. |
| 4SICS, HAI, CIC-IDS2018/CIC-DDoS2019 | Mentioned in config/report only; 4SICS/HAI variables are `None`; report explicitly says cross-dataset data absent. | Not evaluated; data/license/size/split NOT FOUND. |

Training commands, from the archived scripts, not a validated one-command procedure: `python run_all.py --quick --skip-stage1 --skip-stage7` under `scratch/model_extract/training/training/` for beacon, or `python training/train_lgbm.py`, `python training/train_iforest.py`, `python training/calibrate.py` in archived `scratch/model_extract/newmodel/newmodel/`. Inputs are external/missing and scripts may overwrite archived model artifacts; no retraining command was executed. Archived evaluation commands that ran are `python evaluation/eval_leave_days.py`, `python evaluation/eval_leave_class.py`, `python evaluation/eval_input_matrix.py`, `python evaluation/eval_evasion.py` and `python ops/benchmark.py` from the latter directory, after installing temporary PyArrow 23.0.1 and psutil. The backend requirements do not install a parquet engine or psutil.

## 6. Model performance (measured vs recorded)

The first `python evaluation/eval_evasion.py` attempt failed because pandas had no parquet engine. PyArrow 23.0.1 was then installed in a temporary environment and archived evaluators ran. These scripts evaluate `scratch/model_extract/newmodel/newmodel/` models/data, not the live app end to end. They are fresh commands against archived files, not necessarily the deployed artifact versions. No random-split versus cross-capture comparison script/result was found.

Artifact-recorded metrics:

- Char-CNN validation/test card: benign precision/recall/F1 `0.9212/0.9793/0.9494` support 7,000; DGA `0.9150/0.7269/0.8102` support 2,146; DNS tunnel `1/1/1` support 1,623. Matrix (true rows) `[[6855,145,0],[586,1560,0],[0,0,1623]]`. Archived PNGs: `scratch/model_extract/charcnn/CHAR-Cnn anti/Char-Cnn/outputs/confusion_matrix_v4_full.png`, `roc_pr_curves.png`.
- Beacon card: binary P/R/F1 `0.9936/0.8379/0.9091`, support 11,255 (`n_positive=8388`, `n_negative=2867` in `training_results.json`); matrix `[[2822,45],[1360,7028]]`; calibration ECE raw .3098, calibrated .0797; HIGH threshold test FPR 3.28%, recall 85.93%; REVIEW test FPR 48.59%, recall 97.47%. This is C2/botnet model validation, not all six problem classes.
- LightGBM binary card: high tier attack recall .9956, precision .999, FPR .0031; review recall .9964, precision .999, FPR .0149. Isolation Forest card: benign FPR .0119, Portscan recall .787, DDoS .018. Card says cross-dataset CIC-IDS2018 untested and exfil/DNS tunneling not labeled.
- Scratch-only flow report claims E6 feature perturbation results: padding +50 B/pkt: binary HIGH 99.5%, review 99.6%, IForest recall 3.2%, benign FPR 1.4%; 50ms jitter: 99.6%, 99.6%, 3.7%, 1.1%; low-and-slow 10x: 99.5%, 99.6%, 6.0%, 1.4%. It reports E7 known periodic NTP/DNS FPR 0%, but deployed pipeline has no benign-beacon down-weighting; these archived numbers are NOT evidence of current backend behavior.

Fresh archived evaluator outputs, run from `scratch/model_extract/newmodel/newmodel/` with temporary Python 3.13 dependencies:

```text
python evaluation/eval_leave_days.py
test rows: 288,796 (held-out Friday data; 238,826 benign and 49,970 attacks)
Binary HIGH: ROC-AUC 0.9993, PR-AUC 0.9980; confusion [[238070,756],[222,49748]]
Binary REVIEW: confusion [[235264,3562],[182,49788]]
Multiclass supports and P/R/F1 (class names mapped by config):
BENIGN          N=238826  P=.998 R=1.000 F1=.999
Botnet          N=82      P=.953 R=1.000 F1=.976
DDoS            N=19306   P=.999 R=1.000 F1=1.000
DoS GoldenEye   N=2447    P=.993 R=.985 F1=.989
DoS Hulk        N=25043   P=.998 R=1.000 F1=.999
DoS Slow        N=313     P=.874 R=.466 F1=.608
FTP-Patator     N=802     P=.999 R=.988 F1=.993
Portscan        N=1945    P=.994 R=.810 F1=.893
SSH-Patator     N=1       P=.000 R=.000 F1=.000 (weak support)
Web Attack      N=21      P=.800 R=.381 F1=.516 (weak support)
Isolation Forest: ROC-AUC .9341, PR-AUC .6442; confusion [[236420,2406],[48247,1723]]
Isolation Forest flagged: benign 1.0%, Botnet 0.0%, DDoS 1.0%, GoldenEye 0.0%, Hulk 0.1%, Slow 4.2%, FTP 0.0%, Heartbleed 100% (N=3), Infiltration 0% (N=7), Portscan 76.5%, SSH 0% (N=1), Web Attack 0% (N=21).

python evaluation/eval_leave_class.py
Botnet 6.0% (736, unseen); Portscan 94.1% (1,572, supervised-seen); DDoS 0.7% (95,144, unseen)

python evaluation/eval_input_matrix.py
Full PCAP uniflow: binary recall 100.0%, IForest recall 2.3%
Truncated flows:   binary recall 100.0%, IForest recall 100.0%
NetFlow/IPFIX:     binary recall 32.7%, IForest recall 100.0%

python evaluation/eval_evasion.py
Test Set Attacks: 97,452
Baseline:                 Binary HIGH 99.9%, REVIEW 100.0%, IForest 2.3%
Padding avg 50 B/pkt:     Binary HIGH 99.9%, REVIEW 99.9%, IForest 1.5%
Padding avg 250 B/pkt:    Binary HIGH 99.9%, REVIEW 99.9%, IForest 1.6%
Timing jitter max 50 ms:  Binary HIGH 99.9%, REVIEW 99.9%, IForest 2.4%
Timing jitter max 200 ms: Binary HIGH 99.9%, REVIEW 99.9%, IForest 2.7%
Padding + jitter:         Binary HIGH 99.7%, REVIEW 99.8%, IForest 1.5%
Low and slow 10x:         Binary HIGH 99.2%, REVIEW 99.8%, IForest 3.4%
Low and slow 100x:        Binary HIGH 99.2%, REVIEW 99.8%, IForest 98.1%
```

The evasion script prints recall/flag rates but not benign-only FPR per perturbation. These are archived CIC-style model evaluations, not 4SICS/HAI or live sensor results. The E8 input matrix output differs from narrative values in `reports/REPORT.md`.

Not found or not measured: six required SIH classes' P/R/F1/support as a single system; benign-only API alerts/hour or per-million; current backend ECE/reliability run; random-split versus cross-capture comparison; IT vs 4SICS/HAI; current model ROC/PR paths for all six; L1/L1+L2/L1+L2+L3 ablation; PSI drift. `scratch/model_extract/training/training/model_bundle/reliability_diagram.png` and `psi_baseline.json` are legacy/archive artifacts, not a current app evaluation.

## 7. System performance

An archived model benchmark **was** run with `python ops/benchmark.py` from `scratch/model_extract/newmodel/newmodel/`. It uses precomputed `test.parquet`, feature preparation, binary/multiclass LightGBM and Isolation Forest; throughput uses batches of 10,000. Batch-1 latency precomputes feature frames and measures inference only, not HTTP, sensor, storage or WebSocket.

```text
Pinned process to CPU core: [0]
Feature Prep Time (per batch): 13.6 ms
Binary Eval Time (per batch):  132.2 ms
Multi Eval Time (per batch):   608.5 ms
IForest Eval Time (per batch): 325.9 ms
Total Throughput:              9,257 flows / sec
P50 Latency: 15.687 ms
P95 Latency: 20.211 ms
P99 Latency: 23.170 ms
```

Host for this archived benchmark: Windows 11 Home Single Language 64-bit, build 26300; Intel Core i5-13420H, 8 physical/12 logical cores, 15.7 GiB RAM. Process affinity was pinned to CPU 0. On this archived model-only benchmark, the numeric target values in the request (>=5,000 flows/s and p99 <1 s) are met. This does **not** show those targets are met end-to-end by live sensor→API→storage→WebSocket/dashboard. Mbps, maximum ceiling, tcpreplay speed/flags, CPU/RAM under load and attack-load continuity remain unmeasured. Model cards separately report LightGBM 13,209 flows/s and 15.6 ms p99; Beacon ONNX 24,917 flows/s at batch 256 and .071 ms p50; Char-CNN batch 1 58.9 qps, p50 16.77, p95 19.03, p99 24.20 ms on “Intel CPU”. Those are different scopes/hardware.

Inspection API smoke: 50 CSV feature rows accepted; API returned processing time `137.501 ms` and `alerts_generated=50`. This is one batch timing, not p99 or sustained throughput. Metrics endpoint defines a trailing 3-second `received flows / 3` measure; during post-smoke query the backend was stopped, so no sustained number remains. No Mbps metric exists.

Slides cited in request are NOT FOUND in repository; comparison target >=5,000 flows/s and p99 <1s cannot be cross-checked against slides. A config default `TARGET_FLOWS_PER_SEC=5000` and schema target value are declarations only, not measurements. Status against a measured system target: **NOT MEASURED; do not claim met**.

The archived `python ops/benchmark.py` run used the temporary PyArrow/psutil install and is documented above; it does not benchmark the running API/sensor. `tcpreplay` is neither present nor used in code.

## 8. Output generated by the system

### Real API smoke output

The backend was launched with all three model families loaded. `Invoke-RestMethod POST /api/flows` used all 50 rows from `data/samples/sample_50.csv`, excluding the `Label` column; it returned 50 alerts. These are actual model predictions on the supplied sample features, but the sample has no tuple/domain/sequence values and is not evidence of real traffic detection. Output classes: 40 `SCAN`, 10 `DDOS`. No C2, DNS, TLS Malware or Exfil alerts were generated. Do not create one JSON alert per absent class by hand.

Representative exact DDoS model-generated alert:

```json
{
  "alert_id": "2b975a6b-7d96-4b1d-bda8-53494557a4df",
  "timestamp": "2026-10-09T18:52:29.416109",
  "detected_at": "2026-10-09T18:52:29.416120",
  "latency_ms": 137.5011000000086,
  "flow_id": "",
  "five_tuple": {"src_ip": "0.0.0.0", "src_port": 0, "dst_ip": "0.0.0.0", "dst_port": 0, "proto": "0"},
  "threat_class": "DDOS",
  "severity": "CRITICAL",
  "confidence": 0.9259259259259259,
  "models": [
    {"name": "lgbm_binary", "score": 0.9259259259259259, "label": "ATTACK", "version": "1.0.0"},
    {"name": "lgbm_multi", "score": 0.999999470720477, "label": "DDoS", "version": "1.0.0"}
  ],
  "rules_fired": [], "mitre": [],
  "evidence": {"observability": "uniflow_fwd_only"},
  "explanation": "", "incident_id": null, "prev_hash": "",
  "hash": "c06ae1cd8a81cc3624af111c4d3537c69eb80a3d9fd4499684f2d61973a52797"
}
```

Representative exact `SCAN` alert from the same batch (the multiclass output is `BENIGN`, demonstrating the overbroad mapping):

```json
{
  "alert_id": "e02cc6ce-16d1-4b17-b988-efbf2dc45f2e",
  "timestamp": "2026-10-09T18:52:29.416560",
  "detected_at": "2026-10-09T18:52:29.416570",
  "latency_ms": 137.5011000000086,
  "flow_id": "",
  "five_tuple": {"src_ip": "0.0.0.0", "src_port": 0, "dst_ip": "0.0.0.0", "dst_port": 0, "proto": "0"},
  "threat_class": "SCAN",
  "severity": "CRITICAL",
  "confidence": 0.9259259259259259,
  "models": [
    {"name": "lgbm_binary", "score": 0.9259259259259259, "label": "ATTACK", "version": "1.0.0"},
    {"name": "lgbm_multi", "score": 0.999999818667979, "label": "BENIGN", "version": "1.0.0"}
  ],
  "rules_fired": [], "mitre": [], "evidence": {"observability": "uniflow_fwd_only"},
  "explanation": "", "incident_id": null, "prev_hash": "",
  "hash": "a1ffd884d8fd24c44d8a3106164a4f7babebf86e21d2e06b64487b54a84b2a89"
}
```

This output exposes gaps: `flow_id` empty, all tuple fields zero, no evidence features, no MITRE mapping; `prev_hash` empty. The model schema (`backend/app/schemas.py`) defines `alert_id`, timestamps, latency, `flow_id`, `five_tuple`, `threat_class`, `severity`, `confidence`, model scores, rules, MITRE list, `evidence`, explanation, incident ID, previous hash/hash. It does **not** define requested `observability_state`, `evidence_features`, or `evidence_hash` as top-level fields; evidence is an unvalidated dictionary. Hash is a SHA-256 digest of selected alert fields, with `seal()` defaulting `prev_hash=""`; active code does not persist a chain or validate/tamper-test a chain. It is not a blockchain ledger.

One real example each for C2, DGA, DNS tunnel, TLS malware and Exfil: **NOT FOUND** in this run; TLS Malware and Exfil have no active detector. One `SCAN` example appears above (40 predictions in total). No correlated incident join/correlation is active. `Incident` schema/database table exists but no endpoint/correlation pipeline was found.

SIEM CEF/syslog exporter: NOT FOUND. Hash-chain ledger verification/tamper demo: NOT FOUND in active backend. `scratch/model_extract/newmodel/newmodel/ops/ledger.py` implements a separate archived SQLite ledger with `verify_chain()`, but it is not imported by the running API; no run/ledger DB shipped.

Read-only output: no zero-TX counters, nftables egress drop rules, or command/test output in repository. `sensor/flow_sensor.py` uses Scapy `sniff(..., store=False)` and HTTP POST export only; no packet sending method.

Existing log filenames include `scratch/runlogs/backend.stdout.log`, `backend.stderr.log`, `frontend.stdout.log`, `frontend.stderr.log` and older `scratch/backend-*.log`/`scratch/frontend-*.log`. They predate this documentation run and are not treated as current output. Current Uvicorn startup/API request output was returned in the terminal session; a complete transcript was not saved. Normal run output files: SQLite at the path determined by `DATABASE_URL` (default `./uniguard.db`, relative to backend process working directory); recent alerts also remain in memory (`maxlen=500`); Vite build output is `frontend/dist/`. No plots were generated by the API smoke. Archived plots live under `scratch/model_extract/`.

Actual FastAPI routes (`backend/app/main.py`): `GET /api/health`, `GET /api/models`, `GET /api/metrics`, `POST /api/metrics/http-activity`, `GET /api/alerts?limit=...`, `DELETE /api/alerts`, `POST /api/flows`, WebSocket `/ws`. Docs URL while running locally: `http://localhost:8000/docs`; no ReDoc (`redoc_url=None`). WebSocket JSON envelope: `{"type":"NEW_ALERT","data":<Alert>}` and `{"type":"METRICS_UPDATE","data":<PipelineMetrics>}`. Client does not send meaningful messages; server waits on text. UI main pages are Overview, Alerts, Hosts, Models, Settings (`frontend/src/App.tsx`). Repository has no screenshot/demo recording files; README links externally to a Google Drive folder. Capture current UI screenshots or recordings manually.

Raw smoke command result:

```text
POST /api/flows (50 rows from data/samples/sample_50.csv, no Label column)
{"flows_received":50,"alerts_generated":50,"processing_time_ms":137.501}
GET /api/models → beacon_cnn REAL, charcnn_dns REAL, lgbm_iforest REAL
GET /api/alerts?limit=500 grouped → SCAN 40, DDOS 10
```

The 50 rows written to the pre-existing `backend/uniguard.db` by this smoke run were deleted afterward using a precise timestamp/empty-flow-ID/zero-address predicate; cleanup verified exactly 50 matches before deletion and 0 afterward. The database file itself was retained.

## 9. Constraint compliance evidence

| Constraint | Code evidence and result |
|---|---|
| (1) Read-only ingest | `sensor/flow_sensor.py` uses `sniff` and `store=False`, only selects target-bound IP/TCP/UDP packets, then sends flow JSON via HTTP POST. No packet-transmit call. This supports passive capture implementation, but no hardware diode, TX counter or firewall test proves physical read-only. |
| (2) No decryption/raw payload storage | Sensor reads packet headers, payload lengths and optional cleartext DNS question name; only sends features/domain/metadata. No TLS decryption code and no raw payload field. `sniff(store=False)` avoids Scapy packet-list storage. No explicit privacy test proves “payload bytes never stored” across host, logs or OS; source only shows app code behavior. |
| (3) Streaming/bounded state/midstream alert | Sensor processes packets on capture callback; emits flow on FIN/RST, idle timeout 5s default or active timeout 60s; sequence capped at first 32; export queue maxsize 10,000; recent alerts deque max 500; receipt deque prunes after 3s. The active `flows` dict and per-flow packet stats lists have no count/byte cap; HLL/Space-Saving absent. API analyzes complete batches, not a microbatch worker, and emits after flow completion, not proof of a mid-flow alert. |
| (4) Stated/demoed throughput | Config target is 5,000 flows/s, but no end-to-end benchmark result. No tcpreplay. Request smoke is one 50-flow batch, 137.501 ms; not sustained throughput or p99. |
| (5) Standard alert validation | `Alert` Pydantic model exists, but `POST /api/flows` takes `list[dict[str, Any]]`; pipeline constructs alert instances. `Alert` constrains confidence [0,1] and enum fields but does not require nonempty flow ID/evidence/MITRE/feature schema. Hash validation/chaining is not implemented. |

## 10. Tests

Test files: `backend/tests/test_ensemble_attack_mapping.py`; `sensor/test_flow_sensor.py`; archived tests under `scratch/model_extract`. Commands/results:

```text
backend/tests using original backend/venv launcher:
failed before test import: did not find executable at C:\Program Files\Python313\python.exe

python -m unittest discover -s backend\tests -v (system Python 3.13.13 plus backend/venv site-packages):
ERROR: test module imports lgbm_input_is_compatible which does not exist in backend/app/pipeline/ensemble.py
Ran 1 test; FAILED (errors=1)

python -m unittest discover -s sensor -p 'test_*.py' -v (without venv path):
ERROR: No module named 'scapy'

python -m unittest discover -s sensor -p 'test_*.py' -v (with backend/venv site-packages):
Ran 5 tests; OK

npm run build --prefix frontend:
✓ built in 663ms (Vite 8.3.2); chunk warning: one JS bundle >500 kB

npm run lint --prefix frontend:
exit 0; 10 warnings (one react/only-export-components; nine unused imports/variables in src/App.jsx)
```

The fresh `.venv-doc-facts` was used to install declared backend dependencies and load the actual app successfully; all three models logged “loaded successfully”. It was not used to repair repository tests. There is no `npm test` script. `backend/test_ws.py` is a script, not discovered as a test suite; not run.

## 11. Limitations and gaps

- Only three deployed models. Required DDoS subtypes, source entropy, active periodic beacon logic, DNS record-type features, TLS JA3/JA3S/JA4/TLS/QUIC malware, horizontal/vertical fan-out, exfil ratios, OT/Modbus/DNP3/IEC 104 are absent or partial as in §4.
- Only passive live Linux capture to private target/port; no PCAP replay reader, `tcpreplay` integration, NetFlow/IPFIX/sFlow intake, full bidirectional-to-unidirectional conversion recipe, or production diode hardware proof.
- Sensor's packet-derived LightGBM fields are explicitly not CICFlowMeter-equivalent. It batches only complete flows. State memory grows with tracked flows and all packet-length/payload/IAT lists until timeout/close.
- Performance and end-to-end target proof missing; model-card benchmark numbers are not system results. Dataset and cross-capture/OT validation incomplete.
- Alert evidence, correlation, MITRE, SIEM export, incident correlation API, blockchain/ledger, and alert-chain verification incomplete. Although schema has `mitre`, active code emits empty list; schema computes per-alert hash but does not link alerts (`prev_hash=""`).
- No license file, no tests/CI badge/workflow. Backend ensemble test is stale. Docker Compose untested due missing Docker and omits the declared asyncpg driver. README dashboard includes live telemetry, but no generated attack stream; ordinary benign traffic may yield no alert.
- `frontend/src/App.jsx` includes hard-coded sample/dummy UI data and JA4/OT marketing-looking figures; active `main.tsx` imports `App.tsx`, whose UI is the API-backed implementation. Do not quote `App.jsx` decorative JA4/Mbps figures as system evidence.
- No TODO/FIXME markers were found in active first-party `backend/app`, `sensor`, or frontend application source search. Scratch scripts have implementation caveats and external absolute paths; dependency files contain many unrelated upstream TODOs and were excluded from this claim.

## 12. Misc

README lists team: Shrihari Girish Rodda, Bryan R Fernandes, Sourabh Shankar Itagi, Kiran A Patil; no roles or team ID found in files beyond project context. `README.md` cites GitHub clone URL `https://github.com/BryanFerns1/SIH-26145.git`, project PS SIH26145, Team CeaserX; external demo folder linked at `https://drive.google.com/drive/folders/1SSa41mV76reUJwQiKMfRAyxqldMEMnto`. `docs/MODEL_DISCOVERY.md` gives model artifact and paper-style feature/metric notes but no dataset primary-source URLs/license texts. `scratch/model_extract/newmodel/newmodel/reports/REPORT.md` has claims about time-blocked metrics, evasion, 0-day and HMAC; its ledger text conflicts with current schema SHA-256 and is not runtime evidence. No slides containing “60% completed” or “to be measured” were found; slides are NOT FOUND.

### Missing information I must supply manually

| Missing item | Exact command/file needed |
|---|---|
| Docker Engine/Compose version and tested Compose startup | Install Docker Desktop (or Linux Docker Engine + Compose plugin), then `docker --version; docker compose version; docker compose up --build`; save full logs and `docker compose ps`. |
| Supported Python version and pinned full dependency set | Add `requires-python`/lock or constraints file, then run `python --version; python -m pip freeze` in supported clean environment. |
| Live sensor privileges, packets and firewall posture | On Linux Kali: `id; getcap "$(command -v python3)"; ip -br address; sudo nft list ruleset; ip -s link`; perform documented lab capture and provide interface/target. `CAP_NET_RAW` needed; only add nft rules if policy requires them. |
| Hardware diode proof/zero-TX counters | Attach TAP/diode model and vendor evidence; run its documented RX/TX counter command during capture and save output. No repo command exists. |
| Ports reachable and browser screenshot | Run API and UI; `Test-NetConnection <host> -Port 8000/5173` on Windows or `curl`; manually capture screenshot/recording. |
| PCAP ingest/replay or NetFlow/IPFIX/sFlow support | Provide a supported PCAP/flow exporter and exact sample file/command; current sensor accepts live Scapy capture only. |
| Full detector evidence for all six classes and thresholds | Supply implementations/configs for missing detectors, or state approved exclusions; then provide detector-specific tests/config and captured output. Existing exact entry points are `backend/app/pipeline/ensemble.py` and `sensor/flow_sensor.py`. |
| Raw datasets, total sizes, licenses and provenance | Supply source download URLs, license files, and `Get-ChildItem <dataset> -Recurse -File | Measure-Object Length -Sum`; provide split/class-count script output. Current archived `config.py` expects CIC path outside repo. |
| End-to-end model evaluation/curves/calibration for deployed API | Archived test scripts ran and their distinct results are above; for deployed artifacts, pair a labeled held-out PCAP/flow set with actual API output and compute per-class metrics/FPR/calibration; current app has no such evaluator. Random/cross-capture and 4SICS/HAI data must also be supplied. |
| Cross-capture/random-vs-time split; 4SICS/HAI; PSI; ablation; unseen-attack and evasion results | Supply captures/datasets and run a versioned evaluation script; `scratch/model_extract/newmodel/newmodel/config.py` currently sets `ICS_4SICS_DIR = None`, `HAI_DIR = None`. |
| End-to-end flows/s, Mbps, latency percentiles, CPU/RAM, attack-load behavior | Run a versioned benchmark against the actual app with `tcpreplay` capture/flags and host specs; record p50/p95/p99 at sustained load, CPU/RAM, dropped flows and attack continuation. No current benchmark command supports the API end to end. |
| Six live JSON alerts, DNS/C2 output, evidence features | Run real captured lab traffic for each implemented class and save `GET /api/alerts` output. Current smoke only yielded DDOS/SCAN from archived feature CSV; actual classes C2/DNS not run. TLS malware/exfil have no detector to produce output. |
| Incident correlation, chained ledger, tamper demonstration | Implement/link production code; archived helper is `scratch/model_extract/newmodel/newmodel/ops/ledger.py`. Then provide ledger DB, verification command output, and modified-row tamper result. |
| SIEM CEF/syslog example | Add exporter and run it with a generated alert; no exporter currently exists. |
| Physical egress drop verification and payload retention audit | Provide system firewall/TAP configuration and commands/output, plus documented storage/log audit; source-level `sniff(store=False)` is not whole-host proof. |
| Dataset citations, source references, member roles, SIH slides/updated completion claim | Provide source bibliographic links/licenses, roles, and slide files; exact commands: `rg --files -g '*.pptx' -g '*.pdf'` (currently none found), and inspect team roster source. |
| License and CI status | Add chosen license text and CI workflow, then provide CI run URL/status. No current command can infer a license or CI badge. |
| Full-run stdout/logs and output locations on target system | Run live sensor/backend and save terminal output; backend SQLite path defaults to `backend/uniguard.db` when launched from `backend/`, alerts also remain in memory and recent history max 500. |
| Quick demo-to-visible-alert elapsed time | Run the documented backend/dashboard/sample POST and time it with PowerShell `Measure-Command`; recorded 137.501 ms is API processing time for a single batch, not clone-to-browser time. |
