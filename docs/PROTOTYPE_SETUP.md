# UniGuard — Passive One-Way Network Threat Intelligence Platform

## Phase 1 & Prototype Assumptions

Due to the absence of Docker, Redis, and PostgreSQL/TimescaleDB on the host Windows environment, the prototype has been adapted to run completely standalone:
1. **Database**: SQLite (via `aiosqlite`) is used instead of TimescaleDB. While we lose TimescaleDB's continuous aggregates and hypertables, SQLite is sufficient for a 90-second functional demo.
2. **Message Broker**: Python's `asyncio.Queue` replaces Redis for the micro-batch pipeline. This means the entire backend runs in a single process rather than separate worker nodes.
3. **Execution**: The backend is run via `uvicorn` and the frontend via `npm run dev` directly on the host machine.

## How to Run
**Terminal 1 (Backend)**
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 (Frontend)**
```powershell
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

## Live private-lab traffic sensor

The backend does not generate or replay traffic. To observe traffic against a
controlled lab server, run the Linux/Kali capture/exporter in [`../sensor/`](../sensor/).
It captures only the explicitly configured private target/interface/port and
posts observed flows to the existing `POST /api/flows` endpoint. Read
[`../sensor/README.md`](../sensor/README.md) for setup, Windows firewall guidance, dry
run, and a small Kali-to-lab-server check.

The lab adapter reports packet-derived features and marks its CICFlowMeter
semantic differences. It does not silently invent unavailable initial-window
data: LightGBM/Isolation Forest are skipped for flows whose TCP SYN was missed.
The inference pipeline runs Beacon only with an observed packet sequence and
Char-CNN only with an observed DNS query name.

The prototype also exposes `GET /api/alerts` for the latest in-memory model
detections, `DELETE /api/alerts` to clear that in-memory list, and
`GET /api/metrics` for measured flow throughput over a rolling three-second
window. These values reset when the backend process restarts.
