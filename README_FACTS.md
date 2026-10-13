<a id="top"></a>

<div align="center">

# 🛡️ UniGuard — Evidence Notes

**Smart India Hackathon 2026 · SIH26145 · Team CeaserX**

*The evidence file behind [README.md](README.md): every metric, claim and gap, with its source.*

</div>

| | |
|---|---|
| 📅 **Inspection date** | 2026-10-09 (Asia/Calcutta) |
| 💻 **Host** | Windows 11 (unless a command is marked otherwise) |
| 📁 **Paths** | Relative to the repository root; line numbers refer to this checkout |

## Status legend

| Badge | Meaning |
|---|---|
| 🟢 **MEASURED** | Run during this inspection |
| 🔵 **RECORDED** | Read from a checked-in model card or report; not rerun |
| 🔴 **NOT MEASURED** | No valid result was obtained |

## At a glance

| Area | Status | Headline |
|---|---|---|
| Active source inventory | 🟢 MEASURED | Sensor passive-capture call, bounds, alert timing and missing features documented with line numbers |
| Host and tool versions | 🟢 MEASURED | Intel Core i5-13420H, Python 3.13.13, Node v24.21.0, npm 11.19.0; Docker not installed |
| Model cards and artifact sizes | 🔵 RECORDED | LightGBM + Isolation Forest, Beacon CNN, DNS Char-CNN |
| Frontend build and lint | 🟢 MEASURED | Build passes; lint exits 0 with 10 warnings |
| Archived evaluator, evasion, benchmark | 🔴 NOT MEASURED | Reruns stopped at `ModuleNotFoundError: joblib` |
| Backend and sensor tests | 🔴 NOT MEASURED | Collection errors from missing packages |
| Backend sample POST | 🔴 NOT MEASURED | Runtime dependencies missing |
| Windows + Kali live demo | 🔴 NOT MEASURED | Template only (section 10) |

### Key findings

- 🔴 **`BENIGN` can map to `SCAN`**, because every multiclass label without `DoS` maps to `SCAN` (`backend/app/pipeline/ensemble.py:133-136`).
- 🔴 **Missing from active runtime:** HyperLogLog, Space-Saving, JA3/JA4, QUIC, DNS record-type features, MITRE mapping, incident correlation, hash chaining, CEF/syslog.
- 🟡 **Unbounded state:** the sensor flow dictionary and per-flow packet lists have no size cap (`sensor/flow_sensor.py:93-127,221`).
- 🟡 **README numbers not reproduced:** the exact evaluator, benchmark and smoke-run figures are unsupported by this inspection (section 12).

### Next steps

- [ ] Create an isolated environment and install `scratch/model_extract/newmodel/newmodel/requirements.txt`, `backend/requirements.txt` and `sensor/requirements.txt`
- [ ] Rerun `python -m evaluation.run_evals`, `python -m evaluation.eval_evasion` and `python -m ops.benchmark`, and archive the logs
- [ ] Rerun the backend sample POST using `data/samples/sample_50.csv`
- [ ] Fill in the live demo log (section 10) and commit dashboard screenshots under `docs/`
- [ ] Fix the `BENIGN` to `SCAN` mapping, then update the README

## Contents

| # | Section | What it covers |
|---|---|---|
| 1 | [Source inventory](#1-source-inventory) | Capture, privacy, bounds, alert schema, threat mapping, missing features |
| 2 | [Environment and hardware](#2-environment-and-hardware) | CPU, versions, Docker, packages |
| 3 | [Model details](#3-model-details) | Features, hyperparameters, thresholds, datasets, file sizes |
| 4 | [Evaluation evidence](#4-evaluation-evidence) | Evaluator and evasion reruns |
| 5 | [Benchmark evidence](#5-benchmark-evidence) | Throughput and latency |
| 6 | [Smoke runs and test logs](#6-smoke-runs-and-test-logs) | Build, lint and test output |
| 7 | [Artifact-reported metrics](#7-artifact-reported-metrics) | Model-card numbers |
| 8 | [Known defects and gaps](#8-known-defects-and-gaps) | Bugs and inconsistencies |
| 9 | [Open information requests](#9-open-information-requests) | What is missing and how to get it |
| 10 | [Live demo log](#10-live-demo-log) | Template for the Windows + Kali test |
| 11 | [README claims referencing this file](#11-readme-claims-referencing-this-file) | Claim-to-evidence map |
| 12 | [README statements not supported or contradicted](#12-readme-statements-not-supported-or-contradicted) | Unsupported claims |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 1. Source inventory

> [!NOTE]
> Source evidence shows what the code does. It does not prove a physical diode, host-wide absence of transmissions, or hardware-level read-only behavior.

### Capture, privacy, bounds and alert timing

| Fact | Evidence |
|---|---|
| Passive packet capture call | `sensor/flow_sensor.py:381`: `sniff(iface=self.args.interface, filter=bpf, prn=self.handle_packet, store=False, ...)`. This is source evidence for this sensor's call; it does not prove a physical diode or host-wide absence of transmissions. |
| Transmit-call search | **🟢 MEASURED**, command `rg -n "send|sendp|sr\(|srp\(" sensor`. Output: no matches. This scoped search does not establish absence in installed libraries, other programs, or all OS networking. HTTP export exists at `sensor/flow_sensor.py:315-343` and is application traffic. |
| Payload handling | `sensor/flow_sensor.py:255-266` obtains transport payload length and optional DNS question metadata; `sensor/flow_sensor.py:98-205` stores scalar lengths/statistics, flags, timings, and domain metadata. No raw payload byte field is added to the flow output. No payload decryptor found in active `backend/app` or `sensor` source (`rg -n "decrypt|TLS.*decrypt|SSLContext" backend/app sensor` returned no matches). Host-wide storage/log audit: **🔴 NOT MEASURED**. |
| Bounded/unbounded state | `sensor/flow_sensor.py:221` has `self.flows: dict[...]` without a capacity limit; entries expire by timers (`:287-313`) but simultaneous flow count/bytes are uncapped. Per-flow `FlowState` lists (`:93-107`, appended at `:127`) store packet statistics without a per-flow packet cap. Export queue is `queue.Queue(maxsize=10_000)` (`:222`). Beacon model input uses up to 32 packets, see `backend/app/ml/preprocess/beacon.py`. Backend recent alerts are `deque(maxlen=500)` (`backend/app/ingestion.py:22`). Backend receipt deque has no maxlen (`:24`) and is pruned by time in `record_received_flows` (`:26-43`). |
| Alert timing | Sensor exports on connection FIN/RST, idle timeout, active timeout and shutdown (`sensor/flow_sensor.py:287-313`, `:381-383`). `backend/app/main.py:152-165` accepts batches and `backend/app/ingestion.py:45-57` processes immediately. This is completed-flow inference; no active mid-flow alert path was found. |
| Throughput target default | `backend/app/core/config.py:19` and `backend/app/schemas.py:141`: `target_flows_per_sec: float = 5000.0`. This is a configuration default, not a measured system capacity. |

### Alert schema, construction and threat mapping

- `backend/app/schemas.py:69-108`: `Alert` fields include IDs/time, flow ID default `""` (`:76`), five tuple, threat class, severity, confidence, model scores, rules, MITRE refs default `[]`, evidence default `{}`, explanation, incident ID, previous hash and hash. `seal()` creates a per-alert hash (`:102-108`); this alone is not proof of a linked ledger.
- `backend/app/pipeline/ensemble.py:19-20, 110-198`: `process_batch` evaluates models and creates alerts. At `:133-136`, when multiclass LightGBM emits a class, code maps strings containing `DoS` to `DDOS`; every other class, including `BENIGN`, `Portscan`, and Botnet, maps to `SCAN`. Binary attack score/review gating determines whether the output is emitted, so **BENIGN can become SCAN** when that gate passes. This contradicts the stronger implication that only Portscan labels map to SCAN.
- `backend/app/pipeline/ensemble.py:187-198` constructs the active alert and evidence; `backend/app/ingestion.py:61-92` translates serialized alert data for storage/broadcast. API input is `list[dict[str, Any]]` (`backend/app/main.py:152-153`), not a list validated as `Alert` on request. Smoke response contents were not reproducible here because runtime dependencies are missing (see section 6).

### Runtime feature search

Search scope: active runtime code `sensor/` and `backend/app/`, command `rg -n "HyperLogLog|Space-Saving|JA3|JA4|QUIC|record.?type|MITRE|incident|prev_hash|CEF|syslog" sensor backend/app`.

| Feature | Active runtime finding |
|---|---|
| HyperLogLog | 🔴 NOT FOUND. It exists in archived `scratch/model_extract/newmodel/newmodel/uniguard/host_features.py`, which is not active backend runtime. |
| Space-Saving | 🔴 NOT FOUND active; archived host feature module only. |
| JA3/JA4 | 🔴 NOT FOUND. |
| QUIC | 🔴 NOT FOUND. |
| DNS record-type features | 🔴 NOT FOUND in active extractor. |
| MITRE | Schema field exists, but active alert builder supplies no populated mapping in the observed path; runtime mapping search found no mapping table. Artifact cards and scratch config include MITRE mappings. |
| Incident correlation | No active correlation implementation found. Schema/database incident fields exist but are not correlation behavior. |
| Hash chaining | Alert schema has `seal(prev_hash=...)`, but no active persistent chain sequence/verification found. |
| CEF/syslog | 🔴 NOT FOUND. |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 2. Environment and hardware

All version and package commands were run from repository root except npm commands, which ran in `frontend/`.

| Item | Result / status |
|---|---|
| CPU | **🟢 MEASURED** `Get-CimInstance Win32_Processor`: Intel(R) Core(TM) i5-13420H, 8 cores, 12 logical processors. |
| RAM | **🔴 NOT MEASURED**: `Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory` returned blank on this host. Obtain with `Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory` or `systeminfo`. |
| OS | **🔴 NOT MEASURED**: `Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber` returned blank. Obtain with `Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber`. |
| Python | **🟢 MEASURED** `python --version`: `Python 3.13.13`. |
| Node | **🟢 MEASURED** `node --version`: `v24.21.0`. |
| npm | **🟢 MEASURED** `npm --version`: `11.19.0`. |
| Docker | **🟢 MEASURED** `docker --version`: command not found (not installed/on PATH). |
| Python packages | **🟢 MEASURED** `python -m pip freeze` from repository root. Full output included `fastapi==0.136.1`, `pydantic==2.13.4`, `SQLAlchemy==2.0.49`, `uvicorn==0.46.0`, `pytest==9.1.1`; `numpy`, `joblib`, `scapy`, and `pydantic-settings` were absent. The full environment freeze is machine-wide and not a project lock. |
| Frontend packages | **🟢 MEASURED** `npm ls --depth=0` in `frontend/`; tree listed top-level packages including `vite@8.3.2`, `react@19.3.0`, `typescript@6.0.3`, `oxlint@1.86.0`. `frontend/package-lock.json` is present (189,644 bytes). |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 3. Model details

The three `backend/artifacts/*/model_card.json` files are the source of the card details below. Values here are **🔵 RECORDED**, not independently validated unless another section explicitly says 🟢 MEASURED.

### `lgbm_iforest`

- Card: `backend/artifacts/lgbm_iforest/model_card.json`. Runtime model files and byte sizes: `lgbm_binary.txt` 11,652,769; `lgbm_multi.txt` 25,702,780; `iforest.joblib` 66,376,349; `calibrator_binary.joblib` 4,036,006; `calibrator_multi.joblib` 2,443,235 bytes.
- Input: 28 base features followed by 10 derived features, exactly in card order: **base** `Flow Duration`, `Total Fwd Packet`, `Total Length of Fwd Packet`, `Fwd Packet Length Max`, `Fwd Packet Length Min`, `Fwd Packet Length Mean`, `Fwd Packet Length Std`, `Fwd IAT Total`, `Fwd IAT Mean`, `Fwd IAT Std`, `Fwd IAT Max`, `Fwd IAT Min`, `Fwd PSH Flags`, `Fwd URG Flags`, `Fwd RST Flags`, `Fwd Header Length`, `Fwd Packets/s`, `SYN Flag Count`, `FIN Flag Count`, `RST Flag Count`, `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count`, `Subflow Fwd Packets`, `Subflow Fwd Bytes`, `FWD Init Win Bytes`, `Fwd Act Data Pkts`, `Fwd Seg Size Min`, `Fwd Segment Size Avg`; **derived** `d_fwd_bytes_per_pkt`, `d_fwd_hdr_per_pkt`, `d_fwd_pkts_per_s`, `d_fwd_bytes_per_s`, `d_fwd_iat_cv`, `d_fwd_len_cv`, `d_fwd_len_range`, `d_subflow_bytes_per_pkt`, `d_fwd_hdr_ratio`, `d_fwd_active_ratio`.
- Card hyperparameters: binary LGBM `num_leaves=63`, `max_depth=-1`, `min_child_samples=50`, `feature_fraction=0.8`, `bagging_fraction=0.8`, `learning_rate=0.05`, `n_estimators=2000`; IForest `n_estimators=300`, `max_samples=0.1`, `contamination=auto`, input `log1p(clip(x, lower=0))`, NaN to 0. Multi model settings not stated in card. Calibrators are `CalibratedClassifierCV` wrappers.
- Labels: binary `BENIGN`,`ATTACK`; multiclass `BENIGN`, `Botnet`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slow`, `FTP-Patator`, `Portscan`, `SSH-Patator`, `Web Attack`. Merge/exclusion details in card: DoS subtypes merged; several Web Attack subtypes merged; Infiltration-Portscan to Portscan; Heartbleed and Infiltration excluded.
- Thresholds: high `0.14516129032258066`, review `0.005563282336578581`, IForest review `0.08472404543136625`.
- Dataset/split: card says CIC-IDS2017 Improved and time-blocked Train Mon-Wed, Val Thu, Test Fri. Seed and label-cleaning procedure not specified in the card; inspect archived `scratch/model_extract/newmodel/newmodel/training/prepare_data.py`, `train_lgbm.py`, `calibrate.py` and config for workflow. Archived scripts require external/raw dataset paths set in `config.py`; full original dataset is absent from this repository.

### `beacon_cnn`

- Card `backend/artifacts/beacon_cnn/model_card.json`; `model.onnx` 92,471 bytes; `calibrator.pkl` 565 bytes.
- Input `(batch,32,7)` float32, channels in order: `log1p_pkt_size`, `log1p_iat_us`, `padding_mask`, `tcp_syn`, `tcp_fin`, `tcp_rst`, `tcp_psh`. First 32 forward packets; remaining slots padded with zero. Scales `0.09090909090909091` and `0.054288816503800214`, IAT clipped at `100000000.0` microseconds.
- Architecture: 3 conv blocks + BatchNorm + GlobalAvgPool + Dense; 21,697 parameters. Isotonic regression calibrator, file `calibrator.pkl`. Labels benign/botnet. Card does not state conventional training hyperparameters or random seed.
- Thresholds: HIGH `0.914893627166748`; REVIEW `0.4285714030265808`. Dataset/split recorded as CTU-13 scenarios 1-5 train, 6-7 validation, 13 calibration, 8+12 test (card wording). Training code/data paths and random seeds are not provided in active backend. Archived counterpart/training sources are under `scratch/model_extract/charcnn/` only for DNS; no reproducible beacon training pipeline was confirmed.

### `charcnn_dns`

- Card `backend/artifacts/charcnn/model_card.json`; `uniguard_charcnn.onnx` 102,912 bytes; external data `uniguard_charcnn.onnx.data` 3,779,520 bytes; `feature_stats.npz` 644 bytes.
- Inputs: 128 int64 character tokens and 18 float32 features, order: `length`, `log_len`, `entropy`, `norm_entropy`, `digit_ratio`, `alpha_ratio`, `vowel_ratio`, `max_consonant_run`, `sep_ratio`, `unique_char_ratio`, `n_labels`, `max_label_len`, `mean_label_len`, `hex_fraction`, `base32_fraction`, `base64_fraction`, `dict_word_ratio`, `subdomain_entropy`. Card documents z-score using `feature_stats.npz`; temperature scaling `1.0124481916427612` embedded in ONNX. Active code-specific caveat in README: dictionary ratio forced 0 and subdomain entropy uses whole-domain entropy; verify at `backend/app/ml/preprocess/dns.py`.
- Architecture HybridNet_v4, multiscale CNN + BiGRU + lexical gating; 943,923 parameters; labels benign/DGA/DNS tunnel; thresholds DGA `0.6551020408163265`, tunnel `0.1`.
- Dataset recorded as DNS Threats multiclass, 10,769 test samples. Card does not specify split method or seed. Archived scripts/data are in `scratch/model_extract/charcnn/CHAR-Cnn anti/Char-Cnn/`; external data paths and full license/citation details are not established.

### Training/evaluation code and external paths

Archived LGBM/IForest scripts: `scratch/model_extract/newmodel/newmodel/training/{prepare_data.py,train_lgbm.py,train_iforest.py,calibrate.py,refit_final.py}` and evaluations in `.../evaluation/`. Archived benchmark in `.../ops/benchmark.py`. Data parquets are present under `.../data_processed/`. `config.py` defines raw/cross-dataset paths; actual original raw datasets are not included. Archived DNS training scripts are under the path above. Exact external machine paths and reproducibility of all scripts: **🔴 NOT MEASURED**; inspect each script's `config` and supply licensed source datasets.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 4. Evaluation evidence

> [!WARNING]
> The evaluator reruns **did not complete** in this inspection (`ModuleNotFoundError: No module named 'joblib'`). Per-class reports, confusion matrices and evasion results below are not freshly measured.

Requested command from `scratch/model_extract/newmodel/newmodel/`:

```powershell
$env:PYTHONPATH='.'
python -m evaluation.run_evals
python -m evaluation.eval_evasion
```

**🟢 MEASURED attempt, not a successful evaluation.** Both commands stopped at import with `ModuleNotFoundError: No module named 'joblib'`. Therefore this inspection did not rerun a full per-class report, confusion matrices, binary FPR/recall, or perturbation/evasion results. `data_processed/test.parquet` is present. The requested row count (288,796) and README's per-class/CM values are report claims, not newly reproduced here.

For exact availability, scripts present: `evaluation/run_evals.py`, `evaluation/eval_evasion.py`, `evaluation/eval_e7.py`, `evaluation/eval_leave_days.py`; model artifacts in `models/`. `run_evals.py` includes baseline, padding, jitter, low-and-slow and NetFlow-like perturbations. `eval_evasion.py` includes padding, timing jitter, padding+jitter, and low-and-slow scenarios. No per-detector rerun output was produced. Install archived `requirements.txt` in an isolated environment and run the commands above to obtain raw output; do not substitute the model-card metrics for this evaluator.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 5. Benchmark evidence

> [!WARNING]
> The benchmark rerun **failed before running** (missing `joblib`). The 9,257 flows/s figure is only a recorded README claim, with no raw log found.

Command attempted from `scratch/model_extract/newmodel/newmodel/`:

```powershell
$env:PYTHONPATH='.'
python -m ops.benchmark
```

**🟢 MEASURED attempt failed before benchmark** with `ModuleNotFoundError: No module named 'joblib'`. The script source (`ops/benchmark.py`) pins its process to CPU core 0 using `psutil.Process().cpu_affinity([0])`, loads `data_processed/test.parquet`, and calculates throughput and batch-one latency. No CPU/RAM utilization during run was obtained. End-to-end pipeline, Mbps, p50/p95/p99 and target verdict: **🔴 NOT MEASURED** in this inspection.

README.md lines 396-397 state a prior/archived 9,257 flows/s and p50/p95/p99 15.687/20.211/23.170 ms, pinned to one CPU. These numbers are **🔵 RECORDED only as README claims**; no separate raw benchmark log was found to independently support them in this pass. Claimed model-only comparison would numerically exceed 5,000 flows/s and have p99 below 1 s, but because rerun did not execute, status for that result remains **🔴 NOT MEASURED** here. It would not establish end-to-end system throughput regardless.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 6. Smoke runs and test logs

> [!WARNING]
> Backend POST, backend tests and sensor tests could not run because runtime packages (`pydantic-settings`, `numpy`, `joblib`, ONNX Runtime, `scapy`) were missing on the inspection host. Only the frontend build and lint ran.

### Backend sample POST

Requested source sample path `backend/data/samples/sample_50.csv` is **🔴 NOT FOUND** at that path; repository sample is `data/samples/sample_50.csv`. Starting the API and POSTing the sample was not successful because the host environment lacks required runtime packages including `pydantic-settings`, `numpy`, `joblib`, and ONNX Runtime. Raw POST response and generated class counts: **🔴 NOT MEASURED** in this inspection. Exact intended command after installing `backend/requirements.txt`: start `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` from `backend/`, then POST JSON rows from `data/samples/sample_50.csv` to `http://127.0.0.1:8000/api/flows` (exclude Label). README.md lines 82-89 report an earlier response `{"flows_received":50,"alerts_generated":50,"processing_time_ms":137.501}` and 40 SCAN/10 DDOS; those are prior recorded claims, not this run.

### Frontend commands

`npm ci` was first mistakenly run from the repository root and failed with `ENOENT` because no root `package.json` exists. It was then run from `frontend/` and completed sufficiently for the subsequent build and lint to run; the lockfile `frontend/package-lock.json` is present. `npm ls --depth=0` in `frontend/` listed the installed top-level dependencies.

`npm run build` in `frontend/` (🟢 MEASURED):

```text
vite v8.3.2 building client environment for production...
✓ 2470 modules transformed.
dist/index.html                   0.64 kB │ gzip:   0.38 kB
dist/assets/index-BeNVsyHk.css  104.39 kB │ gzip:  19.93 kB
dist/assets/index-DdXm8Kc-.js   643.38 kB │ gzip: 191.94 kB
(!) Some chunks are larger than 500 kB after minification.
✓ built in 9.61s
```

`npm run lint` in `frontend/` (🟢 MEASURED, exited 0): 10 warnings. Full lint output:

```text
src/components/ui/button-1.tsx:412:31: warning react(only-export-components): Fast refresh only works when a file only exports components. Use a new file to share constants or functions between components.
src/App.jsx:5:28: warning eslint(no-unused-vars): Identifier 'ArrowDownToLine' is imported but never used.
src/App.jsx:6:9: warning eslint(no-unused-vars): Identifier 'BookOpen' is imported but never used.
src/App.jsx:6:19: warning eslint(no-unused-vars): Identifier 'Check' is imported but never used.
src/App.jsx:9:52: warning eslint(no-unused-vars): Identifier 'Settings2' is imported but never used.
src/App.jsx:10:48: warning eslint(no-unused-vars): Identifier 'Sparkles' is imported but never used.
src/App.jsx:129:7: warning eslint(no-unused-vars): Variable 'detections' is declared but never used.
src/App.jsx:144:7: warning eslint(no-unused-vars): Variable 'models' is declared but never used.
src/App.jsx:260:9: warning eslint(no-unused-vars): Variable 'detections' is declared but never used.
src/App.jsx:335:10: warning eslint(no-unused-vars): Function 'BurstChart' is declared but never used.
```

### Backend and sensor tests

`python -m pytest -q` from `backend/` (🟢 MEASURED, exit 1):

```text
ERROR test_classification.py: ModuleNotFoundError: No module named 'pydantic_settings'
ERROR test_ws.py: SyntaxError: source code string cannot contain null bytes
ERROR tests/test_ensemble_attack_mapping.py: ModuleNotFoundError: No module named 'numpy'
!!!!!!!!!!!!!!!!!!! Interrupted: 3 errors during collection !!!!!!!!!!!!!!!!!!!
3 errors in 0.57s
```

`python -m pytest -q` from `sensor/` (🟢 MEASURED, exit 1):

```text
ERROR test_flow_sensor.py: ModuleNotFoundError: No module named 'scapy'
!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!
1 error in 0.11s
```

Thus README's prior “5 passed” sensor statement was not reproduced on this host; install `sensor/requirements.txt` in its environment to rerun.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 7. Artifact-reported metrics

All values below are **🔵 RECORDED** from the specified cards, not rerun in this inspection.

| Family | Card metrics | Source |
|---|---|---|
| LightGBM binary | High tier FPR 0.31%, recall 99.56%, precision 99.9%; review FPR 1.49%, recall 99.64%, precision 99.9%; recorded 13,209 flows/s and p99 15.6 ms. | `backend/artifacts/lgbm_iforest/model_card.json`, `validation_metrics` |
| Isolation Forest | FPR 1.19%; Portscan recall 78.7%; DDoS recall 1.8%. | Same card, `iforest_backstop` |
| Beacon CNN | Test precision 99.36%, recall 83.79%, F1 90.91%, ROC-AUC 0.9380, PR-AUC 0.9786; confusion matrix `[[2822,45],[1360,7028]]`; high threshold test FPR 3.3%, recall 85.9%; review FPR 48.6%, recall 97.5%. | `backend/artifacts/beacon_cnn/model_card.json` |
| DNS Char-CNN | 10,769 samples, accuracy 93.21%, macro F1 91.99%; benign P/R/F1 0.9212/0.9793/0.9494 (7,000); DGA 0.9150/0.7269/0.8102 (2,146); tunnel 1/1/1 (1,623). | `backend/artifacts/charcnn/model_card.json` |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 8. Known defects and gaps

- `BENIGN` and arbitrary non-`DoS` multiclass labels can map to `SCAN`: `backend/app/pipeline/ensemble.py:133-136`.
- Empty `flow_id` default: `backend/app/schemas.py:76`; sample output claim in README lines 84-89.
- MITRE/evidence omissions: schema defaults at `backend/app/schemas.py:83-84`; builder `backend/app/pipeline/ensemble.py:187-198`. Need populated evidence/MITRE fields verified for each emitted alert.
- Compose mismatch: `docker-compose.yml` configures PostgreSQL/`asyncpg` and Redis; backend default is SQLite in `backend/app/db/database.py`, and active code search did not find Redis consumer. `asyncpg` is not declared in `backend/requirements.txt`. Docker unavailable, Compose not run.
- Unpinned dependencies: `backend/requirements.txt` includes unpinned ML packages. Frontend lockfile is present.
- Unbounded flow state and per-flow packet-stat lists: `sensor/flow_sensor.py:93-127,221`; expiry is time-based only.
- Backend test collection defects shown in section 6, including null bytes in `backend/test_ws.py`, missing dependency imports, plus stale test assumptions in `backend/tests/test_ensemble_attack_mapping.py` (some tests target prior pipeline behavior; not executed past import failure).
- TODO/FIXME scan: `rg -n "TODO|FIXME" backend sensor frontend/src` produced no matches (🟢 MEASURED scoped search); this does not include generated/dependency files or all archived scratch.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 9. Open information requests

| Item | Why needed | Exact command or data required |
|---|---|---|
| End-to-end throughput, Mbps, p99 under load | Model-only numbers do not include capture, HTTP, persistence or dashboard. | Run a controlled Linux/Kali + Windows lab at declared load; preserve sensor logs, `ab` summary, API timestamps, CPU/RAM samples and packet/byte counts. Include repetitions and duration. |
| False alerts per hour | Needed to quantify operational alert burden. | Capture a labeled benign workload for a declared duration; export alert log and total monitored hours. |
| Cross-capture vs random split | Estimate generalization and split leakage. | Supply capture IDs and labels; evaluate identical model on capture-held-out and random splits with seeds and per-class reports. |
| 4SICS / HAI validation | OT-domain evaluation is not in card metrics. | Provide licensed dataset files, provenance/citation and an explicit feature mapping; execute evaluator and archive outputs. |
| PSI drift | Need baseline and current feature distributions over time. | Supply a time-stamped production feature sample plus baseline; run `python -m ops.psi` with documented windows/config and output. |
| Ablation | Attribute performance to detectors/features. | Run per-detector and per-feature-group disabled configurations on the same fixed split and publish metrics. |
| Dataset licenses and citation URLs | Cards name datasets but repository does not preserve license/provenance evidence. | Provide source URLs, exact versions, license texts/permissions, acquisition date and citations for CIC-IDS2017 Improved, CTU-13, DNS threats, 4SICS and HAI as used. |
| Dashboard screenshots | README reports no screenshot artifacts in repository. | Capture dashboard Overview and Alerts views during a timestamped demo and commit image files under `docs/`. |
| Reproducible evaluator | Current rerun stops because environment lacks required packages. | Create isolated environment, install `scratch/model_extract/newmodel/newmodel/requirements.txt`, record `pip freeze`, then run `python -m evaluation.run_evals`, `python -m evaluation.eval_evasion`, `python -m ops.benchmark` from that directory. |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 10. Live demo log

> [!NOTE]
> This section is a template for the Windows + Kali test. Fill it in from your own run and recording.

**Template — fill during Windows + Kali test. This inspection did not run that environment.**

```text
Date/time and timezone:
Windows private IP:
Kali interface:
Sensor command (include full options):
ab command:
ab summary output (Requests per second; Failed requests):
Flows exported by sensor:
Alerts seen on dashboard by class and count:
Flows/s shown on dashboard:
Screenshot file paths:
Notes/errors:
```

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 11. README claims referencing this file

Direct README.md links to `README_FACTS.md` occur at lines 13, 394, 396, 407, 417 and 550. Coverage:

| README claim | Evidence location here |
|---|---|
| Source inventory, evaluation evidence, open requests (line 13) | Sections 1, 4, 9. |
| Full archived test class supports/weak classes (line 394) | 🔴 NOT MEASURED on this host; section 4 explains failure and makes clear README values are not rerun. The complete per-class report is therefore not answered by new evidence. |
| Evaluator detail, perturbations, benchmark host (line 396) | Sections 4-5; evaluator/benchmark reruns failed for missing `joblib`; historical figures are labeled README-recorded only. |
| Archived reports / missing cross-capture, OT, drift, ablation, evasion (line 407) | Sections 4, 7, 9. |
| Feature order, hyperparameters, data splits, missing evaluation (line 417) | Section 3; unspecified seeds/split details are explicitly marked. |
| Working facts and commands/data needed (line 550) | Sections 1-10. |

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## 12. README statements not supported or contradicted

> [!IMPORTANT]
> Items below are **unsupported by this inspection**, not proven false. Rerun the listed scripts in a fully populated environment before claiming freshly measured results.

- README lines 394-397 present exact evaluator and benchmark numbers as factual results. This inspection could not reproduce them because `joblib` is absent and no raw evaluator/benchmark log was located. Treat these as **unsupported by this inspection**, not falsified; rerun the listed scripts in a populated environment before claiming freshly measured results.
- README line 361 says the mapping maps a `Portscan` label to `SCAN`, but the runtime code at `backend/app/pipeline/ensemble.py:136` maps every multiclass output without the substring `DoS` to `SCAN`. Thus `BENIGN` can also map to `SCAN`; section 1 documents the contradiction.
- README lines 82-89 report a successful smoke POST, 50 alerts and class counts. Not independently reproduced here because backend dependencies are missing and its described `backend/data/samples/sample_50.csv` path does not exist; repository path is `data/samples/sample_50.csv`.
- README line 384 says sensor unit suite had 5 passed; this host's requested pytest command cannot collect tests because `scapy` is absent. This is not evidence those earlier five passes are false, but is not reproduced here.
- The README describes in line 13 a complete evidence index; this file marks several requested results 🔴 NOT MEASURED because external data, machine configuration, or dependencies were unavailable. Those gaps remain open information requests.

<div align="right"><a href="#top">↑ Back to top</a></div>

---

## Summary status

| Item | Status | Source |
|---|---|---|
| Active source inventory | 🟢 MEASURED | `sensor/flow_sensor.py`; `backend/app/*`; scoped `rg` commands, section 1 |
| Host CPU, language/tool versions, Docker availability | 🟢 MEASURED | PowerShell CIM / `--version` commands; section 2 (RAM/OS fields failed and are separately 🔴 NOT MEASURED) |
| Model card values and artifact sizes | 🔵 RECORDED | `backend/artifacts/*/model_card.json`; filesystem size listing, section 3 |
| Archived evaluator rerun | 🔴 NOT MEASURED | Attempted `python -m evaluation.run_evals`; missing `joblib`, section 4 |
| Archived evasion rerun | 🔴 NOT MEASURED | Attempted `python -m evaluation.eval_evasion`; missing `joblib`, section 4 |
| Archived benchmark rerun | 🔴 NOT MEASURED | Attempted `python -m ops.benchmark`; missing `joblib`, section 5 |
| Frontend build/lint | 🟢 MEASURED | `npm run build`, `npm run lint` in `frontend/`, section 6 |
| npm clean install | 🟢 MEASURED | `npm ci` from `frontend/` completed; root-level attempt used incorrect working directory, section 6 |
| Backend tests | 🔴 NOT MEASURED | `python -m pytest -q` in `backend/`; collection errors, section 6 |
| Sensor tests | 🔴 NOT MEASURED | `python -m pytest -q` in `sensor/`; missing Scapy, section 6 |
| Backend sample POST | 🔴 NOT MEASURED | Missing runtime dependencies; section 6 |
| Windows + Kali live demo | 🔴 NOT MEASURED | External lab/demo required; section 10 |

<div align="right"><a href="#top">↑ Back to top</a></div>
