# UniGuard private lab flow sensor

This Linux/Kali sensor passively observes packets going **to one explicitly
configured RFC1918/loopback/IPv6-ULA server address and destination port**. It
groups those packets into directional five-tuples and submits completed flow
records to the existing UniGuard `POST /api/flows` endpoint. It does not create
traffic, scan hosts, spoof packets, or capture arbitrary destinations.

## What the sensor can observe

The sensor uses the exact LightGBM input names from
`backend/app/ml/preprocess/lgbm.py`. It derives packet counts, IP lengths,
inter-arrival times, TCP flags, header lengths, payload lengths, and the first
TCP SYN window from packets actually captured. It also emits up to 32 observed
packet sizes, intervals, and TCP flags for the Beacon CNN. A captured DNS query
name is passed to Char-CNN only when one is present.

The LightGBM model was trained with CICFlowMeter features. This small adapter
does not reproduce CICFlowMeter's subflow averages or segment-size definitions;
those fields are marked in each record as `packet-derived-lab-v1`. They are
measured packet-derived values, not CICFlowMeter-equivalent values, so model
scores from this adapter are for a controlled prototype demonstration. If the
capture starts after a TCP SYN, the initial-window field is unavailable and the
backend skips LightGBM/Isolation Forest for that flow rather than filling it
with a made-up value. The Beacon model can still use an observed packet
sequence. Char-CNN runs only on a captured DNS question name.

## Install on Kali/Linux

```bash
sudo apt update
sudo apt install -y python3-venv libpcap-dev
cd sensor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest -v test_flow_sensor.py
```

Packet capture needs root privileges. Run with `sudo .venv/bin/python ...` or
grant the Python executable `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.
The sensor checks Linux interface names before starting. Use `ip -br address`
and `ip route get <WINDOWS_LAB_IP>` to select the interface used to reach the
controlled server.

## Start UniGuard

On the Windows host, find its private address with `ipconfig`. Bind Uvicorn to
all interfaces so the Vite proxy and Kali VM can reach it, and restrict the
backend port with the Windows Firewall rule below:

```powershell
cd C:\Documents\Engineering\SIH\Prototype\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Add a Private-profile inbound rule restricted to the Kali VM's IP (run
PowerShell as Administrator; replace both sample IPs):

```powershell
New-NetFirewallRule -DisplayName "UniGuard lab sensor API" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress <WINDOWS_LAB_IP> -LocalPort 8000 -RemoteAddress <KALI_PRIVATE_IP> -Profile Private
```

Start the frontend in a second Windows terminal if Kali should open the
dashboard:

```powershell
cd C:\Documents\Engineering\SIH\Prototype\frontend
npm run dev -- --host 0.0.0.0
```

## Start the sensor

First check the backend from Kali:

```bash
curl http://10.234.163.159:8000/api/health
```

List interfaces and determine the interface that routes to the server:

```bash
ip -br address
ip route get 10.234.163.159
```

Start in dry-run mode first. Use the actual interface name reported by your
Kali VM:

```bash
cd ~/SIH/Prototype/sensor
sudo .venv/bin/python flow_sensor.py \
  --mode private-lab \
  --interface eth0 \
  --target 10.234.163.159 \
  --port 5173 \
  --backend-url http://10.234.163.159:8000/api/flows \
  --flow-timeout 3 \
  --dry-run
```

The dry run prints observed flow JSON and sends nothing to the API. Once the
captured fields look sensible, stop it with Ctrl+C and run the same command
without `--dry-run` to export flows.

## Small controlled traffic check from Kali

Only run this against the private lab server you control. With the sensor
running, make a small number of ordinary requests to the configured target:

```bash
ab -n 20 -c 2 http://10.234.163.159:5173/
```

Wait for the flow's FIN or the configured idle timeout. The sensor should log
`[SENSOR]`, `[FLOW]`, `[EXPORT]`, and `[MODEL]` lines. A normal page load may
produce zero alerts; the sensor reports whether the backend accepted and
analyzed the flows, and only model outputs meeting existing thresholds produce
dashboard detections. This check validates capture and export, not attack
detection quality.

## Verify flow intake

- Sensor output reports `[FLOW] completed ...` after FIN/RST or timeout.
- `[EXPORT] POST ...` confirms the API request was sent.
- `[MODEL] backend accepted N flow(s), returned M alert(s)` confirms API/model
  processing. `M` can be zero for ordinary traffic.
- Open `http://10.234.163.159:5173` and confirm observed detections arrive via
  the dashboard WebSocket. The sensor does not create dashboard alerts itself.
- `http://10.234.163.159:8000/docs` lists the same `POST /api/flows` endpoint.

## Troubleshooting

- **Permission denied / capture socket error:** run via `sudo`; install
  `libpcap-dev`; confirm the interface exists with `ip -br address`.
- **No `[SENSOR]` packet messages:** confirm interface, private target IP,
  destination port, and route. The BPF filter deliberately captures only
  packets directed to that target and port.
- **`[EXPORT] backend unavailable`:** check `/api/health`, bind Uvicorn to
  `0.0.0.0`, and allow TCP/8000 from the Kali IP in Windows
  Firewall.
- **Flow exported but no alert:** ordinary traffic need not be malicious. Check
  the returned alert count; predictions come only from the existing models.
- **No LightGBM result for a flow:** sensor metadata reports missing features.
  In particular, a capture that starts mid-connection has no observed initial
  SYN window, so LightGBM/Isolation Forest are intentionally skipped.
- **Model score differs from offline evaluation:** the live adapter is
  packet-derived and not CICFlowMeter-compatible. Use a compatible CICFlowMeter
  exporter for evaluation-grade LightGBM features.
