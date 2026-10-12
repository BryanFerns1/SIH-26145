import concurrent.futures
import urllib.request
import time
import json

def fetch(_):
    try:
        urllib.request.urlopen("http://127.0.0.1:5173", timeout=2)
    except:
        pass

def send_requests():
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(fetch, range(500))

def run_test():
    print("[1] Simulating 500 HTTP requests to Frontend (Vite) from localhost...")
    send_requests()
    print("Done sending HTTP requests.")
    
    # Give the frontend telemetry plugin 1-2 seconds to flush to the backend
    time.sleep(2)
    
    print("\n[2] Simulating sensor sending a flow record from localhost (127.0.0.1)...")
    flow = {
        "Src IP": "127.0.0.1",
        "Src Port": 55555,
        "Dst IP": "10.0.0.2",
        "Dst Port": 5173,
        "Protocol": 6,
        "Total Length of Fwd Packet": 500,
        "SYN Flag Count": 1,
        "Fwd IAT Mean": 100.0,
        "Total Fwd Packet": 10,
        "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 50,
        "Fwd Packet Length Mean": 75.0,
        "Fwd Packet Length Std": 10.0,
        "Fwd IAT Total": 1000.0,
        "Fwd IAT Std": 10.0,
        "Fwd IAT Max": 150.0,
        "Fwd IAT Min": 50.0,
        "Fwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Fwd RST Flags": 0,
        "Fwd Header Length": 200,
        "Fwd Packets/s": 10.0,
        "FIN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 10,
        "URG Flag Count": 0,
        "Subflow Fwd Packets": 10,
        "Subflow Fwd Bytes": 500,
        "FWD Init Win Bytes": 2048,
        "Fwd Act Data Pkts": 5,
        "Fwd Seg Size Min": 50,
        "Fwd Segment Size Avg": 75.0,
        "Flow Duration": 1000000.0,
        "sensor_metadata": {"lgbm_inputs_complete": True}
    }
    
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/flows", data=json.dumps([flow]).encode('utf-8'), headers={'Content-Type': 'application/json'})
        res = urllib.request.urlopen(req)
        print("Backend Response to /api/flows:", res.status, res.read().decode('utf-8'))
    except Exception as e:
        print("Error sending flow:", e)
        
    print("\n[3] Checking Backend Alerts...")
    time.sleep(1)
    try:
        res = urllib.request.urlopen("http://127.0.0.1:8000/api/alerts")
        alerts = json.loads(res.read().decode('utf-8')).get("alerts", [])
        print(f"Total Alerts: {len(alerts)}")
        if alerts:
            alert = alerts[0]
            print("Latest Alert Threat Class:", alert.get("threat_class"))
            print("Latest Alert Evidence:", json.dumps(alert.get("evidence"), indent=2))
            
            if alert.get("threat_class") == "HTTP_FLOOD":
                print("\n✅ SUCCESS: HTTP_FLOOD detected accurately!")
            else:
                print(f"\n❌ FAILURE: Expected HTTP_FLOOD, got {alert.get('threat_class')}")
        else:
            print("\n❌ FAILURE: No alerts generated.")
    except Exception as e:
        print("Error checking alerts:", e)

if __name__ == "__main__":
    run_test()
