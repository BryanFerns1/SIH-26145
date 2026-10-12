import pytest
import pandas as pd
import json
import hashlib
import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.detector import UniGuardDetector

def test_alert_tamper_evidence():
    detector = UniGuardDetector()
    
    # Create dummy row
    row = pd.Series({f: 1.0 for f in config.BASE_FEATURES})
    row['Src IP'] = '192.168.1.1'
    row['Dst IP'] = '10.0.0.1'
    row['Dst Port'] = 80
    row['Protocol'] = 6
    
    # Compute hash
    ev_hash = detector.compute_evidence_hash(row)
    
    # Verify it matches expected HMAC-SHA256
    input_data = {f: 1.0 for f in config.BASE_FEATURES}
    canonical = json.dumps(input_data, sort_keys=True)
    secret_key = b"UniGuard_SIH2026_Secret_Key_v1"
    expected = hmac.new(secret_key, canonical.encode('utf-8'), hashlib.sha256).hexdigest()
    
    assert ev_hash == expected
    
def test_no_backward_ports():
    detector = UniGuardDetector()
    
    # Create a batch of flows
    batch = pd.DataFrame([{f: 1.0 for f in config.BASE_FEATURES}])
    batch['Src IP'] = '192.168.1.1'
    batch['Dst IP'] = '10.0.0.1'
    batch['Src Port'] = 12345
    batch['Dst Port'] = 80
    batch['Protocol'] = 6
    batch['Timestamp'] = '2026-01-01'
    
    # Force an alert by hacking the thresholds temporarily
    detector.thresholds["binary_high"]["value"] = 0.0
    detector.thresholds["binary_review"]["value"] = 0.0
    
    alerts = detector.predict(batch)
    
    if len(alerts) > 0:
        alert = alerts[0]
        # Should not contain Src Port or backward IPs
        assert 'src_port' not in alert
        assert 'bwd_packet' not in str(alert).lower()
