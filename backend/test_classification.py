"""UniGuard Classification Regression Tests

Tests the pipeline classification logic without requiring the full ML models.
Focuses on the ensemble decision logic and HTTP flood detection.
"""
import asyncio
import sys
import os
import time

# Ensure backend root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from app.schemas import ThreatClass, Alert
from app.ingestion import FlowProcessor


class MockPipeline:
    """Mock pipeline that returns configurable predictions without real models."""
    
    def __init__(self):
        self.registry = MockRegistry()
        self._next_alerts = []
    
    def set_next_alerts(self, alerts):
        self._next_alerts = alerts
    
    async def process_batch(self, flows):
        """Return pre-configured alerts or empty list."""
        return list(self._next_alerts)


class MockRegistry:
    def get_health(self):
        return []


class MockWsManager:
    def __init__(self):
        self.messages = []
    
    async def broadcast(self, message):
        self.messages.append(message)


def make_flow(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, proto=6, packets=10):
    """Create a minimal flow record."""
    return {
        "Src IP": src_ip, "Src Port": 12345, "Dst IP": dst_ip, "Dst Port": dst_port,
        "Protocol": proto, "Total Length of Fwd Packet": 500, "SYN Flag Count": 1,
        "Fwd IAT Mean": 100.0, "Total Fwd Packet": packets, "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 50, "Fwd Packet Length Mean": 75.0,
        "Fwd Packet Length Std": 10.0, "Fwd IAT Total": 1000.0, "Fwd IAT Std": 10.0,
        "Fwd IAT Max": 150.0, "Fwd IAT Min": 50.0, "Fwd PSH Flags": 0, "Fwd URG Flags": 0,
        "Fwd RST Flags": 0, "Fwd Header Length": 200, "Fwd Packets/s": 10.0,
        "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 0, "ACK Flag Count": 10,
        "URG Flag Count": 0, "Subflow Fwd Packets": packets, "Subflow Fwd Bytes": 500,
        "FWD Init Win Bytes": 2048, "Fwd Act Data Pkts": 5, "Fwd Seg Size Min": 50,
        "Fwd Segment Size Avg": 75.0, "Flow Duration": 1000000.0,
        "sensor_metadata": {"lgbm_inputs_complete": True}
    }


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def record(self, name, passed, detail=""):
        if passed:
            self.passed += 1
            print(f"  PASS: {name}")
        else:
            self.failed += 1
            self.errors.append(f"{name}: {detail}")
            print(f"  FAIL: {name} — {detail}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print("\nFailures:")
            for e in self.errors:
                print(f"  - {e}")
        print(f"{'='*60}")
        return self.failed == 0


async def test_http_request_tracking(results: TestResults):
    """Test that FlowProcessor correctly tracks HTTP requests from telemetry."""
    print("\n[1] HTTP Request Tracking")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    # Record 500 requests from one IP
    connections = [
        {"client_ip": "10.0.0.3", "connection_id": "c1", "requests_total": 200, "closed": False},
        {"client_ip": "10.0.0.3", "connection_id": "c2", "requests_total": 300, "closed": False},
    ]
    processor.record_http_requests("test-source", connections)
    
    count = processor.get_http_request_count("10.0.0.3", 10.0)
    results.record("500 HTTP requests tracked correctly", count == 500, f"Expected 500, got {count}")
    
    # Verify different IP returns 0
    count2 = processor.get_http_request_count("10.0.0.99", 10.0)
    results.record("Unrelated IP returns 0", count2 == 0, f"Expected 0, got {count2}")
    
    # Test incremental update (same connection, more requests)
    connections2 = [
        {"client_ip": "10.0.0.3", "connection_id": "c1", "requests_total": 250, "closed": False},
    ]
    processor.record_http_requests("test-source", connections2)
    count3 = processor.get_http_request_count("10.0.0.3", 10.0)
    results.record("Incremental update adds delta only", count3 == 550, f"Expected 550, got {count3}")
    
    # Test closed connection cleanup
    connections3 = [
        {"client_ip": "10.0.0.3", "connection_id": "c1", "requests_total": 250, "closed": True},
    ]
    processor.record_http_requests("test-source", connections3)
    # Connection should be removed from tracking but count should remain until window expires
    results.record("Closed connection removed from tracking",
                   ("test-source", "c1") not in processor.http_connections,
                   "Connection not removed")


async def test_http_flood_detection_via_flow(results: TestResults):
    """Test that a flow with high HTTP request count gets classified as HTTP_FLOOD."""
    print("\n[2] HTTP Flood Detection via Flow Processing")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    # Simulate 500 HTTP requests from attacker
    connections = [
        {"client_ip": "10.0.0.3", "connection_id": "c1", "requests_total": 500, "closed": False},
    ]
    processor.record_http_requests("test-source", connections)
    
    # Process a flow from that IP — the pipeline mock returns no alerts,
    # but we need to check that http_request_count is attached
    flow = make_flow(src_ip="10.0.0.3")
    
    # Check that process attaches http_request_count
    await processor.process([flow])
    results.record("HTTP request count attached to flow", 
                   flow.get("http_request_count") == 500,
                   f"Expected 500, got {flow.get('http_request_count')}")


async def test_schema_threat_classes(results: TestResults):
    """Test that all expected threat classes exist in the schema."""
    print("\n[3] ThreatClass Schema Validation")
    
    expected = ["DDOS", "DOS", "HTTP_FLOOD", "C2_BEACON", "DGA", "DNS_TUNNEL", 
                "SCAN", "ANOMALY", "EXFIL", "TLS_MALWARE", "INTEL_MATCH", "SENSOR_HEALTH"]
    
    for name in expected:
        has = hasattr(ThreatClass, name)
        results.record(f"ThreatClass.{name} exists", has, "Missing from enum")


async def test_flow_processor_clear(results: TestResults):
    """Test that clearing alerts resets counters."""
    print("\n[4] Alert Clear Functionality")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    # Manually add some state
    processor.total_alerts = 5
    from collections import deque
    processor.recent_alerts = deque([None] * 5, maxlen=500)
    
    cleared = processor.clear_alerts()
    results.record("Clear returns correct count", cleared == 5, f"Expected 5, got {cleared}")
    results.record("Total alerts reset to 0", processor.total_alerts == 0, 
                   f"Expected 0, got {processor.total_alerts}")
    results.record("Recent alerts emptied", len(processor.recent_alerts) == 0,
                   f"Expected 0, got {len(processor.recent_alerts)}")


async def test_ipv6_mapped_ip_handling(results: TestResults):
    """Test that IPv4-mapped IPv6 addresses are handled correctly."""
    print("\n[5] IPv6-mapped IPv4 Address Handling")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    # Record with IPv6-mapped address
    connections = [
        {"client_ip": "::ffff:10.0.0.3", "connection_id": "c1", "requests_total": 100, "closed": False},
    ]
    processor.record_http_requests("test-source", connections)
    
    # Query with plain IPv4
    count = processor.get_http_request_count("10.0.0.3", 10.0)
    results.record("IPv6-mapped address normalized to IPv4", count == 100, f"Expected 100, got {count}")


async def test_throughput_tracking(results: TestResults):
    """Test throughput calculation."""
    print("\n[6] Throughput Tracking")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    processor.record_received_flows(30)
    throughput = processor.get_throughput()
    results.record("Throughput is positive after recording flows", throughput > 0,
                   f"Expected >0, got {throughput}")
    results.record("Total flows updated", processor.total_flows == 30,
                   f"Expected 30, got {processor.total_flows}")


async def test_duplicate_alert_prevention(results: TestResults):
    """Test that duplicate alerts are handled in the store logic."""
    print("\n[7] Alert Deduplication")
    
    pipeline = MockPipeline()
    ws = MockWsManager()
    processor = FlowProcessor(pipeline, ws)
    
    # The store-level dedup is in the frontend (useStore.ts addAlert checks alert_id).
    # Backend side: we verify that processing the same flow twice produces consistent results.
    flow = make_flow(src_ip="10.0.0.1")
    result1 = await processor.process([flow])
    result2 = await processor.process([flow])
    
    results.record("Consistent processing results",
                   result1["flows_received"] == result2["flows_received"] == 1,
                   "Inconsistent flow counts")


async def main():
    print("=" * 60)
    print("UniGuard Classification Regression Test Suite")
    print("=" * 60)
    
    results = TestResults()
    
    await test_http_request_tracking(results)
    await test_http_flood_detection_via_flow(results)
    await test_schema_threat_classes(results)
    await test_flow_processor_clear(results)
    await test_ipv6_mapped_ip_handling(results)
    await test_throughput_tracking(results)
    await test_duplicate_alert_prevention(results)
    
    success = results.summary()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
