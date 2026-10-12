"""Process observed network flows through the UniGuard ensemble."""

import time
from collections import deque
from typing import Any

from app.db.database import AsyncSessionLocal
from app.db.models import AlertRecord
from app.schemas import PipelineMetrics
from app.schemas import Alert


class FlowProcessor:
    """Analyze only flows explicitly received from an external sensor."""

    def __init__(self, pipeline, ws_manager):
        self.pipeline = pipeline
        self.ws_manager = ws_manager
        self.started_at = time.perf_counter()
        self.total_flows = 0
        self.total_alerts = 0
        self.recent_alerts: deque[Alert] = deque(maxlen=500)
        self.flow_rate_window_seconds = 3.0
        self.flow_receipts: deque[tuple[float, int]] = deque()

    def record_received_flows(self, count: int) -> None:
        """Record an actual received batch for the trailing throughput window."""
        now = time.monotonic()
        self.total_flows += count
        self.flow_receipts.append((now, count))
        self._prune_flow_receipts(now)

    def _prune_flow_receipts(self, now: float) -> None:
        cutoff = now - self.flow_rate_window_seconds
        while self.flow_receipts and self.flow_receipts[0][0] < cutoff:
            self.flow_receipts.popleft()

    def get_throughput(self) -> float:
        """Return actual received flows/second over the trailing 3 seconds."""
        now = time.monotonic()
        self._prune_flow_receipts(now)
        flow_count = sum(count for _, count in self.flow_receipts)
        return flow_count / self.flow_rate_window_seconds

    async def process(self, flows: list[dict[str, Any]]) -> dict[str, Any]:
        if not flows:
            raise ValueError("At least one observed flow is required.")

        self.record_received_flows(len(flows))
        started = time.perf_counter()
        alerts = await self.pipeline.process_batch(flows)
        elapsed = max(time.perf_counter() - started, 0.000001)
        elapsed_ms = elapsed * 1000
        self.total_alerts += len(alerts)
        self.recent_alerts.extend(alerts)

        async with AsyncSessionLocal() as session:
            for alert in alerts:
                data = alert.model_dump(mode="json")
                five_tuple = data.pop("five_tuple", {})
                alert.latency_ms = elapsed_ms
                session.add(AlertRecord(
                    alert_id=alert.alert_id,
                    timestamp=alert.timestamp,
                    detected_at=alert.detected_at,
                    latency_ms=elapsed_ms,
                    flow_id=alert.flow_id,
                    src_ip=five_tuple.get("src_ip", ""),
                    src_port=five_tuple.get("src_port", 0),
                    dst_ip=five_tuple.get("dst_ip", ""),
                    dst_port=five_tuple.get("dst_port", 0),
                    proto=five_tuple.get("proto", ""),
                    threat_class=data["threat_class"],
                    severity=data["severity"],
                    confidence=data["confidence"],
                    models=data.get("models", []),
                    rules_fired=data.get("rules_fired", []),
                    mitre=data.get("mitre", []),
                    evidence=data.get("evidence", {}),
                    explanation=data.get("explanation", ""),
                    incident_id=data.get("incident_id"),
                    prev_hash=data.get("prev_hash", ""),
                    hash=data.get("hash", ""),
                ))
            if alerts:
                await session.commit()

        for alert in alerts:
            await self.ws_manager.broadcast({
                "type": "NEW_ALERT",
                "data": alert.model_dump(mode="json"),
            })

        uptime = max(time.perf_counter() - self.started_at, 0.000001)
        metrics = PipelineMetrics(
            flows_per_sec=self.get_throughput(),
            measurement_window_seconds=self.flow_rate_window_seconds,
            target_flows_per_sec=0,
            processing_latency_ms=elapsed_ms,
            alerts_per_min=self.total_alerts / uptime * 60,
            queue_depth=0,
            dropped_records=0,
            models=self.pipeline.registry.get_health(),
            uptime_seconds=uptime,
        )
        await self.ws_manager.broadcast({
            "type": "METRICS_UPDATE",
            "data": metrics.model_dump(mode="json"),
        })

        return {
            "flows_received": len(flows),
            "alerts_generated": len(alerts),
            "processing_time_ms": round(elapsed_ms, 3),
        }

    def clear_alerts(self) -> int:
        """Clear prototype alert history and its displayed total."""
        cleared = len(self.recent_alerts)
        self.recent_alerts.clear()
        self.total_alerts = 0
        return cleared
