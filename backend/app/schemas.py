"""UniGuard Pydantic schemas — single source of truth for the alert schema.
Generated TypeScript types via OpenAPI → openapi-typescript."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, computed_field


# ── Enums ─────────────────────────────────────────────────────────────

class ThreatClass(str, Enum):
    DDOS = "DDOS"
    C2_BEACON = "C2_BEACON"
    DGA = "DGA"
    DNS_TUNNEL = "DNS_TUNNEL"
    TLS_MALWARE = "TLS_MALWARE"
    SCAN = "SCAN"
    EXFIL = "EXFIL"
    ANOMALY = "ANOMALY"
    INTEL_MATCH = "INTEL_MATCH"
    SENSOR_HEALTH = "SENSOR_HEALTH"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CLOSED = "CLOSED"


# ── Sub-models ────────────────────────────────────────────────────────

class FiveTuple(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str


class ModelScore(BaseModel):
    name: str
    score: float
    label: str
    version: str


class MitreRef(BaseModel):
    id: str
    name: str


# ── Alert ─────────────────────────────────────────────────────────────

class Alert(BaseModel):
    """UniGuard standardised alert schema — Section 6."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(description="Event time (ISO 8601)")
    detected_at: datetime = Field(default_factory=datetime.utcnow,
                                   description="Detection time (ISO 8601)")
    latency_ms: float = Field(default=0.0)
    flow_id: str = Field(default="", description="Community ID v1")
    five_tuple: FiveTuple
    threat_class: ThreatClass
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    models: List[ModelScore] = Field(default_factory=list)
    rules_fired: List[str] = Field(default_factory=list)
    mitre: List[MitreRef] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    explanation: str = ""
    incident_id: Optional[str] = None
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 hash over canonical fields for tamper evidence."""
        canonical = json.dumps({
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "flow_id": self.flow_id,
            "threat_class": self.threat_class.value,
            "confidence": round(self.confidence, 8),
            "prev_hash": self.prev_hash,
        }, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self, prev_hash: str = "") -> "Alert":
        """Set prev_hash and compute hash for chain."""
        self.prev_hash = prev_hash
        self.hash = self.compute_hash()
        return self


# ── Incident ──────────────────────────────────────────────────────────

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: IncidentStatus = IncidentStatus.NEW
    title: str = ""
    alert_ids: List[str] = Field(default_factory=list)
    kill_chain: List[str] = Field(default_factory=list,
                                    description="Ordered threat classes in kill chain")
    severity: Severity = Severity.MEDIUM
    host_ip: str = ""
    notes: str = ""


# ── Metrics ───────────────────────────────────────────────────────────

class ModelHealth(BaseModel):
    name: str
    status: str  # "REAL" | "MOCK" | "ERROR"
    version: str
    inference_count: int = 0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0


class PipelineMetrics(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    flows_per_sec: float = 0.0
    measurement_window_seconds: float = 3.0
    target_flows_per_sec: float = 5000.0
    p95_latency_ms: float = 0.0
    processing_latency_ms: float = 0.0
    alerts_per_min: float = 0.0
    queue_depth: int = 0
    dropped_records: int = 0
    models: List[ModelHealth] = Field(default_factory=list)
    uptime_seconds: float = 0.0


# ── Host ──────────────────────────────────────────────────────────────

class HostInfo(BaseModel):
    ip: str
    first_seen: datetime
    last_seen: datetime
    risk_score: float = 0.0
    alert_count: int = 0
    flow_count: int = 0
    os_guess: str = ""
    is_internal: bool = False


# ── Simulation ────────────────────────────────────────────────────────

class SimulationScenario(BaseModel):
    name: str
    description: str
    threat_class: ThreatClass
    duration_seconds: float = 10.0
    intensity: float = 1.0  # multiplier


class JudgeModeStep(BaseModel):
    time_offset: float  # seconds from start
    scenario: str
    description: str
    expected_class: ThreatClass
