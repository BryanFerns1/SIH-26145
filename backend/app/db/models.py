"""UniGuard SQLAlchemy models."""

from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, JSON, Boolean
from app.db.database import Base

class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    detected_at = Column(DateTime)
    latency_ms = Column(Float)
    flow_id = Column(String, index=True)
    
    # 5-tuple flattened
    src_ip = Column(String, index=True)
    src_port = Column(Float)
    dst_ip = Column(String, index=True)
    dst_port = Column(Float)
    proto = Column(String)
    
    threat_class = Column(String, index=True)
    severity = Column(String, index=True)
    confidence = Column(Float)
    
    # JSON fields
    models = Column(JSON)
    rules_fired = Column(JSON)
    mitre = Column(JSON)
    evidence = Column(JSON)
    
    explanation = Column(String)
    incident_id = Column(String, index=True, nullable=True)
    
    prev_hash = Column(String)
    hash = Column(String, unique=True, index=True)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String, index=True)
    title = Column(String)
    alert_ids = Column(JSON)
    kill_chain = Column(JSON)
    severity = Column(String, index=True)
    host_ip = Column(String, index=True)
    notes = Column(String)


class HostRecord(Base):
    __tablename__ = "hosts"
    
    ip = Column(String, primary_key=True, index=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    risk_score = Column(Float, default=0.0)
    alert_count = Column(Float, default=0.0) # Using float as SQLite integers are a bit weird sometimes, but Integer is fine
    flow_count = Column(Float, default=0.0)
    os_guess = Column(String)
    is_internal = Column(Boolean, default=False)
