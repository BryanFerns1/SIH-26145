"""UniGuard application configuration."""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # ── Paths ─────────────────────────────────────────────
    artifacts_dir: str = str(Path(__file__).resolve().parent.parent.parent / "artifacts")
    data_dir: str = "/data"

    # ── Redis ─────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Database ──────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./uniguard.db"

    # ── Pipeline ──────────────────────────────────────────
    target_flows_per_sec: float = 5000.0
    micro_batch_size: int = 256
    micro_batch_timeout_ms: int = 100
    max_queue_depth: int = 10000

    # ── Ensemble weights ──────────────────────────────────
    weight_supervised: float = 0.45
    weight_anomaly: float = 0.25
    weight_rules: float = 0.30
    multi_signal_boost: float = 0.15

    # ── WebSocket ─────────────────────────────────────────
    ws_broadcast_interval_ms: int = 250

    # ── Logging ───────────────────────────────────────────
    log_level: str = "INFO"

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
