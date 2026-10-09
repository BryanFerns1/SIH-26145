"""UniGuard FastAPI application."""

import logging
import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings

log = logging.getLogger("uniguard")
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


from app.ml.registry import ModelRegistry
from app.pipeline.ensemble import Pipeline
from app.db.database import engine, Base
from app.ingestion import FlowProcessor
from typing import List

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                log.error(f"Error sending message to client: {e}")
                self.disconnect(connection)

manager = ConnectionManager()

# Global instances
registry = None
pipeline = None
flow_processor = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global registry, pipeline, flow_processor
    log.info("UniGuard Backend starting up...")
    
    # Init DB
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    # Init Models
    registry = ModelRegistry(settings.artifacts_dir)
    await registry.load_all()
    pipeline = Pipeline(registry)
    
    # Wait for real sensor input; do not generate sample or attack traffic.
    flow_processor = FlowProcessor(pipeline, manager)
    
    yield
    log.info("UniGuard Backend shutting down...")
    flow_processor = None


app = FastAPI(
    title="UniGuard API",
    description="Passive One-Way Network Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)

# Allow frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/api/models")
async def get_models():
    """List all registered models and health."""
    return registry.get_health() if registry else []


@app.get("/api/metrics")
async def get_metrics():
    """Return live throughput measured from received flow records."""
    if flow_processor is None:
        raise HTTPException(status_code=503, detail="The analysis pipeline is not ready.")
    return {
        "flows_per_sec": flow_processor.get_throughput(),
        "measurement_window_seconds": flow_processor.flow_rate_window_seconds,
        "total_flows": flow_processor.total_flows,
        "total_alerts": flow_processor.total_alerts,
        "total_detections": flow_processor.total_alerts,
    }


@app.post("/api/metrics/http-activity")
async def report_http_activity(activity: dict[str, Any], x_sensor_key: str | None = Header(default=None)):
    """Dummy endpoint to satisfy Vite frontend telemetry plugin."""
    return {"accepted": True}


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(default=100, ge=1, le=500)):
    """Return recent alerts produced by the existing model pipeline in this process."""
    if flow_processor is None:
        raise HTTPException(status_code=503, detail="The analysis pipeline is not ready.")
    alerts = list(reversed(flow_processor.recent_alerts))[:limit]
    return {
        "total": flow_processor.total_alerts,
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
    }


@app.delete("/api/alerts")
async def clear_alerts(x_admin_key: str | None = Header(default=None)):
    """Clear the prototype's in-memory alert history."""
    if settings.admin_api_key and not secrets.compare_digest(x_admin_key or "", settings.admin_api_key):
        raise HTTPException(status_code=401, detail="A valid admin API key is required.")
    if flow_processor is None:
        raise HTTPException(status_code=503, detail="The analysis pipeline is not ready.")
    cleared = flow_processor.clear_alerts()
    return {"success": True, "cleared": cleared}


@app.post("/api/flows")
async def ingest_flows(
    flows: list[dict[str, Any]],
    x_sensor_key: str | None = Header(default=None),
):
    """Analyze actual flow records supplied by a network sensor."""
    if settings.sensor_api_key and not secrets.compare_digest(x_sensor_key or "", settings.sensor_api_key):
        raise HTTPException(status_code=401, detail="A valid sensor API key is required.")
    if not flows:
        raise HTTPException(status_code=422, detail="Send at least one observed flow.")
    if len(flows) > 4096:
        raise HTTPException(status_code=413, detail="A batch may contain at most 4096 flows.")
    if flow_processor is None:
        raise HTTPException(status_code=503, detail="The analysis pipeline is not ready.")
    try:
        return await flow_processor.process(flows)
    except Exception as error:
        log.exception("Failed to process an incoming flow batch")
        raise HTTPException(status_code=500, detail="The flow batch could not be processed.") from error



@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from client in this prototype, just keep alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
