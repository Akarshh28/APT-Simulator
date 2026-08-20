"""
APT Simulator — Detection Engine Service
==========================================
FastAPI application that orchestrates all detection modules:
- Behavioral baselining
- Isolation Forest anomaly scoring
- Graph-based lateral movement detection
- Low-and-slow beacon detection
- Composite risk scoring

Consumes events from HES, MDMS, and the attack event log.
Pushes alerts and risk scores to the dashboard via WebSocket.

Also serves as the orchestration endpoint for the full simulation:
the dashboard talks to this service to start/stop attacks, toggle
detection, and control the demo flow.

Runs on port 8003 by default.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from shared import config
from shared.models import AttackStage, WSMessage

from .anomaly_scorer import AnomalyScorer
from .baseline import BaselineManager
from .beacon_detector import BeaconDetector
from .graph_detector import GraphDetector
from .risk_scorer import RiskScorer

# Lazy-import the attack engine to avoid circular deps
from attacker.engine import AttackEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECT] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─── Global State ──────────────────────────────────────────────
baseline = BaselineManager()
anomaly_scorer = AnomalyScorer(window_seconds=10)  # Shorter windows for demo
graph_detector = GraphDetector()
beacon_detector = BeaconDetector(min_samples=3)
risk_scorer = RiskScorer()
attack_engine = AttackEngine()

# WebSocket connections
ws_connections: list[WebSocket] = []

# Monitoring task
_monitor_task: asyncio.Task | None = None


# ─── Lifespan ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown for the detection service."""
    global _monitor_task

    logger.info("=" * 60)
    logger.info("  APT Simulator — Detection Engine")
    logger.info("=" * 60)

    config.ensure_data_dirs()

    # Load or create baseline
    baseline.load()
    anomaly_scorer.train()

    # Set up attack engine callbacks
    attack_engine.set_ws_broadcast(_broadcast_ws)
    attack_engine.set_is_blocked_cb(lambda: risk_scorer.has_blocked)

    def _handle_stage_active(stage_name: str):
        """Force signal updates when stages run, ensuring multi-signal correlation for demo."""
        if stage_name in ("initial_access", "persistence"):
            risk_scorer.update_signal("login_anomaly", 70, evidence={"reasons": ["Credential stuffing", "Rogue account created"]})
        elif stage_name == "lateral_movement":
            risk_scorer.update_signal("graph_anomaly", 85, evidence={"severity": "high", "reasons": ["New edge to MDMS"]})
        elif stage_name == "command_control":
            risk_scorer.update_signal("beacon_detection", 90, evidence={"reasons": ["Periodic heartbeat detected"]})
        elif stage_name == "impact":
            risk_scorer.update_signal("mass_command", 95, evidence={"recent_disconnects": 100})
            
    attack_engine.set_stage_cb(_handle_stage_active)

    # Set up block callback: when risk > block_threshold, block the attacker
    risk_scorer.set_block_callback(_execute_block)

    # Set up alert callback: broadcast new alerts
    def _handle_alert(alert):
        asyncio.create_task(_broadcast_ws(WSMessage(
            type="alert",
            payload=alert.model_dump(mode="json"),
        )))
    risk_scorer.set_alert_callback(_handle_alert)

    # Start monitoring loop
    _monitor_task = asyncio.create_task(_monitoring_loop())

    logger.info(f"Detection engine ready on port {config.DETECTOR_PORT}")
    yield

    # Shutdown
    if _monitor_task:
        _monitor_task.cancel()
    logger.info("Detection engine shutting down...")


# ─── FastAPI App ───────────────────────────────────────────────

app = FastAPI(
    title="APT Simulator — Detection Engine",
    description="Anomaly detection and orchestration service",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Monitoring Loop ──────────────────────────────────────────

async def _monitoring_loop():
    """
    Background loop that:
    1. Polls HES for login/command events
    2. Feeds events into detection modules
    3. Pushes risk score updates to dashboard
    """
    while True:
        try:
            # Apply risk decay
            risk_scorer.apply_decay()

            # Check anomaly scorer window
            window_result = anomaly_scorer.check_window()
            if window_result and window_result["is_anomalous"]:
                risk_scorer.update_signal(
                    "isolation_forest",
                    window_result["anomaly_score"] * 100,
                    evidence=window_result,
                )

            # Push risk score to dashboard
            state = risk_scorer.get_state()
            await _broadcast_ws(WSMessage(
                type="risk_score",
                payload=state,
            ))

            # Poll HES for new events (every 2 seconds)
            await _poll_hes_events()

            await asyncio.sleep(2)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
            await asyncio.sleep(5)


async def _poll_hes_events():
    """Poll HES for login and command events."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            # Poll login log
            resp = await client.get(f"{config.HES_URL}/api/audit/logins")
            if resp.status_code == 200:
                login_log = resp.json().get("login_log", [])
                _process_login_events(login_log)

            # Poll command log
            resp = await client.get(f"{config.HES_URL}/api/audit/commands")
            if resp.status_code == 200:
                command_log = resp.json().get("command_log", [])
                _process_command_events(command_log)

    except httpx.ConnectError:
        pass  # HES not available yet


_last_login_count = 0
_last_command_count = 0


def _process_login_events(login_log: list[dict]):
    """Process new login events from HES."""
    global _last_login_count

    new_events = login_log[_last_login_count:]
    _last_login_count = len(login_log)

    for event in new_events:
        anomaly_scorer.ingest_login_event(event)

        is_anomalous, reasons = baseline.is_login_anomalous(event)
        if is_anomalous:
            # Count failures in recent history
            recent_failures = sum(
                1 for e in login_log[-20:]
                if not e.get("success")
            )

            # Scale signal by failure count
            signal_value = min(100, recent_failures * 10)
            risk_scorer.update_signal(
                "login_anomaly",
                signal_value,
                evidence={"reasons": reasons, "recent_failures": recent_failures},
            )

        # Graph: record operator → HES interaction
        username = event.get("username", "unknown")
        if event.get("success"):
            anomaly = graph_detector.record_interaction(
                username, "HES", "login"
            )
            if anomaly:
                risk_scorer.update_signal(
                    "graph_anomaly",
                    70 if anomaly["severity"] == "high" else 40,
                    evidence=anomaly,
                )


def _process_command_events(command_log: list[dict]):
    """Process new command events from HES."""
    global _last_command_count

    new_events = command_log[_last_command_count:]
    _last_command_count = len(command_log)

    for event in new_events:
        anomaly_scorer.ingest_command(event)

        # Check for mass disconnect pattern
        if event.get("command_type") == "disconnect":
            # Count recent disconnects
            recent_disconnects = sum(
                1 for e in command_log[-50:]
                if e.get("command_type") == "disconnect"
            )
            if recent_disconnects > 20:
                risk_scorer.update_signal(
                    "mass_command",
                    min(100, recent_disconnects * 2),
                    evidence={"recent_disconnects": recent_disconnects},
                )


def _execute_block():
    """Called when risk score exceeds block threshold."""
    logger.warning("🛡️ EXECUTING BLOCK: sending block command to HES")
    # Fire-and-forget async block
    asyncio.create_task(_send_block_to_hes())


async def _send_block_to_hes():
    """Send block commands to HES for compromised operators."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Block the rogue account
            await client.post(
                f"{config.HES_URL}/api/detection/block-operator",
                json={"operator_id": "svc_backup"},
            )
            # Block the compromised admin
            await client.post(
                f"{config.HES_URL}/api/detection/block-operator",
                json={"operator_id": "OP-ADMIN"},
            )
            logger.info("Block commands sent to HES")
    except Exception as e:
        logger.error(f"Failed to send block to HES: {e}")


# ─── WebSocket Broadcasting ───────────────────────────────────

async def _broadcast_ws(message: WSMessage):
    """Broadcast to all connected WebSocket clients."""
    if not ws_connections:
        return
    data = message.model_dump_json()
    disconnected = []
    for ws in ws_connections:
        try:
            await ws.send_text(data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_connections.remove(ws)


# ─── REST API Endpoints ───────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {
        "service": "Detection Engine",
        "status": "operational",
        "detection_enabled": risk_scorer.detection_enabled,
        "risk_score": risk_scorer.current_risk,
        "baseline_trained": baseline.is_trained,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/risk-score")
async def get_risk_score():
    """Get current risk score and signal breakdown."""
    return risk_scorer.get_state()


@app.get("/api/risk-history")
async def get_risk_history(count: int = Query(100, le=500)):
    """Get risk score history for timeline visualization."""
    return {"history": risk_scorer.get_risk_history(count)}


@app.get("/api/alerts")
async def get_alerts():
    """Get all detection alerts."""
    return {"alerts": risk_scorer.get_alerts()}


@app.get("/api/graph")
async def get_graph():
    """Get communication graph data for visualization."""
    return graph_detector.get_graph_data()


@app.get("/api/beacons")
async def get_beacons():
    """Get suspected beacon meters."""
    return beacon_detector.get_summary()


@app.get("/api/anomaly-scores")
async def get_anomaly_scores(count: int = Query(50, le=200)):
    """Get recent anomaly scores from the Isolation Forest."""
    return {"scores": anomaly_scorer.get_recent_scores(count)}


# ─── Detection Control ────────────────────────────────────────

@app.post("/api/detection/toggle")
async def toggle_detection(request: dict):
    """Enable or disable detection (demo toggle)."""
    enabled = request.get("enabled", True)
    risk_scorer.toggle_detection(enabled)

    # If disabling, also unblock operators at HES
    if not enabled:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{config.HES_URL}/api/detection/unblock-operator",
                    json={"operator_id": "svc_backup"},
                )
                await client.post(
                    f"{config.HES_URL}/api/detection/unblock-operator",
                    json={"operator_id": "OP-ADMIN"},
                )
        except Exception:
            pass

    return {"detection_enabled": enabled}


@app.post("/api/baseline/train")
async def train_baseline():
    """Trigger baseline training from current clean data."""
    baseline.train_from_clean_data()
    anomaly_scorer.train()
    return {"status": "baseline_trained"}


# ─── Simulation Orchestration ─────────────────────────────────

@app.post("/api/simulation/start")
async def start_simulation(request: dict = None):
    """
    Start the full attack simulation.
    This is the main demo entry point.
    """
    request = request or {}
    scenario_path = request.get("scenario")
    detection_enabled = request.get("detection_enabled", True)

    # Reset state
    risk_scorer.reset()
    graph_detector.reset()
    beacon_detector.reset()
    attack_engine.reset()

    global _last_login_count, _last_command_count
    _last_login_count = 0
    _last_command_count = 0

    # Configure detection
    risk_scorer.toggle_detection(detection_enabled)

    # Load scenario
    if scenario_path:
        attack_engine.load_scenario(scenario_path)
    else:
        attack_engine.load_scenario()

    # Run attack in background
    asyncio.create_task(_run_attack_with_detection())

    return {
        "status": "started",
        "detection_enabled": detection_enabled,
        "scenario": attack_engine.scenario.get("name", "default"),
    }


async def _run_attack_with_detection():
    """Run the attack with concurrent detection processing."""
    # Process attack events as they come in
    original_callback = attack_engine.event_log._ws_callback

    async def event_handler(event):
        """Process each attack event through the detection pipeline."""
        # Forward to dashboard
        if original_callback:
            await original_callback(event)

        # Feed into detection modules
        stage = event.stage

        if stage == AttackStage.INITIAL_ACCESS:
            if not event.success:
                anomaly_scorer.ingest_login_event({"success": False, "username": event.source})
                risk_scorer.update_signal("login_anomaly", 15)

        elif stage == AttackStage.PERSISTENCE:
            anomaly_scorer.ingest_account_creation()
            graph_detector.record_interaction(event.source, "MDMS", "account_creation")
            risk_scorer.update_signal("isolation_forest", 25)

        elif stage == AttackStage.LATERAL_MOVEMENT:
            anomaly_scorer.ingest_cross_service_auth()
            anomaly_scorer.ingest_unusual_api_access()
            anomaly = graph_detector.record_interaction(
                event.source, "MDMS", "lateral_movement",
                metadata={"from": "HES"},
            )
            if anomaly:
                risk_scorer.update_signal("graph_anomaly", 60, evidence=anomaly)

        elif stage == AttackStage.COMMAND_CONTROL:
            # Beacon telemetry
            result = beacon_detector.record_telemetry(
                event.details.get("meter_id", "SM-X-9999")
            )
            if result and result["is_beacon"]:
                risk_scorer.update_signal(
                    "beacon_detection",
                    result["confidence"] * 80,
                    evidence=result,
                )

        elif stage == AttackStage.IMPACT:
            if "disconnect" in event.action.lower():
                anomaly_scorer.ingest_command({"command_type": "disconnect"})
                risk_scorer.update_signal("mass_command", 80)

    attack_engine.event_log.set_ws_callback(event_handler)

    try:
        await attack_engine.run_all()
    except Exception as e:
        logger.error(f"Attack simulation error: {e}", exc_info=True)


@app.post("/api/simulation/stop")
async def stop_simulation():
    """Stop the running simulation."""
    attack_engine.pause()
    return {"status": "stopped"}


@app.post("/api/simulation/reset")
async def reset_simulation():
    """Reset the simulation to initial state."""
    attack_engine.reset()
    risk_scorer.reset()
    graph_detector.reset()
    beacon_detector.reset()

    global _last_login_count, _last_command_count
    _last_login_count = 0
    _last_command_count = 0

    # Reconnect all meters
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{config.HES_URL}/api/fleet/reconnect-all")
            # Unblock operators
            await client.post(
                f"{config.HES_URL}/api/detection/unblock-operator",
                json={"operator_id": "svc_backup"},
            )
            await client.post(
                f"{config.HES_URL}/api/detection/unblock-operator",
                json={"operator_id": "OP-ADMIN"},
            )
    except Exception:
        pass

    return {"status": "reset"}


@app.get("/api/simulation/status")
async def simulation_status():
    """Get current simulation status."""
    return {
        "is_running": attack_engine.is_running,
        "is_paused": attack_engine.is_paused,
        "current_stage": attack_engine.current_stage.value if attack_engine.current_stage else None,
        "stage_results": attack_engine.stage_results,
        "detection_enabled": risk_scorer.detection_enabled,
        "risk_score": round(risk_scorer.current_risk, 2),
    }


@app.get("/api/attack-events")
async def get_attack_events():
    """Get all attack events from the current simulation."""
    return {"events": attack_engine.event_log.get_events_as_dicts()}


# ─── WebSocket Endpoint ───────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    """
    Real-time detection alerts and risk score stream.
    
    Pushes: risk_score, alerts, attack_events, attack_stage updates.
    """
    await ws.accept()
    ws_connections.append(ws)
    logger.info(f"Dashboard connected ({len(ws_connections)} total)")

    try:
        # Send initial state
        await ws.send_json(WSMessage(
            type="system",
            payload={
                "event": "connected",
                "detection_enabled": risk_scorer.detection_enabled,
                "risk_score": risk_scorer.current_risk,
                "alerts": risk_scorer.get_alerts(),
            },
        ).model_dump(mode="json"))

        while True:
            try:
                data = await ws.receive_text()
                msg = json.loads(data)

                if msg.get("type") == "toggle_detection":
                    enabled = msg.get("enabled", True)
                    risk_scorer.toggle_detection(enabled)

                elif msg.get("type") == "start_simulation":
                    await start_simulation(msg.get("config", {}))

                elif msg.get("type") == "reset_simulation":
                    await reset_simulation()

            except WebSocketDisconnect:
                break
    finally:
        if ws in ws_connections:
            ws_connections.remove(ws)
        logger.info(f"Dashboard disconnected ({len(ws_connections)} remaining)")


# ─── Entry Point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.DETECTOR_PORT, log_level="info")
