"""
APT Simulator — Head-End System (HES) Mock Service
====================================================
FastAPI application that simulates a Head-End System for smart meter
management. Ingests telemetry from meters via MQTT/event bus, exposes
REST and WebSocket APIs, and handles meter commands.

Runs on port 8001 by default.

This is the primary target of the attacker's Initial Access stage
and the entry point for lateral movement to the MDMS.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from shared import config
from shared.event_bus import EventBus
from shared.models import (
    AttackStage,
    MeterCommand,
    MeterStatus,
    MeterTelemetry,
    OperatorLogin,
    WSMessage,
)
from meters.fleet_manager import FleetManager

from .auth import AuthManager
from .commands import CommandEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [HES] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─── Global State ──────────────────────────────────────────────
fleet_manager: FleetManager | None = None
auth_manager = AuthManager()
command_engine = CommandEngine()
event_bus = EventBus.get_instance()

# Ring buffer: last 100 readings per meter
telemetry_buffer: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

# Active WebSocket connections for live streaming
ws_connections: list[WebSocket] = []

# Telemetry counter for stats
telemetry_count = 0


# ─── Lifespan ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle for the HES service."""
    global fleet_manager
    logger.info("=" * 60)
    logger.info("  APT Simulator — Head-End System (HES)")
    logger.info(f"  Spawning {config.METER_COUNT} virtual smart meters...")
    logger.info("=" * 60)

    config.ensure_data_dirs()

    # Initialize fleet manager with in-process event bus
    fleet_manager = FleetManager(
        meter_count=config.METER_COUNT,
        telemetry_interval=config.TELEMETRY_INTERVAL_SECONDS,
        event_bus=event_bus,
    )
    command_engine.fleet_manager = fleet_manager

    # Subscribe to meter telemetry via event bus
    event_bus.subscribe("meters/+/telemetry", _handle_telemetry)

    # Start the meter fleet
    await fleet_manager.start()

    # Start background task to forward readings to MDMS
    mdms_task = asyncio.create_task(_mdms_forwarder())

    logger.info(f"HES ready on port {config.HES_PORT}")
    yield

    # Shutdown
    logger.info("HES shutting down...")
    mdms_task.cancel()
    await fleet_manager.stop()


# ─── FastAPI App ───────────────────────────────────────────────

app = FastAPI(
    title="APT Simulator — HES",
    description="Head-End System mock service for smart meter management",
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


# ─── Telemetry Handling ───────────────────────────────────────

async def _handle_telemetry(topic: str, payload: dict):
    """Process incoming meter telemetry from the event bus."""
    global telemetry_count
    try:
        reading = MeterTelemetry(**payload) if isinstance(payload, dict) else MeterTelemetry.model_validate_json(payload)
        telemetry_buffer[reading.meter_id].append(reading.model_dump())
        telemetry_count += 1

        # Broadcast to WebSocket clients (throttled — every 10th reading)
        if telemetry_count % 10 == 0:
            await _broadcast_ws(WSMessage(
                type="telemetry",
                payload=reading.model_dump(mode="json"),
            ))
    except Exception as e:
        logger.error(f"Telemetry processing error: {e}")


# Buffer of readings to forward to MDMS in batches
_mdms_buffer: list[dict] = []
_mdms_buffer_lock = asyncio.Lock()


async def _mdms_forwarder():
    """Background task: batch-forward readings to MDMS every 5 seconds."""
    while True:
        try:
            await asyncio.sleep(5)
            async with _mdms_buffer_lock:
                # Collect recent readings from all meters
                batch = []
                for meter_id, readings in telemetry_buffer.items():
                    if readings:
                        batch.append(readings[-1])  # Latest reading per meter

                if batch:
                    try:
                        async with httpx.AsyncClient(timeout=5.0) as client:
                            resp = await client.post(
                                f"{config.MDMS_URL}/api/readings",
                                json=batch,
                            )
                            if resp.status_code == 200:
                                logger.debug(f"Forwarded {len(batch)} readings to MDMS")
                    except httpx.ConnectError:
                        pass  # MDMS not running yet — silently retry
                    except Exception as e:
                        logger.debug(f"MDMS forward error: {e}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"MDMS forwarder error: {e}")


# ─── WebSocket Broadcasting ───────────────────────────────────

async def _broadcast_ws(message: WSMessage):
    """Send a message to all connected WebSocket clients."""
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
    """Health check endpoint."""
    return {
        "service": "HES",
        "status": "operational",
        "meters_active": fleet_manager.status_summary if fleet_manager else {},
        "telemetry_count": telemetry_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/meters")
async def list_meters(
    zone: Optional[str] = Query(None, description="Filter by zone"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, le=2000),
    offset: int = Query(0, ge=0),
):
    """List all known smart meters with their last reading."""
    if not fleet_manager:
        raise HTTPException(status_code=503, detail="Fleet not initialized")

    meters = fleet_manager.get_all_meter_info()

    if zone:
        meters = [m for m in meters if m.zone == zone.upper()]
    if status:
        meters = [m for m in meters if m.status.value == status]

    total = len(meters)
    meters = meters[offset:offset + limit]

    # Attach last reading
    result = []
    for m in meters:
        info = m.model_dump()
        buffer = telemetry_buffer.get(m.meter_id)
        if buffer:
            info["last_reading"] = buffer[-1]
        result.append(info)

    return {"total": total, "offset": offset, "limit": limit, "meters": result}


@app.get("/api/meters/{meter_id}")
async def get_meter(meter_id: str):
    """Get detailed info for a specific meter."""
    if not fleet_manager:
        raise HTTPException(status_code=503, detail="Fleet not initialized")

    meter = fleet_manager.get_meter(meter_id)
    if not meter:
        raise HTTPException(status_code=404, detail=f"Meter {meter_id} not found")

    readings = list(telemetry_buffer.get(meter_id, []))
    return {
        "meter_id": meter.meter_id,
        "zone": meter.zone,
        "latitude": meter.latitude,
        "longitude": meter.longitude,
        "profile_type": meter.profile_type,
        "status": meter.status.value,
        "readings": readings[-20:],  # Last 20 readings
    }


@app.post("/api/meters/{meter_id}/command")
async def send_command(meter_id: str, command: dict):
    """
    Send a command to a meter.
    Requires authentication via token header.
    """
    # Extract auth (intentionally simple — header or body)
    operator_id = command.get("operator_id", "unknown")
    command_type = command.get("command_type")

    if not command_type:
        raise HTTPException(status_code=400, detail="command_type required")

    result = await command_engine.execute_command(
        command_type=command_type,
        target_meter_id=meter_id,
        operator_id=operator_id,
        parameters=command.get("parameters", {}),
    )

    if result.blocked:
        raise HTTPException(status_code=403, detail="Command blocked by detection engine")

    # Broadcast command event to dashboard
    await _broadcast_ws(WSMessage(
        type="command",
        payload=result.model_dump(mode="json"),
    ))

    return result.model_dump(mode="json")


@app.post("/api/meters/mass-command")
async def mass_command(request: dict):
    """
    Execute a command on multiple meters (by zone).
    Used legitimately for maintenance and maliciously for the Impact stage.
    """
    zone = request.get("zone")
    command_type = request.get("command_type")
    operator_id = request.get("operator_id", "unknown")

    if not zone or not command_type:
        raise HTTPException(status_code=400, detail="zone and command_type required")

    if command_type == "disconnect":
        result = await command_engine.execute_mass_disconnect(
            zone=zone,
            operator_id=operator_id,
            batch_size=request.get("batch_size", 100),
            batch_delay=request.get("batch_delay", 0.5),
        )
    else:
        raise HTTPException(status_code=400, detail=f"Mass command '{command_type}' not supported")

    # Broadcast status update
    await _broadcast_ws(WSMessage(
        type="meter_status",
        payload={
            "event": "mass_disconnect",
            "zone": zone,
            **result,
        },
    ))

    return result


# ─── Authentication Endpoints ─────────────────────────────────

@app.post("/api/auth/login")
async def operator_login(credentials: OperatorLogin):
    """
    Operator login to HES portal.
    Intentionally weak — no rate limiting, no lockout.
    """
    token = auth_manager.authenticate(
        credentials.username,
        credentials.password,
    )

    if not token:
        # Log failed attempt for detection engine
        await _broadcast_ws(WSMessage(
            type="system",
            payload={
                "event": "login_failure",
                "username": credentials.username,
            },
        ))
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Broadcast successful login
    await _broadcast_ws(WSMessage(
        type="system",
        payload={
            "event": "login_success",
            "username": credentials.username,
        },
    ))

    return {"token": token, "username": credentials.username}


@app.get("/api/operators")
async def list_operators():
    """List operator accounts (useful for recon)."""
    return {"operators": auth_manager.get_operators_list()}


@app.post("/api/operators")
async def create_operator(request: dict):
    """Create a new operator account (used by attacker for persistence)."""
    username = request.get("username")
    password = request.get("password")
    role = request.get("role", "operator")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    success = auth_manager.create_account(username, password, role)
    if not success:
        raise HTTPException(status_code=409, detail="Username already exists")

    # Broadcast account creation event
    await _broadcast_ws(WSMessage(
        type="system",
        payload={
            "event": "account_created",
            "username": username,
            "role": role,
        },
    ))

    return {"success": True, "username": username, "role": role}


# ─── Fleet Status Endpoints ───────────────────────────────────

@app.get("/api/fleet/status")
async def fleet_status():
    """Get overall fleet status summary."""
    if not fleet_manager:
        raise HTTPException(status_code=503, detail="Fleet not initialized")
    return fleet_manager.status_summary


@app.post("/api/fleet/reconnect-all")
async def reconnect_all():
    """Reconnect all disconnected meters (reset after demo)."""
    if not fleet_manager:
        raise HTTPException(status_code=503, detail="Fleet not initialized")
    count = await fleet_manager.reconnect_all()
    return {"reconnected": count}


# ─── Audit / Detection Endpoints ──────────────────────────────

@app.get("/api/audit/logins")
async def get_login_log():
    """Return login attempt log (consumed by detection engine)."""
    return {"login_log": auth_manager.get_login_log()}


@app.get("/api/audit/commands")
async def get_command_log():
    """Return command log (consumed by detection engine)."""
    return {"command_log": command_engine.get_command_log()}


# ─── Detection Engine Integration ─────────────────────────────

@app.post("/api/detection/block-operator")
async def block_operator(request: dict):
    """Called by detection engine to block a compromised operator."""
    operator_id = request.get("operator_id")
    if operator_id:
        command_engine.block_operator(operator_id)
        return {"blocked": operator_id}
    raise HTTPException(status_code=400, detail="operator_id required")


@app.post("/api/detection/unblock-operator")
async def unblock_operator(request: dict):
    """Remove an operator block."""
    operator_id = request.get("operator_id")
    if operator_id:
        command_engine.unblock_operator(operator_id)
        return {"unblocked": operator_id}
    raise HTTPException(status_code=400, detail="operator_id required")


# ─── WebSocket Endpoint ───────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """
    Live telemetry and event stream for the dashboard.
    
    Streams: telemetry, commands, meter status changes, system events.
    """
    await ws.accept()
    ws_connections.append(ws)
    logger.info(f"WebSocket client connected ({len(ws_connections)} total)")

    try:
        # Send initial fleet status
        if fleet_manager:
            await ws.send_json(WSMessage(
                type="system",
                payload={"event": "connected", "fleet": fleet_manager.status_summary},
            ).model_dump(mode="json"))

        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await ws.receive_text()
                msg = json.loads(data)

                # Handle control messages from dashboard
                if msg.get("type") == "request_fleet_status":
                    if fleet_manager:
                        await ws.send_json(WSMessage(
                            type="meter_status",
                            payload=fleet_manager.status_summary,
                        ).model_dump(mode="json"))

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    finally:
        if ws in ws_connections:
            ws_connections.remove(ws)
        logger.info(f"WebSocket client disconnected ({len(ws_connections)} remaining)")


# ─── Entry Point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.HES_PORT, log_level="info")
