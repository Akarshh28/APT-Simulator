"""
APT Simulator — Meter Data Management System (MDMS) Mock Service
=================================================================
FastAPI application that simulates the MDMS — stores meter readings,
billing data, and customer records in SQLite. Exposes REST APIs for
data aggregation and reporting.

Runs on port 8002 by default.

The MDMS is the secondary target: the attacker pivots here from the
HES during the Lateral Movement stage, creates a rogue account
(Persistence), and accesses customer data.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from shared import config

from .database import DatabaseManager
from .seed_data import seed_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MDMS] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─── Global State ──────────────────────────────────────────────
db = DatabaseManager()


# ─── Lifespan ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle for the MDMS service."""
    logger.info("=" * 60)
    logger.info("  APT Simulator — Meter Data Management System (MDMS)")
    logger.info("=" * 60)

    config.ensure_data_dirs()
    await db.initialize()

    # Seed database with synthetic data if empty
    seed_result = await seed_database(db)
    logger.info(f"Seed result: {seed_result}")

    logger.info(f"MDMS ready on port {config.MDMS_PORT}")
    yield

    # Shutdown
    logger.info("MDMS shutting down...")
    await db.close()


# ─── FastAPI App ───────────────────────────────────────────────

app = FastAPI(
    title="APT Simulator — MDMS",
    description="Meter Data Management System mock service",
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


# ─── Health Check ─────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    reading_count = await db.get_reading_count()
    customer_count = await db.get_customer_count()
    return {
        "service": "MDMS",
        "status": "operational",
        "readings_stored": reading_count,
        "customers": customer_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Meter Readings ───────────────────────────────────────────

@app.post("/api/readings")
async def ingest_readings(readings: list[dict]):
    """
    Bulk ingest meter readings from the HES.
    This is the primary data pipeline endpoint.
    """
    if not readings:
        return {"inserted": 0}

    count = await db.insert_readings(readings)
    logger.debug(f"Ingested {count} readings")
    return {"inserted": count}


@app.get("/api/readings/{meter_id}")
async def get_readings(
    meter_id: str,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
):
    """Get historical readings for a specific meter."""
    readings = await db.get_readings(meter_id, limit, offset)
    return {"meter_id": meter_id, "count": len(readings), "readings": readings}


# ─── Customer Records ─────────────────────────────────────────

@app.get("/api/customers")
async def list_customers(
    zone: Optional[str] = Query(None),
    limit: int = Query(100, le=2000),
    offset: int = Query(0, ge=0),
):
    """List customer records with optional zone filter."""
    customers = await db.get_customers(zone=zone, limit=limit, offset=offset)
    total = await db.get_customer_count()
    return {"total": total, "count": len(customers), "customers": customers}


@app.get("/api/customers/{customer_id}")
async def get_customer(customer_id: str):
    """Get a specific customer record."""
    customer = await db.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Customer {customer_id} not found")
    return customer


# ─── Billing ──────────────────────────────────────────────────

@app.get("/api/billing/{customer_id}")
async def get_billing(
    customer_id: str,
    limit: int = Query(12, le=60),
):
    """Get billing history for a customer."""
    billing = await db.get_billing(customer_id, limit)
    return {"customer_id": customer_id, "records": billing}


# ─── Reports ──────────────────────────────────────────────────

@app.get("/api/reports/consumption")
async def consumption_report(
    zone: Optional[str] = Query(None),
    meter_id: Optional[str] = Query(None),
):
    """
    Aggregated consumption report.
    
    Without filters: returns per-zone aggregation.
    With zone: returns time-series for that zone.
    With meter_id: returns time-series for that meter.
    """
    if meter_id:
        data = await db.get_consumption_timeseries(meter_id=meter_id)
        return {"type": "meter", "meter_id": meter_id, "data": data}
    elif zone:
        data = await db.get_consumption_timeseries(zone=zone)
        return {"type": "zone", "zone": zone, "data": data}
    else:
        data = await db.get_consumption_by_zone()
        return {"type": "summary", "data": data}


# ─── Operator Management ─────────────────────────────────────
# These endpoints are targeted by the attacker during Persistence
# and Lateral Movement stages.

@app.get("/api/operators")
async def list_operators():
    """List operator accounts in MDMS."""
    operators = await db.get_operators()
    # Strip password hashes from response (minimal security)
    return {
        "operators": [
            {k: v for k, v in op.items() if k != "password_hash"}
            for op in operators
        ]
    }


@app.post("/api/operators")
async def create_operator(request: dict):
    """
    Create an operator account in MDMS.
    Used legitimately by admins and maliciously by the attacker.
    """
    username = request.get("username")
    password = request.get("password")
    role = request.get("role", "operator")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    operator = {
        "operator_id": f"OP-{hash(username) % 10000:04d}",
        "username": username,
        "password_hash": password,  # Intentionally storing plaintext
        "role": role,
        "is_rogue": request.get("is_rogue", 0),
    }

    success = await db.insert_operator(operator)
    if not success:
        raise HTTPException(status_code=409, detail="Failed to create operator")

    # Audit log
    await db.log_audit(
        actor=request.get("created_by", "system"),
        action="create_operator",
        target=username,
        details=f"Role: {role}",
        is_suspicious=(role == "admin"),  # Admin creation is suspicious
    )

    return {"success": True, "username": username, "role": role}


# ─── Audit Log ────────────────────────────────────────────────

@app.get("/api/audit")
async def get_audit_log(
    limit: int = Query(100, le=1000),
    suspicious_only: bool = Query(False),
):
    """Get audit log entries (consumed by detection engine)."""
    entries = await db.get_audit_log(limit=limit, suspicious_only=suspicious_only)
    return {"entries": entries}


@app.post("/api/audit")
async def add_audit_entry(entry: dict):
    """Add an audit log entry (used by HES and attacker)."""
    await db.log_audit(
        actor=entry.get("actor", "unknown"),
        action=entry.get("action", "unknown"),
        target=entry.get("target", ""),
        details=entry.get("details", ""),
        source_ip=entry.get("source_ip", "127.0.0.1"),
        is_suspicious=entry.get("is_suspicious", False),
    )
    return {"success": True}


# ─── Entry Point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.MDMS_PORT, log_level="info")
