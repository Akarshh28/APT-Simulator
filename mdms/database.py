"""
APT Simulator — MDMS Database Manager
=======================================
SQLite database manager for the Meter Data Management System.
Handles schema creation, data insertion, and queries for meter
readings, customer records, billing, and audit logs.

Uses aiosqlite for async operations within the FastAPI event loop.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from shared import config

logger = logging.getLogger(__name__)


# ─── Schema Definitions ───────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meter_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    voltage REAL,
    current REAL,
    power_factor REAL,
    consumption_kwh REAL,
    active_power_w REAL,
    zone TEXT,
    latitude REAL,
    longitude REAL,
    status TEXT DEFAULT 'connected',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_readings_meter ON meter_readings(meter_id);
CREATE INDEX IF NOT EXISTS idx_readings_time ON meter_readings(timestamp);
CREATE INDEX IF NOT EXISTS idx_readings_zone ON meter_readings(zone);

CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT,
    zone TEXT,
    meter_id TEXT,
    phone TEXT,
    email TEXT,
    account_status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_customers_meter ON customers(meter_id);
CREATE INDEX IF NOT EXISTS idx_customers_zone ON customers(zone);

CREATE TABLE IF NOT EXISTS billing (
    billing_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    meter_id TEXT NOT NULL,
    period TEXT NOT NULL,
    total_kwh REAL,
    rate_per_kwh REAL DEFAULT 6.50,
    amount_inr REAL,
    status TEXT DEFAULT 'unpaid',
    due_date TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_billing_customer ON billing(customer_id);
CREATE INDEX IF NOT EXISTS idx_billing_period ON billing(period);

CREATE TABLE IF NOT EXISTS operators (
    operator_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'operator',
    created_at TEXT DEFAULT (datetime('now')),
    is_rogue INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    source_ip TEXT DEFAULT '127.0.0.1',
    is_suspicious INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
"""


class DatabaseManager:
    """
    Async SQLite database manager for the MDMS.
    
    Provides methods for:
    - Inserting meter readings (bulk)
    - Querying historical data
    - Managing customer records
    - Billing operations
    - Audit logging
    """

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or config.MDMS_DB_PATH
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self):
        """Create the database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA_SQL)
        await self._db.commit()
        logger.info(f"MDMS database initialized at {self.db_path}")

    async def close(self):
        """Close the database connection."""
        if self._db:
            await self._db.close()
            logger.info("MDMS database closed")

    # ─── Meter Readings ───────────────────────────────────────

    async def insert_readings(self, readings: list[dict]) -> int:
        """Bulk insert meter readings. Returns count of inserted rows."""
        if not readings:
            return 0

        sql = """
            INSERT INTO meter_readings 
            (meter_id, timestamp, voltage, current, power_factor, 
             consumption_kwh, active_power_w, zone, latitude, longitude, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                r.get("meter_id"), r.get("timestamp"), r.get("voltage"),
                r.get("current"), r.get("power_factor"), r.get("consumption_kwh"),
                r.get("active_power_w", 0), r.get("zone"), r.get("latitude"),
                r.get("longitude"), r.get("status", "connected"),
            )
            for r in readings
        ]
        await self._db.executemany(sql, rows)
        await self._db.commit()
        return len(rows)

    async def get_readings(
        self,
        meter_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Get historical readings for a specific meter."""
        sql = """
            SELECT * FROM meter_readings 
            WHERE meter_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """
        cursor = await self._db.execute(sql, (meter_id, limit, offset))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_reading_count(self) -> int:
        """Get total number of readings in the database."""
        cursor = await self._db.execute("SELECT COUNT(*) as cnt FROM meter_readings")
        row = await cursor.fetchone()
        return row["cnt"] if row else 0

    # ─── Customer Records ─────────────────────────────────────

    async def insert_customer(self, customer: dict) -> bool:
        """Insert a customer record."""
        sql = """
            INSERT OR IGNORE INTO customers 
            (customer_id, name, address, zone, meter_id, phone, email)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        await self._db.execute(sql, (
            customer["customer_id"], customer["name"], customer.get("address", ""),
            customer.get("zone", ""), customer.get("meter_id", ""),
            customer.get("phone", ""), customer.get("email", ""),
        ))
        await self._db.commit()
        return True

    async def insert_customers_bulk(self, customers: list[dict]) -> int:
        """Bulk insert customer records."""
        sql = """
            INSERT OR IGNORE INTO customers 
            (customer_id, name, address, zone, meter_id, phone, email)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (c["customer_id"], c["name"], c.get("address", ""),
             c.get("zone", ""), c.get("meter_id", ""),
             c.get("phone", ""), c.get("email", ""))
            for c in customers
        ]
        await self._db.executemany(sql, rows)
        await self._db.commit()
        return len(rows)

    async def get_customers(
        self,
        zone: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Get customer records with optional zone filter."""
        if zone:
            sql = "SELECT * FROM customers WHERE zone = ? LIMIT ? OFFSET ?"
            cursor = await self._db.execute(sql, (zone, limit, offset))
        else:
            sql = "SELECT * FROM customers LIMIT ? OFFSET ?"
            cursor = await self._db.execute(sql, (limit, offset))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_customer(self, customer_id: str) -> Optional[dict]:
        """Get a single customer record."""
        cursor = await self._db.execute(
            "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_customer_count(self) -> int:
        """Get total number of customers."""
        cursor = await self._db.execute("SELECT COUNT(*) as cnt FROM customers")
        row = await cursor.fetchone()
        return row["cnt"] if row else 0

    # ─── Billing ──────────────────────────────────────────────

    async def insert_billing(self, billing: dict) -> bool:
        """Insert a billing record."""
        sql = """
            INSERT OR IGNORE INTO billing 
            (billing_id, customer_id, meter_id, period, total_kwh, 
             rate_per_kwh, amount_inr, status, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        await self._db.execute(sql, (
            billing["billing_id"], billing["customer_id"], billing["meter_id"],
            billing["period"], billing["total_kwh"], billing.get("rate_per_kwh", 6.50),
            billing["amount_inr"], billing.get("status", "unpaid"),
            billing.get("due_date", ""),
        ))
        await self._db.commit()
        return True

    async def insert_billing_bulk(self, records: list[dict]) -> int:
        """Bulk insert billing records."""
        sql = """
            INSERT OR IGNORE INTO billing 
            (billing_id, customer_id, meter_id, period, total_kwh, 
             rate_per_kwh, amount_inr, status, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (b["billing_id"], b["customer_id"], b["meter_id"],
             b["period"], b["total_kwh"], b.get("rate_per_kwh", 6.50),
             b["amount_inr"], b.get("status", "unpaid"),
             b.get("due_date", ""))
            for b in records
        ]
        await self._db.executemany(sql, rows)
        await self._db.commit()
        return len(rows)

    async def get_billing(
        self,
        customer_id: str,
        limit: int = 12,
    ) -> list[dict]:
        """Get billing records for a customer."""
        sql = """
            SELECT * FROM billing 
            WHERE customer_id = ? 
            ORDER BY period DESC 
            LIMIT ?
        """
        cursor = await self._db.execute(sql, (customer_id, limit))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ─── Operators ────────────────────────────────────────────

    async def insert_operator(self, operator: dict) -> bool:
        """Insert an operator record (used by attacker for persistence)."""
        sql = """
            INSERT OR IGNORE INTO operators 
            (operator_id, username, password_hash, role, is_rogue)
            VALUES (?, ?, ?, ?, ?)
        """
        await self._db.execute(sql, (
            operator.get("operator_id", ""),
            operator["username"],
            operator["password_hash"],
            operator.get("role", "operator"),
            operator.get("is_rogue", 0),
        ))
        await self._db.commit()
        return True

    async def get_operators(self) -> list[dict]:
        """Get all operator records."""
        cursor = await self._db.execute("SELECT * FROM operators")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ─── Audit Log ────────────────────────────────────────────

    async def log_audit(
        self,
        actor: str,
        action: str,
        target: str = "",
        details: str = "",
        source_ip: str = "127.0.0.1",
        is_suspicious: bool = False,
    ):
        """Write an audit log entry."""
        sql = """
            INSERT INTO audit_log (actor, action, target, details, source_ip, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        await self._db.execute(sql, (
            actor, action, target, details, source_ip, int(is_suspicious),
        ))
        await self._db.commit()

    async def get_audit_log(
        self,
        limit: int = 100,
        suspicious_only: bool = False,
    ) -> list[dict]:
        """Get audit log entries."""
        if suspicious_only:
            sql = "SELECT * FROM audit_log WHERE is_suspicious = 1 ORDER BY timestamp DESC LIMIT ?"
            cursor = await self._db.execute(sql, (limit,))
        else:
            sql = "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?"
            cursor = await self._db.execute(sql, (limit,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ─── Aggregation / Reports ────────────────────────────────

    async def get_consumption_by_zone(self) -> list[dict]:
        """Aggregate total consumption by zone."""
        sql = """
            SELECT zone, 
                   COUNT(DISTINCT meter_id) as meter_count,
                   SUM(consumption_kwh) as total_kwh,
                   AVG(consumption_kwh) as avg_kwh,
                   MAX(timestamp) as latest_reading
            FROM meter_readings 
            GROUP BY zone 
            ORDER BY zone
        """
        cursor = await self._db.execute(sql)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_consumption_timeseries(
        self,
        meter_id: Optional[str] = None,
        zone: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Get consumption time series, optionally filtered by meter or zone."""
        if meter_id:
            sql = """
                SELECT meter_id, timestamp, consumption_kwh, active_power_w, voltage
                FROM meter_readings WHERE meter_id = ?
                ORDER BY timestamp DESC LIMIT ?
            """
            cursor = await self._db.execute(sql, (meter_id, limit))
        elif zone:
            sql = """
                SELECT meter_id, timestamp, AVG(consumption_kwh) as consumption_kwh, 
                       AVG(active_power_w) as active_power_w, AVG(voltage) as voltage
                FROM meter_readings WHERE zone = ?
                GROUP BY strftime('%H:%M', timestamp)
                ORDER BY timestamp DESC LIMIT ?
            """
            cursor = await self._db.execute(sql, (zone, limit))
        else:
            sql = """
                SELECT zone, timestamp, AVG(consumption_kwh) as consumption_kwh,
                       AVG(active_power_w) as active_power_w
                FROM meter_readings
                GROUP BY zone, strftime('%H', timestamp)
                ORDER BY timestamp DESC LIMIT ?
            """
            cursor = await self._db.execute(sql, (limit,))

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
