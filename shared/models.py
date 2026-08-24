"""
APT Simulator — Shared Pydantic Models
=======================================
Data models shared across all services. Using Pydantic v2 for validation
and serialization. These models define the 'language' of the simulation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Enums ─────────────────────────────────────────────────────

class MeterStatus(str, Enum):
    """Operational status of a smart meter."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FIRMWARE_UPDATING = "firmware_updating"
    ERROR = "error"


class CommandType(str, Enum):
    """Commands that can be issued to meters via the HES."""
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    FIRMWARE_PUSH = "firmware_push"
    READ_ON_DEMAND = "read_on_demand"


class AttackStage(str, Enum):
    """MITRE ATT&CK for ICS kill-chain stages used in our simulation."""
    RECONNAISSANCE = "reconnaissance"
    PHYSICAL_TAMPER = "physical_tampering"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_CONTROL = "command_control"
    IMPACT = "impact"
    BENIGN_ACTIVITY = "benign_activity"


class AlertSeverity(str, Enum):
    """Severity levels for detection alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─── Meter Telemetry ──────────────────────────────────────────

class MeterTelemetry(BaseModel):
    """A single telemetry reading from a smart meter (DLMS/COSEM-style)."""
    meter_id: str = Field(..., description="Meter identifier, e.g. SM-A-0042")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    voltage: float = Field(..., ge=0, le=500, description="Voltage in volts")
    # Industrial meters can exceed 100A during peak load (e.g., 50kW / 415V), so we use le=500 for safety.
    current: float = Field(..., ge=0, le=500, description="Current in amps")
    power_factor: float = Field(..., ge=0, le=1, description="Power factor")
    consumption_kwh: float = Field(..., ge=0, description="Cumulative kWh (FWD)")
    active_power_w: float = Field(0, ge=0, description="Instantaneous active power in watts")
    max_demand_kw: float = Field(0, ge=0, description="Maximum demand (MD) in kW")
    battery_voltage: float = Field(3.6, description="Battery voltage in V")
    diag_status: str = Field("Good", description="Diagnostics status")
    wan_status: str = Field("Connected", description="WAN connectivity status")
    han_status: str = Field("Connected", description="HAN connectivity status")
    power_fail_count: int = Field(0, ge=0, description="Power failure history counter")
    zone: str = Field(..., description="Zone A-F")
    latitude: float = Field(..., description="Meter latitude")
    longitude: float = Field(..., description="Meter longitude")
    status: MeterStatus = Field(default=MeterStatus.CONNECTED)

    model_config = {"json_schema_extra": {"example": {
        "meter_id": "SM-A-0042",
        "timestamp": "2024-01-15T14:30:00Z",
        "voltage": 230.5,
        "current": 4.2,
        "power_factor": 0.95,
        "consumption_kwh": 1542.7,
        "active_power_w": 920.0,
        "max_demand_kw": 1.2,
        "battery_voltage": 3.732,
        "diag_status": "Good",
        "wan_status": "Connected",
        "han_status": "Connected",
        "power_fail_count": 0,
        "zone": "A",
        "latitude": 26.45,
        "longitude": 80.35,
        "status": "connected"
    }}}


class MeterInfo(BaseModel):
    """Static information about a smart meter."""
    meter_id: str
    zone: str
    latitude: float
    longitude: float
    profile_type: str = Field(..., description="residential/commercial/industrial")
    status: MeterStatus = Field(default=MeterStatus.CONNECTED)
    customer_id: Optional[str] = None
    last_reading: Optional[MeterTelemetry] = None


# ─── HES Commands ─────────────────────────────────────────────

class MeterCommand(BaseModel):
    """A command issued to a meter through the HES."""
    command_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    command_type: CommandType
    target_meter_id: str
    operator_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    parameters: dict[str, Any] = Field(default_factory=dict)
    success: Optional[bool] = None
    blocked: bool = Field(default=False, description="True if detection engine blocked this")


class OperatorLogin(BaseModel):
    """Login request to HES operator portal."""
    username: str
    password: str


class OperatorSession(BaseModel):
    """Active operator session."""
    operator_id: str
    username: str
    role: str
    token: str
    login_time: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str = "127.0.0.1"


# ─── MDMS Records ─────────────────────────────────────────────

class CustomerRecord(BaseModel):
    """A utility customer record in the MDMS."""
    customer_id: str
    name: str
    address: str
    zone: str
    meter_id: str
    account_status: str = "active"


class BillingRecord(BaseModel):
    """A billing record for a customer."""
    billing_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    customer_id: str
    meter_id: str
    period: str  # e.g. "2024-01"
    total_kwh: float
    amount_inr: float
    status: str = "unpaid"


# ─── Attack Events ────────────────────────────────────────────

class AttackEvent(BaseModel):
    """
    Structured event from the attack engine. Each kill-chain action
    produces one of these. Consumed by the detector and dashboard.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sim_timestamp: Optional[datetime] = None  # Simulated (compressed) time
    stage: AttackStage
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID, e.g. T0846")
    tactic: str = Field("", description="MITRE tactic name")
    source: str = Field("attacker", description="Source entity")
    target: str = Field(..., description="Target entity/service")
    action: str = Field(..., description="Human-readable action description")
    details: dict[str, Any] = Field(default_factory=dict)
    success: bool = True


# ─── Detection Alerts ─────────────────────────────────────────

class DetectionAlert(BaseModel):
    """
    Structured alert from the detection engine. Pushed to dashboard
    in real-time via WebSocket.
    """
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    stage: Optional[AttackStage] = None
    technique_id: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.LOW
    confidence: float = Field(..., ge=0, le=1, description="Detection confidence 0-1")
    risk_score: float = Field(..., ge=0, le=100, description="Composite risk score")
    title: str
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommended_action: str = ""


# ─── WebSocket Message Wrapper ─────────────────────────────────

class WSMessage(BaseModel):
    """
    Wrapper for all WebSocket messages. The `type` field tells the
    dashboard which component should handle the payload.
    """
    type: str = Field(..., description="Message type: telemetry|command|alert|risk_score|attack_event|meter_status|system")
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
