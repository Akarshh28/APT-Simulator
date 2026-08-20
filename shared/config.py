"""
APT Simulator — Central Configuration
======================================
Loads all configuration from environment variables with sensible defaults.
All services import from here to stay in sync.
"""

import os
from pathlib import Path

# ─── Project Root ──────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ─── MQTT Broker ───────────────────────────────────────────────
MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "localhost")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", "1883"))

# ─── Service URLs / Ports ──────────────────────────────────────
HES_HOST = os.getenv("HES_HOST", "localhost")
HES_PORT = int(os.getenv("HES_PORT", "8001"))
HES_URL = f"http://{HES_HOST}:{HES_PORT}"

MDMS_HOST = os.getenv("MDMS_HOST", "localhost")
MDMS_PORT = int(os.getenv("MDMS_PORT", "8002"))
MDMS_URL = f"http://{MDMS_HOST}:{MDMS_PORT}"

DETECTOR_HOST = os.getenv("DETECTOR_HOST", "localhost")
DETECTOR_PORT = int(os.getenv("DETECTOR_PORT", "8003"))
DETECTOR_URL = f"http://{DETECTOR_HOST}:{DETECTOR_PORT}"

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "3000"))

# ─── Simulation ────────────────────────────────────────────────
METER_COUNT = int(os.getenv("METER_COUNT", "500"))
TELEMETRY_INTERVAL_SECONDS = int(os.getenv("TELEMETRY_INTERVAL_SECONDS", "15"))
SIMULATION_SPEED = float(os.getenv("SIMULATION_SPEED", "1.0"))

# ─── Database ──────────────────────────────────────────────────
MDMS_DB_PATH = PROJECT_ROOT / os.getenv("MDMS_DB_PATH", "data/mdms.db")

# ─── Attack Event Log ─────────────────────────────────────────
ATTACK_LOG_PATH = PROJECT_ROOT / os.getenv("ATTACK_LOG_PATH", "data/attack_events.jsonl")

# ─── Baseline Model ───────────────────────────────────────────
BASELINE_DIR = PROJECT_ROOT / os.getenv("BASELINE_DIR", "data/baseline")

# ─── Detection ─────────────────────────────────────────────────
DETECTION_ENABLED = os.getenv("DETECTION_ENABLED", "true").lower() == "true"
RISK_ALERT_THRESHOLD = float(os.getenv("RISK_ALERT_THRESHOLD", "65"))
RISK_BLOCK_THRESHOLD = float(os.getenv("RISK_BLOCK_THRESHOLD", "75"))

# ─── Synthetic City Grid ──────────────────────────────────────
# Bounding box for our synthetic city (loosely based on Kanpur coords)
CITY_LAT_MIN = 26.40
CITY_LAT_MAX = 26.50
CITY_LNG_MIN = 80.30
CITY_LNG_MAX = 80.40

# Zones divide the city into 6 sectors
ZONES = ["A", "B", "C", "D", "E", "F"]

# ─── JWT Secret (intentionally weak for demo) ─────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "apt-sim-demo-secret-key-not-for-production")
JWT_ALGORITHM = "HS256"

# ─── Ensure data directories exist ────────────────────────────
def ensure_data_dirs():
    """Create runtime data directories if they don't exist."""
    MDMS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
