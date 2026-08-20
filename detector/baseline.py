"""
APT Simulator — Behavioral Baselining Module
==============================================
Builds normal-behavior profiles from a "clean" simulation run.
These profiles define what legitimate activity looks like, so the
anomaly scorer can identify deviations during an attack.

Baseline features:
- Login patterns (time of day, frequency)
- Command patterns (type distribution, rate per operator)
- Telemetry patterns (per-meter mean/std of consumption metrics)
- Communication graph (which operators access which services)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from shared import config

logger = logging.getLogger(__name__)


class BaselineManager:
    """
    Builds and stores behavioral baselines for the detection engine.
    
    The baseline represents 'normal' — any deviation is a potential
    anomaly signal. Features are aggregated in time windows and
    stored as numpy arrays.
    """

    def __init__(self, baseline_dir: Path = None):
        self.baseline_dir = baseline_dir or config.BASELINE_DIR
        self.is_trained = False

        # Baseline data stores
        self.login_baseline: dict[str, Any] = {
            "typical_hours": list(range(8, 18)),  # 8 AM - 6 PM
            "max_failures_per_window": 3,
            "known_operators": {"operator1", "admin"},
            "known_ips": {"127.0.0.1"},
        }

        self.command_baseline: dict[str, Any] = {
            "max_commands_per_minute": 5.0,
            "typical_command_types": {"connect", "disconnect", "read_on_demand"},
            "max_disconnect_batch": 10,  # Legitimate maintenance rarely disconnects more than 10
        }

        self.telemetry_baseline: dict[str, dict] = {}
        # Per-meter: {"mean_voltage": X, "std_voltage": Y, ...}

        self.communication_graph_edges: set[tuple[str, str]] = {
            # Known legitimate edges: (source, target)
            ("operator1", "HES"),
            ("admin", "HES"),
            ("HES", "MDMS"),
        }

        # Telemetry interval baselines
        self.known_intervals: dict[str, float] = {}
        # meter_id -> expected interval in seconds

    def train_from_clean_data(
        self,
        login_log: list[dict] = None,
        command_log: list[dict] = None,
        telemetry_samples: list[dict] = None,
    ):
        """
        Train the baseline from clean simulation data.
        
        In practice, this would run during a 'clean' period before
        introducing the attacker. For the demo, we use reasonable
        defaults augmented with any provided data.
        """
        logger.info("Training baseline from clean data...")

        if login_log:
            successful_logins = [l for l in login_log if l.get("success")]
            if successful_logins:
                hours = [
                    datetime.fromisoformat(l["timestamp"]).hour
                    for l in successful_logins
                ]
                self.login_baseline["typical_hours"] = list(set(hours))
                self.login_baseline["known_operators"] = {
                    l["username"] for l in successful_logins
                }

        if command_log:
            if command_log:
                # Calculate typical command rate
                rates = []
                # Simple: count per 60-second window
                self.command_baseline["max_commands_per_minute"] = max(
                    5.0, len(command_log) / max(1, len(command_log) // 10)
                )

        if telemetry_samples:
            # Group by meter and calculate statistics
            meter_data: dict[str, list[dict]] = {}
            for sample in telemetry_samples:
                mid = sample.get("meter_id", "")
                if mid not in meter_data:
                    meter_data[mid] = []
                meter_data[mid].append(sample)

            for meter_id, samples in meter_data.items():
                voltages = [s.get("voltage", 230) for s in samples]
                currents = [s.get("current", 1) for s in samples]
                self.telemetry_baseline[meter_id] = {
                    "mean_voltage": float(np.mean(voltages)),
                    "std_voltage": float(np.std(voltages)),
                    "mean_current": float(np.mean(currents)),
                    "std_current": float(np.std(currents)),
                }

        self.is_trained = True
        self.save()
        logger.info(f"Baseline trained: {len(self.login_baseline['known_operators'])} operators, "
                     f"{len(self.telemetry_baseline)} meter profiles")

    def save(self):
        """Persist baseline to disk."""
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "login_baseline": {
                **self.login_baseline,
                "known_operators": list(self.login_baseline["known_operators"]),
                "known_ips": list(self.login_baseline["known_ips"]),
            },
            "command_baseline": {
                **self.command_baseline,
                "typical_command_types": list(self.command_baseline["typical_command_types"]),
            },
            "communication_graph_edges": [list(e) for e in self.communication_graph_edges],
            "is_trained": True,
        }
        path = self.baseline_dir / "baseline.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Baseline saved to {path}")

    def load(self) -> bool:
        """Load baseline from disk. Returns True if loaded."""
        path = self.baseline_dir / "baseline.json"
        if not path.exists():
            logger.info("No baseline file found, using defaults")
            self.is_trained = True  # Use default baseline
            return False

        with open(path) as f:
            data = json.load(f)

        self.login_baseline = data.get("login_baseline", self.login_baseline)
        self.login_baseline["known_operators"] = set(self.login_baseline.get("known_operators", []))
        self.login_baseline["known_ips"] = set(self.login_baseline.get("known_ips", []))

        self.command_baseline = data.get("command_baseline", self.command_baseline)
        self.command_baseline["typical_command_types"] = set(
            self.command_baseline.get("typical_command_types", [])
        )

        edges = data.get("communication_graph_edges", [])
        self.communication_graph_edges = {tuple(e) for e in edges}

        self.is_trained = True
        logger.info("Baseline loaded from disk")
        return True

    def is_login_anomalous(self, login_event: dict) -> tuple[bool, list[str]]:
        """Check if a login event is anomalous against the baseline."""
        reasons = []

        username = login_event.get("username", "")
        success = login_event.get("success", False)

        # Unknown username
        if username not in self.login_baseline["known_operators"]:
            reasons.append(f"Unknown operator: {username}")

        # Failed login (individual failures are weak signals)
        if not success:
            reasons.append(f"Failed login for {username}")

        return len(reasons) > 0, reasons

    def is_command_anomalous(self, command_event: dict) -> tuple[bool, list[str]]:
        """Check if a command event is anomalous."""
        reasons = []

        cmd_type = command_event.get("command_type", "")
        operator = command_event.get("operator_id", "")

        # Unknown operator issuing commands
        if operator and operator not in {"OP-001", "OP-ADMIN"}:
            reasons.append(f"Unknown operator: {operator}")

        return len(reasons) > 0, reasons

    def is_edge_anomalous(self, source: str, target: str) -> bool:
        """Check if a communication edge exists in the baseline graph."""
        return (source, target) not in self.communication_graph_edges
