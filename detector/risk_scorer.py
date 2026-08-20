"""
APT Simulator — Composite Risk Scorer
=======================================
The heart of the detection engine: combines multiple weak signals
from the anomaly scorer, graph detector, and beacon detector into
a single rolling risk score (0-100).

KEY DESIGN PRINCIPLE: No single signal can push the risk above 40.
The alert threshold is 65, so multi-signal correlation is REQUIRED.
This realistically models how APTs evade single-signal detection.

Signal weights:
- Isolation Forest anomaly score: 0.30
- Graph anomaly (new edges):     0.25
- Beacon detection:              0.20
- Login anomalies:               0.15
- Mass command anomaly:          0.10
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

from shared import config
from shared.models import AlertSeverity, AttackStage, DetectionAlert

logger = logging.getLogger(__name__)

# Signal contribution caps — no single signal exceeds 40
SIGNAL_CAPS = {
    "isolation_forest": 35,
    "graph_anomaly": 30,
    "beacon_detection": 25,
    "login_anomaly": 20,
    "mass_command": 25,
}

# Signal weights
SIGNAL_WEIGHTS = {
    "isolation_forest": 0.30,
    "graph_anomaly": 0.25,
    "beacon_detection": 0.20,
    "login_anomaly": 0.15,
    "mass_command": 0.10,
}


class RiskScorer:
    """
    Composite risk scoring engine.
    
    Combines multiple weak detection signals into a single risk
    score that rises over time as more signals correlate. Decays
    naturally when signals stop.
    """

    def __init__(
        self,
        alert_threshold: float = None,
        block_threshold: float = None,
    ):
        self.alert_threshold = alert_threshold or config.RISK_ALERT_THRESHOLD
        self.block_threshold = block_threshold or config.RISK_BLOCK_THRESHOLD

        # Current signal values (0-100 each, before cap)
        self.signals: dict[str, float] = {
            "isolation_forest": 0,
            "graph_anomaly": 0,
            "beacon_detection": 0,
            "login_anomaly": 0,
            "mass_command": 0,
        }

        # Risk score history for timeline visualization
        self.risk_history: deque[dict] = deque(maxlen=500)

        # Alert history
        self.alerts: list[DetectionAlert] = []

        # Detection state
        self.detection_enabled = True
        self.has_alerted = False
        self.has_blocked = False

        # Decay timing
        self._last_update = time.time()
        self._decay_rate = 2.0  # Points per second of decay

        # Block callback (called when risk > block_threshold)
        self._block_callback = None

        # Alert callback (called when a new alert is generated)
        self._alert_callback = None

    @property
    def current_risk(self) -> float:
        """Calculate the current composite risk score."""
        total = 0.0
        for signal_name, raw_value in self.signals.items():
            cap = SIGNAL_CAPS.get(signal_name, 30)
            capped = min(raw_value, cap)
            weight = SIGNAL_WEIGHTS.get(signal_name, 0.1)
            total += capped * weight / 0.3  # Normalize so full contribution ≈ cap

        # Final clamp
        return min(100, max(0, total))

    def set_block_callback(self, callback):
        """Register callback for when blocking is triggered."""
        self._block_callback = callback

    def set_alert_callback(self, callback):
        """Register callback for when an alert is generated."""
        self._alert_callback = callback

    def update_signal(self, signal_name: str, value: float, evidence: dict = None):
        """
        Update a specific signal value.
        
        Args:
            signal_name: One of the signal names in SIGNAL_WEIGHTS
            value:       New value for this signal (0-100)
            evidence:    Supporting evidence dict
        """
        if signal_name not in self.signals:
            logger.warning(f"Unknown signal: {signal_name}")
            return

        old_value = self.signals[signal_name]
        # Signals accumulate — take the max of old and new
        self.signals[signal_name] = max(old_value, value)

        # Record in history
        risk = self.current_risk
        self.risk_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": round(risk, 2),
            "signals": dict(self.signals),
            "trigger_signal": signal_name,
        })

        # Check thresholds
        if self.detection_enabled:
            self._check_thresholds(risk, signal_name, evidence or {})

        self._last_update = time.time()

    def apply_decay(self):
        """Apply time-based decay to all signals."""
        now = time.time()
        self._last_update = now
        # Decay logic completely removed as per requirements. 
        # Risk score is now monotonically non-decreasing and freezes at its terminal value until explicitly reset.

    def _check_thresholds(self, risk: float, trigger_signal: str, evidence: dict):
        """Check if risk score crosses alert/block thresholds."""
        # Alert threshold
        if risk >= self.alert_threshold and not self.has_alerted:
            self.has_alerted = True
            alert = DetectionAlert(
                stage=self._infer_stage(trigger_signal),
                technique_id=self._infer_technique(trigger_signal),
                severity=AlertSeverity.HIGH,
                confidence=min(1.0, risk / 100),
                risk_score=risk,
                title="APT Attack Detected — Multi-Signal Correlation",
                description=(
                    f"Composite risk score ({risk:.1f}) exceeded alert threshold "
                    f"({self.alert_threshold}). Multiple anomalous signals detected: "
                    f"{', '.join(s for s, v in self.signals.items() if v > 5)}"
                ),
                evidence=[
                    {"signal": s, "value": round(v, 2)}
                    for s, v in self.signals.items() if v > 0
                ],
                recommended_action="Investigate operator sessions and isolate compromised accounts",
            )
            self.alerts.append(alert)
            logger.warning(f"🚨 ALERT: Risk score {risk:.1f} — APT attack detected!")
            if self._alert_callback:
                try:
                    self._alert_callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

        # Block threshold
        if risk >= self.block_threshold and not self.has_blocked:
            self.has_blocked = True
            alert = DetectionAlert(
                stage=AttackStage.IMPACT,
                technique_id="T0826",
                severity=AlertSeverity.CRITICAL,
                confidence=min(1.0, risk / 100),
                risk_score=risk,
                title="APT Attack BLOCKED — Automated Response Triggered",
                description=(
                    f"Composite risk score ({risk:.1f}) exceeded block threshold "
                    f"({self.block_threshold}). Blocking compromised operator sessions "
                    f"and preventing further meter commands."
                ),
                evidence=[
                    {"signal": s, "value": round(v, 2)}
                    for s, v in self.signals.items() if v > 0
                ],
                recommended_action="Review blocked commands and revoke compromised credentials",
            )
            self.alerts.append(alert)
            logger.warning(f"🛡️ BLOCK: Risk score {risk:.1f} — automated response triggered!")
            if self._alert_callback:
                try:
                    self._alert_callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

            # Execute block callback
            if self._block_callback:
                try:
                    self._block_callback()
                except Exception as e:
                    logger.error(f"Block callback error: {e}")

    @staticmethod
    def _infer_stage(signal_name: str) -> AttackStage:
        """Infer the most likely attack stage from the signal name."""
        mapping = {
            "login_anomaly": AttackStage.INITIAL_ACCESS,
            "graph_anomaly": AttackStage.LATERAL_MOVEMENT,
            "beacon_detection": AttackStage.COMMAND_CONTROL,
            "mass_command": AttackStage.IMPACT,
            "isolation_forest": AttackStage.LATERAL_MOVEMENT,
        }
        return mapping.get(signal_name, AttackStage.RECONNAISSANCE)

    @staticmethod
    def _infer_technique(signal_name: str) -> str:
        """Infer the most likely MITRE technique from the signal name."""
        mapping = {
            "login_anomaly": "T0859",
            "graph_anomaly": "T0886",
            "beacon_detection": "T0869",
            "mass_command": "T0826",
            "isolation_forest": "T0886",
        }
        return mapping.get(signal_name, "T0846")

    # ─── State Management ─────────────────────────────────────

    def toggle_detection(self, enabled: bool):
        """Enable or disable detection (for demo toggle)."""
        self.detection_enabled = enabled
        if not enabled:
            logger.info("Detection DISABLED")
        else:
            logger.info("Detection ENABLED")

    def reset(self):
        """Reset all scores and state."""
        for key in self.signals:
            self.signals[key] = 0
        self.risk_history.clear()
        self.alerts.clear()
        self.has_alerted = False
        self.has_blocked = False
        self._last_update = time.time()

    def get_state(self) -> dict:
        """Return current scorer state for dashboard."""
        risk = self.current_risk
        return {
            "risk_score": round(risk, 2),
            "signals": {k: round(v, 2) for k, v in self.signals.items()},
            "alert_threshold": self.alert_threshold,
            "block_threshold": self.block_threshold,
            "has_alerted": self.has_alerted,
            "has_blocked": self.has_blocked,
            "detection_enabled": self.detection_enabled,
            "alert_count": len(self.alerts),
        }

    def get_alerts(self) -> list[dict]:
        """Return all alerts as serializable dicts."""
        return [a.model_dump(mode="json") for a in self.alerts]

    def get_risk_history(self, count: int = 100) -> list[dict]:
        """Return recent risk score history."""
        return list(self.risk_history)[-count:]
