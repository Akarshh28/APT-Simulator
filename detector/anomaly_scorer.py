"""
APT Simulator — Isolation Forest Anomaly Scorer
=================================================
Uses scikit-learn's Isolation Forest to detect anomalous patterns
in time-windowed feature vectors derived from HES/MDMS telemetry
and command data.

Feature vector (per 30-second window):
- login_failure_rate
- new_account_count
- command_rate (normalized vs baseline)
- cross_service_auth_count
- unusual_api_access_count
- telemetry_volume_deviation
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class AnomalyScorer:
    """
    Isolation Forest-based anomaly scorer.
    
    Collects features in rolling windows and scores each window
    for anomalousness. Higher scores (closer to -1 from the IF
    output) indicate more anomalous behavior.
    
    The scorer is trained on baseline (clean) data and produces
    scores on live data during the attack simulation.
    """

    def __init__(self, window_seconds: float = 30.0):
        self.window_seconds = window_seconds

        # Isolation Forest model
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expect ~10% anomalous (generous for demo)
            random_state=42,
        )
        self.is_trained = False

        # Feature accumulators (reset each window)
        self._current_window_start = datetime.now(timezone.utc)
        self._features = self._empty_features()

        # Historical feature vectors for training
        self._training_data: list[list[float]] = []

        # Recent scores for visualization
        self.score_history: deque[dict] = deque(maxlen=200)

    @staticmethod
    def _empty_features() -> dict:
        """Return a fresh feature accumulator."""
        return {
            "login_failures": 0,
            "login_successes": 0,
            "new_accounts": 0,
            "commands_issued": 0,
            "disconnect_commands": 0,
            "cross_service_auths": 0,
            "unusual_api_accesses": 0,
            "telemetry_count": 0,
            "unknown_meter_ids": 0,
        }

    def _features_to_vector(self, features: dict) -> list[float]:
        """Convert feature dict to a numeric vector for the model."""
        total_logins = features["login_failures"] + features["login_successes"]
        login_failure_rate = (
            features["login_failures"] / max(1, total_logins)
        )

        return [
            login_failure_rate,
            features["new_accounts"],
            features["commands_issued"],
            features["disconnect_commands"],
            features["cross_service_auths"],
            features["unusual_api_accesses"],
            features["unknown_meter_ids"],
        ]

    # ─── Event Ingestion ──────────────────────────────────────

    def ingest_login_event(self, event: dict):
        """Record a login event in the current window."""
        if event.get("success"):
            self._features["login_successes"] += 1
        else:
            self._features["login_failures"] += 1

    def ingest_account_creation(self):
        """Record an account creation event."""
        self._features["new_accounts"] += 1

    def ingest_command(self, event: dict):
        """Record a command event."""
        self._features["commands_issued"] += 1
        if event.get("command_type") == "disconnect":
            self._features["disconnect_commands"] += 1

    def ingest_cross_service_auth(self):
        """Record a cross-service authentication."""
        self._features["cross_service_auths"] += 1

    def ingest_unusual_api_access(self):
        """Record an unusual API access pattern."""
        self._features["unusual_api_accesses"] += 1

    def ingest_unknown_meter(self):
        """Record telemetry from an unknown meter ID."""
        self._features["unknown_meter_ids"] += 1

    def ingest_telemetry(self):
        """Record a telemetry reading."""
        self._features["telemetry_count"] += 1

    # ─── Window Management & Scoring ──────────────────────────

    def check_window(self) -> dict | None:
        """
        Check if the current window has elapsed. If so, score it
        and start a new window.
        
        Returns the scored window result, or None if window hasn't elapsed.
        """
        now = datetime.now(timezone.utc)
        elapsed = (now - self._current_window_start).total_seconds()

        if elapsed < self.window_seconds:
            return None

        # Window complete — score it
        vector = self._features_to_vector(self._features)
        score = self.score_vector(vector)

        result = {
            "timestamp": now.isoformat(),
            "window_start": self._current_window_start.isoformat(),
            "features": dict(self._features),
            "anomaly_score": score,
            "is_anomalous": score > 0.5,
        }

        self.score_history.append(result)

        # Reset window
        self._current_window_start = now
        self._features = self._empty_features()

        return result

    def score_vector(self, vector: list[float]) -> float:
        """
        Score a feature vector for anomalousness.
        
        Returns:
            Anomaly score between 0 (normal) and 1 (highly anomalous)
        """
        if sum(vector) == 0.0:
            return 0.0  # Zero activity is completely normal

        if not self.is_trained:
            # Use heuristic scoring before model is trained
            return self._heuristic_score(vector)

        try:
            X = np.array([vector])
            # Isolation Forest returns -1 for anomaly, 1 for normal
            raw_score = self.model.decision_function(X)[0]
            # Convert to 0-1 scale (lower decision function = more anomalous)
            normalized = max(0, min(1, 0.5 - raw_score))
            return float(normalized)
        except Exception as e:
            logger.error(f"Scoring error: {e}")
            return self._heuristic_score(vector)

    def _heuristic_score(self, vector: list[float]) -> float:
        """
        Fallback heuristic scoring when model isn't trained.
        
        This is a simple rule-based scorer that produces reasonable
        anomaly signals based on known attack patterns.
        """
        score = 0.0
        (login_failure_rate, new_accounts, commands, disconnects,
         cross_service, unusual_api, unknown_meters) = vector

        # Login failure rate (credential stuffing signal)
        if login_failure_rate > 0.5:
            score += 0.15
        if login_failure_rate > 0.8:
            score += 0.10

        # New account creation (persistence signal)
        if new_accounts > 0:
            score += 0.20 * min(new_accounts, 3)

        # High disconnect rate (impact signal)
        if disconnects > 10:
            score += 0.25
        elif disconnects > 5:
            score += 0.15

        # Cross-service auth (lateral movement signal)
        if cross_service > 0:
            score += 0.15 * min(cross_service, 3)

        # Unusual API access
        if unusual_api > 0:
            score += 0.10 * min(unusual_api, 3)

        # Unknown meter IDs (beacon signal)
        if unknown_meters > 0:
            score += 0.10

        return min(1.0, score)

    # ─── Training ─────────────────────────────────────────────

    def add_training_sample(self, vector: list[float]):
        """Add a feature vector from clean data for training."""
        self._training_data.append(vector)

    def train(self):
        """Train the Isolation Forest on collected clean data."""
        if len(self._training_data) < 10:
            # Not enough data — generate synthetic clean data
            logger.info("Generating synthetic clean training data...")
            for _ in range(100):
                self._training_data.append([
                    np.random.uniform(0, 0.2),    # Low login failure rate
                    0,                             # No new accounts
                    np.random.uniform(0, 3),       # Low command rate
                    np.random.uniform(0, 1),       # Very few disconnects
                    0,                             # No cross-service auth
                    0,                             # No unusual API access
                    0,                             # No unknown meters
                ])

        X = np.array(self._training_data)
        self.model.fit(X)
        self.is_trained = True
        logger.info(f"Anomaly scorer trained on {len(self._training_data)} samples")

    def get_recent_scores(self, count: int = 50) -> list[dict]:
        """Return recent anomaly scores for visualization."""
        return list(self.score_history)[-count:]
