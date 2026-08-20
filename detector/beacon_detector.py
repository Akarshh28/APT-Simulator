"""
APT Simulator — Low-and-Slow Beacon Detector
==============================================
Detects covert C2 beaconing by analyzing the interval patterns of
meter telemetry. Legitimate meters publish at ~15-second intervals;
the attacker's beacon uses a ~47-second interval.

Detection methods:
1. Interval mean analysis: flag meters with intervals far from known profiles
2. Coefficient of variation: beacons have deliberately irregular timing
3. Autocorrelation: detect the periodicity of beacon traffic
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict, deque
from datetime import datetime, timezone

import numpy as np

logger = logging.getLogger(__name__)

# Known legitimate polling intervals (seconds)
LEGITIMATE_INTERVALS = {15.0, 30.0, 60.0, 300.0}
INTERVAL_TOLERANCE = 5.0  # ± tolerance in seconds


class BeaconDetector:
    """
    Detects low-and-slow beacon traffic hidden in meter telemetry.
    
    For each meter, tracks inter-arrival times and uses statistical
    analysis to distinguish legitimate polling from C2 beaconing.
    """

    def __init__(self, min_samples: int = 5, window_size: int = 50):
        self.min_samples = min_samples
        self.window_size = window_size

        # Per-meter timestamp tracking
        self._timestamps: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

        # Detection results
        self.suspected_beacons: dict[str, dict] = {}
        self.cleared_meters: set[str] = set()

    def record_telemetry(self, meter_id: str, timestamp: float = None) -> dict | None:
        """
        Record a telemetry timestamp for a meter and check for beaconing.
        
        Returns a detection result if beaconing is suspected, None otherwise.
        """
        ts = timestamp or datetime.now(timezone.utc).timestamp()
        self._timestamps[meter_id].append(ts)

        # Need at least min_samples to analyze
        if len(self._timestamps[meter_id]) < self.min_samples:
            return None

        # Calculate inter-arrival times
        timestamps = list(self._timestamps[meter_id])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if not intervals:
            return None

        result = self._analyze_intervals(meter_id, intervals)

        if result and result["is_beacon"]:
            self.suspected_beacons[meter_id] = result
            logger.warning(
                f"BEACON DETECTED: meter {meter_id} — "
                f"mean interval {result['mean_interval']:.1f}s, "
                f"confidence {result['confidence']:.2f}"
            )
            return result

        return None

    def _analyze_intervals(self, meter_id: str, intervals: list[float]) -> dict | None:
        """
        Analyze inter-arrival intervals for beaconing patterns.
        
        Returns detection result dict or None.
        """
        arr = np.array(intervals)
        mean_interval = float(np.mean(arr))
        std_interval = float(np.std(arr))
        cv = std_interval / mean_interval if mean_interval > 0 else 0

        # Check 1: Does the mean interval match any known legitimate interval?
        matches_legitimate = any(
            abs(mean_interval - legit) < INTERVAL_TOLERANCE
            for legit in LEGITIMATE_INTERVALS
        )

        if matches_legitimate:
            return None

        # Check 2: Beacon detection — interval is consistent but unusual
        confidence = 0.0
        reasons = []

        # Non-standard interval
        if not matches_legitimate and mean_interval > 10:
            confidence += 0.3
            reasons.append(f"Non-standard interval: {mean_interval:.1f}s")

        # Check periodicity via autocorrelation (simplified)
        if len(arr) >= 5:
            # Normalize
            norm = arr - np.mean(arr)
            if np.std(norm) > 0:
                autocorr_1 = float(np.correlate(norm[:-1], norm[1:])[0] / (np.std(norm) ** 2 * (len(norm) - 1)))
                if abs(autocorr_1) > 0.3:
                    confidence += 0.2
                    reasons.append(f"High autocorrelation: {autocorr_1:.3f}")

        # Check for deliberate jitter (non-zero but bounded variance)
        if 0.05 < cv < 0.3:
            confidence += 0.2
            reasons.append(f"Deliberate jitter pattern: CV={cv:.3f}")

        # Check for non-standard zone (our beacon uses zone "X")
        if meter_id.startswith("SM-X"):
            confidence += 0.15
            reasons.append(f"Non-standard zone in meter ID: {meter_id}")

        # Is it a beacon?
        is_beacon = confidence >= 0.4

        if confidence > 0.2:
            return {
                "meter_id": meter_id,
                "is_beacon": is_beacon,
                "confidence": min(1.0, confidence),
                "mean_interval": mean_interval,
                "std_interval": std_interval,
                "cv": cv,
                "sample_count": len(intervals),
                "reasons": reasons,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        return None

    def get_suspected_beacons(self) -> list[dict]:
        """Return all currently suspected beacon meters."""
        return list(self.suspected_beacons.values())

    def get_summary(self) -> dict:
        """Return detection summary."""
        return {
            "meters_tracked": len(self._timestamps),
            "suspected_beacons": len(self.suspected_beacons),
            "beacon_ids": list(self.suspected_beacons.keys()),
        }

    def reset(self):
        """Reset all tracking data."""
        self._timestamps.clear()
        self.suspected_beacons.clear()
        self.cleared_meters.clear()
