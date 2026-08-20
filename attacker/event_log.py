"""
APT Simulator — Attack Event Logger
=====================================
Structured JSON-lines event logger for the attack engine.
Writes to both a persistent file and pushes events to the
detector/dashboard via WebSocket.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared import config
from shared.models import AttackEvent, AttackStage

logger = logging.getLogger(__name__)


class EventLog:
    """
    Structured attack event logger.
    
    Writes JSON-lines to data/attack_events.jsonl and provides
    in-memory access for the detector and dashboard.
    """

    def __init__(self, log_path: Path = None):
        self.log_path = log_path or config.ATTACK_LOG_PATH
        self.events: list[AttackEvent] = []
        self._ws_callback = None  # Set by engine to broadcast events

    def initialize(self):
        """Ensure log file directory exists and clear previous log."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Clear previous run's log
        with open(self.log_path, "w") as f:
            pass
        logger.info(f"Attack event log initialized: {self.log_path}")

    async def log_event(
        self,
        stage: AttackStage,
        technique_id: str,
        tactic: str,
        target: str,
        action: str,
        details: dict[str, Any] = None,
        success: bool = True,
        source: str = "attacker",
    ) -> AttackEvent:
        """
        Log a structured attack event.
        
        Writes to file, stores in memory, and broadcasts via callback.
        """
        event = AttackEvent(
            timestamp=datetime.now(timezone.utc),
            stage=stage,
            technique_id=technique_id,
            tactic=tactic,
            source=source,
            target=target,
            action=action,
            details=details or {},
            success=success,
        )

        # Store in memory
        self.events.append(event)

        # Write to file
        try:
            with open(self.log_path, "a") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception as e:
            logger.error(f"Failed to write event log: {e}")

        # Broadcast via callback if registered
        if self._ws_callback:
            try:
                await self._ws_callback(event)
            except Exception as e:
                logger.error(f"Failed to broadcast event: {e}")

        logger.info(
            f"ATTACK EVENT: [{event.stage.value}] {event.technique_id} — {event.action} "
            f"({'SUCCESS' if event.success else 'FAILED'})"
        )

        return event

    def set_ws_callback(self, callback):
        """Register a callback for WebSocket broadcasting."""
        self._ws_callback = callback

    def get_events(self, stage: AttackStage = None) -> list[AttackEvent]:
        """Get events, optionally filtered by stage."""
        if stage:
            return [e for e in self.events if e.stage == stage]
        return list(self.events)

    def get_events_as_dicts(self) -> list[dict]:
        """Get all events as serializable dicts."""
        return [e.model_dump(mode="json") for e in self.events]

    def clear(self):
        """Clear all events (for scenario reset)."""
        self.events.clear()
        if self.log_path.exists():
            with open(self.log_path, "w") as f:
                pass
