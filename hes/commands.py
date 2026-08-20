"""
APT Simulator — HES Command Engine
====================================
Handles meter command operations: connect/disconnect, firmware push,
read-on-demand. All commands are logged for audit and detection.

The command engine integrates with the fleet manager to execute commands
on virtual meters, and with the detection engine which monitors for
anomalous command patterns (e.g., mass disconnect during the Impact stage).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from shared.models import CommandType, MeterCommand

logger = logging.getLogger(__name__)


class CommandEngine:
    """
    Executes and logs commands sent to smart meters through the HES.
    
    Maintains a command log that the detection engine consumes to spot
    anomalous patterns like:
    - Unusual command frequency
    - Mass disconnect commands
    - Commands from unexpected operators
    - Commands at unusual times
    """

    def __init__(self, fleet_manager=None):
        self.fleet_manager = fleet_manager
        self.command_log: list[dict] = []
        self.blocked_commands: list[dict] = []

        # Detection engine can set this to block commands
        self.blocking_enabled = False

    async def execute_command(
        self,
        command_type: str,
        target_meter_id: str,
        operator_id: str,
        parameters: dict = None,
        source_ip: str = "127.0.0.1",
    ) -> MeterCommand:
        """
        Execute a command on a meter.
        
        If blocking is enabled (detection triggered), commands from
        suspicious sessions are rejected.
        """
        parameters = parameters or {}

        command = MeterCommand(
            command_type=CommandType(command_type),
            target_meter_id=target_meter_id,
            operator_id=operator_id,
            parameters=parameters,
        )

        # Check if detection engine is blocking this operator
        if self.blocking_enabled and self._should_block(operator_id, command_type):
            command.success = False
            command.blocked = True
            self.blocked_commands.append(self._log_entry(command, source_ip, blocked=True))
            logger.warning(
                f"COMMAND BLOCKED: {command_type} on {target_meter_id} "
                f"by {operator_id} — detection engine active"
            )
            return command

        # Execute the command on the fleet
        success = False
        if self.fleet_manager:
            meter = self.fleet_manager.get_meter(target_meter_id)
            if meter:
                await meter.handle_command(command_type, parameters)
                success = True
            else:
                logger.warning(f"Meter {target_meter_id} not found")
        else:
            # No fleet manager — just log the command
            success = True

        command.success = success
        self.command_log.append(self._log_entry(command, source_ip))

        logger.info(
            f"COMMAND: {command_type} on {target_meter_id} by {operator_id} "
            f"— {'SUCCESS' if success else 'FAILED'}"
        )
        return command

    async def execute_mass_disconnect(
        self,
        zone: str,
        operator_id: str,
        batch_size: int = 100,
        batch_delay: float = 0.5,
    ) -> dict:
        """
        Execute mass disconnect on all meters in a zone.
        Used by the attacker during the Impact stage.
        
        Returns summary of results.
        """
        if not self.fleet_manager:
            return {"error": "No fleet manager connected"}

        zone_meters = self.fleet_manager.get_meters_by_zone(zone)
        total = len(zone_meters)
        disconnected = 0
        blocked = 0

        for i, meter in enumerate(zone_meters):
            cmd = await self.execute_command(
                command_type="disconnect",
                target_meter_id=meter.meter_id,
                operator_id=operator_id,
            )
            if cmd.blocked:
                blocked += 1
            elif cmd.success:
                disconnected += 1

            # Batch delay to simulate realistic command pacing
            if (i + 1) % batch_size == 0 and i < total - 1:
                await asyncio.sleep(batch_delay)

        result = {
            "zone": zone,
            "total_meters": total,
            "disconnected": disconnected,
            "blocked": blocked,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.warning(f"MASS DISCONNECT zone {zone}: {disconnected}/{total} disconnected, {blocked} blocked")
        return result

    # ─── Blocking Logic ────────────────────────────────────────

    _blocked_operators: set[str] = set()

    def block_operator(self, operator_id: str):
        """Block all commands from a specific operator (called by detection engine)."""
        self._blocked_operators.add(operator_id)
        self.blocking_enabled = True
        logger.warning(f"OPERATOR BLOCKED: {operator_id}")

    def unblock_operator(self, operator_id: str):
        """Remove an operator block."""
        self._blocked_operators.discard(operator_id)
        if not self._blocked_operators:
            self.blocking_enabled = False

    def _should_block(self, operator_id: str, command_type: str) -> bool:
        """Check if a command should be blocked."""
        # Block if operator is on the blocked list
        if operator_id in self._blocked_operators:
            return True
        # Block mass disconnect attempts when blocking is enabled
        if self.blocking_enabled and command_type == "disconnect":
            return True
        return False

    # ─── Logging ───────────────────────────────────────────────

    @staticmethod
    def _log_entry(command: MeterCommand, source_ip: str, blocked: bool = False) -> dict:
        """Create a structured log entry for a command."""
        return {
            "command_id": command.command_id,
            "timestamp": command.timestamp.isoformat(),
            "command_type": command.command_type.value,
            "target_meter_id": command.target_meter_id,
            "operator_id": command.operator_id,
            "parameters": command.parameters,
            "success": command.success,
            "blocked": blocked,
            "source_ip": source_ip,
        }

    def get_command_log(self) -> list[dict]:
        """Return the full command log."""
        return list(self.command_log)

    def get_recent_commands(self, window_seconds: int = 300) -> list[dict]:
        """Return commands in the last N seconds."""
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        return [
            entry for entry in self.command_log
            if datetime.fromisoformat(entry["timestamp"]).timestamp() > cutoff
        ]

    def get_command_rate(self, window_seconds: int = 60) -> float:
        """Return commands per minute in the last N seconds."""
        recent = self.get_recent_commands(window_seconds)
        return len(recent) * 60.0 / max(window_seconds, 1)
