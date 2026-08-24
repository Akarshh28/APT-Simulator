"""
APT Simulator — Attack Engine Orchestrator
============================================
Orchestrates the full APT kill-chain by running attack stages in
sequence (or individually). Loads scenario configuration from YAML,
manages timing and stage transitions, and coordinates with the
event logger for real-time dashboard updates.

This is the entry point for running attack simulations.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from shared import config
from shared.models import AttackStage, WSMessage

from .event_log import EventLog
from .stages import (
    recon,
    physical_tamper,
    initial_access,
    persistence,
    lateral_movement,
    command_control,
    impact,
    benign_activity,
)

logger = logging.getLogger(__name__)


class AttackEngine:
    """
    Orchestrates the full APT attack simulation.

    Supports:
    - Running the complete kill-chain from a scenario YAML
    - Running individual stages for demo/testing
    - Pausing, resuming, and speed control
    - Broadcasting stage progress to the dashboard
    """

    STAGE_MODULES = {
        AttackStage.RECONNAISSANCE: recon,
        AttackStage.PHYSICAL_TAMPER: physical_tamper,
        AttackStage.INITIAL_ACCESS: initial_access,
        AttackStage.PERSISTENCE: persistence,
        AttackStage.LATERAL_MOVEMENT: lateral_movement,
        AttackStage.COMMAND_CONTROL: command_control,
        AttackStage.IMPACT: impact,
        AttackStage.BENIGN_ACTIVITY: benign_activity,
    }

    def __init__(self, scenario_path: str = None):
        self.event_log = EventLog()
        self.scenario: dict = {}
        self.scenario_path = scenario_path

        # State tracking
        self.current_stage: Optional[AttackStage] = None
        self.stage_results: dict[str, Any] = {}
        self.is_running = False
        self.is_paused = False
        self.speed_multiplier = 1.0

        # Shared state across stages
        self._credentials: dict = {}

        # WebSocket broadcast callback
        self._ws_broadcast = None
        
        # Callback to check if detection has blocked the attack
        self._is_blocked_cb = None

        # Callback for when a new stage becomes active
        self._stage_cb = None

    def set_is_blocked_cb(self, callback):
        """Register a callback to check if the attack is blocked by detection."""
        self._is_blocked_cb = callback

    def set_stage_cb(self, callback):
        """Register a callback for when a stage becomes active."""
        self._stage_cb = callback

    def load_scenario(self, scenario_path: str = None) -> dict:
        """Load attack scenario from YAML file."""
        path = scenario_path or self.scenario_path
        if not path:
            # Use default scenario
            default_path = config.PROJECT_ROOT / "scenarios" / "default_apt.yaml"
            if default_path.exists():
                path = str(default_path)
            else:
                logger.warning("No scenario file found, using built-in defaults")
                self.scenario = self._default_scenario()
                return self.scenario

        with open(path, "r") as f:
            self.scenario = yaml.safe_load(f)

        logger.info(f"Loaded scenario: {self.scenario.get('name', 'unnamed')}")
        self.validate_scenarios()
        return self.scenario

    @classmethod
    def validate_scenarios(cls):
        """Dev-only safety check to ensure scenarios are genuinely distinct."""
        import glob
        scenario_dir = config.PROJECT_ROOT / "scenarios"
        seen_signatures = {}
        for yaml_file in glob.glob(str(scenario_dir / "*.yaml")):
            try:
                with open(yaml_file, "r") as f:
                    scen = yaml.safe_load(f)
                    name = scen.get("name", Path(yaml_file).stem)
                    graph_config = scen.get("graph_config", {})
                    origin = graph_config.get("origin", "external")
                    compromised = graph_config.get("compromised_identity", "operator1")
                    stages = tuple(s.get("name") for s in scen.get("stages", []))
                    
                    sig = (origin, compromised, stages)
                    if sig in seen_signatures:
                        logger.warning(
                            f"\n[SAFETY WARNING] Scenarios '{name}' and '{seen_signatures[sig]}' "
                            f"share the exact same structural signature:\n"
                            f"  Origin: {origin}\n"
                            f"  Identity: {compromised}\n"
                            f"  Stages: {stages}\n"
                            f"Please differentiate them to ensure the demo is credible!"
                        )
                    else:
                        seen_signatures[sig] = name
            except Exception as e:
                logger.error(f"Failed to parse scenario {yaml_file} for validation: {e}")

    def set_ws_broadcast(self, callback):
        """Register a callback for WebSocket broadcasting."""
        self._ws_broadcast = callback
        self.event_log.set_ws_callback(self._handle_event_broadcast)

    async def _handle_event_broadcast(self, event):
        """Broadcast attack events via WebSocket."""
        if self._ws_broadcast:
            await self._ws_broadcast(WSMessage(
                type="attack_event",
                payload=event.model_dump(mode="json"),
            ))

    async def _broadcast_stage_update(self, stage: str, status: str, details: dict = None):
        """Broadcast stage status update to dashboard."""
        if self._ws_broadcast:
            await self._ws_broadcast(WSMessage(
                type="attack_stage",
                payload={
                    "stage": stage,
                    "status": status,
                    "details": details or {},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ))

    async def run_all(self) -> dict:
        """
        Run the complete attack kill-chain.
        
        Returns summary of all stage results.
        """
        if not self.scenario:
            self.load_scenario()

        self.event_log.initialize()
        self.is_running = True
        self.stage_results = {}

        logger.info("=" * 60)
        logger.info(f"  ATTACK SIMULATION: {self.scenario.get('name', 'APT Attack')}")
        logger.info("=" * 60)

        stages_to_run = []
        for s in self.scenario.get("stages", []):
            try:
                stage_enum = AttackStage(s["name"])
                stages_to_run.append((stage_enum, s))
            except ValueError:
                logger.warning(f"Unknown stage name {s['name']} in scenario config")

        if self.scenario.get("name") == "false_positive" or not any(s[0] != AttackStage.BENIGN_ACTIVITY for s in stages_to_run):
            terminal_state = "normal_ops"
        else:
            terminal_state = "succeeded"

        for i, (stage, stage_cfg) in enumerate(stages_to_run):
            extra = {}
            if stage == AttackStage.COMMAND_CONTROL:
                extra = {"duration_seconds": stage_cfg.get("duration_seconds", 60)}

            result = await self._run_stage(stage, stage_cfg, extra_kwargs=extra)

            # Post-stage logic
            if stage == AttackStage.INITIAL_ACCESS and result and result.get("success"):
                self._credentials = result
            elif stage == AttackStage.PERSISTENCE and result and not result.get("error"):
                self._credentials["rogue_username"] = result.get("rogue_username", "svc_backup")

            if result and result.get("error"):
                is_blocked = result.get("blocked_by_detection", False)
                terminal_state = "blocked" if is_blocked else "failed"
                logger.warning(f"Stage {stage.value} errored (Blocked: {is_blocked}). Halting downstream stages.")
                # Halt remaining
                for halt_stage, _ in stages_to_run[i+1:]:
                    await self._broadcast_stage_update(
                        halt_stage.value, 
                        "halted", 
                        {"error": f"Halted due to {stage.value} error"}
                    )
                    self.stage_results[halt_stage.value] = {"status": "halted"}
                break

        self.is_running = False

        if self._ws_broadcast:
            await self._ws_broadcast(WSMessage(
                type="simulation_state",
                payload={"state": terminal_state}
            ))

        logger.info("=" * 60)
        logger.info(f"  ATTACK SIMULATION COMPLETE: {terminal_state.upper()}")
        logger.info("=" * 60)

        return self.stage_results

    async def run_stage(self, stage_name: str, config_override: dict = None) -> dict:
        """Run a single stage by name (for interactive demo use)."""
        stage = AttackStage(stage_name)
        if not self.scenario:
            self.load_scenario()

        self.event_log.initialize()

        stages_config = {s["name"]: s for s in self.scenario.get("stages", [])}
        stage_cfg = config_override or stages_config.get(stage_name, {})

        return await self._run_stage(stage, stage_cfg)

    async def _run_stage(
        self,
        stage: AttackStage,
        stage_config: dict,
        extra_kwargs: dict = None,
    ) -> dict:
        """Internal: execute a single stage with logging and error handling."""
        stage_name = stage.value
        self.current_stage = stage

        # Wait if paused
        while self.is_paused:
            await asyncio.sleep(0.5)

        logger.info(f"\n{'─' * 40}")
        logger.info(f"STAGE: {stage_name.upper()}")
        logger.info(f"{'─' * 40}")

        await self._broadcast_stage_update(stage_name, "active")
        if self._stage_cb:
            self._stage_cb(stage_name)

        # Get the stage-specific config section
        cfg = stage_config.get("config", stage_config)

        # Build kwargs
        kwargs = {"event_log": self.event_log, "stage_config": cfg}

        # Some stages need credentials
        if stage in (AttackStage.PERSISTENCE, AttackStage.LATERAL_MOVEMENT, AttackStage.IMPACT):
            kwargs["credentials"] = self._credentials

        # Additional kwargs (like duration for C2)
        if extra_kwargs:
            kwargs.update(extra_kwargs)

        module = self.STAGE_MODULES[stage]
        max_attempts = 3
        attempt = 1

        while attempt <= max_attempts:
            try:
                # If we are actively blocked by detection, skip retries and fail immediately
                if self._is_blocked_cb and self._is_blocked_cb():
                    raise Exception("BLOCKED BY DETECTION")
                
                # Command Control stage can run long, adjust timeout if needed. 
                # For others, 15 seconds is a good safeguard against freezing.
                timeout = 15.0
                if stage == AttackStage.COMMAND_CONTROL and extra_kwargs and "duration_seconds" in extra_kwargs:
                    timeout = extra_kwargs["duration_seconds"] + 5.0
                    
                result = await asyncio.wait_for(module.execute(**kwargs), timeout=timeout)
                
                self.stage_results[stage_name] = result
                await self._broadcast_stage_update(stage_name, "complete", result)
                logger.info(f"Stage {stage_name} complete: {result}")

                # Delay between stages
                delay = stage_config.get("delay_after", 2)
                await asyncio.sleep(delay / self.speed_multiplier)

                return result

            except asyncio.TimeoutError:
                err_msg = f"Timeout after {timeout}s"
                logger.error(f"Stage {stage_name} attempt {attempt} failed: {err_msg}")
            except Exception as e:
                err_msg = str(e)
                logger.error(f"Stage {stage_name} attempt {attempt} failed: {e}")

            # If detection blocked it, we don't retry. We report it as blocked.
            if err_msg == "BLOCKED BY DETECTION" or (self._is_blocked_cb and self._is_blocked_cb()):
                res = {"error": "BLOCKED BY DETECTION", "blocked_by_detection": True}
                self.stage_results[stage_name] = res
                await self._broadcast_stage_update(stage_name, "blocked", res)
                return res

            if attempt < max_attempts:
                logger.info(f"Retrying stage {stage_name} ({attempt}/{max_attempts-1}) in 3 seconds...")
                await self._broadcast_stage_update(stage_name, "retrying", {"attempt": attempt})
                await asyncio.sleep(3)
            
            attempt += 1

        # If we exhausted retries
        res = {"error": err_msg, "blocked_by_detection": False}
        self.stage_results[stage_name] = res
        await self._broadcast_stage_update(stage_name, "error", res)
        return res

    def pause(self):
        """Pause the attack simulation."""
        self.is_paused = True
        logger.info("Attack simulation PAUSED")

    def resume(self):
        """Resume the attack simulation."""
        self.is_paused = False
        logger.info("Attack simulation RESUMED")

    def set_speed(self, multiplier: float):
        """Set simulation speed multiplier."""
        self.speed_multiplier = max(0.1, min(10.0, multiplier))
        logger.info(f"Speed set to {self.speed_multiplier}x")

    def reset(self):
        """Reset the engine for a fresh run."""
        self.current_stage = None
        self.stage_results = {}
        self.is_running = False
        self.is_paused = False
        self._credentials = {}
        self.event_log.clear()
        logger.info("Attack engine RESET")

    @staticmethod
    def _default_scenario() -> dict:
        """Built-in default scenario if no YAML file is found."""
        return {
            "name": "APT Smart Grid Attack — Default",
            "description": "Multi-stage APT targeting HES/MDMS infrastructure",
            "duration_minutes": 5,
            "stages": [
                {"name": "reconnaissance", "config": {}},
                {"name": "initial_access", "config": {
                    "wordlist": ["password", "admin", "grid2024", "admin123"],
                    "target_users": ["operator1", "admin"],
                }},
                {"name": "persistence", "config": {
                    "rogue_account": {"username": "svc_backup", "password": "Sup3rS3cur3!", "role": "admin"},
                }},
                {"name": "lateral_movement", "config": {}},
                {"name": "command_control", "config": {
                    "beacon_interval_seconds": 47,
                    "fake_meter_id": "SM-X-9999",
                }, "duration_seconds": 30},
                {"name": "impact", "config": {
                    "zone_order": ["A", "B", "C", "D", "E", "F"],
                    "disconnect_batch_size": 100,
                }},
            ],
        }
