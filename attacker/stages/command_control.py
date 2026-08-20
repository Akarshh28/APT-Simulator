"""
APT Simulator — Stage 5: Command and Control
==============================================
MITRE ATT&CK for ICS: T0869 — Standard Application Layer Protocol

Establishes a covert C2 channel by registering a fake meter that
publishes beacon traffic disguised as normal telemetry. The beacon
uses a distinctive interval (~47s ± jitter) that differs from
legitimate meter polling intervals (15s).

This is the "low-and-slow" pattern that the beacon detector module
in the detection engine is designed to catch via autocorrelation
and interval-variance analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone

from shared import config
from shared.event_bus import EventBus
from shared.models import AttackStage
from attacker.event_log import EventLog

logger = logging.getLogger(__name__)

STAGE = AttackStage.COMMAND_CONTROL
TECHNIQUE_ID = "T0869"
TACTIC = "Command and Control"


async def execute(
    event_log: EventLog,
    stage_config: dict = None,
    duration_seconds: float = 60,
) -> dict:
    """
    Execute the Command & Control stage.
    
    Registers a fake meter and starts beaconing via the event bus,
    disguised as normal telemetry traffic.
    
    Args:
        event_log:        Shared event logger
        stage_config:     Config from scenario YAML
        duration_seconds: How long to beacon before stopping
    """
    stage_config = stage_config or {}
    fake_meter_id = stage_config.get("fake_meter_id", "SM-X-9999")
    beacon_interval = stage_config.get("beacon_interval_seconds", 47)
    beacon_jitter = stage_config.get("beacon_jitter_seconds", 5)

    event_bus = EventBus.get_instance()

    logger.info(f"[C2] Starting beacon via fake meter '{fake_meter_id}'")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="MQTT/EventBus",
        action=f"C2 beacon initialized — fake meter '{fake_meter_id}'",
        details={
            "fake_meter_id": fake_meter_id,
            "beacon_interval": beacon_interval,
            "beacon_jitter": beacon_jitter,
            "duration": duration_seconds,
        },
    )

    beacon_count = 0
    start_time = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start_time) < duration_seconds:
        # Generate beacon payload disguised as telemetry
        beacon_payload = {
            "meter_id": fake_meter_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "voltage": round(random.uniform(228, 232), 2),
            "current": round(random.uniform(0.1, 0.5), 3),
            "power_factor": round(random.uniform(0.90, 0.95), 3),
            "consumption_kwh": round(random.uniform(100, 200), 2),
            "active_power_w": round(random.uniform(20, 100), 1),
            "zone": "X",  # Non-standard zone — a subtle indicator
            "latitude": 26.449,
            "longitude": 80.349,
            "status": "connected",
            # Hidden C2 data embedded in telemetry
            "_c2_cmd": "heartbeat",
            "_c2_seq": beacon_count,
        }

        # Publish via event bus (same channel as legitimate meters)
        await event_bus.publish(
            f"meters/{fake_meter_id}/telemetry",
            beacon_payload,
        )

        beacon_count += 1

        if beacon_count % 5 == 0:
            await event_log.log_event(
                stage=STAGE,
                technique_id=TECHNIQUE_ID,
                tactic=TACTIC,
                target="MQTT/EventBus",
                action=f"C2 beacon #{beacon_count} sent",
                details={"beacon_count": beacon_count, "meter_id": fake_meter_id},
            )

        # Wait with distinctive interval (different from legitimate 15s)
        interval = beacon_interval + random.uniform(-beacon_jitter, beacon_jitter)
        interval = max(5, interval)  # Minimum 5 seconds

        # In demo mode, compress the interval
        demo_interval = min(interval, 3.0)  # Cap at 3s for demo pacing
        await asyncio.sleep(demo_interval)

    summary = {
        "success": True,
        "fake_meter_id": fake_meter_id,
        "beacons_sent": beacon_count,
        "duration_seconds": duration_seconds,
        "beacon_interval": beacon_interval,
    }

    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="MQTT/EventBus",
        action=f"C2 beaconing complete — {beacon_count} beacons sent over {duration_seconds}s",
        details=summary,
    )

    logger.info(f"[C2] Beaconing complete: {beacon_count} beacons in {duration_seconds}s")
    return summary
