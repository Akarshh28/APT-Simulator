"""
APT Simulator — Stage 4: Lateral Movement
===========================================
MITRE ATT&CK for ICS: T0886 — Remote Services

After establishing persistence, the attacker pivots from the HES
to the MDMS database. They access customer records, billing data,
and other sensitive information that should be inaccessible from
the HES network segment.

This stage generates cross-service authentication events that the
graph-based detector watches for.
"""

from __future__ import annotations

import asyncio
import logging
import random

import httpx

from shared import config
from shared.models import AttackStage
from attacker.event_log import EventLog

logger = logging.getLogger(__name__)

STAGE = AttackStage.LATERAL_MOVEMENT
TECHNIQUE_ID = "T0886"
TACTIC = "Lateral Movement"


async def execute(
    event_log: EventLog,
    stage_config: dict = None,
    credentials: dict = None,
) -> dict:
    """
    Execute the Lateral Movement stage.
    
    Uses compromised/rogue credentials to access the MDMS from
    the HES network context — crossing a trust boundary.
    """
    stage_config = stage_config or {}
    credentials = credentials or {}

    mdms_url = config.MDMS_URL
    target_apis = stage_config.get("target_apis", [
        "/api/customers",
        "/api/billing",
        "/api/reports/consumption",
        "/api/operators",
        "/api/audit",
    ])

    rogue_user = credentials.get("rogue_username", "svc_backup")

    logger.info(f"[LATERAL MOVEMENT] Pivoting from HES to MDMS using '{rogue_user}'")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="MDMS",
        action=f"Lateral movement: HES → MDMS via rogue account '{rogue_user}'",
        details={
            "source_service": "HES",
            "target_service": "MDMS",
            "method": "rogue_credentials",
            "account": rogue_user,
        },
    )

    accessed_data = {}
    exfiltrated_records = 0

    async with httpx.AsyncClient(timeout=10.0) as client:
        for api_path in target_apis:
            url = f"{mdms_url}{api_path}"

            try:
                resp = await client.get(url)

                if resp.status_code == 200:
                    data = resp.json()

                    # Count records accessed
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if isinstance(value, list):
                                record_count = len(value)
                                exfiltrated_records += record_count
                                accessed_data[api_path] = {
                                    "status": resp.status_code,
                                    "records": record_count,
                                }
                                break
                        else:
                            accessed_data[api_path] = {"status": resp.status_code}
                    else:
                        accessed_data[api_path] = {"status": resp.status_code}

                    await event_log.log_event(
                        stage=STAGE,
                        technique_id=TECHNIQUE_ID,
                        tactic=TACTIC,
                        target=f"MDMS {api_path}",
                        action=f"Accessed {api_path} — {accessed_data[api_path].get('records', '?')} records",
                        details={
                            "url": url,
                            "status_code": resp.status_code,
                            "data_accessed": accessed_data[api_path],
                        },
                    )
                    logger.info(f"[LATERAL MOVEMENT] Accessed {api_path} → {resp.status_code}")

                else:
                    accessed_data[api_path] = {"status": resp.status_code, "error": True}
                    await event_log.log_event(
                        stage=STAGE,
                        technique_id=TECHNIQUE_ID,
                        tactic=TACTIC,
                        target=f"MDMS {api_path}",
                        action=f"Access denied to {api_path} (HTTP {resp.status_code})",
                        success=False,
                    )

            except httpx.ConnectError:
                logger.error(f"[LATERAL MOVEMENT] Cannot connect to MDMS at {url}")
                accessed_data[api_path] = {"status": "connection_failed", "error": True}

            await asyncio.sleep(random.uniform(1.0, 3.0))

    # Simulate data exfiltration logging
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target="MDMS",
        action=f"Data exfiltration: {exfiltrated_records} records accessed from MDMS",
        details={
            "total_records": exfiltrated_records,
            "apis_accessed": list(accessed_data.keys()),
        },
    )

    summary = {
        "success": any(d.get("status") == 200 for d in accessed_data.values()),
        "apis_accessed": accessed_data,
        "total_records_exfiltrated": exfiltrated_records,
    }

    logger.info(f"[LATERAL MOVEMENT] Complete: {exfiltrated_records} records exfiltrated")
    return summary
