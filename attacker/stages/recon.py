"""
APT Simulator — Stage 1: Reconnaissance
=========================================
MITRE ATT&CK for ICS: T0846 — Remote System Discovery

Simulates an attacker scanning the HES service to discover available
endpoints, ports, and service information. This is the intelligence-
gathering phase before the actual attack begins.

In a real scenario, this would involve nmap scans, web crawling,
and OSINT. Here we simulate systematic probing of the HES REST API.
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

STAGE = AttackStage.RECONNAISSANCE
TECHNIQUE_ID = "T0846"
TACTIC = "Discovery"

# Endpoints to probe (simulating what an attacker would discover)
TARGET_ENDPOINTS = [
    ("/api/health", "GET", "Health check endpoint"),
    ("/api/meters", "GET", "Meter listing API"),
    ("/api/meters/SM-A-0001", "GET", "Individual meter detail"),
    ("/api/auth/login", "POST", "Authentication endpoint"),
    ("/api/operators", "GET", "Operator account listing"),
    ("/api/fleet/status", "GET", "Fleet status endpoint"),
    ("/api/audit/logins", "GET", "Login audit log"),
    ("/api/audit/commands", "GET", "Command audit log"),
    ("/docs", "GET", "Swagger/OpenAPI documentation"),
]


async def execute(event_log: EventLog, stage_config: dict = None) -> dict:
    """
    Execute the Reconnaissance stage.
    
    Probes the HES for available endpoints and records discoveries.
    
    Args:
        event_log:    Shared event logger
        stage_config: Optional config overrides from scenario YAML
        
    Returns:
        Summary of discoveries
    """
    stage_config = stage_config or {}
    base_url = stage_config.get("target_url", config.HES_URL)
    endpoints = stage_config.get("target_endpoints", None)

    if endpoints:
        # Use custom endpoint list from scenario config
        targets = [(ep, "GET", f"Custom endpoint {ep}") for ep in endpoints]
    else:
        targets = TARGET_ENDPOINTS

    logger.info(f"[RECON] Starting reconnaissance against {base_url}")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target=base_url,
        action="Starting port/endpoint reconnaissance",
        details={"target_url": base_url, "total_endpoints": len(targets)},
    )

    discoveries = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        for endpoint, method, description in targets:
            url = f"{base_url}{endpoint}"

            try:
                if method == "POST":
                    resp = await client.post(url, json={})
                else:
                    resp = await client.get(url)

                discovery = {
                    "endpoint": endpoint,
                    "method": method,
                    "status_code": resp.status_code,
                    "description": description,
                    "accessible": resp.status_code < 500,
                }
                discoveries.append(discovery)

                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target=endpoint,
                    action=f"Probed {method} {endpoint} → {resp.status_code}",
                    details=discovery,
                    success=(resp.status_code < 500),
                )

                logger.info(f"[RECON] {method} {endpoint} → {resp.status_code}")

            except httpx.ConnectError:
                await event_log.log_event(
                    stage=STAGE,
                    technique_id=TECHNIQUE_ID,
                    tactic=TACTIC,
                    target=endpoint,
                    action=f"Connection failed to {endpoint}",
                    success=False,
                )
                logger.warning(f"[RECON] {method} {endpoint} → CONNECTION FAILED")

            # Random delay between probes (simulating cautious scanning)
            await asyncio.sleep(random.uniform(0.5, 2.0))

    # Summary
    accessible = [d for d in discoveries if d["accessible"]]
    summary = {
        "total_probed": len(targets),
        "accessible": len(accessible),
        "endpoints_found": [d["endpoint"] for d in accessible],
    }

    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target=base_url,
        action=f"Reconnaissance complete: {len(accessible)}/{len(targets)} endpoints accessible",
        details=summary,
    )

    logger.info(f"[RECON] Complete: {len(accessible)}/{len(targets)} endpoints accessible")
    return summary
