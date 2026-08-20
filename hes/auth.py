"""
APT Simulator — HES Authentication Module
==========================================
Intentionally simplified (weak) authentication for the HES operator
portal. This is a deliberate simulation of real-world weak auth that
the attacker exploits during the Initial Access stage.

DO NOT use this pattern in production — this is a demo artifact.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from jose import jwt

from shared import config

logger = logging.getLogger(__name__)


# ─── Hardcoded Operator Accounts (intentionally weak) ──────────
# In a real HES, these would be in a database with proper hashing.
# Here we keep plaintext passwords to simulate the vulnerability.
DEFAULT_OPERATORS = {
    "operator1": {
        "password": "grid2024",
        "role": "operator",
        "operator_id": "OP-001",
    },
    "admin": {
        "password": "admin123",
        "role": "admin",
        "operator_id": "OP-ADMIN",
    },
}


class AuthManager:
    """
    Manages HES operator authentication.
    
    Deliberately insecure features (for attack simulation):
    - Plaintext password comparison
    - No account lockout after failed attempts
    - No rate limiting
    - JWT with no expiry
    - Predictable session tokens
    
    All login attempts are logged for the detection engine to consume.
    """

    def __init__(self):
        self.operators = dict(DEFAULT_OPERATORS)
        self.active_sessions: dict[str, dict] = {}  # token -> session info
        self.login_log: list[dict] = []  # All login attempts (for detector)

    def authenticate(self, username: str, password: str, source_ip: str = "127.0.0.1") -> Optional[str]:
        """
        Attempt to authenticate an operator.
        
        Returns:
            JWT token string on success, None on failure.
        """
        success = False
        operator_info = self.operators.get(username)

        if operator_info and operator_info["password"] == password:
            # Create JWT token (intentionally no expiry)
            token_data = {
                "sub": username,
                "role": operator_info["role"],
                "operator_id": operator_info["operator_id"],
            }
            token = jwt.encode(token_data, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

            # Store session
            self.active_sessions[token] = {
                "username": username,
                "role": operator_info["role"],
                "operator_id": operator_info["operator_id"],
                "login_time": datetime.now(timezone.utc).isoformat(),
                "source_ip": source_ip,
            }
            success = True

            logger.info(f"AUTH SUCCESS: user='{username}' ip={source_ip}")
        else:
            logger.warning(f"AUTH FAILURE: user='{username}' ip={source_ip}")

        # Log the attempt (consumed by detection engine)
        self.login_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "source_ip": source_ip,
            "success": success,
        })

        return token if success else None

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify a JWT token and return the session info.
        Returns None if token is invalid.
        """
        try:
            payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
            if token in self.active_sessions:
                return self.active_sessions[token]
            # Token is valid JWT but session not found — still accept it
            # (another intentional weakness)
            return {
                "username": payload.get("sub"),
                "role": payload.get("role"),
                "operator_id": payload.get("operator_id"),
            }
        except Exception:
            return None

    def create_account(self, username: str, password: str, role: str = "operator") -> bool:
        """
        Create a new operator account.
        Used legitimately by admins and maliciously by the attacker (persistence stage).
        
        Returns True if account created, False if username already exists.
        """
        if username in self.operators:
            return False

        operator_id = f"OP-{len(self.operators) + 1:03d}"
        self.operators[username] = {
            "password": password,
            "role": role,
            "operator_id": operator_id,
        }
        logger.info(f"ACCOUNT CREATED: user='{username}' role={role}")
        return True

    def get_login_log(self) -> list[dict]:
        """Return all login attempts (for detection engine)."""
        return list(self.login_log)

    def get_recent_failures(self, window_seconds: int = 300) -> list[dict]:
        """Return failed login attempts in the last N seconds."""
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        return [
            entry for entry in self.login_log
            if not entry["success"]
            and datetime.fromisoformat(entry["timestamp"]).timestamp() > cutoff
        ]

    def get_operators_list(self) -> list[dict]:
        """Return list of operator accounts (without passwords)."""
        return [
            {"username": u, "role": info["role"], "operator_id": info["operator_id"]}
            for u, info in self.operators.items()
        ]
