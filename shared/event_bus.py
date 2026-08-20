"""
APT Simulator — In-Process Event Bus
=====================================
Lightweight asyncio-based pub/sub that mimics MQTT topic semantics.
Used as a fallback when the MQTT broker is unavailable, and also used
for inter-service communication within the same process.

Supports wildcard topics with '+' (single level) and '#' (multi level).
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class EventBus:
    """
    In-process pub/sub event bus with MQTT-style topic matching.
    Thread-safe via asyncio — all operations run on the event loop.
    """

    _instance: EventBus | None = None

    def __init__(self):
        # topic_pattern -> list of async callback functions
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._message_count = 0

    @classmethod
    def get_instance(cls) -> EventBus:
        """Singleton accessor — one bus per process."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def subscribe(self, topic_pattern: str, callback: Callable[..., Coroutine]):
        """
        Subscribe to a topic pattern.
        
        Args:
            topic_pattern: MQTT-style topic with optional '+' and '#' wildcards.
                           e.g. "meters/+/telemetry" or "alerts/#"
            callback:      Async function(topic: str, payload: dict) -> None
        """
        self._subscribers[topic_pattern].append(callback)
        logger.debug(f"EventBus: subscribed to '{topic_pattern}' ({len(self._subscribers[topic_pattern])} handlers)")

    def unsubscribe(self, topic_pattern: str, callback: Callable | None = None):
        """Remove a subscription. If callback is None, removes all for that pattern."""
        if callback is None:
            self._subscribers.pop(topic_pattern, None)
        elif topic_pattern in self._subscribers:
            self._subscribers[topic_pattern] = [
                cb for cb in self._subscribers[topic_pattern] if cb != callback
            ]

    async def publish(self, topic: str, payload: dict[str, Any] | str):
        """
        Publish a message to a topic. All matching subscribers are notified.
        
        Args:
            topic:   Concrete topic string (no wildcards), e.g. "meters/SM-A-0042/telemetry"
            payload: Message payload (dict or JSON string)
        """
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {"raw": payload}

        self._message_count += 1
        matched = 0

        for pattern, callbacks in self._subscribers.items():
            if self._topic_matches(pattern, topic):
                for callback in callbacks:
                    try:
                        await callback(topic, payload)
                        matched += 1
                    except Exception as e:
                        logger.error(f"EventBus: error in subscriber for '{pattern}': {e}")

        if matched == 0:
            logger.debug(f"EventBus: no subscribers for topic '{topic}'")

    @staticmethod
    def _topic_matches(pattern: str, topic: str) -> bool:
        """
        Match MQTT-style topic patterns.
        '+' matches exactly one level, '#' matches zero or more levels.
        """
        pattern_parts = pattern.split("/")
        topic_parts = topic.split("/")

        i = 0
        for i, p in enumerate(pattern_parts):
            if p == "#":
                return True  # '#' matches everything remaining
            if i >= len(topic_parts):
                return False
            if p == "+":
                continue  # '+' matches any single level
            if p != topic_parts[i]:
                return False

        return i + 1 == len(topic_parts)

    @property
    def stats(self) -> dict:
        """Return bus statistics."""
        return {
            "total_messages": self._message_count,
            "subscription_count": sum(len(cbs) for cbs in self._subscribers.values()),
            "topic_patterns": list(self._subscribers.keys()),
        }


# ─── Module-level convenience functions ────────────────────────

_bus = EventBus.get_instance()

subscribe = _bus.subscribe
unsubscribe = _bus.unsubscribe
publish = _bus.publish
