"""
APT Simulator — Smart Meter Agent
===================================
Each MeterAgent instance simulates a single smart meter, generating
periodic telemetry readings based on its consumption profile and
publishing them via MQTT (or the in-process event bus).

Meters respond to control commands (connect/disconnect/firmware update)
and can be manipulated by both the legitimate HES and the attacker.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from datetime import datetime, timezone

from shared.models import MeterStatus, MeterTelemetry

from .profiles import ConsumptionProfile, get_profile

logger = logging.getLogger(__name__)


class MeterAgent:
    """
    Simulates a single smart meter in the grid.

    Each meter has:
    - A unique ID (SM-{zone}-{seq})
    - A geographic location (lat/lng within a zone)
    - A consumption profile (residential/commercial/industrial)
    - A status (connected/disconnected)
    - A cumulative energy counter (kWh)

    The agent publishes DLMS/COSEM-style telemetry at regular intervals
    to MQTT topic: meters/{meter_id}/telemetry
    """

    def __init__(
        self,
        meter_id: str,
        zone: str,
        latitude: float,
        longitude: float,
        profile_type: str = "residential",
        telemetry_interval: float = 15.0,
        mqtt_client=None,
        event_bus=None,
    ):
        self.meter_id = meter_id
        self.zone = zone
        self.latitude = latitude
        self.longitude = longitude
        self.profile_type = profile_type
        self.profile: ConsumptionProfile = get_profile(profile_type)
        self.telemetry_interval = telemetry_interval

        # MQTT or in-process event bus
        self._mqtt_client = mqtt_client
        self._event_bus = event_bus

        # Meter state
        self.status = MeterStatus.CONNECTED
        self.cumulative_kwh = random.uniform(500, 15000)  # Start with some history
        self._running = False
        self._task: asyncio.Task | None = None

        # Simulated time tracking
        self._sim_hour = random.uniform(0, 24)  # Start at random hour
        self._sim_day = random.randint(1, 365)

    async def start(self):
        """Start the meter agent's telemetry publishing loop."""
        self._running = True
        self._task = asyncio.create_task(self._telemetry_loop())
        logger.debug(f"Meter {self.meter_id} started (zone {self.zone}, profile {self.profile_type})")

    async def stop(self):
        """Stop the meter agent gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.debug(f"Meter {self.meter_id} stopped")

    def disconnect(self):
        """Simulate meter disconnect (e.g., by attacker or legitimate command)."""
        self.status = MeterStatus.DISCONNECTED
        logger.info(f"Meter {self.meter_id} DISCONNECTED")

    def reconnect(self):
        """Simulate meter reconnect."""
        self.status = MeterStatus.CONNECTED
        logger.info(f"Meter {self.meter_id} RECONNECTED")

    async def _telemetry_loop(self):
        """Main loop: generate and publish telemetry at regular intervals."""
        # Add small random offset to avoid all meters publishing simultaneously
        await asyncio.sleep(random.uniform(0, self.telemetry_interval * 0.5))

        while self._running:
            try:
                if self.status == MeterStatus.CONNECTED:
                    reading = self._generate_reading()
                    await self._publish(reading)

                # Advance simulated time
                # Each real-second interval represents a configurable simulated duration
                self._sim_hour = (self._sim_hour + 0.25) % 24  # Each tick = 15 min simulated
                if self._sim_hour < 0.25:
                    self._sim_day = (self._sim_day % 365) + 1

                await asyncio.sleep(self.telemetry_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Meter {self.meter_id} error: {e}")
                await asyncio.sleep(self.telemetry_interval)

    def _generate_reading(self) -> MeterTelemetry:
        """Generate a realistic telemetry reading based on the meter's profile."""
        load_kw = self.profile.get_load_kw(self._sim_hour, self._sim_day)
        voltage = self.profile.get_voltage()
        power_factor = self.profile.get_power_factor()

        # Calculate current from power, voltage, and power factor
        # P = V * I * PF  =>  I = P / (V * PF)
        active_power_w = load_kw * 1000
        raw_current = active_power_w / (voltage * power_factor) if voltage > 0 else 0
        
        # Defensive safety clamp to prevent silent validation drops in the pipeline
        current = min(max(raw_current, 0.0), 500.0)

        # Accumulate energy (kWh) — interval in hours
        interval_hours = 0.25  # Simulated 15 minutes
        self.cumulative_kwh += load_kw * interval_hours

        return MeterTelemetry(
            meter_id=self.meter_id,
            timestamp=datetime.now(timezone.utc),
            voltage=round(voltage, 2),
            current=round(current, 3),
            power_factor=round(power_factor, 3),
            consumption_kwh=round(self.cumulative_kwh, 2),
            active_power_w=round(active_power_w, 1),
            zone=self.zone,
            latitude=self.latitude,
            longitude=self.longitude,
            status=self.status,
        )

    async def _publish(self, reading: MeterTelemetry):
        """Publish telemetry via MQTT or in-process event bus."""
        topic = f"meters/{self.meter_id}/telemetry"
        payload = reading.model_dump_json()

        if self._mqtt_client:
            self._mqtt_client.publish(topic, payload, qos=0)
        elif self._event_bus:
            await self._event_bus.publish(topic, payload)
        else:
            logger.warning(f"Meter {self.meter_id}: no transport configured")

    async def handle_command(self, command_type: str, parameters: dict = None):
        """
        Handle an incoming command from the HES.
        
        Args:
            command_type: "connect", "disconnect", "firmware_push", "read_on_demand"
            parameters:   Additional command parameters
        """
        parameters = parameters or {}

        if command_type == "disconnect":
            self.disconnect()
        elif command_type == "connect":
            self.reconnect()
        elif command_type == "firmware_push":
            self.status = MeterStatus.FIRMWARE_UPDATING
            logger.info(f"Meter {self.meter_id} firmware update started (v{parameters.get('version', '?.?')})")
            # Simulate firmware update delay
            await asyncio.sleep(2)
            self.status = MeterStatus.CONNECTED
            logger.info(f"Meter {self.meter_id} firmware update complete")
        elif command_type == "read_on_demand":
            if self.status == MeterStatus.CONNECTED:
                reading = self._generate_reading()
                await self._publish(reading)
        else:
            logger.warning(f"Meter {self.meter_id}: unknown command '{command_type}'")
