"""
APT Simulator — Fleet Manager
==============================
Manages the fleet of virtual smart meters. Handles spawning, zone
assignment, location generation, and fleet-wide operations like
mass disconnect (used by the attack engine).

The fleet is organized into zones A-F, each covering a sector of the
synthetic city grid.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional

from shared import config
from shared.models import MeterInfo, MeterStatus

from .meter_agent import MeterAgent
from .profiles import PROFILES

logger = logging.getLogger(__name__)


class FleetManager:
    """
    Manages N virtual smart meters distributed across the city grid.

    Responsibilities:
    - Spawning meter agents with zone/location/profile assignments
    - Providing fleet status to the HES
    - Executing fleet-wide commands (mass disconnect, etc.)
    - Tracking meter state changes
    """

    def __init__(
        self,
        meter_count: int = None,
        telemetry_interval: float = None,
        mqtt_client=None,
        event_bus=None,
    ):
        self.meter_count = meter_count or config.METER_COUNT
        self.telemetry_interval = telemetry_interval or config.TELEMETRY_INTERVAL_SECONDS
        self._mqtt_client = mqtt_client
        self._event_bus = event_bus

        self.meters: dict[str, MeterAgent] = {}
        self._running = False

    async def start(self):
        """Initialize and start all meter agents."""
        logger.info(f"Fleet Manager: spawning {self.meter_count} virtual meters...")
        self._generate_fleet()

        # Start all meters concurrently
        start_tasks = [meter.start() for meter in self.meters.values()]
        await asyncio.gather(*start_tasks)

        self._running = True
        logger.info(f"Fleet Manager: {len(self.meters)} meters running across {len(config.ZONES)} zones")

    async def stop(self):
        """Stop all meter agents gracefully."""
        logger.info("Fleet Manager: stopping all meters...")
        stop_tasks = [meter.stop() for meter in self.meters.values()]
        await asyncio.gather(*stop_tasks)
        self._running = False
        logger.info("Fleet Manager: all meters stopped")

    def _generate_fleet(self):
        """
        Generate the meter fleet with zone assignments and locations.
        
        Distribution:
        - 75% residential, 20% commercial, 5% industrial
        - Evenly distributed across zones A-F
        - Random lat/lng within each zone's sector of the city grid
        """
        zones = config.ZONES
        meters_per_zone = self.meter_count // len(zones)
        remainder = self.meter_count % len(zones)

        # Define zone boundaries within the city grid
        zone_bounds = self._calculate_zone_bounds(zones)

        meter_seq = 0
        for zone_idx, zone in enumerate(zones):
            count = meters_per_zone + (1 if zone_idx < remainder else 0)

            for i in range(count):
                meter_seq += 1
                meter_id = f"SM-{zone}-{meter_seq:04d}"

                # Random location within zone bounds
                bounds = zone_bounds[zone]
                lat = random.uniform(bounds["lat_min"], bounds["lat_max"])
                lng = random.uniform(bounds["lng_min"], bounds["lng_max"])

                # Assign profile type based on distribution
                profile_type = self._assign_profile()

                agent = MeterAgent(
                    meter_id=meter_id,
                    zone=zone,
                    latitude=round(lat, 6),
                    longitude=round(lng, 6),
                    profile_type=profile_type,
                    telemetry_interval=self.telemetry_interval,
                    mqtt_client=self._mqtt_client,
                    event_bus=self._event_bus,
                )
                self.meters[meter_id] = agent

    @staticmethod
    def _calculate_zone_bounds(zones: list[str]) -> dict[str, dict]:
        """
        Divide the city grid into zone sectors.
        Layout: 2 rows × 3 columns
        
            A | B | C
            ---------
            D | E | F
        """
        lat_range = config.CITY_LAT_MAX - config.CITY_LAT_MIN
        lng_range = config.CITY_LNG_MAX - config.CITY_LNG_MIN

        cols = 3
        rows = 2
        lat_step = lat_range / rows
        lng_step = lng_range / cols

        zone_map = {
            "A": (0, 0), "B": (0, 1), "C": (0, 2),
            "D": (1, 0), "E": (1, 1), "F": (1, 2),
        }

        bounds = {}
        for zone in zones:
            if zone in zone_map:
                row, col = zone_map[zone]
                bounds[zone] = {
                    "lat_min": config.CITY_LAT_MIN + row * lat_step,
                    "lat_max": config.CITY_LAT_MIN + (row + 1) * lat_step,
                    "lng_min": config.CITY_LNG_MIN + col * lng_step,
                    "lng_max": config.CITY_LNG_MIN + (col + 1) * lng_step,
                }
        return bounds

    @staticmethod
    def _assign_profile() -> str:
        """Assign a consumption profile based on realistic distribution."""
        roll = random.random()
        if roll < 0.75:
            return "residential"
        elif roll < 0.95:
            return "commercial"
        else:
            return "industrial"

    # ─── Fleet Operations ──────────────────────────────────────

    def get_meter(self, meter_id: str) -> Optional[MeterAgent]:
        """Get a specific meter agent by ID."""
        return self.meters.get(meter_id)

    def get_all_meter_info(self) -> list[MeterInfo]:
        """Get info for all meters (for HES API)."""
        return [
            MeterInfo(
                meter_id=m.meter_id,
                zone=m.zone,
                latitude=m.latitude,
                longitude=m.longitude,
                profile_type=m.profile_type,
                status=m.status,
            )
            for m in self.meters.values()
        ]

    def get_meters_by_zone(self, zone: str) -> list[MeterAgent]:
        """Get all meters in a specific zone."""
        return [m for m in self.meters.values() if m.zone == zone]

    def get_zone_stats(self) -> dict[str, dict]:
        """Get per-zone statistics."""
        stats = {}
        for zone in config.ZONES:
            zone_meters = self.get_meters_by_zone(zone)
            stats[zone] = {
                "total": len(zone_meters),
                "connected": sum(1 for m in zone_meters if m.status == MeterStatus.CONNECTED),
                "disconnected": sum(1 for m in zone_meters if m.status == MeterStatus.DISCONNECTED),
            }
        return stats

    async def disconnect_meter(self, meter_id: str) -> bool:
        """Disconnect a single meter. Returns True if found and disconnected."""
        meter = self.meters.get(meter_id)
        if meter:
            meter.disconnect()
            return True
        return False

    async def reconnect_meter(self, meter_id: str) -> bool:
        """Reconnect a single meter. Returns True if found and reconnected."""
        meter = self.meters.get(meter_id)
        if meter:
            meter.reconnect()
            return True
        return False

    async def disconnect_zone(self, zone: str) -> int:
        """Disconnect all meters in a zone. Returns count of affected meters."""
        count = 0
        for meter in self.get_meters_by_zone(zone):
            if meter.status == MeterStatus.CONNECTED:
                meter.disconnect()
                count += 1
        logger.warning(f"Fleet Manager: MASS DISCONNECT zone {zone} — {count} meters affected")
        return count

    async def reconnect_all(self) -> int:
        """Reconnect all disconnected meters. Returns count."""
        count = 0
        for meter in self.meters.values():
            if meter.status == MeterStatus.DISCONNECTED:
                meter.reconnect()
                count += 1
        logger.info(f"Fleet Manager: reconnected {count} meters")
        return count

    @property
    def status_summary(self) -> dict:
        """Quick fleet status summary."""
        connected = sum(1 for m in self.meters.values() if m.status == MeterStatus.CONNECTED)
        return {
            "total_meters": len(self.meters),
            "connected": connected,
            "disconnected": len(self.meters) - connected,
            "running": self._running,
            "zones": self.get_zone_stats(),
        }
