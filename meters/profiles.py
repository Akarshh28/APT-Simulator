"""
APT Simulator — Consumption Profiles
=====================================
Predefined load profiles for different customer types. Each profile
defines the shape of a 24-hour consumption curve that meters follow,
plus variance and seasonal factors to make the data look realistic.

The profiles are based on typical Indian residential / commercial /
industrial consumption patterns (approximate).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


@dataclass
class ConsumptionProfile:
    """
    Defines a 24-hour consumption pattern for a meter type.
    
    Attributes:
        name:            Profile identifier
        base_load_kw:    Minimum load in kW (always-on appliances)
        peak_load_kw:    Maximum load in kW during peak hours
        peak_hours:      List of (start_hour, end_hour) peak periods
        variance:        Gaussian noise standard deviation (fraction of load)
        seasonal_factor: Multiplier for seasonal variation (1.0 = no variation)
        voltage_nominal: Nominal voltage in volts
        voltage_variance: Voltage fluctuation std dev
        power_factor_range: (min, max) power factor range
    """
    name: str
    base_load_kw: float
    peak_load_kw: float
    peak_hours: list[tuple[int, int]] = field(default_factory=list)
    variance: float = 0.1
    seasonal_factor: float = 1.0
    voltage_nominal: float = 230.0
    voltage_variance: float = 5.0
    power_factor_range: tuple[float, float] = (0.85, 0.98)

    def get_load_kw(self, hour: float, day_of_year: int = 180) -> float:
        """
        Calculate the expected load at a given hour (0-23.99) and day.
        Returns load in kW with noise.
        
        Uses a smooth sinusoidal interpolation between base and peak,
        with Gaussian noise and seasonal drift.
        """
        # Seasonal factor: higher in summer (Indian context: April-June peak)
        # Simple sinusoidal approximation centered on day 120 (May)
        seasonal = 1.0 + self.seasonal_factor * 0.15 * math.sin(
            2 * math.pi * (day_of_year - 120) / 365
        )

        # Calculate base → peak interpolation
        in_peak = False
        for start, end in self.peak_hours:
            if start <= hour < end:
                in_peak = True
                # Smooth ramp using cosine interpolation within peak window
                mid = (start + end) / 2
                half_width = (end - start) / 2
                peak_factor = 0.5 * (1 + math.cos(math.pi * (hour - mid) / half_width))
                break

        if in_peak:
            load = self.base_load_kw + (self.peak_load_kw - self.base_load_kw) * peak_factor
        else:
            load = self.base_load_kw

        # Apply seasonal and noise
        load *= seasonal
        load += random.gauss(0, load * self.variance)
        return max(0.05, load)  # Never exactly zero

    def get_voltage(self) -> float:
        """Return voltage with realistic fluctuation."""
        return random.gauss(self.voltage_nominal, self.voltage_variance)

    def get_power_factor(self) -> float:
        """Return power factor within the configured range."""
        pf_min, pf_max = self.power_factor_range
        return random.uniform(pf_min, pf_max)


# ─── Predefined Profiles ──────────────────────────────────────

RESIDENTIAL = ConsumptionProfile(
    name="residential",
    base_load_kw=0.3,       # Fridge, router, standby loads
    peak_load_kw=2.5,       # AC, cooking, lighting, TV
    peak_hours=[
        (6, 9),              # Morning: cooking, water heater
        (17, 23),            # Evening: AC, cooking, lighting, entertainment
    ],
    variance=0.15,
    seasonal_factor=1.2,     # Strong AC usage in summer
    power_factor_range=(0.80, 0.95),
)

COMMERCIAL = ConsumptionProfile(
    name="commercial",
    base_load_kw=1.0,       # Security, servers, standby
    peak_load_kw=8.0,       # Full office load
    peak_hours=[
        (9, 18),             # Business hours
    ],
    variance=0.08,
    seasonal_factor=0.8,
    voltage_nominal=230.0,
    power_factor_range=(0.88, 0.98),
)

INDUSTRIAL = ConsumptionProfile(
    name="industrial",
    base_load_kw=15.0,      # Continuous process loads
    peak_load_kw=50.0,      # Full production
    peak_hours=[
        (6, 14),             # Day shift
        (14, 22),            # Evening shift
    ],
    variance=0.05,           # More stable than residential
    seasonal_factor=0.3,
    voltage_nominal=415.0,   # 3-phase
    voltage_variance=8.0,
    power_factor_range=(0.90, 0.99),
)

# Profile registry for easy lookup
PROFILES: dict[str, ConsumptionProfile] = {
    "residential": RESIDENTIAL,
    "commercial": COMMERCIAL,
    "industrial": INDUSTRIAL,
}


def get_profile(profile_type: str) -> ConsumptionProfile:
    """Get a consumption profile by type name."""
    return PROFILES.get(profile_type, RESIDENTIAL)
