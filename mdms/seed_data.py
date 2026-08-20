"""
APT Simulator — MDMS Seed Data Generator
==========================================
Generates synthetic customer records, billing history, and operator
accounts to populate the MDMS database on first run. Uses Faker
for realistic Indian names and addresses.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime

from faker import Faker

from shared import config

logger = logging.getLogger(__name__)

# Use Indian locale for realistic names/addresses
fake = Faker("en_IN")
Faker.seed(42)  # Reproducible data for consistent demos


def generate_customers(meter_count: int = None) -> list[dict]:
    """
    Generate synthetic customer records, one per meter.
    
    Returns list of customer dicts ready for database insertion.
    """
    meter_count = meter_count or config.METER_COUNT
    zones = config.ZONES
    meters_per_zone = meter_count // len(zones)
    customers = []

    meter_seq = 0
    for zone_idx, zone in enumerate(zones):
        count = meters_per_zone + (1 if zone_idx < meter_count % len(zones) else 0)

        for i in range(count):
            meter_seq += 1
            meter_id = f"SM-{zone}-{meter_seq:04d}"
            customer_id = f"CUST-{zone}-{meter_seq:04d}"

            customers.append({
                "customer_id": customer_id,
                "name": fake.name(),
                "address": f"{fake.building_number()}, {fake.street_name()}, Zone {zone}, {fake.city()}",
                "zone": zone,
                "meter_id": meter_id,
                "phone": fake.phone_number(),
                "email": fake.email(),
            })

    logger.info(f"Generated {len(customers)} synthetic customer records")
    return customers


def generate_billing_history(customers: list[dict], months: int = 2) -> list[dict]:
    """
    Generate billing history for the past N months.
    
    Creates realistic billing records with varying consumption
    based on the zone (proxy for customer type mix).
    """
    billing_records = []
    base_year = 2024

    for customer in customers:
        zone = customer["zone"]

        # Base consumption varies by zone (mix of profiles)
        zone_base = {
            "A": 250, "B": 300, "C": 280,
            "D": 350, "E": 220, "F": 400,
        }.get(zone, 300)

        for month_offset in range(months):
            month = 12 - month_offset  # December, November, ...
            if month <= 0:
                month += 12
                year = base_year - 1
            else:
                year = base_year

            period = f"{year}-{month:02d}"
            total_kwh = zone_base + random.gauss(0, zone_base * 0.2)
            total_kwh = max(50, total_kwh)

            rate = 6.50  # INR per kWh (approximate Indian domestic tariff)
            amount = round(total_kwh * rate, 2)

            billing_records.append({
                "billing_id": str(uuid.uuid4())[:8],
                "customer_id": customer["customer_id"],
                "meter_id": customer["meter_id"],
                "period": period,
                "total_kwh": round(total_kwh, 2),
                "rate_per_kwh": rate,
                "amount_inr": amount,
                "status": random.choice(["paid", "paid", "paid", "unpaid"]),
                "due_date": f"{year}-{month:02d}-15",
            })

    logger.info(f"Generated {len(billing_records)} billing records ({months} months)")
    return billing_records


def generate_default_operators() -> list[dict]:
    """Generate default operator accounts for the MDMS."""
    return [
        {
            "operator_id": "OP-001",
            "username": "operator1",
            "password_hash": "grid2024",  # Plaintext for demo
            "role": "operator",
            "is_rogue": 0,
        },
        {
            "operator_id": "OP-ADMIN",
            "username": "admin",
            "password_hash": "admin123",  # Plaintext for demo
            "role": "admin",
            "is_rogue": 0,
        },
    ]


async def seed_database(db_manager) -> dict:
    """
    Seed the MDMS database with synthetic data if empty.
    
    Returns summary of seeded data.
    """
    # Check if already seeded
    customer_count = await db_manager.get_customer_count()
    if customer_count > 0:
        logger.info(f"Database already seeded ({customer_count} customers). Skipping.")
        return {"status": "already_seeded", "customer_count": customer_count}

    logger.info("Seeding MDMS database with synthetic data...")

    # Generate and insert customers
    customers = generate_customers()
    await db_manager.insert_customers_bulk(customers)

    # Generate and insert billing history
    billing = generate_billing_history(customers, months=2)
    await db_manager.insert_billing_bulk(billing)

    # Insert default operators
    operators = generate_default_operators()
    for op in operators:
        await db_manager.insert_operator(op)

    summary = {
        "status": "seeded",
        "customers": len(customers),
        "billing_records": len(billing),
        "operators": len(operators),
    }
    logger.info(f"Database seeded: {summary}")
    return summary
