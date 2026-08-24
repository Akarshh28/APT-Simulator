"""
Benign Activity Stage
=====================
Simulates normal, legitimate activity to test false positive rates.
"""
import asyncio
from shared.models import AttackStage, AttackEvent

async def execute(event_log, stage_config, **kwargs):
    """Execute benign activity that shouldn't trigger high risk."""
    event_log.log(AttackEvent(
        stage=AttackStage("benign_activity"),
        action="Routine maintenance login by OP-ADMIN",
        source="OP-ADMIN",
        target="HES",
        technique="Legitimate Admin Access",
        success=True,
        details={"reason": "Monthly audit and patch management"}
    ))
    
    await asyncio.sleep(2)
    
    event_log.log(AttackEvent(
        stage=AttackStage("benign_activity"),
        action="Standard telemetry pull for Zone A",
        source="HES",
        target="MDMS",
        technique="API Request",
        success=True,
        details={"records_pulled": 5000}
    ))
    
    await asyncio.sleep(2)
    
    return {"success": True, "message": "Benign activity completed"}
