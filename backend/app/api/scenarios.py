"""API endpoints for educational simulated attack scenarios."""
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.knowledge_base.scenarios_data import get_all_scenarios, AttackScenario
from app.rules.engine import DiagnosisReport
from app.services.incident_service import analyze_incident_and_save

router = APIRouter(prefix="/api/scenarios", tags=["Attack Scenarios"])


@router.get("", response_model=List[AttackScenario])
def list_scenarios():
    """Lists safe educational attack scenarios."""
    return get_all_scenarios()


@router.get("/{scenario_id}", response_model=AttackScenario)
def get_scenario(scenario_id: str):
    """Retrieves an attack scenario by ID."""
    scenarios = get_all_scenarios()
    for s in scenarios:
        if s.id.lower() == scenario_id.lower():
            return s
    raise HTTPException(status_code=404, detail="Scenario not found")


@router.post("/{scenario_id}/run", response_model=DiagnosisReport)
def run_scenario(scenario_id: str, db: Session = Depends(get_db)):
    """
    Executes the expert rule engine against the simulated telemetry of the scenario.
    Demonstrates deterministic evidence evaluation and defense prescription.
    """
    scenarios = get_all_scenarios()
    scenario = next((s for s in scenarios if s.id.lower() == scenario_id.lower()), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    report = analyze_incident_and_save(
        db=db,
        facts=scenario.facts,
        title=f"Scenario: {scenario.title}",
        input_method="scenario",
        save_to_history=True
    )
    return report
