"""API endpoints for Threat Library and active diagnostic rules."""
from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException

from app.knowledge_base.threats_data import get_all_threat_profiles, ThreatProfile
from app.services.incident_service import get_engine
from app.rules.condition import Rule

router = APIRouter(prefix="/api/threats", tags=["Threat Library"])


@router.get("", response_model=List[ThreatProfile])
def list_threats(
    query: Optional[str] = Query(None, description="Search query across name and description"),
    category: Optional[str] = Query(None, description="Filter by threat domain category")
):
    """Returns the defensive threat catalog with optional search filtering."""
    threats = get_all_threat_profiles()
    if category:
        threats = [t for t in threats if t.category.lower() == category.lower()]
    if query:
        q = query.lower()
        threats = [
            t for t in threats
            if q in t.name.lower() or q in t.summary.lower() or q in t.detailed_description.lower()
        ]
    return threats


@router.get("/{threat_id}", response_model=ThreatProfile)
def get_threat(threat_id: str):
    """Retrieves a single threat profile by ID."""
    threats = get_all_threat_profiles()
    for t in threats:
        if t.id.lower() == threat_id.lower():
            return t
    raise HTTPException(status_code=404, detail="Threat profile not found")


@router.get("/system/rules", response_model=List[Rule])
def list_active_rules():
    """Lists all active deterministic diagnostic rules registered in the CyberMate engine."""
    engine = get_engine()
    return engine.rules
