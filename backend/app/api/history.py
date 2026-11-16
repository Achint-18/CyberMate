"""API endpoints for managing analyzed incident history in SQLite."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.schemas.incident import IncidentSummary, IncidentDetail
from app.services.incident_service import (
    list_incidents,
    get_incident_by_id,
    delete_incident,
    clear_all_incidents
)

router = APIRouter(prefix="/api/history", tags=["Incident History"])


@router.get("", response_model=List[IncidentSummary])
def get_incident_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieves chronological incident history."""
    return list_incidents(db, limit=limit)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident_details(incident_id: str, db: Session = Depends(get_db)):
    """Retrieves full diagnostic report and evidence for a specific incident."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident record not found")
    return incident


@router.delete("/{incident_id}")
def remove_incident(incident_id: str, db: Session = Depends(get_db)):
    """Deletes an incident by ID."""
    success = delete_incident(db, incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Incident record not found")
    return {"status": "success", "message": f"Incident {incident_id} deleted"}


@router.delete("")
def clear_history(db: Session = Depends(get_db)):
    """Clears all analyzed incident history."""
    count = clear_all_incidents(db)
    return {"status": "success", "deleted_count": count}
