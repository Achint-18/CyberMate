"""API endpoint for live dashboard metrics."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.schemas.incident import DashboardMetrics
from app.services.incident_service import get_dashboard_metrics

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/metrics", response_model=DashboardMetrics)
def fetch_metrics(db: Session = Depends(get_db)):
    """Computes real-time dashboard metrics from local database and expert engine."""
    return get_dashboard_metrics(db)
