"""API endpoints for structured incident analysis and risk calculation."""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.schemas.incident import AnalyzeRequest
from app.rules.engine import DiagnosisReport, SecurityRiskScore
from app.services.incident_service import analyze_incident_and_save, get_engine
from app.knowledge_base.indicators_data import get_all_indicators, IndicatorMetadata

router = APIRouter(prefix="/api", tags=["Incident Analysis"])


@router.get("/indicators", response_model=List[IndicatorMetadata])
def list_indicators():
    """Returns the comprehensive catalog of security indicators organized by domain."""
    return get_all_indicators()


@router.post("/analyze", response_model=DiagnosisReport)
def analyze_incident(req: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Submits structured security observations to the deterministic expert system.
    Evaluates rules, detects threats, generates explanations, and assigns risk.
    """
    try:
        report = analyze_incident_and_save(
            db=db,
            facts=req.facts,
            title=req.title or "Incident Analysis",
            input_method=req.input_method or "structured",
            save_to_history=req.save_to_history
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error during incident analysis: {str(e)}")


@router.post("/risk-score", response_model=SecurityRiskScore)
def calculate_risk_score(facts: Dict[str, Any]):
    """Calculates a deterministic 0-100 security risk score directly from observed facts."""
    try:
        engine = get_engine()
        report = engine.diagnose(facts)
        return report.risk_score
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk scoring evaluation error: {str(e)}")
