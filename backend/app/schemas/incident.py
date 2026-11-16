"""Pydantic schemas for CyberMate API requests and responses."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.rules.engine import DiagnosisReport, SecurityRiskScore


class AnalyzeRequest(BaseModel):
    title: Optional[str] = "Incident Analysis"
    facts: Dict[str, Any] = Field(default_factory=dict)
    input_method: Optional[str] = "structured"
    save_to_history: bool = True


class ChatDiagnosisRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=2000, description="Natural language description of security observations")
    save_to_history: bool = True


class ChatDiagnosisResponse(BaseModel):
    user_query: str
    extracted_observations: List[str]
    extracted_facts: Dict[str, Any]
    diagnosis_report: DiagnosisReport


class IncidentSummary(BaseModel):
    id: str
    title: str
    timestamp: str
    input_method: str
    primary_threat: str
    severity: str
    confidence: float
    confidence_label: str
    risk_score: int
    risk_level: str
    summary: str


class IncidentDetail(BaseModel):
    id: str
    title: str
    timestamp: str
    input_method: str
    primary_threat: str
    severity: str
    confidence: float
    confidence_label: str
    risk_score: int
    risk_level: str
    summary: str
    facts: Dict[str, Any]
    report: DiagnosisReport


class DashboardMetrics(BaseModel):
    overall_risk_score: int
    overall_risk_level: str
    incidents_analyzed: int
    high_critical_count: int
    threat_library_count: int
    rules_active_count: int
    recent_diagnoses: List[IncidentSummary]
