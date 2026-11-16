"""Incident service managing rule execution, report generation, and SQLite persistence."""
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.rules.engine import ExpertSystemEngine, DiagnosisReport
from app.rules.definitions import get_all_rules
from app.models.incident import IncidentRecord
from app.schemas.incident import (
    IncidentSummary,
    IncidentDetail,
    DashboardMetrics
)
from app.knowledge_base.threats_data import get_all_threat_profiles

# Singleton instance of the Expert System Engine loaded with all 49 rules
_engine = ExpertSystemEngine()
_engine.register_rules(get_all_rules())


def get_engine() -> ExpertSystemEngine:
    return _engine


def analyze_incident_and_save(
    db: Session,
    facts: Dict[str, Any],
    title: str = "Incident Analysis",
    input_method: str = "structured",
    save_to_history: bool = True
) -> DiagnosisReport:
    """Runs deterministic diagnosis and optionally persists the incident."""
    engine = get_engine()
    report = engine.diagnose(facts)

    if save_to_history:
        primary_threat = report.primary_threat.threat if report.primary_threat else "No Threat Detected"
        severity = report.primary_threat.severity if report.primary_threat else "LOW"
        confidence = report.primary_threat.confidence if report.primary_threat else 0.0
        confidence_label = report.primary_threat.confidence_label if report.primary_threat else "Uncertain"

        record = IncidentRecord(
            title=title or (f"{primary_threat} Analysis"),
            timestamp=datetime.now(timezone.utc),
            input_method=input_method,
            primary_threat=primary_threat,
            severity=severity,
            confidence=confidence,
            confidence_label=confidence_label,
            risk_score=report.risk_score.score,
            risk_level=report.risk_score.level,
            summary=report.summary,
            facts_json=json.dumps(facts),
            report_json=report.model_dump_json()
        )
        db.add(record)
        db.commit()
        db.refresh(record)

    return report


def list_incidents(db: Session, limit: int = 50) -> List[IncidentSummary]:
    """Retrieves chronological incident history."""
    records = db.query(IncidentRecord).order_by(desc(IncidentRecord.timestamp)).limit(limit).all()
    summaries = []
    for r in records:
        summaries.append(IncidentSummary(
            id=r.id,
            title=r.title,
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            input_method=r.input_method,
            primary_threat=r.primary_threat,
            severity=r.severity,
            confidence=r.confidence,
            confidence_label=r.confidence_label,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            summary=r.summary
        ))
    return summaries


def get_incident_by_id(db: Session, incident_id: str) -> Optional[IncidentDetail]:
    """Retrieves full detail of a previously saved incident."""
    r = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
    if not r:
        return None

    try:
        report_data = json.loads(r.report_json)
        report = DiagnosisReport(**report_data)
    except Exception:
        report = get_engine().diagnose(json.loads(r.facts_json))

    return IncidentDetail(
        id=r.id,
        title=r.title,
        timestamp=r.timestamp.isoformat() if r.timestamp else "",
        input_method=r.input_method,
        primary_threat=r.primary_threat,
        severity=r.severity,
        confidence=r.confidence,
        confidence_label=r.confidence_label,
        risk_score=r.risk_score,
        risk_level=r.risk_level,
        summary=r.summary,
        facts=json.loads(r.facts_json) if r.facts_json else {},
        report=report
    )


def delete_incident(db: Session, incident_id: str) -> bool:
    """Deletes an incident record by ID."""
    r = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
    if not r:
        return False
    db.delete(r)
    db.commit()
    return True


def clear_all_incidents(db: Session) -> int:
    """Clears all incident history from the database."""
    count = db.query(IncidentRecord).delete()
    db.commit()
    return count


def get_dashboard_metrics(db: Session) -> DashboardMetrics:
    """Calculates live dashboard metrics from database and expert system."""
    total_analyzed = db.query(IncidentRecord).count()
    high_critical = db.query(IncidentRecord).filter(IncidentRecord.severity.in_(["HIGH", "CRITICAL"])).count()
    recent_records = db.query(IncidentRecord).order_by(desc(IncidentRecord.timestamp)).limit(5).all()

    # Calculate aggregate or recent risk score
    if recent_records:
        avg_score = int(sum(r.risk_score for r in recent_records) / len(recent_records))
    else:
        avg_score = 0

    if avg_score <= 25:
        risk_level = "Low"
    elif avg_score <= 50:
        risk_level = "Moderate"
    elif avg_score <= 75:
        risk_level = "High"
    else:
        risk_level = "Critical"

    recent_summaries = [
        IncidentSummary(
            id=r.id,
            title=r.title,
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            input_method=r.input_method,
            primary_threat=r.primary_threat,
            severity=r.severity,
            confidence=r.confidence,
            confidence_label=r.confidence_label,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            summary=r.summary
        )
        for r in recent_records
    ]

    return DashboardMetrics(
        overall_risk_score=avg_score,
        overall_risk_level=risk_level,
        incidents_analyzed=total_analyzed,
        high_critical_count=high_critical,
        threat_library_count=len(get_all_threat_profiles()),
        rules_active_count=get_engine().get_rule_count(),
        recent_diagnoses=recent_summaries
    )
