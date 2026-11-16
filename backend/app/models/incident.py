"""SQLAlchemy ORM Model for persisting analyzed security incidents."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, DateTime
from app.database.db import Base


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False, default="Security Incident Analysis")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    input_method = Column(String(50), default="structured")  # structured, chat, scenario
    primary_threat = Column(String(255), nullable=False, default="Unclassified")
    severity = Column(String(50), nullable=False, default="LOW")
    confidence = Column(Float, nullable=False, default=0.0)
    confidence_label = Column(String(50), nullable=False, default="Uncertain")
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(50), nullable=False, default="Low")
    summary = Column(Text, nullable=False, default="")
    facts_json = Column(Text, nullable=False, default="{}")
    report_json = Column(Text, nullable=False, default="{}")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "input_method": self.input_method,
            "primary_threat": self.primary_threat,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
        }
