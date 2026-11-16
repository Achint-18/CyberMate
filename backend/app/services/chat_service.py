"""Chat diagnosis service for CyberMate.
Bridges natural language descriptions with deterministic expert system reasoning.
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.utils.nlp_extractor import NaturalLanguageExtractor
from app.services.incident_service import analyze_incident_and_save
from app.schemas.incident import ChatDiagnosisResponse

_nlp_extractor = NaturalLanguageExtractor()


def process_chat_diagnosis(
    db: Session,
    query: str,
    save_to_history: bool = True
) -> ChatDiagnosisResponse:
    """Processes natural language inquiry, extracts facts, and executes rule diagnosis."""
    facts, observations = _nlp_extractor.extract_facts(query)

    title = f"Chat: {query[:45]}..." if len(query) > 45 else f"Chat: {query}"
    report = analyze_incident_and_save(
        db=db,
        facts=facts,
        title=title,
        input_method="chat",
        save_to_history=save_to_history
    )

    return ChatDiagnosisResponse(
        user_query=query,
        extracted_observations=observations,
        extracted_facts=facts,
        diagnosis_report=report
    )
