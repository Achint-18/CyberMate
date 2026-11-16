"""API endpoint for conversational security assistant diagnosis."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.schemas.incident import ChatDiagnosisRequest, ChatDiagnosisResponse
from app.services.chat_service import process_chat_diagnosis

router = APIRouter(prefix="/api/chat", tags=["Chat Diagnosis"])


@router.post("", response_model=ChatDiagnosisResponse)
def chat_diagnose(req: ChatDiagnosisRequest, db: Session = Depends(get_db)):
    """
    Parses natural language security observations, extracts facts,
    and feeds them through the deterministic expert rule engine.
    """
    try:
        response = process_chat_diagnosis(
            db=db,
            query=req.query,
            save_to_history=req.save_to_history
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat diagnosis error: {str(e)}")
