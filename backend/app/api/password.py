"""API endpoint for cryptographically secure password generation."""
from fastapi import APIRouter
from app.services.password_service import (
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    generate_secure_password
)

router = APIRouter(prefix="/api/password", tags=["Password Generator"])


@router.post("/generate", response_model=PasswordGenerateResponse)
def generate_password(req: PasswordGenerateRequest):
    """
    Generates a cryptographically strong password using system CSPRNG (secrets module).
    Calculates Shannon entropy and crack resistance.
    Zero-storage guarantee: Never logs or stores generated passwords.
    """
    return generate_secure_password(req)
