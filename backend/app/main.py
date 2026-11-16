"""Main FastAPI Application entry point for CyberMate.
Defensive Cybersecurity Threat Detection & Diagnosis Expert System.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.database.db import init_db
from app.api.analyze import router as analyze_router
from app.api.chat import router as chat_router
from app.api.history import router as history_router
from app.api.threats import router as threats_router
from app.api.scenarios import router as scenarios_router
from app.api.password import router as password_router
from app.api.dashboard import router as dashboard_router

# Initialize database schema tables
init_db()

app = FastAPI(
    title="CyberMate Expert System API",
    description="Defensive Cybersecurity Threat Detection & Diagnosis Expert System powered by a deterministic rule engine.",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(dashboard_router)
app.include_router(analyze_router)
app.include_router(chat_router)
app.include_router(threats_router)
app.include_router(scenarios_router)
app.include_router(password_router)
app.include_router(history_router)


@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "system": "CyberMate Expert Engine",
        "version": "1.0.0",
        "mode": "Defensive Deterministic Reasoning"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """User-friendly global exception handler preventing leaked stack traces."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred during expert system evaluation.",
            "detail": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
