"""Database configuration and session management for CyberMate.
Uses SQLite by default with seamless PostgreSQL migration capability via DATABASE_URL.
Supports Vercel serverless environment by utilizing /tmp for SQLite if VERCEL is detected.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# On Vercel serverless, the root filesystem is read-only; use /tmp for SQLite
default_db = "sqlite:////tmp/cybermate.db" if os.getenv("VERCEL") else "sqlite:///./cybermate.db"
DATABASE_URL = os.getenv("DATABASE_URL", default_db)

# SQLite specific argument check
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency to yield a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes database schema tables."""
    Base.metadata.create_all(bind=engine)
