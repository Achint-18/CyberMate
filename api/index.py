"""Vercel Serverless Function entry point for CyberMate FastAPI backend."""
import sys
import os

# Ensure backend directory is in the import path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app
