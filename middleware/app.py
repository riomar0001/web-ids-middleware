"""
Entry point kept for uvicorn backwards compatibility.

The application is assembled in main.py (clean architecture).
Run with:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from main import app  # noqa: F401
