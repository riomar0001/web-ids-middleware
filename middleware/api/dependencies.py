"""
Dependency providers — the single place where concrete infrastructure
objects are injected into route handlers via FastAPI's Depends() system.

Call `init_services()` once at application startup (lifespan hook in main.py).
"""

from __future__ import annotations

from core.config import get_settings
from domain.interfaces import IAlertService, IDetectionService
from infrastructure.alert_service import WebhookAlertService
from infrastructure.detection_service import ModelDetectionService
from infrastructure.model_loader import load_artifacts

# ── Singleton service instances (set by init_services) ───────────────────────

_detection: IDetectionService | None = None
_alert:     IAlertService     | None = None


def init_services() -> None:
    """Bootstrap all services.  Called once from the application lifespan."""
    global _detection, _alert
    settings = get_settings()
    model, pipeline, meta = load_artifacts(settings.model_dir)
    _detection = ModelDetectionService(model, pipeline, meta)
    _alert     = WebhookAlertService(settings)


# ── FastAPI dependency functions ──────────────────────────────────────────────

def get_detection_service() -> IDetectionService:
    assert _detection is not None, "Services not initialised — call init_services() first."
    return _detection


def get_alert_service() -> IAlertService:
    assert _alert is not None, "Services not initialised — call init_services() first."
    return _alert
