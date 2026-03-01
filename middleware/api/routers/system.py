"""
System router — liveness and model-info endpoints.
"""

from fastapi import APIRouter, Depends

from api.dependencies import get_detection_service
from domain.interfaces import IDetectionService

router = APIRouter(tags=["System"])


@router.get("/health")
def health(svc: IDetectionService = Depends(get_detection_service)):
    """Liveness check — returns 200 when the model is loaded and ready."""
    meta = svc.model_metadata
    return {
        "status": "ok",
        "model_loaded": True,
        "n_trees": meta.get("n_estimators"),
    }


@router.get("/model/info")
def model_info(svc: IDetectionService = Depends(get_detection_service)):
    """Return model metadata including feature list and training performance."""
    return svc.model_metadata
