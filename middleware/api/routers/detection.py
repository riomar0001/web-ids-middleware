"""
Detection router — classify NetFlow records as Normal or Attack.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_alert_service, get_detection_service
from api.schemas.netflow import NetFlowRecord
from api.schemas.responses import BatchRequest, BatchResponse, ExplainResponse, PredictionResponse
from domain.interfaces import IAlertService, IDetectionService

router = APIRouter(tags=["Detection"])


@router.post("/predict", response_model=PredictionResponse)
async def predict(
    record: NetFlowRecord,
    svc:    IDetectionService = Depends(get_detection_service),
    alerts: IAlertService     = Depends(get_alert_service),
) -> PredictionResponse:
    """
    Classify a single NetFlow record as Normal (0) or Attack (1).

    Fires a webhook alert when confidence ≥ ALERT_CONFIDENCE_THRESHOLD.
    """
    try:
        raw = record.model_dump()
        result = svc.predict(raw)
        alerts.record(result.prediction)

        if result.prediction == 1 and result.confidence >= alerts.confidence_threshold:
            await alerts.fire({
                "alert_type":   "HIGH_CONFIDENCE_ATTACK",
                "confidence":   result.confidence,
                "threat_level": result.threat_level.value,
                "dst_port":     raw.get("L4_DST_PORT"),
                "protocol":     raw.get("PROTOCOL"),
            })

        return PredictionResponse.from_entity(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/predict/batch", response_model=BatchResponse)
async def predict_batch(
    body:   BatchRequest,
    svc:    IDetectionService = Depends(get_detection_service),
    alerts: IAlertService     = Depends(get_alert_service),
) -> BatchResponse:
    """
    Classify up to 1 000 NetFlow records in a single call.

    Fires a webhook alert when the batch attack rate ≥ ALERT_RATE_THRESHOLD.
    """
    try:
        batch = svc.predict_batch(body.records)
        for r in batch.results:
            alerts.record(r.prediction)

        if alerts.current_rate() >= alerts.rate_threshold:
            await alerts.fire({
                "alert_type":      "HIGH_ATTACK_RATE",
                "batch_size":      batch.total,
                "attack_count":    batch.attacks,
                "attack_rate_pct": batch.attack_rate_pct,
                "threshold_pct":   round(alerts.rate_threshold * 100, 2),
            })

        return BatchResponse.from_entity(batch)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/predict/explain", response_model=ExplainResponse)
async def predict_explain(
    record: NetFlowRecord,
    svc:    IDetectionService = Depends(get_detection_service),
    alerts: IAlertService     = Depends(get_alert_service),
) -> ExplainResponse:
    """
    Classify a single record and return the top 5 most influential features
    plus a human-readable summary.

    Fires a webhook alert when confidence ≥ ALERT_CONFIDENCE_THRESHOLD.
    """
    try:
        raw = record.model_dump()
        result = svc.predict_explain(raw)
        alerts.record(result.prediction)

        if result.prediction == 1 and result.confidence >= alerts.confidence_threshold:
            await alerts.fire({
                "alert_type":    "HIGH_CONFIDENCE_ATTACK",
                "confidence":    result.confidence,
                "threat_level":  result.threat_level.value,
                "top_indicator": result.top_features[0].feature if result.top_features else None,
                "dst_port":      raw.get("L4_DST_PORT"),
            })

        return ExplainResponse.from_entity(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
