"""
Alerts router — inspect and test the alert configuration.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_alert_service
from domain.interfaces import IAlertService

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/config")
def alerts_config(alerts: IAlertService = Depends(get_alert_service)):
    """Return the current alert thresholds and sliding-window statistics."""
    return alerts.config_summary()


@router.post("/test")
async def alerts_test(alerts: IAlertService = Depends(get_alert_service)):
    """
    Send a test payload to the configured webhook URL.
    Returns HTTP 400 if no webhook is configured.
    """
    summary = alerts.config_summary()
    if not summary.get("webhook_configured"):
        raise HTTPException(
            status_code=400,
            detail="No webhook configured. Set the ALERT_WEBHOOK_URL environment variable.",
        )
    await alerts.fire({
        "alert_type": "TEST",
        "message":    "IDS Middleware alert test — webhook delivery confirmed.",
        "confidence_threshold": alerts.confidence_threshold,
        "rate_threshold_pct":   round(alerts.rate_threshold * 100, 2),
    })
    return {"status": "test alert sent", "webhook_url": summary.get("webhook_url")}
