"""
WebhookAlertService — infrastructure implementation of IAlertService.

Maintains a sliding window of recent predictions for rate-based alerting
and delivers alert payloads over HTTP using httpx.
"""

import logging
from collections import deque
from datetime import datetime, timezone

import httpx

from core.config import Settings
from domain.interfaces import IAlertService

log = logging.getLogger("ids-middleware")


class WebhookAlertService(IAlertService):
    """Sends JSON payloads to a webhook URL when attack thresholds are crossed."""

    def __init__(self, settings: Settings) -> None:
        self._webhook_url          = settings.alert_webhook_url
        self._confidence_threshold = settings.alert_confidence_threshold
        self._rate_threshold       = settings.alert_rate_threshold
        self._window: deque[int]   = deque(maxlen=settings.alert_window_size)
        self._window_size          = settings.alert_window_size

        log.info(
            "Alert config  |  webhook=%s  |  conf_thresh=%.2f  "
            "|  rate_thresh=%.2f  |  window=%d",
            self._webhook_url or "(not set)",
            self._confidence_threshold,
            self._rate_threshold,
            self._window_size,
        )

    # ── IAlertService ─────────────────────────────────────────────────────────

    @property
    def confidence_threshold(self) -> float:
        return self._confidence_threshold

    @property
    def rate_threshold(self) -> float:
        return self._rate_threshold

    def record(self, prediction: int) -> None:
        self._window.append(prediction)

    def current_rate(self) -> float:
        if not self._window:
            return 0.0
        return sum(self._window) / len(self._window)

    async def fire(self, payload: dict) -> None:
        if not self._webhook_url:
            return
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self._webhook_url, json=payload)
                log.info(
                    "Alert sent  |  status=%d  |  type=%s",
                    resp.status_code, payload.get("alert_type"),
                )
        except Exception as exc:
            log.warning("Alert delivery failed: %s", exc)

    def config_summary(self) -> dict:
        window   = list(self._window)
        attacks  = sum(window)
        rate_pct = (attacks / len(window) * 100) if window else 0.0
        return {
            "webhook_configured":      bool(self._webhook_url),
            "webhook_url":             self._webhook_url or None,
            "confidence_threshold":    self._confidence_threshold,
            "rate_threshold_pct":      round(self._rate_threshold * 100, 2),
            "window_size":             self._window_size,
            "window_current_size":     len(window),
            "window_attack_count":     attacks,
            "window_attack_rate_pct":  round(rate_pct, 2),
            "env_vars": {
                "ALERT_WEBHOOK_URL":            "ALERT_WEBHOOK_URL",
                "ALERT_CONFIDENCE_THRESHOLD":   "ALERT_CONFIDENCE_THRESHOLD",
                "ALERT_RATE_THRESHOLD":         "ALERT_RATE_THRESHOLD",
                "ALERT_WINDOW_SIZE":            "ALERT_WINDOW_SIZE",
            },
        }
