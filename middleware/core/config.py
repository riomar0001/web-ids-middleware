"""
Core configuration — reads all settings from environment variables.
Provides a singleton Settings object via get_settings().
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Default model directory: one level above middleware/
_DEFAULT_MODEL_DIR = Path(__file__).parent.parent.parent / "model"


@dataclass(frozen=True)
class Settings:
    """Immutable settings bag.  All values come from env vars at startup."""

    model_dir: Path

    # Alert thresholds
    alert_webhook_url: str
    alert_confidence_threshold: float   # fire alert when P(attack) >= this
    alert_rate_threshold: float         # fire alert when batch attack rate >= this
    alert_window_size: int              # sliding window length for rate tracking

    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            model_dir=Path(os.getenv("MODEL_DIR", str(_DEFAULT_MODEL_DIR))),
            alert_webhook_url=os.getenv("ALERT_WEBHOOK_URL", ""),
            alert_confidence_threshold=float(
                os.getenv("ALERT_CONFIDENCE_THRESHOLD", "0.90")
            ),
            alert_rate_threshold=float(
                os.getenv("ALERT_RATE_THRESHOLD", "0.50")
            ),
            alert_window_size=int(os.getenv("ALERT_WINDOW_SIZE", "100")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )


# ── Singleton ────────────────────────────────────────────────────────────────

_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the process-wide Settings singleton, creating it on first call."""
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings
