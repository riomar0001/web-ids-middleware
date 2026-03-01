"""
Domain interfaces (ports) — abstract boundaries between layers.

The application and API layers depend only on these contracts;
concrete implementations live in the infrastructure layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from domain.entities import BatchPrediction, ExplainedPrediction, Prediction


class IDetectionService(ABC):
    """Port for the intrusion-detection capability."""

    @abstractmethod
    def predict(self, raw: dict) -> Prediction:
        """Classify a single raw NetFlow record."""

    @abstractmethod
    def predict_batch(self, records: list[dict]) -> BatchPrediction:
        """Classify a list of raw NetFlow records in one pass."""

    @abstractmethod
    def predict_explain(self, raw: dict) -> ExplainedPrediction:
        """Classify and explain which features drove the decision."""

    @property
    @abstractmethod
    def model_metadata(self) -> dict:
        """Return serialisable model metadata (version, performance metrics, etc.)."""


class IAlertService(ABC):
    """Port for the async alerting / notification capability."""

    @abstractmethod
    async def fire(self, payload: dict) -> None:
        """Deliver an alert payload to the configured destination.
        Must never raise — failures should be logged and swallowed."""

    @abstractmethod
    def record(self, prediction: int) -> None:
        """Add one prediction (0 or 1) to the sliding window."""

    @abstractmethod
    def current_rate(self) -> float:
        """Return the attack fraction in the current sliding window (0‥1)."""

    @property
    @abstractmethod
    def confidence_threshold(self) -> float:
        """P(attack) threshold above which individual alerts are fired."""

    @property
    @abstractmethod
    def rate_threshold(self) -> float:
        """Attack-rate fraction above which batch alerts are fired."""

    @abstractmethod
    def config_summary(self) -> dict:
        """Return a serialisable snapshot of the current alert configuration."""
