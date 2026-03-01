"""
API response schemas.

These are the Pydantic models returned by all detection and alert endpoints.
Each schema exposes a `from_entity()` class method so that routers stay thin —
they receive a domain entity and call `ResponseModel.from_entity(entity)`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from domain.entities import (
    BatchPrediction,
    ExplainedPrediction,
    FeatureContribution,
    Prediction,
)


# ── Shared sub-models ─────────────────────────────────────────────────────────

class FeatureContributionOut(BaseModel):
    feature:    str
    importance: float
    value:      float

    @classmethod
    def from_entity(cls, fc: FeatureContribution) -> "FeatureContributionOut":
        return cls(feature=fc.feature, importance=fc.importance, value=fc.value)


# ── Single-record response ────────────────────────────────────────────────────

class PredictionResponse(BaseModel):
    prediction:   int   = Field(..., description="0 = Normal, 1 = Attack")
    label:        str   = Field(..., description='"Normal" or "Attack"')
    confidence:   float = Field(..., description="P(Attack)")
    threat_level: str   = Field(..., description="LOW / MEDIUM / HIGH / CRITICAL")
    latency_ms:   float

    @classmethod
    def from_entity(cls, p: Prediction) -> "PredictionResponse":
        return cls(
            prediction=p.prediction,
            label=p.label,
            confidence=p.confidence,
            threat_level=p.threat_level.value,
            latency_ms=p.latency_ms,
        )


# ── Explain response ──────────────────────────────────────────────────────────

class ExplainResponse(PredictionResponse):
    top_features:     list[FeatureContributionOut]
    decision_summary: str

    @classmethod
    def from_entity(cls, p: "ExplainedPrediction") -> "ExplainResponse":  # type: ignore[override]
        return cls(
            prediction=p.prediction,
            label=p.label,
            confidence=p.confidence,
            threat_level=p.threat_level.value,
            latency_ms=p.latency_ms,
            top_features=[FeatureContributionOut.from_entity(f) for f in p.top_features],
            decision_summary=p.decision_summary,
        )


# ── Batch response ────────────────────────────────────────────────────────────

class BatchResultItem(BaseModel):
    prediction:   int
    label:        str
    confidence:   float
    threat_level: str

    @classmethod
    def from_entity(cls, p: Prediction) -> "BatchResultItem":
        return cls(
            prediction=p.prediction,
            label=p.label,
            confidence=p.confidence,
            threat_level=p.threat_level.value,
        )


class BatchSummary(BaseModel):
    total:        int
    attacks:      int
    normal:       int
    attack_rate:  float = Field(..., description="Attack percentage (0–100)")
    latency_ms:   float


class BatchResponse(BaseModel):
    results: list[BatchResultItem]
    summary: BatchSummary

    @classmethod
    def from_entity(cls, bp: BatchPrediction) -> "BatchResponse":
        return cls(
            results=[BatchResultItem.from_entity(r) for r in bp.results],
            summary=BatchSummary(
                total=bp.total,
                attacks=bp.attacks,
                normal=bp.normal,
                attack_rate=bp.attack_rate_pct,
                latency_ms=bp.latency_ms,
            ),
        )


# ── Batch request ─────────────────────────────────────────────────────────────

class BatchRequest(BaseModel):
    records: list[dict[str, Any]] = Field(..., max_length=1000)
