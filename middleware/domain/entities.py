"""
Domain entities — pure Python dataclasses with no framework dependencies.

These are the canonical business objects that flow through every layer:
    ThreatLevel            → enum that maps P(attack) to a risk label
    FeatureContribution    → one feature's influence on a prediction
    Prediction             → result of classifying a single flow
    ExplainedPrediction    → Prediction + top features + human summary
    BatchPrediction        → results of classifying many flows at once
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ── Value objects ─────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @staticmethod
    def from_confidence(confidence: float) -> "ThreatLevel":
        """Map P(attack) → ThreatLevel using fixed industry thresholds."""
        if confidence >= 0.90:
            return ThreatLevel.CRITICAL
        if confidence >= 0.70:
            return ThreatLevel.HIGH
        if confidence >= 0.50:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW


@dataclass(frozen=True)
class FeatureContribution:
    """The influence of a single feature on a prediction."""
    feature:    str
    importance: float   # global Gini importance from the RF model
    value:      float   # actual value in this record


# ── Aggregate roots ───────────────────────────────────────────────────────────

@dataclass
class Prediction:
    """Result of classifying a single NetFlow record."""
    prediction:   int          # 0 = Normal, 1 = Attack
    label:        str          # "Normal" or "Attack"
    confidence:   float        # P(Attack) — probability of class 1
    threat_level: ThreatLevel
    latency_ms:   float        # end-to-end inference time

    @staticmethod
    def classify(confidence: float) -> tuple[int, str]:
        """Convert a raw probability into (prediction_int, label_str)."""
        pred = 1 if confidence >= 0.5 else 0
        return pred, ("Attack" if pred == 1 else "Normal")

    @staticmethod
    def build(confidence: float, latency_ms: float) -> "Prediction":
        pred, label = Prediction.classify(confidence)
        return Prediction(
            prediction=pred,
            label=label,
            confidence=round(confidence, 6),
            threat_level=ThreatLevel.from_confidence(confidence),
            latency_ms=round(latency_ms, 2),
        )


@dataclass
class ExplainedPrediction(Prediction):
    """Prediction enriched with top feature contributions and a plain-English summary."""
    top_features:     list[FeatureContribution] = field(default_factory=list)
    decision_summary: str = ""


@dataclass
class BatchPrediction:
    """Results of classifying a batch of NetFlow records."""
    results:       list[Prediction]
    total:         int
    attacks:       int
    normal:        int
    attack_rate_pct: float
    latency_ms:    float
