"""
ModelDetectionService — infrastructure implementation of IDetectionService.

Wraps the sklearn RandomForestClassifier and FeaturePipeline and converts
raw outputs into domain entities.  No HTTP / FastAPI knowledge here.
"""

import logging
import time

import numpy as np
import pandas as pd

from domain.entities import (
    BatchPrediction,
    ExplainedPrediction,
    FeatureContribution,
    Prediction,
    ThreatLevel,
)
from domain.interfaces import IDetectionService
from infrastructure.feature_pipeline import FeaturePipeline

log = logging.getLogger("ids-middleware")


class ModelDetectionService(IDetectionService):
    """Classifies NetFlow records using the trained Random Forest model."""

    def __init__(self, model, pipeline: FeaturePipeline, meta: dict) -> None:
        self._model    = model
        self._pipeline = pipeline
        self._meta     = meta

    # ── IDetectionService ─────────────────────────────────────────────────────

    @property
    def model_metadata(self) -> dict:
        return self._meta

    def predict(self, raw: dict) -> Prediction:
        t0    = time.perf_counter()
        X     = self._pipeline.transform(raw)
        proba = float(self._model.predict_proba(X)[0][1])
        latency = (time.perf_counter() - t0) * 1000

        p = Prediction.build(proba, latency)
        if p.prediction == 1:
            log.warning(
                "ATTACK detected  |  confidence=%.3f  |  port=%s",
                proba, raw.get("L4_DST_PORT"),
            )
        return p

    def predict_batch(self, records: list[dict]) -> BatchPrediction:
        t0     = time.perf_counter()
        df     = pd.DataFrame(records)
        X      = self._pipeline.transform_batch(df)
        probas = self._model.predict_proba(X)[:, 1]

        results: list[Prediction] = []
        attack_count = 0
        for proba in probas:
            p = Prediction.build(float(proba), latency_ms=0.0)
            attack_count += p.prediction
            results.append(p)

        latency = (time.perf_counter() - t0) * 1000
        total   = len(results)
        log.info(
            "Batch  |  %d records  |  %d attacks  |  %.1f ms",
            total, attack_count, latency,
        )
        return BatchPrediction(
            results=results,
            total=total,
            attacks=int(attack_count),
            normal=int(total - attack_count),
            attack_rate_pct=round(attack_count / total * 100, 2),
            latency_ms=round(latency, 2),
        )

    def predict_explain(self, raw: dict) -> ExplainedPrediction:
        t0     = time.perf_counter()
        X_arr  = self._pipeline.transform(raw)
        X_df   = pd.DataFrame(X_arr, columns=self._pipeline.feature_names)
        proba  = float(self._model.predict_proba(X_arr)[0][1])
        latency = (time.perf_counter() - t0) * 1000

        pred, label = Prediction.classify(proba)
        top = self._top_features(X_df)

        if pred == 1:
            summary = (
                f"Flow classified as Attack (confidence {proba:.1%}). "
                f"Primary indicator: {top[0].feature} = {top[0].value:.4g}. "
                f"Threat level: {ThreatLevel.from_confidence(proba).value}."
            )
        else:
            summary = (
                f"Flow classified as Normal (confidence {1 - proba:.1%}). "
                f"No strong attack indicators detected."
            )

        return ExplainedPrediction(
            prediction=pred,
            label=label,
            confidence=round(proba, 6),
            threat_level=ThreatLevel.from_confidence(proba),
            latency_ms=round(latency, 2),
            top_features=top,
            decision_summary=summary,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _top_features(
        self, record_df: pd.DataFrame, n: int = 5
    ) -> list[FeatureContribution]:
        importances = self._model.feature_importances_
        feat_vals   = record_df.values[0]
        ranked = sorted(
            zip(self._pipeline.feature_names, importances, feat_vals),
            key=lambda t: -t[1],
        )[:n]
        return [
            FeatureContribution(
                feature=name,
                importance=round(float(imp), 4),
                value=round(float(val), 6),
            )
            for name, imp, val in ranked
        ]
