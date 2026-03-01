"""
Model Loader — loads and validates all artifacts exported by train.ipynb.

Returns the raw sklearn model, the FeaturePipeline, and the metadata dict.
Callers (e.g. ModelDetectionService) own further wrapping.
"""

import json
import logging
from pathlib import Path

import joblib

from infrastructure.feature_pipeline import FeaturePipeline

log = logging.getLogger("ids-middleware")


def load_artifacts(model_dir: Path) -> tuple:
    """
    Load model artifacts from *model_dir*.

    Returns
    -------
    tuple[RandomForestClassifier, FeaturePipeline, dict]
        (model, feature_pipeline, metadata)

    Raises
    ------
    RuntimeError
        If any required artifact file is missing.
    """
    log.info("Loading model artifacts from %s ...", model_dir)
    try:
        model    = joblib.load(model_dir / "rf_model.joblib")
        features = json.loads((model_dir / "feature_names.json").read_text())
        dropped  = json.loads((model_dir / "dropped_correlated.json").read_text())
        meta     = json.loads((model_dir / "metadata.json").read_text())
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Model artifact not found: {exc}\n"
            "Run the last notebook cell (model export) before starting the server."
        ) from exc

    pipeline = FeaturePipeline(features, dropped)
    log.info(
        "Model loaded  |  %d features  |  %d trees",
        len(features),
        model.n_estimators,
    )
    return model, pipeline, meta
