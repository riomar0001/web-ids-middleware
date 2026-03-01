"""
Backward-compatibility shim.

The FeaturePipeline implementation lives in
infrastructure/feature_pipeline.py.  This module re-exports it
so that existing code (`from feature_pipeline import FeaturePipeline`)
continues to work unchanged.
"""

from infrastructure.feature_pipeline import FeaturePipeline  # noqa: F401

__all__ = ["FeaturePipeline"]

