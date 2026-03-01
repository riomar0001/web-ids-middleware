"""
Feature Pipeline — infrastructure implementation.

Replicates every transformation from train.ipynb so that raw NetFlow
records submitted to the API receive exactly the same preprocessing
that was applied during training.

This file is the single source of truth for the pipeline.
`middleware/feature_pipeline.py` (root) re-exports from here so that
the notebook cell `from feature_pipeline import FeaturePipeline` keeps
working without change.
"""

import numpy as np
import pandas as pd
from typing import Union


# ── Constants (mirror train.ipynb) ───────────────────────────────────────────

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

DROP_ALWAYS = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
    "ICMP_TYPE", "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
    "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
    "Label", "Attack", "Attack_Label",
]


class FeaturePipeline:
    """
    Stateless transformation pipeline.

    Parameters
    ----------
    feature_names : list[str]
        Ordered features the model was trained on (model/feature_names.json).
    dropped_correlated : list[str]
        Columns removed during correlation filtering (model/dropped_correlated.json).
    """

    def __init__(self, feature_names: list[str], dropped_correlated: list[str]) -> None:
        self.feature_names     = feature_names
        self.dropped_correlated = dropped_correlated

    # ── Public API ────────────────────────────────────────────────────────────

    def transform(self, record: dict) -> np.ndarray:
        """Transform a single NetFlow dict → (1, n_features) array."""
        return self._apply(pd.DataFrame([record]))

    def transform_batch(self, df: pd.DataFrame) -> np.ndarray:
        """Transform a DataFrame of NetFlow records → (n, n_features) array."""
        return self._apply(df.copy())

    # ── Pipeline steps (each mirrors a notebook cell) ────────────────────────

    def _apply(self, df: pd.DataFrame) -> np.ndarray:
        df = self._fix_types(df)
        df = self._drop_raw_columns(df)
        df = self._engineer_features(df)
        df = self._drop_correlated(df)
        df = self._align_columns(df)
        return df.values

    def _fix_types(self, df: pd.DataFrame) -> pd.DataFrame:
        float_cols = df.select_dtypes(include=["float64"]).columns.tolist()
        for col in float_cols:
            df[col] = df[col].replace([np.inf, -np.inf], 0).fillna(0).astype(np.int64)
        return df.fillna(0)

    def _drop_raw_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        return df.drop(columns=[c for c in DROP_ALWAYS if c in df.columns], errors="ignore")

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        idx = df.index

        def col(name: str) -> "pd.Series":
            return df[name] if name in df.columns else pd.Series(0, index=idx)

        if "L4_DST_PORT" in df.columns:
            df["IS_WEB_PORT"] = df["L4_DST_PORT"].isin(WEB_PORTS).astype(int)

        df["BYTES_RATIO"]       = _safe_div(col("IN_BYTES"),  col("OUT_BYTES"))
        df["PKTS_RATIO"]        = _safe_div(col("IN_PKTS"),   col("OUT_PKTS"))
        df["BYTES_PER_PKT_IN"]  = _safe_div(col("IN_BYTES"),  col("IN_PKTS"))
        df["BYTES_PER_PKT_OUT"] = _safe_div(col("OUT_BYTES"), col("OUT_PKTS"))

        if "LONGEST_FLOW_PKT" in df.columns and "SHORTEST_FLOW_PKT" in df.columns:
            df["PKT_SIZE_RANGE"] = df["LONGEST_FLOW_PKT"] - df["SHORTEST_FLOW_PKT"]

        df["RETRANS_RATE_IN"]   = _safe_div(col("RETRANSMITTED_IN_PKTS"),  col("IN_PKTS"))
        df["RETRANS_RATE_OUT"]  = _safe_div(col("RETRANSMITTED_OUT_PKTS"), col("OUT_PKTS"))
        df["THROUGHPUT_RATIO"]  = _safe_div(col("SRC_TO_DST_AVG_THROUGHPUT"), col("DST_TO_SRC_AVG_THROUGHPUT"))
        df["IAT_AVG_RATIO"]     = _safe_div(col("SRC_TO_DST_IAT_AVG"),     col("DST_TO_SRC_IAT_AVG"))

        total_pkts = col("IN_PKTS") + col("OUT_PKTS")
        df["DURATION_PER_PKT"] = _safe_div(col("FLOW_DURATION_MILLISECONDS"), total_pkts)
        df["SMALL_PKT_RATIO"]  = _safe_div(col("NUM_PKTS_UP_TO_128_BYTES"), total_pkts)

        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], 0)
        return df

    def _drop_correlated(self, df: pd.DataFrame) -> pd.DataFrame:
        return df.drop(
            columns=[c for c in self.dropped_correlated if c in df.columns],
            errors="ignore",
        )

    def _align_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        return df[self.feature_names]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_div(
    numerator: "pd.Series",
    denominator: "pd.Series",
) -> "pd.Series":
    """Element-wise division that returns 0 wherever the denominator is 0."""
    return pd.Series(np.where(denominator != 0, numerator / denominator.replace(0, 1), 0), index=numerator.index)
