"""Stage 3 - Validation.

Identifies anomalies relative to the acquired corpus and fuses every indicator
into a single explainable verdict.
"""

from .anomaly import AnomalyModel, extract_features
from .fusion import deduplicate, fuse

__all__ = ["AnomalyModel", "extract_features", "deduplicate", "fuse"]
