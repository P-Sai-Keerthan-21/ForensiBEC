"""Research layer: ML baselines, evaluation, ablation and calibration.

This package exists to EVALUATE the forensic engine's premise, not to replace
it. The engine remains the system's decision path; everything here is the
comparison arm that turns "evidence fusion beats text-only classification"
from an assertion into an experimental result.

Every artifact produced here is computed on SYNTHETIC data and is labelled as
an optimistic upper bound rather than a real-world accuracy estimate.
"""

__all__ = ["features", "baselines", "evaluate", "ablation", "calibration"]
