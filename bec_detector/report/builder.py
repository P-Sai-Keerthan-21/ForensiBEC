"""Assemble case-level reporting structures and write JSON output."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __tool_name__, __version__
from ..models import Assessment, RiskBand

BAND_ORDER = [
    RiskBand.CONFIRMED_BEC,
    RiskBand.LIKELY_BEC,
    RiskBand.SUSPICIOUS,
    RiskBand.BENIGN,
]


def build_case_report(
    assessments: list[Assessment],
    case_name: str = "Untitled case",
    examiner: str | None = None,
    nlp_status: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Build the full case report structure.

    Assessments are ordered highest-risk first, because an examiner reads the
    top of a report and needs the actionable findings there.
    """
    ordered = sorted(assessments, key=lambda a: -a.score)

    band_counts = Counter(a.band.value for a in assessments)
    indicator_counts = Counter(
        indicator.code for a in assessments for indicator in a.indicators
    )

    scores = [a.score for a in assessments]
    flagged = [a for a in assessments if a.band is not RiskBand.BENIGN]

    return {
        "case": {
            "name": case_name,
            "examiner": examiner or (
                assessments[0].artifact.custody.examiner if assessments else "unknown"
            ),
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": f"{__tool_name__} {__version__}",
            "nlp_backends": nlp_status or {},
        },
        "summary": {
            "messages_analysed": len(assessments),
            "messages_flagged": len(flagged),
            "highest_score": max(scores) if scores else 0.0,
            "mean_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "band_counts": {band.value: band_counts.get(band.value, 0) for band in BAND_ORDER},
            "most_common_indicators": indicator_counts.most_common(10),
        },
        "assessments": [a.to_dict() for a in ordered],
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    """Persist the case report as indented JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
