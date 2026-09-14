"""Detection-performance validation against the labelled corpus.

This is the Validation stage of the forensic workflow expressed as a test: the
detector's output is measured against ground truth rather than merely inspected.

Evaluation contract
-------------------
* MALICIOUS messages must reach LIKELY_BEC or CONFIRMED_BEC.
* BENIGN messages must stay below LIKELY_BEC.
* SUSPICIOUS messages are borderline by construction and are reported but not
  asserted on - they exist to show where the boundary sits.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bec_detector.acquisition import load_path
from bec_detector.models import RiskBand
from bec_detector.pipeline import BECPipeline

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
LABELS = SAMPLES / "labels.json"

FLAGGED_BANDS = {RiskBand.LIKELY_BEC, RiskBand.CONFIRMED_BEC}


@pytest.fixture(scope="module")
def results():
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    emails = load_path(SAMPLES)
    pipeline = BECPipeline(examiner="pytest-validation")
    pipeline.fit(emails)

    rows = []
    for email in emails:
        filename = Path(email.custody.source_path).name
        meta = labels.get(filename)
        assert meta, f"{filename} has no ground-truth label"
        rows.append((filename, meta["label"], pipeline.assess(email)))
    return rows


def test_corpus_is_complete(results):
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    assert len(results) == len(labels)


def test_no_malicious_message_is_missed(results):
    """False negatives are the costly error for this tool."""
    missed = [
        (name, a.score, a.band.value)
        for name, label, a in results
        if label == "MALICIOUS" and a.band not in FLAGGED_BANDS
    ]
    assert not missed, f"malicious messages not flagged: {missed}"


def test_no_benign_message_is_flagged_as_bec(results):
    """False positives erode analyst trust and must stay below the BEC bands."""
    false_positives = [
        (name, a.score, a.band.value)
        for name, label, a in results
        if label == "BENIGN" and a.band in FLAGGED_BANDS
    ]
    assert not false_positives, f"benign messages flagged as BEC: {false_positives}"


def test_score_separation_is_meaningful(results):
    """The lowest malicious score must clear the highest benign score."""
    malicious = [a.score for _, label, a in results if label == "MALICIOUS"]
    benign = [a.score for _, label, a in results if label == "BENIGN"]
    assert min(malicious) > max(benign), (
        f"score bands overlap: lowest malicious {min(malicious)}, "
        f"highest benign {max(benign)}"
    )


def test_every_flagged_message_explains_itself(results):
    """A flagged message with no evidence would be unusable in a report."""
    for name, _, assessment in results:
        if assessment.band in FLAGGED_BANDS:
            assert assessment.indicators, f"{name} flagged with no indicators"
            assert assessment.narrative.strip(), f"{name} flagged with no narrative"
            for indicator in assessment.indicators:
                assert indicator.evidence.strip()


def test_detection_metrics(results, capsys):
    """Compute and print precision / recall / F1 for the report appendix."""
    tp = sum(1 for _, l, a in results if l == "MALICIOUS" and a.band in FLAGGED_BANDS)
    fn = sum(1 for _, l, a in results if l == "MALICIOUS" and a.band not in FLAGGED_BANDS)
    fp = sum(1 for _, l, a in results if l == "BENIGN" and a.band in FLAGGED_BANDS)
    tn = sum(1 for _, l, a in results if l == "BENIGN" and a.band not in FLAGGED_BANDS)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    with capsys.disabled():
        print("\n  --- detection metrics (MALICIOUS vs BENIGN) ---")
        print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
        print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}")
        print("  --- per-message scores ---")
        for name, label, a in sorted(results, key=lambda r: -r[2].score):
            print(f"  {a.score:6.1f}  {a.band.value:<14} {label:<11} {name}")

    assert recall == 1.0, "every malicious message must be caught"
    assert precision == 1.0, "no benign message may be flagged"
