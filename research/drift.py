"""Concept-drift detection and cross-generation performance.

Two questions:

  1. DETECTION - does incoming mail still resemble what the system was built
     and trained on? Measured as distribution shift, reported as
     "Distribution shift detected", never as "new attack detected": a shift
     is evidence that the reference data no longer describes the input, not
     evidence of malice.
  2. IMPACT - when the attack pattern changes, how much do the rule engine and
     an ML baseline degrade?

Method
------
* Structured features: Population Stability Index (PSI) per feature, binned on
  reference quantiles. Conventional reading: < 0.10 stable, 0.10-0.25
  moderate, > 0.25 significant.
* Indicator firing rates: absolute change in the share of messages on which
  each engine indicator fires.
* Vocabulary: Jensen-Shannon divergence between unigram distributions.

A CONTROL comparison (generation-1 train vs generation-1 test, same generator)
is always run alongside, so the detector's own noise floor is visible: a
detector that alarms on the control is not detecting drift.

Data provenance: both generations are SYNTHETIC. Generation 2 is a documented,
hand-chosen parameter shift (data/build_drift_corpus.py). It does not
reproduce real attacker evolution.
"""

from __future__ import annotations

import json
import math
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from bec_detector.forensics import IOCStore, NullThreatIntelProvider
from bec_detector.pipeline import BECPipeline

from .baselines import MODELS_BY_KEY, FeatureSpace, labels_of, predict, train
from .evaluate import compute_metrics
from .features import FEATURE_GROUPS, GROUP_CODES, ExtractedSample, load_split

GEN1 = Path("data") / "research"
GEN2 = Path("data") / "research_drift" / "gen2"
RESULTS_DIR = Path("output") / "research"

PSI_MODERATE = 0.10
PSI_SIGNIFICANT = 0.25
RATE_CHANGE_NOTABLE = 0.15
EPS = 1e-4

PROVENANCE = (
    "SYNTHETIC. Generation 2 is a documented, hand-chosen shift of the generator "
    "(more compromised mailboxes, a novel lure worded to avoid the engine's "
    "lexicons, less pressure language, later dates). It does NOT reproduce real "
    "attacker evolution. Results show how this system responds to this shift."
)

ALL_STRUCTURED = [g for g in FEATURE_GROUPS if g != "text"]

# Indicators whose value depends on the OTHER messages in the analysed set
# (behavioural baselines, per-sender stylometry, thread reconstruction), not on
# the message itself. They measure the corpus, so they are not comparable
# between sets of different size or composition and are excluded from drift
# measurement.
#
# This exclusion was added after the first run alarmed on the CONTROL
# comparison (gen1 train vs gen1 test, one generator): DISPLAY_NAME_CHANGED
# fired on 86% of the 539-message train split and 64% of the 182-message test
# split purely because larger sets contain more repeat senders. It is reported
# as such in docs/concept_drift.md.
CORPUS_RELATIVE_CODES = frozenset({
    "FIRST_TIME_SENDER", "DISPLAY_NAME_CHANGED", "NEW_DOMAIN_FOR_KNOWN_NAME",
    "UNUSUAL_RECIPIENT_SET",
    "STYLE_DEVIATION", "STYLE_GREETING_CHANGE", "STYLE_SIGNATURE_CHANGE",
    "THREAD_UNKNOWN_PARENT", "THREAD_NEW_PARTICIPANT", "THREAD_REPLYTO_INTRODUCED",
    "THREAD_SENDER_DIVERGENCE", "THREAD_PAYMENT_PIVOT",
})


# ---------------------------------------------------------------------------
# Distribution-shift measures
# ---------------------------------------------------------------------------

def psi(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index of `current` against `reference`."""
    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)
    if reference.size == 0 or current.size == 0:
        return 0.0
    edges = np.unique(np.quantile(reference, np.linspace(0, 1, bins + 1)))
    if edges.size < 2:
        # Constant in the reference: compare the share equal to that constant.
        value = edges[0] if edges.size else 0.0
        ref_share = np.array([1.0, EPS])
        cur_equal = float(np.mean(current == value))
        cur_share = np.array([max(cur_equal, EPS), max(1 - cur_equal, EPS)])
        ref_share = ref_share / ref_share.sum()
        cur_share = cur_share / cur_share.sum()
        return float(np.sum((cur_share - ref_share) * np.log(cur_share / ref_share)))
    edges[0], edges[-1] = -np.inf, np.inf
    ref_counts = np.histogram(reference, edges)[0] / reference.size
    cur_counts = np.histogram(current, edges)[0] / current.size
    ref_counts = np.clip(ref_counts, EPS, None)
    cur_counts = np.clip(cur_counts, EPS, None)
    return float(np.sum((cur_counts - ref_counts) * np.log(cur_counts / ref_counts)))


def js_divergence(a: Counter, b: Counter) -> float:
    """Jensen-Shannon divergence (base 2, in [0, 1]) of two token counters."""
    vocab = set(a) | set(b)
    if not vocab:
        return 0.0
    ta, tb = sum(a.values()) or 1, sum(b.values()) or 1
    total = 0.0
    for token in vocab:
        p, q = a.get(token, 0) / ta, b.get(token, 0) / tb
        m = (p + q) / 2
        if p:
            total += 0.5 * p * math.log2(p / m)
        if q:
            total += 0.5 * q * math.log2(q / m)
    return round(total, 4)


def _tokens(samples: list[ExtractedSample]) -> Counter:
    counter: Counter = Counter()
    for s in samples:
        counter.update(re.findall(r"[a-z']{3,}", s.text.lower()))
    return counter


def _numeric_matrix(samples: list[ExtractedSample]) -> dict[str, np.ndarray]:
    names = sorted({k for s in samples for k in s.vector_for(ALL_STRUCTURED)
                    if "::ind_" not in k})
    return {n: np.array([s.vector_for(ALL_STRUCTURED).get(n, 0.0) for s in samples])
            for n in names}


def _indicator_rates(samples: list[ExtractedSample]) -> dict[str, float]:
    codes = [c for group in GROUP_CODES.values() for c in group
             if c not in CORPUS_RELATIVE_CODES]
    rates = {}
    for code in codes:
        key = next((f"{g}::ind_{code}" for g, cs in GROUP_CODES.items() if code in cs), None)
        rates[code] = float(np.mean([s.vector_for(ALL_STRUCTURED).get(key, 0.0) for s in samples]))
    return rates


def compare(reference: list[ExtractedSample], current: list[ExtractedSample],
            label: str) -> dict[str, Any]:
    """Full drift report of `current` against `reference`."""
    ref_num, cur_num = _numeric_matrix(reference), _numeric_matrix(current)
    feature_psi = {n: round(psi(ref_num[n], cur_num.get(n, np.zeros(1))), 4) for n in ref_num}
    significant = sorted(((n, v) for n, v in feature_psi.items() if v > PSI_SIGNIFICANT),
                         key=lambda x: -x[1])
    moderate = sorted(((n, v) for n, v in feature_psi.items()
                       if PSI_MODERATE < v <= PSI_SIGNIFICANT), key=lambda x: -x[1])

    ref_rates, cur_rates = _indicator_rates(reference), _indicator_rates(current)
    rate_changes = sorted(
        ({"code": c, "reference_rate": round(ref_rates[c], 3),
          "current_rate": round(cur_rates[c], 3),
          "change": round(cur_rates[c] - ref_rates[c], 3)}
         for c in ref_rates if abs(cur_rates[c] - ref_rates[c]) >= RATE_CHANGE_NOTABLE),
        key=lambda r: -abs(r["change"]))

    jsd = js_divergence(_tokens(reference), _tokens(current))
    ref_vocab, cur_vocab = set(_tokens(reference)), set(_tokens(current))
    novel_share = round(len(cur_vocab - ref_vocab) / (len(cur_vocab) or 1), 4)

    shifted = bool(significant) or bool(rate_changes)
    return {
        "comparison": label,
        "reference_size": len(reference), "current_size": len(current),
        "verdict": ("Distribution shift detected" if shifted
                    else "No significant distribution shift detected"),
        "note": ("A distribution shift means the reference data no longer describes "
                 "the input. It is not, by itself, evidence of malicious activity."),
        "excluded_corpus_relative_indicators": sorted(CORPUS_RELATIVE_CODES),
        "features_significant_psi": [{"feature": n, "psi": v} for n, v in significant],
        "features_moderate_psi": [{"feature": n, "psi": v} for n, v in moderate[:10]],
        "indicator_rate_changes": rate_changes,
        "vocabulary_js_divergence": jsd,
        "novel_vocabulary_share": novel_share,
    }


# ---------------------------------------------------------------------------
# Cross-generation performance
# ---------------------------------------------------------------------------

def _engine_metrics(directory: Path) -> dict[str, Any]:
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = BECPipeline(case_id="CASE-DRIFT", intel=NullThreatIntelProvider(),
                               ioc_store=IOCStore(Path(tmp) / "i.json"), correlate=False)
        assessments = pipeline.run(directory)
    y = np.array([labels[Path(a.artifact.custody.source_path).name]["label"] == "MALICIOUS"
                  for a in assessments], dtype=int)
    pred = np.array([a.band.value in ("LIKELY_BEC", "CONFIRMED_BEC") for a in assessments],
                    dtype=int)
    scores = np.array([a.score for a in assessments])
    metrics = compute_metrics(y, pred, scores)

    novel = [a for a in assessments
             if "novel_lure" in labels[Path(a.artifact.custody.source_path).name]["family"]]
    if novel:
        caught = sum(a.band.value in ("LIKELY_BEC", "CONFIRMED_BEC") for a in novel)
        metrics["novel_lure_recall"] = round(caught / len(novel), 4)
        metrics["novel_lure_n"] = len(novel)
    return metrics


def _ml_metrics(train_samples, eval_samples) -> dict[str, Any]:
    spec = MODELS_BY_KEY["random_forest"]
    space = FeatureSpace(list(ALL_STRUCTURED), use_text=True)
    model = train(spec, space.fit_transform(train_samples), labels_of(train_samples))
    y_pred, scores = predict(model, space.transform(eval_samples))
    metrics = compute_metrics(labels_of(eval_samples), y_pred, scores)
    novel_idx = [i for i, s in enumerate(eval_samples) if "novel_lure" in s.family]
    if novel_idx:
        metrics["novel_lure_recall"] = round(float(np.mean([y_pred[i] for i in novel_idx])), 4)
        metrics["novel_lure_n"] = len(novel_idx)
    return metrics


def run(output_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    if not (GEN2 / "labels.json").exists():
        raise FileNotFoundError("generation 2 absent - run: python data/build_drift_corpus.py")

    gen1_train = load_split(GEN1 / "train")
    gen1_test = load_split(GEN1 / "test")
    gen2 = load_split(GEN2)

    results = {
        "result_type": "RESEARCH CONCEPT-DRIFT RESULTS",
        "provenance": PROVENANCE,
        "not_real_world_accuracy": True,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "thresholds": {"psi_moderate": PSI_MODERATE, "psi_significant": PSI_SIGNIFICANT,
                       "indicator_rate_change": RATE_CHANGE_NOTABLE},
        "drift": {
            "control_gen1_train_vs_gen1_test": compare(gen1_train, gen1_test,
                                                       "gen1 train vs gen1 test (control)"),
            "gen1_train_vs_gen2": compare(gen1_train, gen2, "gen1 train vs gen2"),
        },
        "performance": {
            "rule_engine": {"gen1_test": _engine_metrics(GEN1 / "test"),
                            "gen2": _engine_metrics(GEN2)},
            "random_forest_trained_on_gen1": {
                "gen1_test": _ml_metrics(gen1_train, gen1_test),
                "gen2": _ml_metrics(gen1_train, gen2),
            },
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "drift.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def main() -> int:
    print("CONCEPT DRIFT")
    print(f"  {PROVENANCE}\n")
    r = run()
    for key, report in r["drift"].items():
        print(f"{report['comparison']}: {report['verdict']}")
        print(f"   significant-PSI features: {len(report['features_significant_psi'])}"
              f"   indicator-rate changes: {len(report['indicator_rate_changes'])}"
              f"   vocab JSD: {report['vocabulary_js_divergence']}"
              f"   novel vocab share: {report['novel_vocabulary_share']}")
        for f in report["features_significant_psi"][:5]:
            print(f"     PSI {f['psi']:.3f}  {f['feature']}")
        for c in report["indicator_rate_changes"][:5]:
            print(f"     rate {c['reference_rate']:.2f} -> {c['current_rate']:.2f}  {c['code']}")
    print()
    for system, perf in r["performance"].items():
        for split, m in perf.items():
            extra = (f"  novel-lure recall {m['novel_lure_recall']:.3f} (n={m['novel_lure_n']})"
                     if "novel_lure_recall" in m else "")
            print(f"{system:<32} {split:<10} P={m['precision']:.3f} R={m['recall']:.3f} "
                  f"F1={m['f1']:.3f} FPR={m['false_positive_rate']:.3f}{extra}")
    print(f"\nwritten: {RESULTS_DIR / 'drift.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
