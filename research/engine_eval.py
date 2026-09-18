"""Evaluate the FORENSIC RULE ENGINE itself on the synthetic research corpus.

Why this exists
---------------
Until this module, the research corpus was used only for the ML baselines, and
the rule engine - the component investigators actually rely on - was evaluated
only on the 26 hand-written development messages. The robustness experiment
exposed the gap: on the research test split the engine flags 65 of 106 benign
messages. This module measures that properly, across every split, and
attributes it.

Nothing here changes the engine. Band thresholds are reported as configured;
the threshold table is analysis, not selection.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from bec_detector.config import BAND_THRESHOLDS
from bec_detector.forensics import IOCStore, NullThreatIntelProvider
from bec_detector.pipeline import BECPipeline

RESEARCH = Path("data") / "research"
RESULTS_DIR = Path("output") / "research"
LIKELY = dict((band, t) for t, band in BAND_THRESHOLDS)["LIKELY_BEC"]

PROVENANCE = (
    "SYNTHETIC research corpus. The rule engine was not tuned on this corpus. "
    "Figures describe this engine on this synthetic distribution and are NOT "
    "real-world accuracy estimates."
)


def _benign_group(family: str) -> str:
    if "relayed" in family:
        return "external, relayed (SPF softfail)"
    if "confounded" in family and "internal" in family:
        return "internal, finance/urgency wording"
    if "confounded" in family:
        return "external, finance/urgency wording"
    if "internal" in family:
        return "internal, routine"
    return "external, routine"


def _malicious_group(family: str) -> str:
    return "compromised account" if "compromised" in family else "spoofed identity"


def evaluate_split(split: str) -> dict[str, Any]:
    labels = json.loads((RESEARCH / split / "labels.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = BECPipeline(case_id=f"CASE-ENGINE-{split}", intel=NullThreatIntelProvider(),
                               ioc_store=IOCStore(Path(tmp) / "i.json"), correlate=False)
        assessments = pipeline.run(RESEARCH / split)

    rows = []
    for a in assessments:
        meta = labels[Path(a.artifact.custody.source_path).name]
        rows.append({
            "label": meta["label"], "family": meta["family"], "score": a.score,
            "band": a.band.value, "codes": [i.code for i in a.indicators],
            "identity_verified": a.fusion.get("identity_verified"),
        })

    y = np.array([r["label"] == "MALICIOUS" for r in rows], dtype=int)
    s = np.array([r["score"] for r in rows])

    def at(threshold: float) -> dict[str, Any]:
        pred = s >= threshold
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        return {
            "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        }

    fp_by_group: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    fn_by_group: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    fp_codes: Counter = Counter()
    for r in rows:
        flagged = r["score"] >= LIKELY
        if r["label"] == "BENIGN":
            g = fp_by_group[_benign_group(r["family"])]
            g[1] += 1
            if flagged:
                g[0] += 1
                fp_codes.update(r["codes"])
        else:
            g = fn_by_group[_malicious_group(r["family"])]
            g[1] += 1
            if not flagged:
                g[0] += 1

    def quantiles(values):
        values = np.asarray(values)
        return {q: round(float(np.percentile(values, p)), 1)
                for q, p in (("min", 0), ("p25", 25), ("median", 50), ("p75", 75), ("max", 100))}

    n_fp = sum(v[0] for v in fp_by_group.values()) or 1
    return {
        "split": split,
        "n": len(rows),
        "class_counts": {"MALICIOUS": int(y.sum()), "BENIGN": int(len(y) - y.sum())},
        "at_configured_threshold": at(LIKELY),
        "threshold_table": [at(t) for t in (25, 40, 50, 60, 75, 90)],
        "roc_auc": round(float(roc_auc_score(y, s)), 4),
        "pr_auc": round(float(average_precision_score(y, s)), 4),
        "score_distribution": {
            "malicious": quantiles(s[y == 1]),
            "benign": quantiles(s[y == 0]),
        },
        "false_positives_by_benign_group": {
            k: {"flagged": v[0], "of": v[1], "rate": round(v[0] / v[1], 4) if v[1] else 0.0}
            for k, v in sorted(fp_by_group.items())},
        "missed_by_malicious_group": {
            k: {"missed": v[0], "of": v[1], "rate": round(v[0] / v[1], 4) if v[1] else 0.0}
            for k, v in sorted(fn_by_group.items())},
        "indicators_on_false_positives": [
            {"code": c, "count": n, "share_of_fps": round(n / n_fp, 3)}
            for c, n in fp_codes.most_common(12)],
    }


def run(output_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    results = {
        "result_type": "RESEARCH RESULTS - FORENSIC RULE ENGINE",
        "provenance": PROVENANCE,
        "not_real_world_accuracy": True,
        "engine_tuned_on_this_corpus": False,
        "configured_threshold": {"band": "LIKELY_BEC", "score": LIKELY},
        "configuration": {"threat_intelligence": "disabled", "correlation": "disabled",
                          "baseline": "each split analysed as one corpus (two-pass)"},
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "splits": [evaluate_split(s) for s in ("train", "validation", "test")],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "engine_evaluation.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return results


def main() -> int:
    print("FORENSIC RULE ENGINE on the synthetic research corpus")
    print(f"  {PROVENANCE}\n")
    results = run()
    for sp in results["splits"]:
        m = sp["at_configured_threshold"]
        print(f"{sp['split']:<11} n={sp['n']:<4} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} FPR={m['false_positive_rate']:.3f}  "
              f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}  "
              f"ROC={sp['roc_auc']:.3f} PR={sp['pr_auc']:.3f}")
    test = results["splits"][-1]
    print("\nTEST - false positives by benign group:")
    for k, v in test["false_positives_by_benign_group"].items():
        print(f"  {k:<36} {v['flagged']:>3}/{v['of']:<3} ({v['rate']:.0%})")
    print("TEST - missed by malicious group:")
    for k, v in test["missed_by_malicious_group"].items():
        print(f"  {k:<36} {v['missed']:>3}/{v['of']:<3} ({v['rate']:.0%})")
    print("TEST - indicators present on false positives:")
    for item in test["indicators_on_false_positives"][:8]:
        print(f"  {item['code']:<28} {item['count']:>3}  ({item['share_of_fps']:.0%} of FPs)")
    print("TEST - threshold analysis (not selection):")
    for row in test["threshold_table"]:
        print(f"  >= {row['threshold']:<4} P={row['precision']:.3f} R={row['recall']:.3f} "
              f"F1={row['f1']:.3f} FPR={row['false_positive_rate']:.3f}")
    print(f"\nwritten: {RESULTS_DIR / 'engine_evaluation.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
