"""Ablation study: which evidence sources contribute to BEC detection?

This is the experiment that turns the project's central claim from an
assertion into a result. The claim is:

    multi-source forensic evidence fusion is more useful than text-only
    classification

Configurations are CUMULATIVE, each adding one evidence family to the last, so
the marginal contribution of each family is the difference between consecutive
rows.

    A  text only                    TF-IDF over subject + body
    B  + header                     auth results, Reply-To, Return-Path
    C  + identity                   display-name spoofing, lookalike domains
    D  + behaviour                  corpus-baselined sending deviation
    E  + nlp                        urgency, secrecy, authority
    F  + financial                  payment, banking change, money entities
    G  + thread                     conversation reconstruction
    H  + stylometry                 per-sender writing-style deviation
    I  + artifact (FULL FUSION)     static URL and attachment findings

Reading the results honestly
----------------------------
Ceiling effects are real here. The corpus is synthetic, so absolute numbers are
an upper bound. What the table supports is a RELATIVE comparison between
configurations on identical data with identical seeds - which family moves the
needle, and by how much. It does not support any statement about real-world
performance.

Cross-validation is reported alongside the held-out test result because with
~180 test messages a single split is noisy: a one-message change moves F1 by
roughly half a point.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.model_selection import StratifiedKFold

from .baselines import (
    MODELS_BY_KEY,
    RANDOM_SEED,
    FeatureSpace,
    labels_of,
    predict,
    train,
)
from .evaluate import PROVENANCE, RESULTS_DIR, compute_metrics, environment, load_corpus
from .features import ExtractedSample

# (key, label, feature groups, use_text)
CONFIGURATIONS: tuple[tuple[str, str, list[str], bool], ...] = (
    ("A", "Text only", [], True),
    ("B", "+ Header", ["header"], True),
    ("C", "+ Identity", ["header", "identity"], True),
    ("D", "+ Behaviour", ["header", "identity", "behaviour"], True),
    ("E", "+ NLP", ["header", "identity", "behaviour", "nlp"], True),
    ("F", "+ Financial", ["header", "identity", "behaviour", "nlp", "financial"], True),
    ("G", "+ Thread",
     ["header", "identity", "behaviour", "nlp", "financial", "thread"], True),
    ("H", "+ Stylometry",
     ["header", "identity", "behaviour", "nlp", "financial", "thread", "stylometry"], True),
    ("I", "FULL FUSION",
     ["header", "identity", "behaviour", "nlp", "financial", "thread", "stylometry",
      "artifact"], True),
)

# Reported alongside the cumulative table: evidence WITHOUT the text channel,
# which isolates how much the structured forensic features carry on their own.
STRUCTURED_ONLY = (
    "S", "Structured only (no text)",
    ["header", "identity", "behaviour", "nlp", "financial", "thread", "stylometry",
     "artifact"], False,
)

CV_FOLDS = 5


def _cross_validate(model_key: str, samples: list[ExtractedSample],
                    groups: list[str], use_text: bool) -> dict[str, Any]:
    """Stratified k-fold CV over the pooled corpus.

    The feature space is refitted inside every fold. Fitting the vectoriser
    once outside the loop would leak held-out vocabulary into training and
    inflate every number in the table.
    """
    spec = MODELS_BY_KEY[model_key]
    y = labels_of(samples)
    indices = np.arange(len(samples))
    splitter = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)

    scores: dict[str, list[float]] = {"precision": [], "recall": [], "f1": [], "accuracy": []}

    for train_idx, test_idx in splitter.split(indices, y):
        train_samples = [samples[i] for i in train_idx]
        test_samples = [samples[i] for i in test_idx]

        space = FeatureSpace(groups, use_text)
        x_train = space.fit_transform(train_samples)
        model = train(spec, x_train, labels_of(train_samples))

        x_test = space.transform(test_samples)
        y_pred, _ = predict(model, x_test)
        fold = compute_metrics(labels_of(test_samples), y_pred)

        for key in scores:
            scores[key].append(fold[key])

    return {
        key: {
            "mean": round(float(np.mean(values)), 4),
            "std": round(float(np.std(values)), 4),
        }
        for key, values in scores.items()
    }



def _per_family_recall(model: Any, space: FeatureSpace,
                       samples: list[ExtractedSample]) -> dict[str, dict[str, Any]]:
    """Recall broken down by attack family.

    The aggregate score saturates on this corpus, so it hides the question the
    ablation actually cares about: WHICH cases does each evidence family
    rescue? Compromised-account messages are the discriminating subset - their
    identity and authentication evidence is clean, so a model must rely on
    behaviour, style and the financial ask to catch them.
    """
    x = space.transform(samples)
    y_pred, _ = predict(model, x)

    buckets: dict[str, dict[str, int]] = {}
    for sample, predicted in zip(samples, y_pred):
        if sample.label != 1:
            continue
        family = "compromised" if "compromised" in sample.family else "spoofed"
        bucket = buckets.setdefault(family, {"total": 0, "caught": 0})
        bucket["total"] += 1
        bucket["caught"] += int(predicted == 1)

    return {
        name: {
            "total": b["total"],
            "caught": b["caught"],
            "recall": round(b["caught"] / b["total"], 4) if b["total"] else None,
        }
        for name, b in sorted(buckets.items())
    }


def run_configuration(key: str, label: str, groups: list[str], use_text: bool,
                      splits: dict[str, list[ExtractedSample]],
                      model_key: str) -> dict[str, Any]:
    """Train on train, evaluate on test, plus CV over the pooled corpus."""
    spec = MODELS_BY_KEY[model_key]

    space = FeatureSpace(groups, use_text)
    x_train = space.fit_transform(splits["train"])
    model = train(spec, x_train, labels_of(splits["train"]))

    x_test = space.transform(splits["test"])
    y_pred, scores = predict(model, x_test)
    held_out = compute_metrics(labels_of(splits["test"]), y_pred, scores)

    # Held-out test is only ~180 messages, so the hard subset is evaluated over
    # validation + test together to give the per-family figures usable support.
    hard_pool = splits["validation"] + splits["test"]
    by_family = _per_family_recall(model, space, hard_pool)

    pooled = splits["train"] + splits["validation"] + splits["test"]
    cv = _cross_validate(model_key, pooled, groups, use_text)

    return {
        "configuration": key,
        "label": label,
        "feature_groups": groups,
        "uses_text": use_text,
        "n_features": space.n_features,
        "held_out_test": held_out,
        "recall_by_family": by_family,
        "cross_validation": cv,
    }


def run_ablation(model_key: str = "random_forest",
                 output_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    splits = load_corpus()

    results: dict[str, Any] = {
        "result_type": "RESEARCH ABLATION RESULTS",
        "provenance": PROVENANCE,
        "not_real_world_accuracy": True,
        "research_question": (
            "Which evidence sources contribute to BEC detection, and does "
            "multi-source fusion improve on text-only classification?"
        ),
        "interpretation_note": (
            "Absolute values are ceiling-limited by the synthetic corpus. The "
            "table supports RELATIVE comparison between configurations on "
            "identical data and seeds, not any claim about real-world accuracy."
        ),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment(),
        "model": MODELS_BY_KEY[model_key].config(),
        "cv_folds": CV_FOLDS,
        "configurations": [],
    }

    for key, label, groups, use_text in CONFIGURATIONS:
        results["configurations"].append(
            run_configuration(key, label, groups, use_text, splits, model_key)
        )

    key, label, groups, use_text = STRUCTURED_ONLY
    results["structured_only"] = run_configuration(
        key, label, groups, use_text, splits, model_key
    )

    # Marginal contribution of each added family, on the CV mean so the figure
    # is not dominated by single-split noise.
    deltas = []
    previous = None
    for entry in results["configurations"]:
        current = entry["cross_validation"]["f1"]["mean"]
        deltas.append({
            "configuration": entry["configuration"],
            "label": entry["label"],
            "cv_f1": current,
            "delta_vs_previous": None if previous is None else round(current - previous, 4),
        })
        previous = current
    results["marginal_contribution"] = deltas

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ablation.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return results


def format_table(results: dict[str, Any]) -> str:
    header = (
        f"{'Cfg':<4}{'Configuration':<22}{'Feat':>6}"
        f"{'Prec':>8}{'Rec':>8}{'F1':>8}"
        f"{'CV-F1':>9}{'+/-sd':>7}{'delta':>8}"
    )
    lines = [header, "-" * len(header)]

    deltas = {d["configuration"]: d["delta_vs_previous"]
              for d in results["marginal_contribution"]}

    for entry in results["configurations"]:
        m = entry["held_out_test"]
        cv = entry["cross_validation"]["f1"]
        delta = deltas.get(entry["configuration"])
        delta_text = "  -   " if delta is None else f"{delta:+.4f}"
        lines.append(
            f"{entry['configuration']:<4}{entry['label']:<22}{entry['n_features']:>6}"
            f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
            f"{cv['mean']:>9.4f}{cv['std']:>7.4f}{delta_text:>8}"
        )

    lines.append("")
    lines.append("RECALL BY ATTACK FAMILY (validation + test)")
    fam_header = (f"{'Cfg':<4}{'Configuration':<22}"
                  f"{'spoofed':>12}{'compromised':>14}")
    lines.append(fam_header)
    lines.append("-" * len(fam_header))
    for entry in results["configurations"]:
        fam = entry.get("recall_by_family", {})
        spoofed = fam.get("spoofed", {}).get("recall")
        comp = fam.get("compromised", {}).get("recall")
        lines.append(
            f"{entry['configuration']:<4}{entry['label']:<22}"
            f"{(f'{spoofed:.3f}' if spoofed is not None else '-'):>12}"
            f"{(f'{comp:.3f}' if comp is not None else '-'):>14}"
        )

    structured = results.get("structured_only")
    if structured:
        m = structured["held_out_test"]
        cv = structured["cross_validation"]["f1"]
        lines.append("-" * len(header))
        lines.append(
            f"{structured['configuration']:<4}{structured['label']:<22}"
            f"{structured['n_features']:>6}"
            f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
            f"{cv['mean']:>9.4f}{cv['std']:>7.4f}{'  -   ':>8}"
        )
    return "\n".join(lines)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the ablation study.")
    parser.add_argument("--model", default="random_forest", choices=sorted(MODELS_BY_KEY))
    args = parser.parse_args()

    print("ABLATION STUDY - which evidence sources contribute to BEC detection?")
    print(f"  model: {MODELS_BY_KEY[args.model].label}")
    print(f"  {PROVENANCE}\n")

    results = run_ablation(args.model)
    print(format_table(results))
    print()
    print("delta = change in cross-validated F1 versus the configuration above.")
    print(f"written: {RESULTS_DIR / 'ablation.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
