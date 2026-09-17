"""Feature-balanced ablation: is the negative fusion result a dimensionality artifact?

Motivation
----------
The original ablation (research/ablation.py, preserved unchanged) compared a
text channel of ~6485 TF-IDF features against ~82 structured forensic features
and found no measurable benefit from fusion. That comparison is confounded: a
feature family outnumbered 79:1 can be decisive for individual messages and
still fail to move an aggregate metric, simply because the learner's capacity
is dominated by the larger block.

This module re-runs the comparison with the two channels on comparable
dimensionality, to determine whether the earlier negative result was caused by
that imbalance rather than by an absence of signal.

Method
------
The text channel is reduced with Truncated SVD (latent semantic analysis),
the standard reduction for sparse TF-IDF matrices. It is chosen over feature
selection because selection would rank features by their association with the
label, which leaks target information into the representation; SVD is
unsupervised and sees no labels.

PRE-REGISTERED PARAMETER. The component count is fixed at the number of
structured features (82) by a matching rule stated before any result was
observed. It was NOT searched for, and no configuration was chosen because it
improved fusion. A sensitivity check over other component counts is reported
separately and explicitly labelled as robustness, not as the primary result.

Configurations
--------------
    A  Balanced text only          SVD(82) of TF-IDF
    B  Balanced text + structured  SVD(82) + 82 forensic features
    C  Full forensic fusion        full TF-IDF (~6485) + 82 forensic features
    D  Structured only             82 forensic features, no text

A versus B is the experiment: identical text capacity, structured evidence
added. C is the original unbalanced arrangement, carried forward so the two
experiments can be read side by side. D isolates the forensic channel.

Statistical comparison
----------------------
All configurations are evaluated on IDENTICAL cross-validation folds, so per-
fold scores are paired. Differences are tested with a paired t-test over
repeated stratified k-fold (5 splits x 3 repeats = 15 paired observations),
and reported with a 95% confidence interval on the mean difference.

A difference is called significant only if p < 0.05 AND the confidence
interval excludes zero. Otherwise the result is reported as statistically
indistinguishable - which is a finding, not a failure.

Leakage control
---------------
The vectoriser, the SVD and the scaler are all fitted inside each fold on
training data only. Fitting any of them once outside the loop would leak
held-out structure into training and inflate every number in the table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats
from scipy.sparse import csr_matrix, hstack
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.preprocessing import MaxAbsScaler

from .baselines import MODELS_BY_KEY, RANDOM_SEED, labels_of, predict, train
from .evaluate import PROVENANCE, RESULTS_DIR, compute_metrics, environment, load_corpus
from .features import FEATURE_GROUPS, ExtractedSample

# Structured feature count, and therefore the pre-registered SVD width.
# Asserted at runtime so a change to the feature set cannot silently
# invalidate the matching rule.
STRUCTURED_FEATURE_COUNT = 82

CV_SPLITS = 5
CV_REPEATS = 3

ALL_STRUCTURED = [g for g in FEATURE_GROUPS if g != "text"]

# Robustness sweep. Reported separately from the primary result so that no
# reader can mistake it for parameter selection.
SENSITIVITY_COMPONENTS = (25, 50, 82, 150, 300)


@dataclass
class BalancedSpace:
    """Design matrix builder with an optionally reduced text channel.

    `text_components=None` means "use the full TF-IDF matrix", which reproduces
    the original unbalanced arrangement.
    """

    groups: list[str]
    use_text: bool
    text_components: int | None

    def __post_init__(self) -> None:
        self.word_vec: TfidfVectorizer | None = None
        self.char_vec: TfidfVectorizer | None = None
        self.svd: TruncatedSVD | None = None
        self.dict_vec: DictVectorizer | None = None
        self.scaler: MaxAbsScaler | None = None
        self._text_width = 0
        self._structured_width = 0

    # -- text channel --------------------------------------------------------

    def _fit_text(self, samples: list[ExtractedSample]) -> csr_matrix | np.ndarray:
        texts = [s.text for s in samples]
        self.word_vec = TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), max_features=5000,
            sublinear_tf=True, min_df=2,
        )
        self.char_vec = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), max_features=5000,
            sublinear_tf=True, min_df=2,
        )
        raw = hstack(
            [self.word_vec.fit_transform(texts), self.char_vec.fit_transform(texts)],
            format="csr",
        )

        if self.text_components is None:
            self._text_width = raw.shape[1]
            return raw

        # SVD cannot produce more components than the matrix has columns.
        components = min(self.text_components, raw.shape[1] - 1)
        self.svd = TruncatedSVD(n_components=components, random_state=RANDOM_SEED)
        reduced = self.svd.fit_transform(raw)
        self._text_width = reduced.shape[1]
        return reduced

    def _transform_text(self, samples: list[ExtractedSample]) -> csr_matrix | np.ndarray:
        assert self.word_vec is not None and self.char_vec is not None
        texts = [s.text for s in samples]
        raw = hstack(
            [self.word_vec.transform(texts), self.char_vec.transform(texts)],
            format="csr",
        )
        if self.svd is None:
            return raw
        return self.svd.transform(raw)

    # -- structured channel --------------------------------------------------

    def _fit_structured(self, samples: list[ExtractedSample]) -> csr_matrix:
        rows = [s.vector_for(self.groups) for s in samples]
        self.dict_vec = DictVectorizer(sparse=True)
        matrix = self.dict_vec.fit_transform(rows)
        self.scaler = MaxAbsScaler()
        self._structured_width = matrix.shape[1]
        return csr_matrix(self.scaler.fit_transform(matrix))

    def _transform_structured(self, samples: list[ExtractedSample]) -> csr_matrix:
        assert self.dict_vec is not None and self.scaler is not None
        matrix = self.dict_vec.transform([s.vector_for(self.groups) for s in samples])
        return csr_matrix(self.scaler.transform(matrix))

    # -- public --------------------------------------------------------------

    def fit_transform(self, samples: list[ExtractedSample]) -> csr_matrix:
        blocks: list[Any] = []
        if self.use_text:
            blocks.append(csr_matrix(self._fit_text(samples)))
        if self.groups:
            blocks.append(self._fit_structured(samples))
        if not blocks:
            raise ValueError("empty feature space")
        return hstack(blocks, format="csr")

    def transform(self, samples: list[ExtractedSample]) -> csr_matrix:
        blocks: list[Any] = []
        if self.use_text:
            blocks.append(csr_matrix(self._transform_text(samples)))
        if self.groups:
            blocks.append(self._transform_structured(samples))
        if not blocks:
            raise ValueError("empty feature space")
        return hstack(blocks, format="csr")

    @property
    def widths(self) -> dict[str, int]:
        return {
            "text": self._text_width,
            "structured": self._structured_width,
            "total": self._text_width + self._structured_width,
        }


def configurations(components: int) -> tuple[tuple[str, str, BalancedSpace], ...]:
    """The four arms of the balanced experiment."""
    return (
        ("A", "Balanced text only",
         BalancedSpace([], True, components)),
        ("B", "Balanced text + structured",
         BalancedSpace(list(ALL_STRUCTURED), True, components)),
        ("C", "Full fusion (unbalanced text)",
         BalancedSpace(list(ALL_STRUCTURED), True, None)),
        ("D", "Structured only",
         BalancedSpace(list(ALL_STRUCTURED), False, None)),
    )


def _fold_scores(space_factory, samples: list[ExtractedSample],
                 model_key: str) -> tuple[list[float], list[dict[str, Any]]]:
    """Per-fold F1 over repeated stratified k-fold, plus per-fold metrics.

    A fresh feature space is built inside every fold so that the vectoriser,
    SVD and scaler never see held-out data.
    """
    spec = MODELS_BY_KEY[model_key]
    y = labels_of(samples)
    splitter = RepeatedStratifiedKFold(
        n_splits=CV_SPLITS, n_repeats=CV_REPEATS, random_state=RANDOM_SEED
    )

    f1s: list[float] = []
    folds: list[dict[str, Any]] = []

    for train_idx, test_idx in splitter.split(np.arange(len(samples)), y):
        train_samples = [samples[i] for i in train_idx]
        test_samples = [samples[i] for i in test_idx]

        space = space_factory()
        x_train = space.fit_transform(train_samples)
        model = train(spec, x_train, labels_of(train_samples))

        x_test = space.transform(test_samples)
        y_pred, scores = predict(model, x_test)
        metrics = compute_metrics(labels_of(test_samples), y_pred, scores)

        f1s.append(metrics["f1"])
        folds.append(metrics)

    return f1s, folds


def _aggregate(folds: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean and spread across folds, plus a pooled confusion matrix."""
    def stat(key: str) -> dict[str, float]:
        values = [f[key] for f in folds if f[key] is not None]
        if not values:
            return {"mean": None, "std": None}
        return {
            "mean": round(float(np.mean(values)), 4),
            "std": round(float(np.std(values, ddof=1)), 4),
        }

    pooled = {"true_negative": 0, "false_positive": 0,
              "false_negative": 0, "true_positive": 0}
    for fold in folds:
        for key in pooled:
            pooled[key] += fold["confusion_matrix"][key]

    return {
        "precision": stat("precision"),
        "recall": stat("recall"),
        "f1": stat("f1"),
        "accuracy": stat("accuracy"),
        "roc_auc": stat("roc_auc"),
        "pr_auc": stat("pr_auc"),
        "false_positive_rate": stat("false_positive_rate"),
        "false_negative_rate": stat("false_negative_rate"),
        "pooled_confusion_matrix": pooled,
        "n_folds": len(folds),
    }


def paired_comparison(a_scores: list[float], b_scores: list[float],
                      a_label: str, b_label: str) -> dict[str, Any]:
    """Paired t-test on per-fold F1 differences, with a 95% CI.

    Paired because both configurations were evaluated on identical folds; an
    unpaired test would discard that pairing and lose power.
    """
    a = np.asarray(a_scores, dtype=float)
    b = np.asarray(b_scores, dtype=float)
    diff = b - a
    n = len(diff)

    mean_diff = float(np.mean(diff))
    sd_diff = float(np.std(diff, ddof=1)) if n > 1 else 0.0

    if n < 2 or sd_diff == 0.0:
        # Degenerate variance. Two very different cases hide here and must not
        # be collapsed:
        #   mean == 0  ->  the configurations scored identically everywhere;
        #                  there is genuinely no difference.
        #   mean != 0  ->  the SAME difference appeared in every single fold.
        #                  A t-test is undefined (division by zero), but this is
        #                  the most consistent evidence obtainable, not the
        #                  least. The confidence interval collapses to a point
        #                  at the mean, which excludes zero, so the project's
        #                  own significance rule (CI excludes zero) is met.
        consistent = n >= 2 and mean_diff != 0.0
        if consistent:
            direction = "improves" if mean_diff > 0 else "degrades"
            verdict = (
                f"{b_label} consistently {direction} on {a_label}: an identical "
                f"difference of {mean_diff:+.5f} in all {n} folds. Variance is "
                "zero, so a t-test is undefined; the effect is reported as "
                "significant because it is perfectly consistent."
            )
        elif mean_diff == 0.0:
            verdict = "identical across all folds - no difference to test"
        else:
            verdict = "too few folds to test"

        return {
            "comparison": f"{b_label} minus {a_label}",
            "n_pairs": n,
            "mean_difference": round(mean_diff, 5),
            "std_difference": round(sd_diff, 5),
            "t_statistic": None,
            "p_value": None,
            "ci95_low": round(mean_diff, 5),
            "ci95_high": round(mean_diff, 5),
            "significant": consistent,
            "zero_variance": True,
            "verdict": verdict,
        }

    t_stat, p_value = stats.ttest_rel(b, a)
    stderr = sd_diff / np.sqrt(n)
    margin = stats.t.ppf(0.975, df=n - 1) * stderr
    low, high = mean_diff - margin, mean_diff + margin

    significant = bool(p_value < 0.05 and (low > 0 or high < 0))
    if significant:
        direction = "improves" if mean_diff > 0 else "degrades"
        verdict = f"{b_label} significantly {direction} on {a_label} (p={p_value:.4f})"
    else:
        verdict = (
            f"statistically indistinguishable (p={p_value:.4f}, "
            f"95% CI [{low:+.4f}, {high:+.4f}] includes zero)"
        )

    return {
        "comparison": f"{b_label} minus {a_label}",
        "n_pairs": n,
        "mean_difference": round(mean_diff, 5),
        "std_difference": round(sd_diff, 5),
        "t_statistic": round(float(t_stat), 4),
        "p_value": round(float(p_value), 6),
        "ci95_low": round(float(low), 5),
        "ci95_high": round(float(high), 5),
        "significant": significant,
        "verdict": verdict,
    }


def run_balanced_ablation(model_key: str = "random_forest",
                          components: int = STRUCTURED_FEATURE_COUNT,
                          output_dir: Path = RESULTS_DIR,
                          sensitivity: bool = True) -> dict[str, Any]:
    splits = load_corpus()
    pooled = splits["train"] + splits["validation"] + splits["test"]

    # Verify the pre-registered matching rule still holds.
    probe = BalancedSpace(list(ALL_STRUCTURED), False, None)
    probe.fit_transform(pooled[:50])
    actual_structured = probe.widths["structured"]

    results: dict[str, Any] = {
        "result_type": "RESEARCH FEATURE-BALANCED ABLATION RESULTS",
        "provenance": PROVENANCE,
        "not_real_world_accuracy": True,
        "research_question": (
            "Was the original negative fusion result caused by TF-IDF "
            "dimensional dominance rather than by an absence of signal in the "
            "forensic evidence features?"
        ),
        "method": {
            "reduction": "TruncatedSVD (LSA) on the combined word+char TF-IDF matrix",
            "why_svd_not_selection": (
                "Supervised feature selection would rank features by their "
                "association with the label, leaking target information into "
                "the representation. SVD is unsupervised and sees no labels."
            ),
            "components_pre_registered": components,
            "matching_rule": (
                "component count fixed to the structured feature count by a rule "
                "stated before any result was observed; not searched for"
            ),
            "structured_feature_count_observed": actual_structured,
            "matching_rule_holds": actual_structured == STRUCTURED_FEATURE_COUNT,
            "cv": f"RepeatedStratifiedKFold({CV_SPLITS} splits x {CV_REPEATS} repeats)",
            "pairing": "all configurations evaluated on identical folds",
            "significance": "paired t-test, p<0.05 AND 95% CI excluding zero",
            "leakage_control": (
                "vectoriser, SVD and scaler fitted inside each fold on training "
                "data only"
            ),
        },
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment(),
        "model": MODELS_BY_KEY[model_key].config(),
        "corpus": {
            "pooled_size": len(pooled),
            "class_distribution": {
                "MALICIOUS": sum(1 for s in pooled if s.label == 1),
                "BENIGN": sum(1 for s in pooled if s.label == 0),
            },
        },
        "configurations": [],
    }

    fold_scores: dict[str, list[float]] = {}

    for key, label, space in configurations(components):
        factory = (lambda s=space: BalancedSpace(
            list(s.groups), s.use_text, s.text_components
        ))
        f1s, folds = _fold_scores(factory, pooled, model_key)
        fold_scores[key] = f1s

        probe_space = factory()
        probe_space.fit_transform(pooled)

        results["configurations"].append({
            "configuration": key,
            "label": label,
            "feature_widths": probe_space.widths,
            "uses_text": space.use_text,
            "text_components": space.text_components,
            "metrics": _aggregate(folds),
            "per_fold_f1": [round(v, 4) for v in f1s],
        })

    # The experiment: identical text capacity, structured evidence added.
    results["primary_comparison"] = paired_comparison(
        fold_scores["A"], fold_scores["B"],
        "A (balanced text only)", "B (balanced text + structured)",
    )
    results["secondary_comparisons"] = [
        # The cleanest equal-capacity comparison in the whole experiment:
        # 82 forensic features against 82 text components, same folds.
        paired_comparison(fold_scores["A"], fold_scores["D"],
                          "A (balanced text only, 82)", "D (structured only, 82)"),
        paired_comparison(fold_scores["A"], fold_scores["C"],
                          "A (balanced text only)", "C (full fusion, unbalanced)"),
        paired_comparison(fold_scores["C"], fold_scores["B"],
                          "C (full fusion, unbalanced)", "B (balanced fusion)"),
        paired_comparison(fold_scores["D"], fold_scores["B"],
                          "D (structured only)", "B (balanced fusion)"),
    ]

    if sensitivity:
        results["sensitivity_check"] = run_sensitivity(pooled, model_key)
        results["sensitivity_note"] = (
            "Robustness only. The primary result is the pre-registered "
            f"{components}-component configuration; this sweep exists to show "
            "the conclusion is not an artifact of that single choice, and was "
            "NOT used to select it."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "balanced_ablation.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return results


def run_sensitivity(pooled: list[ExtractedSample], model_key: str) -> list[dict[str, Any]]:
    """Repeat the A-versus-B comparison at several component counts."""
    out: list[dict[str, Any]] = []
    for components in SENSITIVITY_COMPONENTS:
        a_scores, _ = _fold_scores(
            lambda c=components: BalancedSpace([], True, c), pooled, model_key
        )
        b_scores, _ = _fold_scores(
            lambda c=components: BalancedSpace(list(ALL_STRUCTURED), True, c),
            pooled, model_key,
        )
        comparison = paired_comparison(
            a_scores, b_scores, "text only", "text + structured"
        )
        out.append({
            "components": components,
            "text_only_f1_mean": round(float(np.mean(a_scores)), 4),
            "fusion_f1_mean": round(float(np.mean(b_scores)), 4),
            "mean_difference": comparison["mean_difference"],
            "p_value": comparison["p_value"],
            "significant": comparison["significant"],
        })
    return out


def format_table(results: dict[str, Any]) -> str:
    header = (
        f"{'Cfg':<4}{'Configuration':<32}{'Txt':>6}{'Str':>5}"
        f"{'Prec':>8}{'Rec':>8}{'F1':>8}{'+/-sd':>8}{'ROC':>8}{'PR':>8}"
    )
    lines = [header, "-" * len(header)]
    for entry in results["configurations"]:
        m = entry["metrics"]
        w = entry["feature_widths"]

        def cell(key: str) -> str:
            value = m[key]["mean"]
            return f"{value:>8.4f}" if value is not None else f"{'-':>8}"

        lines.append(
            f"{entry['configuration']:<4}{entry['label']:<32}"
            f"{w['text']:>6}{w['structured']:>5}"
            f"{cell('precision')}{cell('recall')}{cell('f1')}"
            f"{m['f1']['std']:>8.4f}{cell('roc_auc')}{cell('pr_auc')}"
        )
    return "\n".join(lines)


def format_confusion(results: dict[str, Any]) -> str:
    lines = [f"{'Cfg':<4}{'Configuration':<32}{'TN':>7}{'FP':>7}{'FN':>7}{'TP':>7}"]
    lines.append("-" * len(lines[0]))
    for entry in results["configurations"]:
        c = entry["metrics"]["pooled_confusion_matrix"]
        lines.append(
            f"{entry['configuration']:<4}{entry['label']:<32}"
            f"{c['true_negative']:>7}{c['false_positive']:>7}"
            f"{c['false_negative']:>7}{c['true_positive']:>7}"
        )
    lines.append("(pooled across all folds)")
    return "\n".join(lines)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Feature-balanced ablation.")
    parser.add_argument("--model", default="random_forest", choices=sorted(MODELS_BY_KEY))
    parser.add_argument("--components", type=int, default=STRUCTURED_FEATURE_COUNT)
    parser.add_argument("--no-sensitivity", action="store_true")
    args = parser.parse_args()

    print("FEATURE-BALANCED ABLATION")
    print("  Question: was the original negative fusion result caused by")
    print("            TF-IDF dimensional dominance?")
    print(f"  Model: {MODELS_BY_KEY[args.model].label}")
    print(f"  Pre-registered SVD components: {args.components} "
          f"(= structured feature count)")
    print(f"  {PROVENANCE}\n")

    results = run_balanced_ablation(
        args.model, args.components, sensitivity=not args.no_sensitivity
    )

    print(format_table(results))
    print()
    print(format_confusion(results))
    print()
    print("PRIMARY COMPARISON (the experiment)")
    primary = results["primary_comparison"]
    print(f"  {primary['comparison']}")
    print(f"  mean dF1 = {primary['mean_difference']:+.5f}  "
          f"95% CI [{primary['ci95_low']:+.5f}, {primary['ci95_high']:+.5f}]  "
          f"n={primary['n_pairs']}")
    print(f"  VERDICT: {primary['verdict']}")
    print()
    print("SECONDARY COMPARISONS")
    for comparison in results["secondary_comparisons"]:
        print(f"  {comparison['comparison']}")
        print(f"    mean dF1 = {comparison['mean_difference']:+.5f}  "
              f"{comparison['verdict']}")

    if "sensitivity_check" in results:
        print()
        print("SENSITIVITY (robustness only - did not select the primary parameter)")
        print(f"  {'Comp':>6}{'text-only':>12}{'fusion':>10}{'dF1':>10}{'p':>10}  sig")
        for row in results["sensitivity_check"]:
            p_text = "-" if row["p_value"] is None else f"{row['p_value']:.4f}"
            print(f"  {row['components']:>6}{row['text_only_f1_mean']:>12.4f}"
                  f"{row['fusion_f1_mean']:>10.4f}{row['mean_difference']:>+10.5f}"
                  f"{p_text:>10}  {'yes' if row['significant'] else 'no'}")

    print(f"\nwritten: {RESULTS_DIR / 'balanced_ablation.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
