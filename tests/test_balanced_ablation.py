"""Tests for the feature-balanced ablation pipeline.

These verify methodology, not outcomes. No test asserts that fusion wins, or
that any configuration reaches a particular score - pinning a result would turn
a research finding into a target. What is asserted is that the experiment is
reproducible, leak-free, fairly paired, and honest about significance.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from research.balanced_ablation import (
    ALL_STRUCTURED,
    CV_REPEATS,
    CV_SPLITS,
    SENSITIVITY_COMPONENTS,
    STRUCTURED_FEATURE_COUNT,
    BalancedSpace,
    configurations,
    paired_comparison,
)
from research.features import load_split

ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DATA = ROOT / "data" / "research"
RESULT_FILE = ROOT / "output" / "research" / "balanced_ablation.json"

pytestmark = pytest.mark.skipif(
    not (RESEARCH_DATA / "train" / "labels.json").exists(),
    reason="research corpus absent - run: python data/build_research_corpus.py",
)


@pytest.fixture(scope="module")
def samples():
    return load_split(RESEARCH_DATA / "train")


@pytest.fixture(scope="module")
def held_out():
    return load_split(RESEARCH_DATA / "test")


# ---------------------------------------------------------------------------
# The balancing itself
# ---------------------------------------------------------------------------

def test_svd_reduces_text_to_the_requested_width(samples):
    space = BalancedSpace([], use_text=True, text_components=82)
    space.fit_transform(samples)
    assert space.widths["text"] == 82
    assert space.widths["structured"] == 0


def test_balanced_channels_are_comparable_in_width(samples):
    """The point of the experiment: neither channel outnumbers the other."""
    space = BalancedSpace(list(ALL_STRUCTURED), use_text=True,
                          text_components=STRUCTURED_FEATURE_COUNT)
    space.fit_transform(samples)
    widths = space.widths
    assert widths["text"] == widths["structured"], (
        f"channels not balanced: {widths}"
    )


def test_matching_rule_still_holds(samples):
    """The pre-registered component count must equal the structured count.

    If the feature set changes, this fails rather than silently invalidating
    the balancing rule the experiment is built on.
    """
    space = BalancedSpace(list(ALL_STRUCTURED), use_text=False, text_components=None)
    space.fit_transform(samples)
    assert space.widths["structured"] == STRUCTURED_FEATURE_COUNT


def test_unbalanced_configuration_keeps_full_text(samples):
    space = BalancedSpace(list(ALL_STRUCTURED), use_text=True, text_components=None)
    space.fit_transform(samples)
    assert space.widths["text"] > 1000, "config C must retain the full TF-IDF matrix"


# ---------------------------------------------------------------------------
# Leakage control
# ---------------------------------------------------------------------------

def test_svd_is_not_fitted_on_held_out_data(samples, held_out):
    """transform() must reuse the fitted projection, never refit it."""
    space = BalancedSpace([], use_text=True, text_components=50)
    x_train = space.fit_transform(samples)
    fitted = space.svd
    x_test = space.transform(held_out)

    assert space.svd is fitted, "transform must not refit the SVD"
    assert x_train.shape[1] == x_test.shape[1]


def test_structured_vectoriser_is_not_refitted(samples, held_out):
    space = BalancedSpace(list(ALL_STRUCTURED), use_text=False, text_components=None)
    x_train = space.fit_transform(samples)
    names = list(space.dict_vec.feature_names_)
    x_test = space.transform(held_out)

    assert list(space.dict_vec.feature_names_) == names
    assert x_train.shape[1] == x_test.shape[1]


def test_reduction_is_unsupervised(samples):
    """SVD must never see labels - a supervised reduction would leak the target."""
    import inspect

    from research import balanced_ablation

    source = inspect.getsource(balanced_ablation.BalancedSpace._fit_text)
    assert "label" not in source.lower()
    assert "y" not in {t.strip() for t in source.split(",")}


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------

def test_balanced_space_is_deterministic(samples, held_out):
    outputs = []
    for _ in range(2):
        space = BalancedSpace(list(ALL_STRUCTURED), use_text=True, text_components=40)
        space.fit_transform(samples)
        outputs.append(space.transform(held_out).toarray())
    np.testing.assert_allclose(outputs[0], outputs[1], rtol=1e-9, atol=1e-12)


def test_configurations_cover_the_required_arms():
    keys = [c[0] for c in configurations(82)]
    assert keys == ["A", "B", "C", "D"]

    by_key = {c[0]: c[2] for c in configurations(82)}
    assert by_key["A"].use_text and not by_key["A"].groups
    assert by_key["B"].use_text and by_key["B"].groups
    assert by_key["C"].text_components is None
    assert by_key["D"].use_text is False


# ---------------------------------------------------------------------------
# Statistical comparison
# ---------------------------------------------------------------------------

def test_paired_comparison_detects_a_real_difference():
    a = [0.90, 0.91, 0.89, 0.90, 0.92, 0.90, 0.91, 0.89, 0.90, 0.91]
    b = [0.95, 0.96, 0.94, 0.95, 0.97, 0.95, 0.96, 0.94, 0.95, 0.96]
    result = paired_comparison(a, b, "A", "B")

    assert result["significant"] is True
    assert result["mean_difference"] > 0
    assert result["ci95_low"] > 0
    assert "improves" in result["verdict"]


def test_paired_comparison_reports_indistinguishable_when_noise():
    rng = np.random.default_rng(7)
    a = (0.95 + rng.normal(0, 0.01, 15)).tolist()
    b = (0.95 + rng.normal(0, 0.01, 15)).tolist()
    result = paired_comparison(a, b, "A", "B")

    assert result["significant"] is False
    assert "indistinguishable" in result["verdict"]
    assert result["ci95_low"] < 0 < result["ci95_high"]


def test_paired_comparison_detects_degradation():
    a = [0.95] * 5 + [0.96] * 5
    b = [0.90] * 5 + [0.91] * 5
    result = paired_comparison(a, b, "A", "B")
    assert result["significant"] is True
    assert result["mean_difference"] < 0
    assert "degrades" in result["verdict"]


def test_identical_scores_are_not_called_significant():
    scores = [0.95] * 12
    result = paired_comparison(scores, list(scores), "A", "B")
    assert result["significant"] is False
    assert result["p_value"] is None
    assert result["mean_difference"] == 0.0


def test_perfectly_consistent_difference_is_significant():
    """A difference identical in every fold is the strongest evidence, not the
    weakest. Zero variance makes the t-test undefined, but the CI collapses to
    a point excluding zero, so the significance rule is still satisfied."""
    a = [0.90] * 10
    b = [0.95] * 10
    result = paired_comparison(a, b, "A", "B")

    assert result["significant"] is True
    assert result["zero_variance"] is True
    assert result["p_value"] is None
    assert result["ci95_low"] == result["ci95_high"] == pytest.approx(0.05)
    assert "consistently improves" in result["verdict"]


def test_significance_requires_both_p_and_ci():
    """A p-value alone must not be enough to claim significance."""
    import inspect

    from research import balanced_ablation

    source = inspect.getsource(balanced_ablation.paired_comparison)
    assert "p_value < 0.05" in source
    assert "low > 0 or high < 0" in source


# ---------------------------------------------------------------------------
# Result artifact
# ---------------------------------------------------------------------------

def test_result_file_declares_provenance():
    if not RESULT_FILE.exists():
        pytest.skip("balanced_ablation.json not generated yet")

    payload = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
    assert payload["not_real_world_accuracy"] is True
    assert "SYNTHETIC" in payload["provenance"]
    assert payload["method"]["matching_rule_holds"] is True


def test_result_file_records_the_preregistration():
    if not RESULT_FILE.exists():
        pytest.skip("balanced_ablation.json not generated yet")

    payload = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
    method = payload["method"]
    assert method["components_pre_registered"] == STRUCTURED_FEATURE_COUNT
    assert "not searched for" in method["matching_rule"]
    assert "unsupervised" in method["why_svd_not_selection"].lower()


def test_result_file_reports_full_metric_set():
    if not RESULT_FILE.exists():
        pytest.skip("balanced_ablation.json not generated yet")

    payload = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
    for entry in payload["configurations"]:
        metrics = entry["metrics"]
        for key in ("precision", "recall", "f1", "accuracy",
                    "roc_auc", "pr_auc", "false_positive_rate",
                    "false_negative_rate"):
            assert key in metrics, f"{key} missing from {entry['configuration']}"
            assert "mean" in metrics[key] and "std" in metrics[key]

        confusion = metrics["pooled_confusion_matrix"]
        for key in ("true_negative", "false_positive",
                    "false_negative", "true_positive"):
            assert key in confusion


def test_result_file_pairs_every_configuration_on_same_folds():
    if not RESULT_FILE.exists():
        pytest.skip("balanced_ablation.json not generated yet")

    payload = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
    expected = CV_SPLITS * CV_REPEATS
    for entry in payload["configurations"]:
        assert len(entry["per_fold_f1"]) == expected
        assert entry["metrics"]["n_folds"] == expected

    assert payload["primary_comparison"]["n_pairs"] == expected


def test_sensitivity_is_labelled_as_robustness_not_selection():
    if not RESULT_FILE.exists():
        pytest.skip("balanced_ablation.json not generated yet")

    payload = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
    if "sensitivity_check" not in payload:
        pytest.skip("sensitivity sweep not run")

    assert "NOT used to select" in payload["sensitivity_note"]
    covered = {row["components"] for row in payload["sensitivity_check"]}
    assert set(SENSITIVITY_COMPONENTS) <= covered


def test_original_ablation_is_preserved():
    """The unbalanced baseline must remain available for comparison."""
    original = ROOT / "research" / "ablation.py"
    assert original.exists(), "original ablation must not be deleted"

    source = original.read_text(encoding="utf-8")
    assert "CONFIGURATIONS" in source
    assert "TruncatedSVD" not in source, (
        "the original ablation must stay unbalanced - it is the baseline"
    )
