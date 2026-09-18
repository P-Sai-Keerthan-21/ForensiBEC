"""Tests for the ML research layer.

These verify reproducibility, absence of leakage, and that every result
artifact carries its own provenance caveat. They deliberately do NOT assert
that any model achieves a particular score - pinning a metric would turn a
research result into a target, which is how fabricated findings happen.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from research.baselines import (
    MODELS,
    MODELS_BY_KEY,
    FeatureSpace,
    labels_of,
    predict,
    train,
)
from research.evaluate import compute_metrics, environment
from research.features import FEATURE_GROUPS, GROUP_CODES, feature_schema, load_split

ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DATA = ROOT / "data" / "research"

pytestmark = pytest.mark.skipif(
    not (RESEARCH_DATA / "train" / "labels.json").exists(),
    reason="research corpus absent - run: python data/build_research_corpus.py",
)


@pytest.fixture(scope="module")
def train_samples():
    return load_split(RESEARCH_DATA / "train")


@pytest.fixture(scope="module")
def test_samples():
    return load_split(RESEARCH_DATA / "test")


# ---------------------------------------------------------------------------
# Corpus provenance
# ---------------------------------------------------------------------------

def test_corpus_metadata_declares_synthetic_provenance():
    meta = json.loads((RESEARCH_DATA / "metadata" / "corpus.json").read_text(encoding="utf-8"))
    assert "SYNTHETIC" in meta["provenance"]
    assert meta["seed"] == 20260918
    assert "invalid_use" in meta["interpretation"]
    assert "real-world" in meta["interpretation"]["invalid_use"].lower()


def test_corpus_is_deterministic(tmp_path):
    """The same seed must reproduce the corpus byte for byte."""
    from data.build_research_corpus import generate

    a = generate(60, seed=999)
    b = generate(60, seed=999)
    assert [x["name"] for x in a] == [x["name"] for x in b]
    assert [x["body"] for x in a] == [x["body"] for x in b]
    assert [x["headers"] for x in a] == [x["headers"] for x in b]


def test_splits_are_disjoint():
    names = {}
    for split in ("train", "validation", "test"):
        labels = json.loads(
            (RESEARCH_DATA / split / "labels.json").read_text(encoding="utf-8")
        )
        names[split] = set(labels)

    assert not names["train"] & names["validation"]
    assert not names["train"] & names["test"]
    assert not names["validation"] & names["test"]


def test_splits_are_stratified():
    """Class balance must be comparable across splits."""
    ratios = []
    for split in ("train", "validation", "test"):
        labels = json.loads(
            (RESEARCH_DATA / split / "labels.json").read_text(encoding="utf-8")
        )
        values = list(labels.values())
        malicious = sum(1 for v in values if v["label"] == "MALICIOUS")
        ratios.append(malicious / len(values))
    assert max(ratios) - min(ratios) < 0.05


def test_corpus_contains_the_hard_subsets():
    """Compromised-account and relayed-benign controls must be present.

    Without them the corpus separates on the authentication header alone and
    the ablation becomes meaningless.
    """
    labels = json.loads((RESEARCH_DATA / "train" / "labels.json").read_text(encoding="utf-8"))
    families = [v["family"] for v in labels.values()]
    assert any("compromised" in f for f in families)
    assert any("relayed" in f for f in families)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def test_feature_groups_are_disjoint():
    """An indicator code must belong to exactly one group, or the ablation's
    cumulative configurations would double-count it."""
    seen: dict[str, str] = {}
    for group, codes in GROUP_CODES.items():
        for code in codes:
            assert code not in seen, f"{code} in both {seen.get(code)} and {group}"
            seen[code] = group


def test_extraction_produces_all_groups(train_samples):
    sample = train_samples[0]
    for group in FEATURE_GROUPS:
        assert group in sample.groups


def test_no_label_leakage_in_feature_names(train_samples):
    """No feature may be derived from the ground-truth label.

    Matched on whole tokens, not substrings: `domain_label_count` counts DNS
    labels and is legitimate, whereas a bare `label` feature would not be.
    """
    schema = feature_schema(train_samples)
    banned = {"label", "labels", "ismalicious", "isbenign", "target",
              "family", "groundtruth", "y"}
    for group in schema["groups"].values():
        for name in group["features"]:
            tokens = set(name.lower().replace("::", "_").split("_"))
            assert not (tokens & banned), f"{name} looks label-derived"


def test_vector_for_respects_group_selection(train_samples):
    sample = train_samples[0]
    only_header = sample.vector_for(["header"])
    assert only_header
    assert all(k.startswith("header::") for k in only_header)
    assert not any(k.startswith("identity::") for k in only_header)


def test_text_group_is_not_scalarised(train_samples):
    """Text is vectorised separately; it must contribute no scalar features."""
    assert train_samples[0].groups["text"] == {}


# ---------------------------------------------------------------------------
# Determinism and leakage in the model pipeline
# ---------------------------------------------------------------------------

def test_training_is_deterministic(train_samples, test_samples):
    groups = [g for g in FEATURE_GROUPS if g != "text"]
    spec = MODELS_BY_KEY["random_forest"]

    outputs = []
    for _ in range(2):
        space = FeatureSpace(groups, use_text=False)
        x = space.fit_transform(train_samples)
        model = train(spec, x, labels_of(train_samples))
        y_pred, _ = predict(model, space.transform(test_samples))
        outputs.append(y_pred.tolist())

    assert outputs[0] == outputs[1], "same seed must produce identical predictions"


def test_vectoriser_is_not_fitted_on_test_data(train_samples, test_samples):
    """transform() must reuse the training vocabulary, never expand it."""
    space = FeatureSpace(["header", "identity"], use_text=True)
    x_train = space.fit_transform(train_samples)
    x_test = space.transform(test_samples)
    assert x_train.shape[1] == x_test.shape[1]


def test_every_model_spec_declares_rationale():
    for spec in MODELS:
        assert spec.rationale.strip(), f"{spec.key} has no stated rationale"
        config = spec.config()
        assert config["params"]
        assert "random_state" in config["params"] or spec.key == "linear_svm"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def test_metrics_match_hand_computed_values():
    y_true = np.array([1, 1, 1, 0, 0, 0, 0])
    y_pred = np.array([1, 1, 0, 0, 0, 0, 1])
    m = compute_metrics(y_true, y_pred)

    assert m["confusion_matrix"] == {
        "true_negative": 3, "false_positive": 1,
        "false_negative": 1, "true_positive": 2,
    }
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["false_positive_rate"] == pytest.approx(0.25, abs=1e-4)
    assert m["false_negative_rate"] == pytest.approx(1 / 3, abs=1e-4)


def test_auc_is_none_when_undefined():
    """A single-class batch must report None, not a misleading 0.0."""
    y_true = np.array([1, 1, 1])
    y_pred = np.array([1, 1, 1])
    m = compute_metrics(y_true, y_pred, np.array([0.9, 0.8, 0.7]))
    assert m["roc_auc"] is None
    assert m["pr_auc"] is None


def test_environment_record_is_complete():
    env = environment()
    for key in ("python", "platform", "numpy", "scikit_learn", "random_seed"):
        assert env[key]


# ---------------------------------------------------------------------------
# Result artifacts must carry their own caveats
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", ["evaluation.json", "ablation.json"])
def test_result_files_declare_they_are_not_real_world_accuracy(filename):
    path = ROOT / "output" / "research" / filename
    if not path.exists():
        pytest.skip(f"{filename} not generated yet")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["not_real_world_accuracy"] is True
    assert "SYNTHETIC" in payload["provenance"]
    assert "UPPER BOUND" in payload["provenance"]


def test_ablation_covers_every_required_configuration():
    from research.ablation import CONFIGURATIONS

    keys = [c[0] for c in CONFIGURATIONS]
    assert keys == list("ABCDEFGHI")

    # Configurations must be strictly cumulative.
    previous: list[str] = []
    for _, _, groups, _ in CONFIGURATIONS:
        assert groups[:len(previous)] == previous, "configurations must be cumulative"
        previous = groups


def test_ablation_reports_uncertainty_not_just_point_estimates():
    """A delta smaller than its own standard deviation must be visible as such."""
    path = ROOT / "output" / "research" / "ablation.json"
    if not path.exists():
        pytest.skip("ablation.json not generated yet")

    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload["configurations"]:
        cv = entry["cross_validation"]["f1"]
        assert "mean" in cv and "std" in cv, "CV must report spread, not just a mean"
