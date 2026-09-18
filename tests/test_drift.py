"""Concept-drift tests: the measures behave correctly, the control stays quiet,
generation 2 is reproducible and documented, and nothing claims to be an attack
detector. No test pins a performance figure."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
import pytest

from research import drift as D

ROOT = Path(__file__).resolve().parent.parent
GEN2 = ROOT / "data" / "research_drift" / "gen2"


# ---------------------------------------------------------------------------
# Measures
# ---------------------------------------------------------------------------

def test_psi_zero_for_identical_distributions():
    rng = np.random.default_rng(1)
    sample = rng.normal(0, 1, 2000)
    assert D.psi(sample, sample) == pytest.approx(0.0, abs=1e-9)


def test_psi_small_for_same_generator():
    rng = np.random.default_rng(2)
    assert D.psi(rng.normal(0, 1, 3000), rng.normal(0, 1, 3000)) < D.PSI_MODERATE


def test_psi_large_for_shifted_distribution():
    rng = np.random.default_rng(3)
    assert D.psi(rng.normal(0, 1, 3000), rng.normal(2, 1, 3000)) > D.PSI_SIGNIFICANT


def test_psi_handles_constant_reference():
    assert D.psi(np.zeros(100), np.zeros(100)) == pytest.approx(0.0, abs=1e-6)
    assert D.psi(np.zeros(100), np.ones(100)) > D.PSI_SIGNIFICANT


def test_psi_handles_empty_input():
    assert D.psi(np.array([]), np.array([1.0])) == 0.0


def test_js_divergence_bounds():
    a = Counter({"alpha": 5, "beta": 5})
    assert D.js_divergence(a, a) == 0.0
    assert D.js_divergence(Counter({"x": 1}), Counter({"y": 1})) == pytest.approx(1.0)
    assert D.js_divergence(Counter(), Counter()) == 0.0


def test_corpus_relative_indicators_are_excluded():
    """Behavioural, stylometric and thread-divergence indicators depend on the
    other messages in the set; they alarmed on the control and are excluded."""
    for code in ("DISPLAY_NAME_CHANGED", "FIRST_TIME_SENDER", "STYLE_DEVIATION",
                 "THREAD_SENDER_DIVERGENCE"):
        assert code in D.CORPUS_RELATIVE_CODES
    for intrinsic in ("SPF_FAIL", "PAYMENT_REQUEST", "LOOKALIKE_DOMAIN"):
        assert intrinsic not in D.CORPUS_RELATIVE_CODES


# ---------------------------------------------------------------------------
# Generation 2 corpus
# ---------------------------------------------------------------------------

pytestmark_gen2 = pytest.mark.skipif(not (GEN2 / "labels.json").exists(),
                                     reason="run: python data/build_drift_corpus.py")


@pytestmark_gen2
def test_gen2_documents_its_shift_and_provenance():
    meta = json.loads((GEN2 / "corpus.json").read_text(encoding="utf-8"))
    assert "SYNTHETIC" in meta["provenance"]
    assert "does not reproduce real attacker evolution" in meta["provenance"].lower()
    assert meta["shift"]["compromised_share_of_attacks"]["gen2"] == 0.8


def test_gen2_is_deterministic():
    import sys
    sys.path.insert(0, str(ROOT / "data"))
    import build_drift_corpus as B

    a, b = B.generate(40, seed=5), B.generate(40, seed=5)
    assert [x["body"] for x in a] == [x["body"] for x in b]


def test_building_gen2_leaves_gen1_generator_untouched():
    """Generation 2 imports the original generator; it must not alter its output."""
    import sys
    sys.path.insert(0, str(ROOT / "data"))
    import build_drift_corpus  # noqa: F401 - importing must have no side effect
    import build_research_corpus as base

    before = base.generate(30, seed=11)
    build_drift_corpus.generate(30, seed=12)
    after = base.generate(30, seed=11)
    assert [x["body"] for x in before] == [x["body"] for x in after]


# ---------------------------------------------------------------------------
# End-to-end result artifact
# ---------------------------------------------------------------------------

RESULT = ROOT / "output" / "research" / "drift.json"


def _result():
    if not RESULT.exists():
        pytest.skip("drift.json not generated - run: python -m research.drift")
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_result_declares_provenance():
    r = _result()
    assert r["not_real_world_accuracy"] is True
    assert "does NOT reproduce real attacker evolution" in r["provenance"]


def test_control_comparison_is_present_and_quiet():
    """A detector that alarms on the control is not detecting drift."""
    control = _result()["drift"]["control_gen1_train_vs_gen1_test"]
    assert control["verdict"] == "No significant distribution shift detected"


def test_verdicts_never_claim_an_attack():
    for report in _result()["drift"].values():
        assert "attack" not in report["verdict"].lower()
        assert "not, by itself, evidence of malicious activity" in report["note"]


def test_both_systems_measured_on_both_generations():
    perf = _result()["performance"]
    for system in ("rule_engine", "random_forest_trained_on_gen1"):
        assert set(perf[system]) == {"gen1_test", "gen2"}
