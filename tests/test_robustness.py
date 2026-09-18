"""Adversarial robustness experiment: methodology tests.

No test asserts a robustness figure. What is asserted: transformations do what
they claim and nothing else, are deterministic, never introduce payloads,
never touch the network, and the result artifact carries its caveats.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest

from research import robustness as R

ROOT = Path(__file__).resolve().parent.parent
TEST_SPLIT = ROOT / "data" / "research" / "test"

pytestmark = pytest.mark.skipif(
    not (TEST_SPLIT / "labels.json").exists(),
    reason="research corpus absent - run: python data/build_research_corpus.py",
)

SAMPLE = (
    b'From: "Ravi Menon (CEO)" <r.menon@northwind-l0gistics.com>\r\n'
    b"To: a@northwind-logistics.com\r\nSubject: Urgent payment today\r\n"
    b"Date: Mon, 01 Sep 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"This is urgent. Please process the wire transfer of GBP 40,000.00 today.\r\n"
    b"Our banking details have changed. Verify: http://203.0.113.45/secure/login.php\r\n"
)


def _apply(key: str, raw: bytes = SAMPLE):
    transform = next(t for t in R.TRANSFORMATIONS if t.key == key)
    msg, change = transform.fn(R._load(raw), random.Random(1))
    return msg, change


def _body(msg) -> str:
    return R._body(msg)


# ---------------------------------------------------------------------------
# Each transformation does what it claims
# ---------------------------------------------------------------------------

def _norm(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def test_uppercase_changes_only_case_and_preserves_urls():
    msg, _ = _apply("uppercase")
    body = _norm(_body(msg))
    assert "THIS IS URGENT" in body
    # URL paths are case-sensitive; upper-casing them would break the link.
    assert "http://203.0.113.45/secure/login.php" in body
    assert body.lower() == _norm(_body(R._load(SAMPLE))).lower()


def test_punctuation_preserves_urls():
    """Regression: stripping dots inside URLs destroyed the link and produced
    an artificial evasion."""
    msg, change = _apply("punctuation")
    assert "http://203.0.113.45/secure/login.php" in _body(msg)
    assert "GBP 40000" in _body(msg)  # prose punctuation is gone
    assert "URLs preserved" in change


def test_soften_removes_urgency_terms():
    msg, change = _apply("soften_urgency")
    body = _body(msg).lower()
    assert "urgent" not in body and "today" not in body
    assert "replacements" in change


def test_paraphrase_removes_financial_terms():
    msg, _ = _apply("paraphrase_financial")
    body = _body(msg).lower()
    assert "wire transfer" not in body and "banking details have changed" not in body


def test_strip_title_changes_display_name_only():
    msg, change = _apply("strip_title")
    display, address = R._sender(msg)
    assert display == "Ravi Menon"
    assert address == "r.menon@northwind-l0gistics.com"


def test_homoglyph_domain_uses_non_ascii():
    msg, change = _apply("homoglyph_domain")
    _, address = R._sender(msg)
    assert not address.isascii()


def test_combosquat_domain_contains_brand():
    msg, _ = _apply("combosquat_domain")
    _, address = R._sender(msg)
    assert address.endswith("@northwind-logistics-payments.com")


@pytest.mark.parametrize("transform", R.TRANSFORMATIONS, ids=lambda t: t.key)
def test_transformations_are_deterministic(transform):
    a, _ = transform.fn(R._load(SAMPLE), random.Random(7))
    b, _ = transform.fn(R._load(SAMPLE), random.Random(7))
    assert a.as_bytes() == b.as_bytes()


@pytest.mark.parametrize("transform", R.TRANSFORMATIONS, ids=lambda t: t.key)
def test_transformations_never_add_payloads(transform):
    """No transformation may introduce an attachment or a new link."""
    msg, _ = transform.fn(R._load(SAMPLE), random.Random(7))
    assert not list(msg.iter_attachments())
    before = set(re.findall(r"https?://\S+", _body(R._load(SAMPLE))))
    after = set(re.findall(r"https?://\S+", _body(msg)))
    assert after <= before


# ---------------------------------------------------------------------------
# The experiment itself
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def small_run(tmp_path_factory):
    return R.run_robustness(limit=24, output_dir=tmp_path_factory.mktemp("rob"))


def test_result_declares_provenance_and_no_tuning(small_run):
    assert small_run["not_real_world_accuracy"] is True
    assert "SYNTHETIC" in small_run["provenance"]
    assert small_run["engine_tuned_in_response"] is False
    assert small_run["configuration"]["threat_intelligence"] == "disabled"


def test_every_transformation_is_reported(small_run):
    keys = [t["key"] for t in small_run["transformations"]]
    assert keys == [t.key for t in R.TRANSFORMATIONS]


def test_metrics_are_internally_consistent(small_run):
    for t in small_run["transformations"]:
        m = t.get("malicious")
        if m:
            assert m["detected_after"] >= m["detected_before"] - m["evaded"]
            assert 0 <= m["evaded"] <= m["detected_before"] <= m["n"]
        b = t.get("benign")
        if b:
            assert 0 <= b["induced_false_positives"] <= b["n"]


def test_evasion_examples_record_what_changed(small_run):
    for example in small_run["evasion_examples"]:
        assert example["original_band"] in R.FLAGGED
        assert example["transformed_band"] not in R.FLAGGED
        assert example["change"]


def test_experiment_makes_no_network_calls():
    source = (ROOT / "research" / "robustness.py").read_text(encoding="utf-8")
    assert not re.search(r"\b(requests|urlopen|httpx|socket)\b", source)
