"""End-to-end and unit tests for the BEC detection pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bec_detector.acquisition import load_bytes, load_eml, load_path
from bec_detector.analysis.sender import _levenshtein, _normalise_domain, analyse_sender
from bec_detector.analysis.text import analyse_text
from bec_detector.models import RiskBand
from bec_detector.pipeline import BECPipeline
from bec_detector.report import build_case_report, render_html
from bec_detector.validation.fusion import deduplicate, fuse

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="module")
def corpus():
    emails = load_path(SAMPLES)
    assert emails, "sample corpus is missing - run: python data/build_corpus.py"
    return emails


@pytest.fixture(scope="module")
def assessments(corpus):
    pipeline = BECPipeline(examiner="pytest")
    pipeline.fit(corpus)
    return {a.artifact.custody.source_path: a for a in (pipeline.assess(e) for e in corpus)}


# ---------------------------------------------------------------------------
# Acquisition
# ---------------------------------------------------------------------------

def test_headers_parse_completely():
    """Regression: CRLF handling once truncated the header block after From."""
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    assert email.subject == "Urgent - confidential wire transfer needed today"
    assert email.from_address == "r.menon@northwind-l0gistics.com"
    assert email.reply_to_address == "ravi.menon.exec@gmail.com"
    assert email.date_utc is not None
    assert email.auth_results


def test_custody_record_hashes_source():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    raw = (SAMPLES / "bec_01_ceo_wire_urgent.eml").read_bytes()
    import hashlib

    assert email.custody.sha256 == hashlib.sha256(raw).hexdigest()
    assert email.custody.size_bytes == len(raw)
    assert email.custody.tool_version.startswith("BEC-Detector")


def test_load_bytes_matches_load_file():
    path = SAMPLES / "ben_01_internal_meeting.eml"
    from_file = load_eml(path)
    from_memory = load_bytes(path.read_bytes(), "upload:test.eml")
    assert from_file.subject == from_memory.subject
    assert from_file.custody.sha256 == from_memory.custody.sha256


# ---------------------------------------------------------------------------
# Sender analysis
# ---------------------------------------------------------------------------

def test_homoglyph_domain_normalises():
    assert _normalise_domain("northwind-l0gistics.com") == _normalise_domain(
        "northwind-logistics.com"
    )


def test_levenshtein_basic():
    assert _levenshtein("abc", "abc") == 0
    assert _levenshtein("abc", "abd") == 1
    assert _levenshtein("", "abc") == 3


def test_display_name_spoofing_detected():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    codes = {i.code for i in analyse_sender(email)}
    assert "LOOKALIKE_DOMAIN" in codes
    assert "REPLY_TO_MISMATCH" in codes
    assert "DISPLAY_NAME_IMPERSONATION" in codes


def test_authentication_failures_detected():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    codes = {i.code for i in analyse_sender(email)}
    assert "SPF_FAIL" in codes
    assert "DMARC_FAIL" in codes


def test_clean_internal_mail_raises_no_identity_findings():
    email = load_eml(SAMPLES / "ben_04_hr_policy.eml")
    codes = {i.code for i in analyse_sender(email)}
    assert "DISPLAY_NAME_IMPERSONATION" not in codes
    assert "LOOKALIKE_DOMAIN" not in codes
    assert "SPF_FAIL" not in codes


# ---------------------------------------------------------------------------
# Content analysis
# ---------------------------------------------------------------------------

def test_urgency_and_payment_detected():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    codes = {i.code for i in analyse_text(email)}
    assert "URGENCY_LANGUAGE" in codes
    assert "PAYMENT_REQUEST" in codes
    assert "SECRECY_REQUEST" in codes


def test_banking_change_detected():
    email = load_eml(SAMPLES / "bec_02_vendor_bank_change.eml")
    codes = {i.code for i in analyse_text(email)}
    assert "BANKING_CHANGE_REQUEST" in codes


def test_gift_card_variant_detected():
    email = load_eml(SAMPLES / "bec_03_gift_card.eml")
    codes = {i.code for i in analyse_text(email)}
    assert "GIFT_CARD_REQUEST" in codes


def test_routine_mail_has_no_financial_findings():
    email = load_eml(SAMPLES / "ben_05_customer_query.eml")
    codes = {i.code for i in analyse_text(email)}
    assert "PAYMENT_REQUEST" not in codes
    assert "BANKING_CHANGE_REQUEST" not in codes


def test_every_indicator_carries_evidence():
    """An indicator that cannot quote its trigger is not explainable."""
    for path in sorted(SAMPLES.glob("*.eml")):
        email = load_eml(path)
        for indicator in analyse_sender(email) + analyse_text(email):
            assert indicator.evidence.strip(), f"{indicator.code} in {path.name}"
            assert indicator.explanation.strip(), f"{indicator.code} in {path.name}"


# ---------------------------------------------------------------------------
# Fusion
# ---------------------------------------------------------------------------

def test_deduplicate_keeps_strongest():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    indicators = analyse_text(email) + analyse_text(email)
    unique = deduplicate(indicators)
    assert len(unique) == len({i.code for i in indicators})


def test_score_is_bounded():
    for path in sorted(SAMPLES.glob("*.eml")):
        email = load_eml(path)
        result = fuse(email, analyse_sender(email) + analyse_text(email))
        assert 0.0 <= result.score <= 100.0


def test_empty_indicator_set_is_benign():
    email = load_eml(SAMPLES / "ben_04_hr_policy.eml")
    result = fuse(email, [])
    assert result.band is RiskBand.BENIGN
    assert result.score == 0.0
    assert result.narrative


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_case_report_and_html_render(assessments):
    report = build_case_report(list(assessments.values()), case_name="pytest")
    assert report["summary"]["messages_analysed"] == len(assessments)

    # Must survive a JSON round trip - the report is a machine-readable artifact.
    json.loads(json.dumps(report))

    document = render_html(report)
    assert "<!doctype html>" in document.lower()
    assert "Chain of custody" in document
    assert "SHA-256" in document


def test_report_includes_custody_for_every_message(assessments):
    report = build_case_report(list(assessments.values()))
    for item in report["assessments"]:
        assert len(item["custody"]["sha256"]) == 64
        assert item["custody"]["acquired_utc"]
