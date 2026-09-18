"""Forensic report tests: completeness, separation, honesty about absence, escaping."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bec_detector.acquisition import load_bytes
from bec_detector.forensics import IOCStore
from bec_detector.pipeline import BECPipeline
from bec_detector.report import render_html
from bec_detector.report.assemble import assemble_report, config_fingerprint

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"

REQUIRED_SECTIONS = [
    "Case information", "Executive summary", "Evidence information",
    "Evidence integrity", "Chain of custody", "Email metadata", "Header forensics",
    "From / Reply-To / Return-Path", "Sender identity and display-name analysis",
    "Domain and Unicode confusable analysis", "SPF / DKIM / DMARC",
    "Behavioural analysis", "NLP and social-engineering indicators",
    "Financial intent", "Thread reconstruction", "Stylometry", "URL analysis",
    "Attachment analysis", "Extracted IOCs", "Evidence graph",
    "Cross-case correlation", "Investigation timeline", "Threat intelligence",
    "Potential ATT&amp;CK mapping", "Evidence fusion", "Risk assessment",
    "Investigator recommendations", "Investigator assessment", "Audit integrity",
    "Limitations", "Reproducibility",
]


def _report(tmp_path, *names: str) -> tuple[dict, str]:
    pipeline = BECPipeline(case_id="CASE-RPT", examiner="Tester",
                           ioc_store=IOCStore(tmp_path / "ioc.json"))
    import shutil
    for name in names:
        shutil.copy(SAMPLES / name, tmp_path / name)
    assessments = pipeline.run(tmp_path)
    report = assemble_report(pipeline, assessments, case_name="Report test", examiner="Tester")
    return report, render_html(report)


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rpt")
    return _report(tmp, "bec_08_link_and_attachment.eml", "thread_01_genuine_opening.eml",
                   "thread_02_genuine_reply.eml", "thread_03_hijack.eml",
                   "bec_01_ceo_wire_urgent.eml")


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", REQUIRED_SECTIONS)
def test_required_section_present(full, section):
    _, document = full
    assert section in document, f"report is missing section {section!r}"


def test_four_way_separation_headings(full):
    """Every finding table separates evidence, inference, risk and recommendation."""
    _, document = full
    header = ("<th>Finding</th><th>Observed evidence</th><th>System inference</th>"
              "<th>Risk</th><th>Recommendation</th>")
    assert header in document


def test_investigator_assessment_is_separate_and_honest_when_empty(full):
    _, document = full
    assert "No investigator assessment has been recorded" in document


def test_every_evidence_hash_appears(full):
    report, document = full
    for item in report["assessments"]:
        assert item["custody"]["sha256"] in document


def test_fusion_arithmetic_is_shown(full):
    report, document = full
    item = report["assessments"][0]
    assert "Corroboration bonus" in document and "Formula" in document
    fusion = item["fusion"]
    assert fusion["subtotal"] >= 0 and fusion["normaliser"] > 0
    capped = sum(fusion["capped_by_category"].values())
    expected = min(100.0, (capped + fusion["corroboration_bonus"]) / fusion["normaliser"] * 100)
    assert item["risk_score"] == pytest.approx(round(expected, 1), abs=0.11)


def test_risk_score_is_not_presented_as_a_probability(full):
    _, document = full
    assert "not a probability" in document


def test_graph_svg_embedded(full):
    _, document = full
    assert re.search(r"<svg[^>]+aria-label=\"Evidence graph\"", document)


def test_reproducibility_fingerprint_matches_configuration(full):
    report, document = full
    fingerprint = config_fingerprint()["sha256"]
    assert report["reproducibility"]["configuration"]["sha256"] == fingerprint
    assert fingerprint in document


def test_fingerprint_changes_when_configuration_changes(monkeypatch):
    from bec_detector import config

    before = config_fingerprint()["sha256"]
    monkeypatch.setitem(config.WEIGHTS, "URGENCY_LANGUAGE", 99.0)
    assert config_fingerprint()["sha256"] != before


def test_address_comparison_flags_divergence(full):
    _, document = full
    assert "differs from From" in document


def test_attachment_and_url_detail_rendered(full):
    _, document = full
    assert "Payslip_September.pdf.exe" in document
    assert "203.0.113.45" in document
    assert "ever resolved or contacted" in document


def test_domain_analysis_names_confusable_target(full):
    report, _ = full
    bec01 = next(i for i in report["assessments"]
                 if i["email"]["from_address"] == "r.menon@northwind-l0gistics.com")
    from_row = next(d for d in bec01["domain_analysis"] if d["role"] == "From")
    assert from_row["resembles_trusted"] is True
    assert from_row["best_match"] == "northwind-logistics.com"


# ---------------------------------------------------------------------------
# Never invent missing evidence
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def minimal(tmp_path_factory):
    """A message with almost nothing in it: no auth, no URLs, no attachments."""
    tmp = tmp_path_factory.mktemp("min")
    (tmp / "bare.eml").write_bytes(
        b"From: someone@example.org\r\nTo: other@example.org\r\n"
        b"Subject: hello\r\n\r\nJust saying hello.\r\n")
    pipeline = BECPipeline(case_id="CASE-MIN", ioc_store=IOCStore(tmp / "ioc.json"))
    assessments = pipeline.run(tmp)
    report = assemble_report(pipeline, assessments)
    return report, render_html(report)


@pytest.mark.parametrize("statement", [
    "No Authentication-Results header",
    "No URLs in the message body.",
    "No attachments.",
    "No payment, bank-change or monetary indicators.",
    "no parsable Date header",
    "No Received headers present.",
    "No thread findings.",
])
def test_absent_evidence_is_stated_not_invented(minimal, statement):
    _, document = minimal
    assert statement in document


def test_minimal_message_has_no_fabricated_findings(minimal):
    report, _ = minimal
    codes = {i["code"] for i in report["assessments"][0]["indicators"]}
    for code in ("PAYMENT_REQUEST", "URL_IP_LITERAL", "ATTACHMENT_EXECUTABLE",
                 "LOOKALIKE_DOMAIN", "SPF_FAIL"):
        assert code not in codes


# ---------------------------------------------------------------------------
# Escaping - evidence is attacker-controlled everywhere it appears
# ---------------------------------------------------------------------------

HOSTILE = (
    b'From: "<script>alert(1)</script>" <x@evil.test>\r\n'
    b"To: <img src=x onerror=alert(2)>@victim.test\r\n"
    b"Reply-To: \"</td><script>alert(3)</script>\" <r@evil.test>\r\n"
    b"Subject: <svg onload=alert(4)>\r\n"
    b"Message-ID: <\"><script>alert(5)</script>@evil.test>\r\n"
    b"Authentication-Results: mx; spf=<b>fail</b>\r\n"
    b"In-Reply-To: <x\"><script>alert(6)</script>>\r\n"
    b"\r\n<script>alert(7)</script> https://evil.test/<script>alert(8)</script>\r\n"
)


def test_hostile_content_is_escaped_in_every_section(tmp_path):
    (tmp_path / "hostile.eml").write_bytes(HOSTILE)
    pipeline = BECPipeline(case_id="CASE-XSS", ioc_store=IOCStore(tmp_path / "ioc.json"))
    report = assemble_report(pipeline, pipeline.run(tmp_path))
    document = render_html(report)

    assert not re.search(r"<script", document, re.I), "unescaped <script> in report"
    assert "<svg onload" not in document
    assert "<img src=x" not in document
    assert "<b>fail</b>" not in document
    # The only <svg> element allowed is the graph the application generates.
    assert len(re.findall(r"<svg\b", document)) == 1


def test_report_is_self_contained(full):
    """No external assets: the report must render from the case file alone."""
    _, document = full
    assert not re.search(r'(src|href)="https?://', document)
    assert "<link " not in document
