"""Tests for the DFIR layer: integrity, IOCs, timeline, correlation, intel, graph."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bec_detector.acquisition import load_eml, load_path
from bec_detector.analysis.attachments import describe_attachment, sniff_type
from bec_detector.analysis.thread import ThreadIndex, normalise_subject
from bec_detector.analysis.urls import extract_urls
from bec_detector.forensics import (
    AuditLog,
    CommunicationGraph,
    IOCStore,
    LocalThreatIntelProvider,
    NullThreatIntelProvider,
    build_case_timeline,
    compute_entry_hash,
    extract_iocs,
    map_indicators,
)
from bec_detector.models import Confidence, RiskBand
from bec_detector.pipeline import BECPipeline

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    """One full pipeline run over the corpus, isolated from the real IOC store."""
    store = IOCStore(tmp_path_factory.mktemp("ioc") / "store.json")
    pipeline = BECPipeline(
        examiner="pytest-forensics",
        case_id="CASE-TEST",
        audit_path=tmp_path_factory.mktemp("audit") / "audit.jsonl",
        ioc_store=store,
    )
    assessments = pipeline.run(SAMPLES)
    return pipeline, assessments


def _by_name(assessments, name):
    for a in assessments:
        if Path(a.artifact.custody.source_path).name == name:
            return a
    raise AssertionError(f"{name} not found in assessments")


# ---------------------------------------------------------------------------
# Tamper-evident audit log
# ---------------------------------------------------------------------------

def test_audit_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", actor="tester")
    log.record("case_opened", "case=CASE-001")
    log.record("evidence_acquired", "sha256=abc", evidence_id="EV-1")
    log.record("message_assessed", "score=90")

    result = log.verify()
    assert result["valid"] is True
    assert result["entries"] == 3
    assert result["broken_at"] is None


def test_audit_detects_content_tampering(tmp_path):
    """Altering an entry's content must break the chain at that entry."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, actor="tester")
    log.record("case_opened", "case=CASE-001")
    log.record("evidence_acquired", "sha256=abc", evidence_id="EV-1")
    log.record("message_assessed", "score=90")
    assert log.verify()["valid"] is True

    # Rewrite entry 2's detail, leaving its stored hash untouched.
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["detail"] = "sha256=TAMPERED"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLog(path).verify()
    assert result["valid"] is False
    assert result["broken_at"] == 2
    assert "content altered" in result["reason"]


def test_audit_detects_deleted_entry(tmp_path):
    """Removing an entry must break the chain, not pass silently."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, actor="tester")
    for i in range(4):
        log.record("action", f"step {i}")

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLog(path).verify()
    assert result["valid"] is False
    assert result["broken_at"] is not None


def test_entry_hash_is_deterministic():
    a = compute_entry_hash(1, "2026-01-01T00:00:00+00:00", "x", "act", "d", "EV", "0" * 64)
    b = compute_entry_hash(1, "2026-01-01T00:00:00+00:00", "x", "act", "d", "EV", "0" * 64)
    c = compute_entry_hash(1, "2026-01-01T00:00:00+00:00", "x", "act", "D", "EV", "0" * 64)
    assert a == b
    assert a != c


def test_pipeline_audit_chain_intact(case):
    pipeline, _ = case
    result = pipeline.integrity()
    assert result["valid"] is True
    assert result["entries"] > 0


# ---------------------------------------------------------------------------
# Evidence identity and integrity
# ---------------------------------------------------------------------------

def test_evidence_id_is_derived_from_hash():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    assert email.evidence_id == f"EV-{email.custody.sha256[:12].upper()}"


def test_evidence_id_is_stable_across_loads():
    a = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    b = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    assert a.evidence_id == b.evidence_id


# ---------------------------------------------------------------------------
# Attachment static analysis
# ---------------------------------------------------------------------------

def test_sniff_detects_common_types():
    assert sniff_type(b"%PDF-1.7 rest") == "pdf"
    assert sniff_type(b"PK\x03\x04rest") == "zip-container"
    assert sniff_type(b"MZ\x90\x00rest") == "pe-executable"
    assert sniff_type(b"") == "empty"


def test_extension_mime_mismatch_detected():
    """A PE executable named .pdf and declared as PDF must be caught."""
    item = describe_attachment("invoice.pdf", "application/pdf", b"MZ\x90\x00payload")
    assert item.type_mismatch is True
    assert item.detected_type == "pe-executable"
    assert item.sha256


def test_matching_type_is_not_flagged():
    item = describe_attachment("report.pdf", "application/pdf", b"%PDF-1.7 body")
    assert item.type_mismatch is False


def test_double_extension_case_detected(case):
    _, assessments = case
    assessment = _by_name(assessments, "bec_08_link_and_attachment.eml")
    codes = {i.code for i in assessment.indicators}
    assert "ATTACHMENT_DOUBLE_EXTENSION" in codes
    assert "ATTACHMENT_EXECUTABLE" in codes
    assert "ATTACHMENT_TYPE_MISMATCH" in codes


# ---------------------------------------------------------------------------
# URL static analysis
# ---------------------------------------------------------------------------

def test_url_extraction_and_ip_literal():
    urls = extract_urls("Visit http://203.0.113.45/secure/login.php now")
    assert len(urls) == 1
    assert urls[0].is_ip_literal is True
    assert urls[0].uses_https is False


def test_anchor_text_mismatch_detected():
    html = '<a href="http://evil.test/login">https://bank.example/secure</a>'
    urls = extract_urls(html, is_html=True)
    mismatched = [u for u in urls if u.display_mismatch]
    assert mismatched, "anchor/href disagreement should be recorded"


def test_url_indicators_on_sample(case):
    _, assessments = case
    assessment = _by_name(assessments, "bec_08_link_and_attachment.eml")
    codes = {i.code for i in assessment.indicators}
    assert "URL_DISPLAY_MISMATCH" in codes
    assert "URL_IP_LITERAL" in codes


def test_punycode_host_flagged():
    urls = extract_urls("see https://xn--80ak6aa92e.example/login")
    assert urls[0].is_punycode is True


# ---------------------------------------------------------------------------
# Thread / conversation analysis
# ---------------------------------------------------------------------------

def test_subject_normalisation():
    assert normalise_subject("Re: Fwd: RE: Invoice 12") == "invoice 12"
    assert normalise_subject("Invoice 12") == "invoice 12"


def test_hijacked_thread_detected(case):
    _, assessments = case
    assessment = _by_name(assessments, "thread_03_hijack.eml")
    codes = {i.code for i in assessment.indicators}
    assert "THREAD_REPLYTO_INTRODUCED" in codes
    assert assessment.band is RiskBand.CONFIRMED_BEC


def test_genuine_reply_not_flagged_as_thread_anomaly(case):
    """A colleague who was addressed in the thread replying is not an intruder."""
    _, assessments = case
    assessment = _by_name(assessments, "thread_02_genuine_reply.eml")
    codes = {i.code for i in assessment.indicators}
    assert "THREAD_SENDER_DIVERGENCE" not in codes
    assert "THREAD_PAYMENT_PIVOT" not in codes
    assert assessment.band is RiskBand.BENIGN


def test_fabricated_reply_requires_absent_threading_headers():
    """A real reply carrying In-Reply-To must not be called fabricated."""
    index = ThreadIndex()
    emails = load_path(SAMPLES)
    index.observe_all(emails)

    genuine = next(e for e in emails
                   if Path(e.custody.source_path).name == "thread_02_genuine_reply.eml")
    codes = {i.code for i in index.analyse(genuine)}
    assert "THREAD_FABRICATED_REPLY" not in codes


def test_unknown_parent_is_reported_as_collection_gap():
    """A missing parent is insufficient data, never an accusation."""
    index = ThreadIndex()
    email = load_eml(SAMPLES / "thread_03_hijack.eml")
    index.observe(email)  # parent deliberately not observed
    found = [i for i in index.analyse(email) if i.code == "THREAD_UNKNOWN_PARENT"]
    assert found
    assert found[0].basis is Confidence.INSUFFICIENT


# ---------------------------------------------------------------------------
# Stylometry
# ---------------------------------------------------------------------------

def test_stylometry_reports_insufficient_history(case):
    """Without a baseline the tool must say so rather than invent one."""
    _, assessments = case
    assessment = _by_name(assessments, "bec_01_ceo_wire_urgent.eml")
    notes = " ".join(assessment.notes).lower()
    assert "insufficient historical data" in notes
    assert not [i for i in assessment.indicators if i.code == "STYLE_DEVIATION"]


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

def test_ioc_extraction_normalises():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    iocs = extract_iocs(email)
    assert "r.menon@northwind-l0gistics.com" in iocs["email_addresses"]
    assert "northwind-l0gistics.com" in iocs["domains"]
    assert all(v == v.lower() for values in iocs.values() for v in values)


def test_ioc_extraction_skips_private_ips():
    email = load_eml(SAMPLES / "bec_01_ceo_wire_urgent.eml")
    iocs = extract_iocs(email)
    assert not any(ip.startswith(("10.", "192.168.", "127.")) for ip in iocs["ipv4"])


def test_attachment_hash_becomes_an_ioc(case):
    _, assessments = case
    assessment = _by_name(assessments, "bec_08_link_and_attachment.eml")
    assert assessment.iocs["attachment_sha256"]


# ---------------------------------------------------------------------------
# Cross-case correlation
# ---------------------------------------------------------------------------

def test_correlation_links_cases(tmp_path):
    store = IOCStore(tmp_path / "store.json")
    store.record({"domains": ["evil.test"], "urls": []}, "CASE-001")
    store.save()

    reloaded = IOCStore(tmp_path / "store.json")
    matches = reloaded.lookup({"domains": ["evil.test"]}, "CASE-004")
    assert len(matches) == 1
    assert matches[0]["seen_in_cases"] == ["CASE-001"]


def test_correlation_ignores_same_case(tmp_path):
    store = IOCStore(tmp_path / "store.json")
    store.record({"domains": ["evil.test"]}, "CASE-001")
    assert store.lookup({"domains": ["evil.test"]}, "CASE-001") == []


def test_correlation_survives_corrupt_store(tmp_path):
    """A damaged store must not abort an investigation."""
    path = tmp_path / "store.json"
    path.write_text("{ not valid json", encoding="utf-8")
    store = IOCStore(path)
    assert store.lookup({"domains": ["x.test"]}, "CASE-1") == []


# ---------------------------------------------------------------------------
# Threat intelligence adapter
# ---------------------------------------------------------------------------

def test_local_intel_matches_and_labels_source(tmp_path):
    intel_file = tmp_path / "intel.json"
    intel_file.write_text(
        json.dumps({"domains": {"northwind-l0gistics.com": "known BEC infrastructure"}}),
        encoding="utf-8",
    )
    provider = LocalThreatIntelProvider(intel_file)
    matches = provider.lookup({"domains": ["northwind-l0gistics.com"]})
    assert len(matches) == 1
    assert matches[0].source == "Local intelligence"
    assert "External intelligence not configured" in provider.status()


def test_missing_intel_file_is_stated_honestly(tmp_path):
    provider = LocalThreatIntelProvider(tmp_path / "absent.json")
    assert provider.lookup({"domains": ["anything.test"]}) == []
    assert "External intelligence not configured" in provider.status()


def test_null_provider_returns_nothing():
    provider = NullThreatIntelProvider()
    assert provider.lookup({"domains": ["x.test"]}) == []


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def test_timeline_is_chronological_and_sourced(case):
    _, assessments = case
    events = build_case_timeline(assessments)
    dated = [e for e in events if e.timestamp]
    assert dated == sorted(dated, key=lambda e: e.timestamp)
    assert all(e.source for e in events), "every event must name its timestamp source"


def test_timeline_does_not_invent_timestamps(case):
    _, assessments = case
    assessment = _by_name(assessments, "bec_01_ceo_wire_urgent.eml")
    sent = [e for e in assessment.timeline if e.kind == "email_sent"]
    assert sent
    assert sent[0].timestamp.startswith(assessment.artifact.date_utc.isoformat()[:19])


# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------

def test_mitre_mapping_is_labelled_as_potential(case):
    _, assessments = case
    assessment = _by_name(assessments, "bec_01_ceo_wire_urgent.eml")
    assert assessment.mitre
    for entry in assessment.mitre:
        assert entry["technique_id"].startswith("T")
        assert "Potential technique mapping" in entry["disclaimer"]
        assert entry["suggested_by"]


def test_mitre_mapping_is_empty_without_indicators():
    assert map_indicators([]) == []


# ---------------------------------------------------------------------------
# Communication graph
# ---------------------------------------------------------------------------

def test_graph_builds_nodes_and_edges(case):
    _, assessments = case
    graph = CommunicationGraph()
    graph.add_all(assessments)
    data = graph.to_dict()
    assert data["node_count"] > 0
    assert data["edge_count"] > 0


def test_graph_highlights_boundary_crossing_relationships(case):
    _, assessments = case
    graph = CommunicationGraph()
    graph.add_all(assessments)
    suspicious = graph.suspicious_relationships()
    assert suspicious, "flagged internal/external relationships should be surfaced"
    assert all(r["crosses_boundary"] for r in suspicious)


def test_graph_records_diverted_replies(case):
    _, assessments = case
    graph = CommunicationGraph()
    graph.add_all(assessments)
    kinds = {k for edge in graph.edges.values() for k in edge["kinds"]}
    assert "replies_diverted_to" in kinds


# ---------------------------------------------------------------------------
# Investigator-facing output contract
# ---------------------------------------------------------------------------

def test_every_indicator_separates_observation_from_inference(case):
    _, assessments = case
    for assessment in assessments:
        for indicator in assessment.indicators:
            payload = indicator.to_dict()
            assert payload["observed_evidence"].strip()
            assert payload["inference"].strip()
            assert payload["basis"] in {"OBSERVED", "INFERRED", "INSUFFICIENT"}


def test_flagged_messages_carry_a_recommendation(case):
    _, assessments = case
    flagged = [a for a in assessments
               if a.band in {RiskBand.LIKELY_BEC, RiskBand.CONFIRMED_BEC}]
    assert flagged
    for assessment in flagged:
        critical = [i for i in assessment.indicators
                    if i.severity.value in {"CRITICAL", "HIGH"} and i.recommendation]
        assert critical, f"{assessment.artifact.evidence_id} has no actionable recommendation"
