"""Investigator feedback: separation from system output, integrity, and the
safeguards on the export used for any future retraining."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bec_detector.cases import CaseStore
from bec_detector.feedback import (
    FeedbackError,
    FeedbackStore,
    agreement_of,
    export_training_candidates,
)
from bec_detector.forensics import IOCStore

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"


@pytest.fixture
def case(tmp_path):
    store = CaseStore(tmp_path / "cases")
    store.create("CASE-FB", examiner="Examiner A")
    for name in ("bec_01_ceo_wire_urgent.eml", "ben_04_hr_policy.eml"):
        store.add_evidence("CASE-FB", (SAMPLES / name).read_bytes(), name)
    store.analyse("CASE-FB", ioc_store=IOCStore(tmp_path / "ioc.json"))
    analysis = store.load_analysis("CASE-FB")
    by_band = {a["risk_band"]: a["evidence_id"] for a in analysis["assessments"]}
    return store, by_band["CONFIRMED_BEC"], by_band["BENIGN"]


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def test_record_captures_system_assessment_at_review_time(case):
    store, bec, _ = case
    record = store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "Examiner B", "Verified by phone")
    assert record.system_band == "CONFIRMED_BEC"
    assert record.system_score > 0
    assert len(record.evidence_sha256) == 64
    assert len(record.system_config_sha256) == 64
    assert record.examiner == "Examiner B"
    assert record.agreement == "agrees"


@pytest.mark.parametrize("band,assessment,expected", [
    ("CONFIRMED_BEC", "confirmed_suspicious", "agrees"),
    ("CONFIRMED_BEC", "confirmed_benign", "system false positive"),
    ("BENIGN", "confirmed_suspicious", "system false negative"),
    ("BENIGN", "confirmed_benign", "agrees"),
    ("SUSPICIOUS", "confirmed_benign", "agrees"),
    ("LIKELY_BEC", "needs_review", "undetermined"),
])
def test_agreement_is_derived_not_entered(band, assessment, expected):
    assert agreement_of(band, assessment) == expected


def test_invalid_assessment_rejected(case):
    store, bec, _ = case
    with pytest.raises(FeedbackError):
        store.record_feedback("CASE-FB", bec, "definitely_fraud", "Examiner B")


def test_examiner_required(case):
    store, bec, _ = case
    with pytest.raises(FeedbackError, match="Examiner"):
        store.record_feedback("CASE-FB", bec, "confirmed_benign", "  ")


def test_unknown_evidence_rejected(case):
    store, _, _ = case
    with pytest.raises(FeedbackError, match="not part of case"):
        store.record_feedback("CASE-FB", "EV-000000000000", "confirmed_benign", "B")


def test_unanalysed_case_rejected(tmp_path):
    store = CaseStore(tmp_path / "c")
    store.create("CASE-NEW")
    record = store.add_evidence("CASE-NEW", (SAMPLES / "ben_01_internal_meeting.eml").read_bytes(), "x")
    with pytest.raises(FeedbackError, match="analysed"):
        store.record_feedback("CASE-NEW", record.evidence_id, "confirmed_benign", "B")


def test_notes_length_bounded(case):
    store, bec, _ = case
    with pytest.raises(FeedbackError):
        store.record_feedback("CASE-FB", bec, "confirmed_benign", "B", "x" * 5000)


# ---------------------------------------------------------------------------
# Append-only history and integrity
# ---------------------------------------------------------------------------

def test_corrections_append_and_latest_wins(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "needs_review", "Examiner B")
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "Examiner B")
    fb = FeedbackStore(store, "CASE-FB")
    assert [r.assessment for r in fb.history()] == ["needs_review", "confirmed_suspicious"]
    assert fb.current()[bec].assessment == "confirmed_suspicious"


def test_feedback_log_is_hash_chained_and_tamper_evident(case):
    store, bec, benign = case
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "B")
    store.record_feedback("CASE-FB", benign, "confirmed_benign", "B")
    fb = FeedbackStore(store, "CASE-FB")
    assert fb.verify()["valid"] is True

    lines = fb.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["detail"] = entry["detail"].replace("confirmed_suspicious", "confirmed_benign")
    lines[0] = json.dumps(entry)
    fb.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert FeedbackStore(store, "CASE-FB").verify()["valid"] is False


def test_feedback_is_mirrored_in_case_audit_chain(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "B")
    actions = [e["action"] for e in store.audit_entries("CASE-FB")]
    assert "investigator_assessment" in actions
    assert store.verify("CASE-FB")["audit"]["valid"] is True


def test_system_findings_unchanged_by_feedback(case):
    """A human determination must never alter the system's findings."""
    store, bec, _ = case
    before = store.load_analysis("CASE-FB")["assessments"]
    store.record_feedback("CASE-FB", bec, "confirmed_benign", "B")
    after = store.load_analysis("CASE-FB")["assessments"]
    assert [(a["risk_score"], a["risk_band"], len(a["indicators"])) for a in before] == \
           [(a["risk_score"], a["risk_band"], len(a["indicators"])) for a in after]


# ---------------------------------------------------------------------------
# Report shows human assessments separately
# ---------------------------------------------------------------------------

def test_report_shows_investigator_assessment_after_feedback(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "confirmed_benign", "Examiner B", "Known vendor")
    html = store.report_path("CASE-FB").read_text(encoding="utf-8")
    assert "Human determinations." in html
    assert "Confirmed benign" in html
    assert "system false positive" in html
    assert "No investigator assessment has been recorded" not in html


def test_feedback_notes_are_escaped_in_report(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "needs_review", "B", "<script>alert(1)</script>")
    html = store.report_path("CASE-FB").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html


# ---------------------------------------------------------------------------
# Export safeguards (poisoning resistance)
# ---------------------------------------------------------------------------

def test_export_excludes_needs_review(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "needs_review", "B")
    data = export_training_candidates(store, ["CASE-FB"])
    assert not data["rows"]
    assert any("needs review" in w["reason"] for w in data["withheld"])


def test_export_withholds_disagreement(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "Examiner B")
    store.record_feedback("CASE-FB", bec, "confirmed_benign", "Examiner C")
    data = export_training_candidates(store, ["CASE-FB"])
    assert not [r for r in data["rows"] if r["evidence_id"] == bec]
    assert any("disagree" in w["reason"] for w in data["withheld"])


def test_export_binds_label_to_evidence_hash(case):
    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "B")
    row = export_training_candidates(store, ["CASE-FB"])["rows"][0]
    assert row["label"] == "MALICIOUS"
    sha = next(e.sha256 for e in store.load("CASE-FB").evidence if e.evidence_id == bec)
    assert row["evidence_sha256"] == sha


def test_export_refuses_cases_that_fail_integrity(case):
    import os
    import stat

    store, bec, _ = case
    store.record_feedback("CASE-FB", bec, "confirmed_suspicious", "B")
    record = store.load("CASE-FB").evidence[0]
    path = store.evidence_path("CASE-FB", record.sha256)
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(b"tampered")
    data = export_training_candidates(store, ["CASE-FB"])
    assert not data["rows"]
    assert data["withheld"][0]["reason"] == "integrity verification failed"


def test_no_code_path_trains_on_feedback():
    """Feedback must never reach a model automatically."""
    for path in (ROOT / "bec_detector").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "research." not in source and "from research" not in source, path
    feedback = (ROOT / "bec_detector" / "feedback.py").read_text(encoding="utf-8")
    assert not re.search(r"\.fit\(|sklearn|train\(", feedback)


# ---------------------------------------------------------------------------
# Web and CLI
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIBEC_DATA_DIR", str(tmp_path))
    from bec_detector.web.app import app
    return TestClient(app)


def test_web_feedback_round_trip(client):
    client.post("/analyse", data={"case": "CASE-WFB"}, files=[
        ("files", ("a.eml", (SAMPLES / "bec_01_ceo_wire_urgent.eml").read_bytes(), "message/rfc822"))])
    evidence_id = CaseStore().load("CASE-WFB").evidence[0].evidence_id
    response = client.post("/cases/CASE-WFB/feedback", follow_redirects=False, data={
        "evidence_id": evidence_id, "assessment": "confirmed_suspicious",
        "examiner": "Web Examiner", "notes": "checked"})
    assert response.status_code == 303
    page = client.get("/cases/CASE-WFB").text
    assert "Confirmed suspicious" in page and "Web Examiner" in page
    history = client.get("/api/cases/CASE-WFB/feedback").json()
    assert history["integrity"]["valid"] and len(history["history"]) == 1


def test_web_feedback_rejects_bad_input(client):
    client.post("/analyse", data={"case": "CASE-WFB2"}, files=[
        ("files", ("a.eml", (SAMPLES / "ben_01_internal_meeting.eml").read_bytes(), "message/rfc822"))])
    response = client.post("/api/cases/CASE-WFB2/feedback",
                           json={"evidence_id": "EV-NOPE", "assessment": "confirmed_benign",
                                 "examiner": "x"})
    assert response.status_code == 400


def test_web_feedback_cross_site_refused(client):
    response = client.post("/cases/ANY/feedback", headers={"origin": "https://evil.example"},
                           data={"evidence_id": "x", "assessment": "confirmed_benign", "examiner": "x"})
    assert response.status_code == 403


def test_cli_feedback_and_export(tmp_path, capsys):
    from bec_detector.__main__ import main

    assert main(["case", "create", "CASE-CFB"]) == 0
    assert main(["case", "add", "CASE-CFB", str(SAMPLES / "bec_03_gift_card.eml")]) == 0
    assert main(["case", "analyse", "CASE-CFB"]) == 0
    evidence_id = CaseStore().load("CASE-CFB").evidence[0].evidence_id
    assert main(["case", "feedback", "CASE-CFB", evidence_id, "confirmed_suspicious",
                 "--examiner", "CLI Examiner"]) == 0
    out = tmp_path / "labels.json"
    assert main(["case", "export-feedback", str(out), "CASE-CFB"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["rows"][0]["label"] == "MALICIOUS"
    assert "Not used for training" in capsys.readouterr().out
