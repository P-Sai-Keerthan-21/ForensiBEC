"""Investigator dashboard tests: the full browser workflow, end to end."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bec_detector.cases import CaseStore
from bec_detector.web.app import app

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Each test gets an empty data directory so page contents are predictable."""
    monkeypatch.setenv("FORENSIBEC_DATA_DIR", str(tmp_path))
    return TestClient(app)


def _files(*names: str):
    return [("files", (n, (SAMPLES / n).read_bytes(), "message/rfc822")) for n in names]


def _submit(client, case_id: str, *names: str, follow: bool = True):
    return client.post("/analyse", files=_files(*names),
                       data={"case": case_id, "examiner": "Examiner A"},
                       follow_redirects=follow)


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def test_dashboard_loads_with_no_fabricated_statistics(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Upload evidence" in page.text
    assert "No cases yet" in page.text


def test_dashboard_lists_real_cases_only(client):
    _submit(client, "CASE-D1", "bec_01_ceo_wire_urgent.eml")
    page = client.get("/").text
    assert "CASE-D1" in page
    assert "CONFIRMED_BEC" in page
    assert "No cases yet" not in page


def test_navigation_present_on_every_page(client):
    _submit(client, "CASE-NAV", "ben_01_internal_meeting.eml")
    for path in ("/", "/cases", "/cases/CASE-NAV", "/search?q=x", "/about"):
        text = client.get(path).text
        for link in ('href="/"', 'href="/cases"', 'href="/about"', 'action="/search"'):
            assert link in text, f"{path} missing {link}"


# ---------------------------------------------------------------------------
# Upload -> analyse -> results
# ---------------------------------------------------------------------------

def test_submission_redirects_to_case_page(client):
    response = _submit(client, "CASE-PRG", "bec_01_ceo_wire_urgent.eml", follow=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/cases/CASE-PRG"


def test_case_page_shows_verdicts_and_evidence(client):
    page = _submit(client, "CASE-R", "thread_01_genuine_opening.eml",
                   "thread_02_genuine_reply.eml", "thread_03_hijack.eml").text
    assert "CONFIRMED_BEC" in page and "BENIGN" in page
    assert "Evidence register" in page
    assert "Request to change payment destination" in page
    assert "Timeline" in page and "Indicators of compromise" in page
    assert "<svg" in page, "evidence graph must be displayed"
    assert "Open full report" in page


def test_report_reachable_from_case_page(client):
    _submit(client, "CASE-RPT", "bec_02_vendor_bank_change.eml")
    report = client.get("/cases/CASE-RPT/report")
    assert report.status_code == 200
    assert "Investigation Report" in report.text


def test_adding_evidence_to_existing_case_accumulates(client):
    _submit(client, "CASE-ACC", "thread_01_genuine_opening.eml")
    _submit(client, "CASE-ACC", "thread_02_genuine_reply.eml")
    assert len(CaseStore().load("CASE-ACC").evidence) == 2


def test_benign_only_case_lists_no_iocs_or_actions(client):
    page = _submit(client, "CASE-BEN", "ben_04_hr_policy.eml").text
    assert "no IOCs are listed" in page
    assert "No message in this case was scored LIKELY_BEC or above." in page


def test_partially_rejected_submission_shows_rejections(client):
    files = _files("bec_01_ceo_wire_urgent.eml") + [
        ("files", ("payload.exe", b"MZ\x90\x00", "application/octet-stream"))]
    page = client.post("/analyse", files=files, data={"case": "CASE-REJ"})
    assert page.status_code == 200
    assert "Some uploads were rejected" in page.text
    assert "payload.exe" in page.text
    assert len(CaseStore().load("CASE-REJ").evidence) == 1


# ---------------------------------------------------------------------------
# Errors are safe
# ---------------------------------------------------------------------------

def test_invalid_case_reference_rejected(client):
    page = client.post("/analyse", files=_files("ben_01_internal_meeting.eml"),
                       data={"case": "../../etc/passwd"})
    assert page.status_code == 400
    assert "Case reference" in page.text
    assert "Traceback" not in page.text


def test_unknown_case_is_404(client):
    for path in ("/cases/CASE-NOPE", "/cases/CASE-NOPE/verify", "/cases/CASE-NOPE/report"):
        page = client.get(path)
        assert page.status_code == 404
        assert "Traceback" not in page.text


def test_all_rejected_submission_is_400(client):
    page = client.post("/analyse", data={"case": "CASE-X"},
                       files=[("files", ("x.exe", b"MZ", "application/octet-stream"))])
    assert page.status_code == 400


# ---------------------------------------------------------------------------
# Integrity from the UI
# ---------------------------------------------------------------------------

def test_verify_page_reports_intact_case_and_logs_the_check(client):
    _submit(client, "CASE-V", "bec_01_ceo_wire_urgent.eml")
    page = client.get("/cases/CASE-V/verify").text
    assert "Integrity verified." in page
    actions = [e["action"] for e in CaseStore().audit_entries("CASE-V")]
    assert actions[-1] == "integrity_verified"
    assert CaseStore().verify("CASE-V")["audit"]["valid"] is True


def test_verify_page_reports_tampering(client):
    _submit(client, "CASE-T", "bec_01_ceo_wire_urgent.eml")
    store = CaseStore()
    record = store.load("CASE-T").evidence[0]
    path = store.evidence_path("CASE-T", record.sha256)
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(b"altered")

    page = client.get("/cases/CASE-T/verify").text
    assert "INTEGRITY FAILURE" in page
    assert "HASH MISMATCH" in page


# ---------------------------------------------------------------------------
# Search and about
# ---------------------------------------------------------------------------

def test_search_finds_case_by_ioc(client):
    _submit(client, "CASE-S", "bec_01_ceo_wire_urgent.eml")
    page = client.get("/search", params={"q": "ravi.menon.exec@gmail.com"}).text
    assert "CASE-S" in page


def test_search_reports_no_match_honestly(client):
    page = client.get("/search", params={"q": "nothing-matches"}).text
    assert "No case matches" in page


def test_search_query_is_escaped(client):
    page = client.get("/search", params={"q": "<script>alert(1)</script>"}).text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_search_bounds_query_length(client):
    page = client.get("/search", params={"q": "x" * 500}).text
    assert "Query too long" in page


def test_about_page_states_limitations(client):
    page = client.get("/about").text
    assert "not calibrated probabilities" in page
    assert "synthetic corpora" in page


# ---------------------------------------------------------------------------
# Hostile evidence on the case page
# ---------------------------------------------------------------------------

def test_hostile_evidence_is_escaped_on_case_page(client):
    hostile = (b'From: "<script>alert(1)</script>" <x@evil.test>\r\n'
               b"To: a@b.test\r\nSubject: <img src=x onerror=alert(2)>\r\n"
               b"Date: Mon, 01 Sep 2026 09:00:00 +0000\r\n\r\nbody\r\n")
    page = client.post("/analyse", data={"case": "CASE-XSS"},
                       files=[("files", ("h.eml", hostile, "message/rfc822"))]).text
    assert "<script>alert(1)</script>" not in page
    assert "<img src=x onerror=alert(2)>" not in page
    # The only <svg> is the generated evidence graph.
    assert page.count("<svg") == 1


def test_related_scan_only_case_is_not_a_dead_link(tmp_path, monkeypatch):
    """Found in the final verification: IOCs recorded by a one-shot `scan`
    (default ID CASE-000) appeared as a related case linking to a 404."""
    from fastapi.testclient import TestClient

    from bec_detector.forensics import IOCStore
    from bec_detector.web.app import app

    monkeypatch.setenv("FORENSIBEC_DATA_DIR", str(tmp_path))
    store = IOCStore(tmp_path / "ioc_store.json")
    store.record({"ipv4": ["203.0.113.88"]}, "CASE-000")
    store.save()
    client = TestClient(app)
    sample = Path(__file__).resolve().parent.parent / "data" / "samples" / "bec_01_ceo_wire_urgent.eml"
    client.post("/analyse", data={"case": "CASE-REL"},
                files=[("files", ("a.eml", sample.read_bytes(), "message/rfc822"))])
    page = client.get("/cases/CASE-REL").text
    assert "CASE-000" in page and 'href="/cases/CASE-000"' not in page
    assert "one-shot scan" in page
