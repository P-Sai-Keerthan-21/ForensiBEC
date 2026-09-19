"""Case management tests: lifecycle, evidence preservation, integrity, search."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bec_detector.cases import CaseError, CaseStore, validate_case_id
from bec_detector.forensics import IOCStore

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture
def store(tmp_path):
    return CaseStore(tmp_path / "cases")


def _raw(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def _make_writable(path: Path) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


# ---------------------------------------------------------------------------
# Case identifiers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("good", ["CASE-001", "case_2", "A", "X" * 64, "2026-INC-7"])
def test_valid_case_ids(good):
    assert validate_case_id(good) == good


@pytest.mark.parametrize("bad", [
    "", " ", "../etc", "..", "CASE/001", "CASE\\001", "-leading", "_leading",
    "has space", "X" * 65, "case\x00id", "C:\\windows", "caseé",
])
def test_invalid_case_ids_rejected(bad):
    with pytest.raises(CaseError):
        validate_case_id(bad)


def test_traversal_case_id_cannot_create_directories(store, tmp_path):
    with pytest.raises(CaseError):
        store.create("../escaped")
    assert not (tmp_path / "escaped").exists()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_create_records_examiner_and_timestamp(store):
    case = store.create("CASE-1", examiner="K. Guthala", title="Vendor fraud")
    loaded = store.load("CASE-1")
    assert loaded.examiner == "K. Guthala"
    assert loaded.title == "Vendor fraud"
    assert loaded.created_utc == case.created_utc
    assert loaded.status == "open"


def test_duplicate_case_rejected(store):
    store.create("CASE-1")
    with pytest.raises(CaseError):
        store.create("CASE-1")


def test_loading_missing_case_raises(store):
    with pytest.raises(CaseError):
        store.load("CASE-NOPE")


def test_list_returns_all_cases(store):
    store.create("CASE-A")
    store.create("CASE-B")
    assert [c.case_id for c in store.list()] == ["CASE-A", "CASE-B"]


# ---------------------------------------------------------------------------
# Evidence preservation
# ---------------------------------------------------------------------------

def test_evidence_stored_under_its_hash_not_its_filename(store):
    store.create("CASE-1")
    raw = _raw("bec_01_ceo_wire_urgent.eml")
    record = store.add_evidence("CASE-1", raw, "../../evil name.eml")
    sha = hashlib.sha256(raw).hexdigest()

    path = store.evidence_path("CASE-1", sha)
    assert path.name == f"{sha}.eml"
    assert path.read_bytes() == raw, "original bytes must be preserved exactly"
    assert record.original_filename == "../../evil name.eml"  # metadata only
    assert not any("evil" in p.name for p in store.root.rglob("*"))


def test_re_adding_identical_evidence_is_a_no_op(store):
    store.create("CASE-1")
    raw = _raw("ben_01_internal_meeting.eml")
    first = store.add_evidence("CASE-1", raw, "a.eml")
    second = store.add_evidence("CASE-1", raw, "renamed.eml")
    assert first.evidence_id == second.evidence_id
    assert len(store.load("CASE-1").evidence) == 1


def test_multiple_evidence_items(store):
    store.create("CASE-1")
    for name in ("thread_01_genuine_opening.eml", "thread_02_genuine_reply.eml",
                 "thread_03_hijack.eml"):
        store.add_evidence("CASE-1", _raw(name), name)
    case = store.load("CASE-1")
    assert len(case.evidence) == 3
    assert len({e.sha256 for e in case.evidence}) == 3


def test_empty_evidence_rejected(store):
    store.create("CASE-1")
    with pytest.raises(CaseError):
        store.add_evidence("CASE-1", b"", "empty.eml")


def test_evidence_path_rejects_non_hash(store):
    store.create("CASE-1")
    with pytest.raises(CaseError):
        store.evidence_path("CASE-1", "../../case.json")


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

def test_verify_passes_on_untouched_case(store):
    store.create("CASE-1")
    store.add_evidence("CASE-1", _raw("bec_01_ceo_wire_urgent.eml"), "x.eml")
    result = store.verify("CASE-1")
    assert result["intact"] is True
    assert result["evidence"][0]["status"] == "VERIFIED"
    assert result["audit"]["valid"] is True


def test_tampered_evidence_is_detected(store):
    store.create("CASE-1")
    record = store.add_evidence("CASE-1", _raw("bec_01_ceo_wire_urgent.eml"), "x.eml")
    path = store.evidence_path("CASE-1", record.sha256)
    _make_writable(path)
    path.write_bytes(path.read_bytes().replace(b"48,500", b"4,850"))

    result = store.verify("CASE-1")
    assert result["intact"] is False
    assert result["evidence"][0]["status"] == "HASH MISMATCH"


def test_analysis_refuses_tampered_evidence(store):
    store.create("CASE-1")
    record = store.add_evidence("CASE-1", _raw("bec_01_ceo_wire_urgent.eml"), "x.eml")
    path = store.evidence_path("CASE-1", record.sha256)
    _make_writable(path)
    path.write_bytes(b"From: someone@else.test\r\n\r\naltered")
    with pytest.raises(CaseError, match="integrity"):
        store.analyse("CASE-1", ioc_store=IOCStore(store.root / "ioc.json"))


def test_missing_evidence_is_reported(store):
    store.create("CASE-1")
    record = store.add_evidence("CASE-1", _raw("ben_01_internal_meeting.eml"), "x.eml")
    path = store.evidence_path("CASE-1", record.sha256)
    _make_writable(path)
    path.unlink()
    assert store.verify("CASE-1")["evidence"][0]["status"] == "MISSING"


def test_evidence_file_is_never_overwritten(store):
    """Exclusive create: a colliding file with different content is refused."""
    store.create("CASE-1")
    raw = _raw("ben_01_internal_meeting.eml")
    sha = hashlib.sha256(raw).hexdigest()
    target = store.evidence_path("CASE-1", sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"planted content")
    with pytest.raises(CaseError, match="refusing to overwrite"):
        store.add_evidence("CASE-1", raw, "x.eml")
    assert target.read_bytes() == b"planted content"


def test_case_audit_trail_records_actions(store):
    store.create("CASE-1", examiner="Examiner A")
    store.add_evidence("CASE-1", _raw("ben_01_internal_meeting.eml"), "x.eml")
    store.analyse("CASE-1", ioc_store=IOCStore(store.root / "ioc.json"))
    actions = [e["action"] for e in store.audit_entries("CASE-1")]
    for expected in ("case_created", "evidence_added", "evidence_acquired",
                     "message_assessed", "case_report_generated"):
        assert expected in actions


# ---------------------------------------------------------------------------
# Analysis and retained findings
# ---------------------------------------------------------------------------

@pytest.fixture
def analysed(store):
    store.create("CASE-T", examiner="Examiner A", title="Thread hijack")
    for name in ("thread_01_genuine_opening.eml", "thread_02_genuine_reply.eml",
                 "thread_03_hijack.eml"):
        store.add_evidence("CASE-T", _raw(name), name)
    report = store.analyse("CASE-T", ioc_store=IOCStore(store.root / "ioc.json"))
    return store, report


def test_analysis_retains_findings_and_report(analysed):
    store, report = analysed
    assert store.analysis_path("CASE-T").exists()
    assert store.report_path("CASE-T").exists()
    saved = store.load_analysis("CASE-T")
    assert saved["summary"]["messages_analysed"] == 3
    for key in ("timeline", "evidence_graph", "audit", "limitations"):
        assert key in saved


def test_case_summary_reports_highest_risk(analysed):
    store, _ = analysed
    summary = store.load("CASE-T").summary
    assert summary["messages"] == 3
    assert summary["highest_risk_band"] == "CONFIRMED_BEC"
    assert summary["ioc_counts"]["domains"] > 0


def test_report_carries_evidence_register(analysed):
    _, report = analysed
    register = report["case"]["evidence_register"]
    assert len(register) == 3
    assert all(len(r["sha256"]) == 64 for r in register)


def test_custody_source_names_case_and_hash(analysed):
    _, report = analysed
    for item in report["assessments"]:
        source = item["custody"]["source_path"]
        assert source.startswith("CASE-T:evidence:")
        assert "/" not in source and "\\" not in source


def test_analysing_empty_case_rejected(store):
    store.create("CASE-EMPTY")
    with pytest.raises(CaseError):
        store.analyse("CASE-EMPTY")


# ---------------------------------------------------------------------------
# Search and related cases
# ---------------------------------------------------------------------------

def test_search_by_ioc_sender_and_evidence(analysed):
    store, report = analysed
    evidence_id = report["assessments"][0]["evidence_id"]
    assert store.search("m.kalina.delaney@mail.com")[0]["case_id"] == "CASE-T"
    assert store.search(evidence_id.lower())[0]["case_id"] == "CASE-T"
    assert store.search("Thread hijack")[0]["case_id"] == "CASE-T"
    assert store.search("nothing-matches-this") == []
    assert store.search("") == []


def test_related_cases_found_through_shared_iocs(store):
    shared = IOCStore(store.root / "ioc.json")
    for case_id in ("CASE-X", "CASE-Y"):
        store.create(case_id)
        store.add_evidence(case_id, _raw("bec_01_ceo_wire_urgent.eml"), "x.eml")
        store.analyse(case_id, ioc_store=shared)

    related = store.related_cases("CASE-Y")
    assert [r["case_id"] for r in related] == ["CASE-X"]
    assert any("northwind-l0gistics.com" in s for s in related[0]["shared_indicators"])


# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return TestClient(__import__("bec_detector.web.app", fromlist=["app"]).app)


def test_web_submission_is_preserved_and_retrievable(client):
    files = [("files", (n, _raw(n), "message/rfc822"))
             for n in ("bec_02_vendor_bank_change.eml", "ben_03_vendor_normal.eml")]
    response = client.post("/api/analyse", files=files,
                           data={"case": "CASE-WEB-1", "examiner": "tester"})
    assert response.status_code == 200

    case = client.get("/api/cases/CASE-WEB-1").json()["case"]
    assert len(case["evidence"]) == 2
    assert case["summary"]["messages"] == 2

    assert client.get("/api/cases/CASE-WEB-1/verify").json()["intact"] is True
    assert client.get("/api/cases/CASE-WEB-1/analysis").status_code == 200
    report = client.get("/cases/CASE-WEB-1/report")
    assert report.status_code == 200 and "FORENSIBEC" in report.text
    assert any(c["case_id"] == "CASE-WEB-1" for c in client.get("/api/cases").json()["cases"])


def test_web_rejects_invalid_case_reference(client):
    response = client.post(
        "/api/analyse",
        files=[("files", ("a.eml", _raw("ben_01_internal_meeting.eml"), "message/rfc822"))],
        data={"case": "../../etc"},
    )
    assert response.status_code == 400
    assert "Case reference" in response.json()["error"]


@pytest.mark.parametrize("path", [
    "/api/cases/CASE-DOES-NOT-EXIST",
    "/api/cases/CASE-DOES-NOT-EXIST/verify",
    "/api/cases/CASE-DOES-NOT-EXIST/analysis",
    "/cases/CASE-DOES-NOT-EXIST/report",
    "/api/cases/..%2F..%2Fetc",
])
def test_unknown_cases_return_404_without_detail(client, path):
    response = client.get(path)
    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_search_endpoint_bounds_query_length(client):
    assert client.get("/api/search", params={"q": "x" * 500}).status_code == 400
    assert client.get("/api/search", params={"q": "CASE"}).status_code == 200


# ---------------------------------------------------------------------------
# The single-email CLI workflow is unchanged
# ---------------------------------------------------------------------------

def test_single_email_scan_still_works(tmp_path, capsys):
    from bec_detector.__main__ import main

    out = tmp_path / "r.json"
    code = main(["scan", str(SAMPLES / "bec_01_ceo_wire_urgent.eml"),
                 "--json", str(out), "--no-correlate"])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["assessments"][0]["risk_band"] == "CONFIRMED_BEC"
    assert "evidence_graph" in data and "limitations" in data


def test_case_cli_round_trip(capsys):
    from bec_detector.__main__ import main

    assert main(["case", "create", "CASE-CLI", "--examiner", "Tester"]) == 0
    assert main(["case", "add", "CASE-CLI", str(SAMPLES / "bec_03_gift_card.eml")]) == 0
    assert main(["case", "analyse", "CASE-CLI"]) == 0
    assert main(["case", "verify", "CASE-CLI"]) == 0
    assert main(["case", "show", "CASE-CLI"]) == 0
    assert main(["case", "search", "gift"]) == 0
    assert main(["case", "create", "../bad"]) == 2
    output = capsys.readouterr().out
    assert "CONFIRMED_BEC" in output and "INTACT" in output


def test_cli_reports_duplicate_evidence_honestly(capsys):
    """Found in the final audit: re-adding identical bytes printed
    '1 item(s) registered' although nothing new was preserved."""
    from bec_detector.__main__ import main

    sample = str(SAMPLES / "ben_01_internal_meeting.eml")
    assert main(["case", "create", "CASE-CLIDUP"]) == 0
    assert main(["case", "add", "CASE-CLIDUP", sample]) == 0
    assert "1 new item(s) registered" in capsys.readouterr().out
    assert main(["case", "add", "CASE-CLIDUP", sample]) == 0
    out = capsys.readouterr().out
    assert "0 new item(s) registered" in out and "1 already present" in out
    assert len(CaseStore().load("CASE-CLIDUP").evidence) == 1
