"""Application security tests.

These verify the controls claimed in docs/security.md. They test the
application's own attack surface, not the mail it analyses.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bec_detector.web.app import app
from bec_detector.web.security import (
    MAX_UPLOAD_BYTES,
    UploadRejected,
    sanitise_filename,
    validate_upload,
)

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"

VALID_EML = b"From: a@b.test\r\nSubject: test\r\nDate: Mon, 01 Sep 2026 09:00:00 +0000\r\n\r\nbody\r\n"


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Filename sanitisation / path traversal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hostile", [
    "../../../etc/passwd.eml",
    "..\\..\\..\\windows\\system32\\config.eml",
    "/etc/shadow.eml",
    "C:\\Windows\\System32\\drivers\\etc\\hosts.eml",
    "....//....//evil.eml",
])
def test_traversal_sequences_are_stripped(hostile):
    safe = sanitise_filename(hostile)
    assert "/" not in safe
    assert "\\" not in safe
    assert ".." not in safe


def test_control_characters_removed():
    safe = sanitise_filename("evil\x00\r\n\tname.eml")
    assert safe.isprintable()
    assert "\x00" not in safe


def test_dot_only_names_are_replaced():
    assert sanitise_filename("..") == "upload.eml"
    assert sanitise_filename(".") == "upload.eml"
    assert sanitise_filename("") == "upload.eml"
    assert sanitise_filename(None) == "upload.eml"


def test_sanitised_name_is_length_bounded():
    assert len(sanitise_filename("a" * 500 + ".eml")) <= 120


def test_traversal_filename_does_not_escape_via_api(client):
    """End-to-end: the recorded source must not retain a traversal path."""
    response = client.post(
        "/api/analyse",
        files=[("files", ("../../../etc/passwd.eml", VALID_EML, "message/rfc822"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 200
    source = response.json()["assessments"][0]["custody"]["source_path"]
    assert ".." not in source
    assert "/" not in source and "\\" not in source


# ---------------------------------------------------------------------------
# Upload type restriction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["payload.exe", "script.js", "macro.docm", "archive.zip"])
def test_disallowed_extensions_rejected(name):
    with pytest.raises(UploadRejected):
        validate_upload(name, "application/octet-stream", 100)


@pytest.mark.parametrize("name", ["evidence.eml", "archive.mbox", "message.txt"])
def test_allowed_extensions_accepted(name):
    assert validate_upload(name, "message/rfc822", 100)


def test_executable_upload_rejected_by_api(client):
    response = client.post(
        "/api/analyse",
        files=[("files", ("payload.exe", b"MZ\x90\x00", "application/octet-stream"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------

def test_empty_upload_rejected():
    with pytest.raises(UploadRejected):
        validate_upload("a.eml", "message/rfc822", 0)


def test_oversize_upload_rejected():
    with pytest.raises(UploadRejected):
        validate_upload("a.eml", "message/rfc822", MAX_UPLOAD_BYTES + 1)


def test_oversize_upload_rejected_by_api(client):
    oversized = b"A" * (MAX_UPLOAD_BYTES + 1024)
    response = client.post(
        "/api/analyse",
        files=[("files", ("big.eml", oversized, "message/rfc822"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 400


def test_empty_submission_rejected_by_api(client):
    response = client.post(
        "/api/analyse",
        files=[("files", ("a.eml", b"", "message/rfc822"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# No code execution anywhere in the codebase
# ---------------------------------------------------------------------------

def test_no_dangerous_calls_in_source():
    """No subprocess, eval, exec, shell or pickle in the application."""
    pattern = re.compile(
        r"\b(subprocess|os\.system|os\.popen|shell\s*=\s*True|pickle\.load|"
        r"\beval\s*\(|\bexec\s*\()"
    )
    offenders = []
    for path in (ROOT / "bec_detector").rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"dangerous constructs found: {offenders}"


def test_no_outbound_network_calls_in_analysis():
    """The analysis path must never contact the network.

    Contacting a URL or host found in evidence would alert the attacker and
    could alter the artifact, so it is prohibited by design.
    """
    pattern = re.compile(
        r"\b(requests\.(get|post|head)|urlopen|httpx\.(get|post)|"
        r"socket\.(connect|create_connection)|aiohttp)"
    )
    offenders = []
    for path in (ROOT / "bec_detector").rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"outbound network calls found: {offenders}"


def test_no_hardcoded_secrets():
    pattern = re.compile(
        r"(api[_-]?key|secret[_-]?key|password|passwd|token)\s*=\s*['\"][A-Za-z0-9+/=_-]{12,}['\"]",
        re.I,
    )
    offenders = []
    for path in (ROOT / "bec_detector").rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"possible hard-coded secrets: {offenders}"


# ---------------------------------------------------------------------------
# Attachments are never written to disk
# ---------------------------------------------------------------------------

def test_attachment_analysis_writes_nothing(tmp_path, monkeypatch):
    """Analysing an attachment must not create any file."""
    from bec_detector.acquisition import load_eml

    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.rglob("*"))
    email = load_eml(SAMPLES / "bec_08_link_and_attachment.eml")
    assert email.attachments
    assert email.attachments[0].sha256
    assert set(tmp_path.rglob("*")) == before


# ---------------------------------------------------------------------------
# Error handling does not disclose internals
# ---------------------------------------------------------------------------

def test_error_page_does_not_leak_internals(client):
    response = client.post(
        "/analyse",
        files=[("files", ("payload.exe", b"MZ", "application/octet-stream"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 400
    body = response.text
    assert "Traceback" not in body
    assert "bec_detector" not in body
    assert "site-packages" not in body


def test_error_message_is_html_escaped(client):
    """A hostile filename must not become markup in the error page."""
    response = client.post(
        "/analyse",
        files=[("files", ("<script>alert(1)</script>.exe", b"MZ", "application/octet-stream"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 400
    assert "<script>alert(1)</script>" not in response.text


def test_report_escapes_hostile_header_content(client):
    """Evidence content is attacker-controlled and must be escaped in reports."""
    hostile = (
        b"From: \"<script>alert('xss')</script>\" <a@b.test>\r\n"
        b"Subject: <img src=x onerror=alert(1)>\r\n"
        b"Date: Mon, 01 Sep 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    response = client.post(
        "/analyse",
        files=[("files", ("hostile.eml", hostile, "message/rfc822"))],
        data={"case": "CASE-SEC"},
    )
    assert response.status_code == 200
    assert "<script>alert('xss')</script>" not in response.text
    assert "<img src=x onerror=alert(1)>" not in response.text


# ---------------------------------------------------------------------------
# Server binding
# ---------------------------------------------------------------------------

def test_server_binds_loopback_only():
    """The launcher must not expose the app on a public interface."""
    source = (ROOT / "run_server.py").read_text(encoding="utf-8")
    assert "127.0.0.1" in source
    assert "0.0.0.0" not in source
