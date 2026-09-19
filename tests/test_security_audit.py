"""Regression tests for vulnerabilities found in the final security audit.

Each test pins a specific finding:

  * MIME nesting bomb - a ~40 KB message with deeply nested multipart
    containers exhausted the stdlib parser's recursion and crashed analysis
    with HTTP 500.
  * Silent evidence loss - directory acquisition dropped unparseable files
    without any record.
  * Cross-site request forgery - with no login, any web page the investigator
    visited could POST to /analyse and plant fabricated evidence into a case.
  * DNS rebinding - a hostile hostname re-pointed at 127.0.0.1 would be
    same-origin with the app and could read case data.

Plus malformed-input robustness: no input may produce a 500 or leak internals.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bec_detector.acquisition import EvidenceParseError, load_bytes, load_path
from bec_detector.web.app import app

ROOT = Path(__file__).resolve().parent.parent


def _nest(depth: int, folded: bool = False) -> bytes:
    header = b"Content-Type:\r\n multipart/mixed" if folded else b"Content-Type: multipart/mixed"
    body = b""
    for i in range(depth):
        body = header + b'; boundary="b%d"\r\n\r\n--b%d\r\n' % (i, i) + body
    return b"From: a@b.test\r\nSubject: nest\r\nMIME-Version: 1.0\r\n" + body


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIBEC_DATA_DIR", str(tmp_path))
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# MIME nesting bomb
# ---------------------------------------------------------------------------

def test_nesting_bomb_raises_clean_error():
    with pytest.raises(EvidenceParseError, match="multipart containers"):
        load_bytes(_nest(2000), "bomb.eml")


def test_folded_header_bomb_still_caught():
    """A folded Content-Type evades the pre-parse count; the recursion guard
    must still turn the crash into a clean error rather than a 500."""
    try:
        load_bytes(_nest(3000, folded=True), "bomb.eml")
    except EvidenceParseError:
        pass  # refused cleanly - the required outcome
    # Parsing it successfully is also acceptable; crashing is not.


def test_ordinary_nesting_still_parses():
    email = load_bytes(_nest(20), "fine.eml")
    assert email.subject == "nest"


def test_nesting_bomb_rejected_at_web_intake(client):
    response = client.post("/api/analyse", data={"case": "CASE-BOMB"},
                           files=[("files", ("bomb.eml", _nest(2000), "message/rfc822"))])
    assert response.status_code == 400
    assert "cannot be parsed safely" in response.json()["rejected"][0]


def test_bomb_alongside_valid_mail_does_not_block_analysis(client):
    ok = b"From: a@b.test\r\nSubject: fine\r\n\r\nhello"
    response = client.post("/api/analyse", data={"case": "CASE-MIX"}, files=[
        ("files", ("bomb.eml", _nest(2000), "message/rfc822")),
        ("files", ("ok.eml", ok, "message/rfc822")),
    ])
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["messages_analysed"] == 1
    assert "bomb.eml" in data["case"]["rejected_uploads"][0]


def test_rejected_bomb_is_never_stored(client, tmp_path):
    client.post("/api/analyse", data={"case": "CASE-NS"},
                files=[("files", ("bomb.eml", _nest(2000), "message/rfc822"))])
    assert not list(tmp_path.rglob("*.eml"))


# ---------------------------------------------------------------------------
# No silent evidence loss
# ---------------------------------------------------------------------------

def test_directory_acquisition_reports_skipped_files(tmp_path):
    (tmp_path / "good.eml").write_bytes(b"From: a@b.test\r\nSubject: ok\r\n\r\nhi")
    (tmp_path / "bad.eml").write_bytes(_nest(2000))
    errors: list[tuple[str, str]] = []
    artifacts = load_path(tmp_path, errors=errors)
    assert len(artifacts) == 1
    assert len(errors) == 1 and errors[0][0].endswith("bad.eml")


def test_pipeline_audit_logs_skipped_evidence(tmp_path):
    from bec_detector.forensics import IOCStore
    from bec_detector.pipeline import BECPipeline

    (tmp_path / "good.eml").write_bytes(b"From: a@b.test\r\nSubject: ok\r\n\r\nhi")
    (tmp_path / "bad.eml").write_bytes(_nest(2000))
    pipeline = BECPipeline(case_id="CASE-SK", ioc_store=IOCStore(tmp_path / "s.json"))
    pipeline.run(tmp_path)
    skipped = [e for e in pipeline.audit.to_list() if e["action"] == "evidence_skipped"]
    assert skipped and "bad.eml" in skipped[0]["detail"]


def test_cli_warns_about_skipped_files(tmp_path, capsys):
    from bec_detector.__main__ import main

    (tmp_path / "good.eml").write_bytes(b"From: a@b.test\r\nSubject: ok\r\n\r\nhi")
    (tmp_path / "bad.eml").write_bytes(_nest(2000))
    assert main(["scan", str(tmp_path), "--no-correlate"]) == 0
    assert "warning: skipped" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Malformed evidence never produces a server error
# ---------------------------------------------------------------------------

MALFORMED = {
    "binary garbage": bytes(range(256)) * 16,
    "headers only": b"From: a@b.test",
    "no headers": b"\r\n\r\njust a body",
    "invalid utf-8": b"Subject: \xff\xfe\xfa\r\nFrom: \xc3\x28@x.test\r\n\r\nbody",
    "broken boundary": (b'From: a@b.test\r\nContent-Type: multipart/mixed; boundary="x"\r\n\r\n'
                        b"--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--y--"),
    "bad base64": (b'From: a@b.test\r\nContent-Type: multipart/mixed; boundary="x"\r\n\r\n'
                   b'--x\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; '
                   b'filename="a.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!***\r\n--x--'),
    "huge header": b"From: a@b.test\r\nSubject: " + b"A" * 1_000_000 + b"\r\n\r\nx",
    "encoded-word flood": b"From: a@b.test\r\nSubject: " + b" ".join([b"=?utf-8?b?QUFBQQ==?="] * 5000) + b"\r\n\r\nx",
    "impossible date": b"From: a@b.test\r\nDate: Feb 30 99999 25:61:61 +9999\r\n\r\nx",
    "malformed urls": b"From: a@b.test\r\n\r\nhttp://[::1 http://999.999.999.999/x https://%%%/ http://xn--/",
    "nul bytes": b"From: a\x00@b.test\r\nSubject: x\x00y\r\n\r\nbo\x00dy",
    "rtl override name": "From: ‮evil <x@evil.test>\r\n\r\nx".encode("utf-8"),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_evidence_never_500(client, name):
    response = client.post("/api/analyse", data={"case": "CASE-MAL"},
                           files=[("files", (f"{name[:10]}.eml", MALFORMED[name], "message/rfc822"))])
    assert response.status_code < 500, f"{name} produced {response.status_code}"
    assert "Traceback" not in response.text
    assert "site-packages" not in response.text


@pytest.mark.parametrize("call", [
    lambda c: c.post("/api/analyse", data={"case": "C"}),
    lambda c: c.post("/api/analyse", json={"x": 1}),
    lambda c: c.post("/api/analyse", content=b"--x\r\nnope",
                     headers={"content-type": "multipart/form-data; boundary=x"}),
    lambda c: c.post("/api/analyse", data={"case": "A" * 100_000},
                     files=[("files", ("a.eml", b"From: a@b.c\r\n\r\nx", "message/rfc822"))]),
])
def test_malformed_requests_are_4xx_without_internals(client, call):
    response = call(client)
    assert 400 <= response.status_code < 500
    assert "Traceback" not in response.text
    assert "bec_detector" not in response.text


# ---------------------------------------------------------------------------
# Cross-site request forgery
# ---------------------------------------------------------------------------

EML = b"From: a@b.test\r\nSubject: s\r\n\r\nx"


@pytest.mark.parametrize("headers", [
    {"origin": "https://evil.example"},
    {"sec-fetch-site": "cross-site"},
    {"origin": "null"},
    {"origin": "http://testserver.evil.example"},
])
def test_cross_site_write_refused(client, tmp_path, headers):
    response = client.post("/analyse", data={"case": "CASE-CSRF"}, headers=headers,
                           files=[("files", ("a.eml", EML, "message/rfc822"))])
    assert response.status_code == 403
    assert not list(tmp_path.rglob("*.eml")), "no evidence may be planted"


def test_same_origin_write_allowed(client):
    response = client.post("/analyse", data={"case": "CASE-SO"},
                           headers={"origin": "http://testserver", "sec-fetch-site": "same-origin"},
                           files=[("files", ("a.eml", EML, "message/rfc822"))],
                           follow_redirects=False)
    assert response.status_code == 303


def test_non_browser_client_without_origin_allowed(client):
    """The CLI and scripts send no Origin header and must keep working."""
    response = client.post("/api/analyse", data={"case": "CASE-NB"},
                           files=[("files", ("a.eml", EML, "message/rfc822"))])
    assert response.status_code == 200


def test_cross_site_reads_are_not_blocked_by_csrf_guard(client):
    """Only state-changing methods are guarded; GET navigation still works."""
    assert client.get("/", headers={"sec-fetch-site": "cross-site"}).status_code == 200


# ---------------------------------------------------------------------------
# DNS rebinding
# ---------------------------------------------------------------------------

def test_unknown_host_header_refused(client):
    assert client.get("/api/cases", headers={"host": "evil.example"}).status_code == 400


def test_default_allowed_hosts_are_loopback_only():
    source = (ROOT / "bec_detector" / "web" / "app.py").read_text(encoding="utf-8")
    assert '"FORENSIBEC_ALLOWED_HOSTS", "127.0.0.1,localhost"' in source


# ---------------------------------------------------------------------------
# Repository-wide static checks (the earlier scan covered bec_detector/ only)
# ---------------------------------------------------------------------------

SCANNED = [ROOT / "bec_detector", ROOT / "research", ROOT / "data", ROOT / "run_server.py"]


def _python_files():
    for base in SCANNED:
        if base.is_file():
            yield base
        else:
            yield from base.rglob("*.py")


@pytest.mark.parametrize("label,pattern", [
    ("code execution", r"\b(subprocess|os\.system|os\.popen|eval\s*\(|exec\s*\(|shell\s*=\s*True)"),
    ("unsafe deserialisation", r"\b(pickle|marshal\.loads?|yaml\.load\s*\(|joblib\.load|dill)\b"),
    ("outbound network", r"\b(requests\.(get|post|put|head)|urlopen|httpx\.|aiohttp|socket\.)"),
    ("debug server", r"\b(debug\s*=\s*True|reload\s*=\s*True)"),
])
def test_repository_free_of(label, pattern):
    offenders = []
    regex = re.compile(pattern)
    for path in _python_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if regex.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"{label}: {offenders}"


# ---------------------------------------------------------------------------
# Clickjacking / response hardening (found in the final audit)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/cases", "/about", "/api/health", "/search?q=x"])
def test_pages_cannot_be_framed_and_forbid_script(client, path):
    """A framed dashboard would let a hostile page trick the investigator into
    a same-origin click (e.g. recording 'confirmed benign'), which the
    Sec-Fetch-Site CSRF check cannot see. Framing is refused, and no page may
    run script or load external resources."""
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY"
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp
    assert "script-src" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_rejected_requests_are_hardened_too(client):
    r = client.post("/analyse", headers={"Origin": "https://evil.example"},
                    data={"case": "CASE-X"})
    assert r.status_code == 403
    assert r.headers["x-frame-options"] == "DENY"


def test_report_page_carries_policy(client):
    client.post("/analyse", data={"case": "CASE-HDR"},
                files=[("files", ("a.eml", (ROOT / "data" / "samples" / "bec_01_ceo_wire_urgent.eml").read_bytes(),
                                  "message/rfc822"))])
    r = client.get("/cases/CASE-HDR/report")
    assert r.status_code == 200 and "<script" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_favicon_and_head_requests_do_not_error(client):
    assert client.get("/favicon.ico").status_code == 204
    assert client.head("/").status_code == 200
    assert client.head("/api/health").status_code == 200


def test_referrer_policy_does_not_null_the_origin_of_own_forms(client):
    """Found in the final audit with a real browser: 'no-referrer' made the
    browser send 'Origin: null' on the dashboard's own upload form, and the
    CSRF check refused every upload from the UI."""
    assert client.get("/").headers["referrer-policy"] == "same-origin"


def test_browser_same_origin_form_post_is_accepted(client):
    """What a browser sends for the dashboard's own form."""
    r = client.post("/analyse", data={"case": "CASE-FORM"},
                    headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
                    files=[("files", ("a.eml", (ROOT / "data" / "samples" / "ben_01_internal_meeting.eml").read_bytes(),
                                      "message/rfc822"))], follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("/cases/CASE-FORM")


def test_feedback_on_missing_case_is_404_like_every_other_case_route(client):
    """Found in the final audit: it returned 400 while all other routes 404."""
    body = {"evidence_id": "EV-X", "assessment": "confirmed_benign", "examiner": "X"}
    assert client.post("/api/cases/NOPE/feedback", json=body).status_code == 404
    assert client.post("/cases/NOPE/feedback", data=body).status_code == 404
    assert client.post("/api/cases/bad%20id/feedback", json=body).status_code == 404
