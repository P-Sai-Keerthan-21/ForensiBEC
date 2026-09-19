"""FastAPI front end - FORENSIBEC investigator dashboard.

Thin by design: the web layer acquires bytes and renders what the pipeline
returns. Every detection decision lives in the engine, so the CLI and the web
UI can never disagree about a verdict.

Security posture is enforced in `security.py`; see that module's docstring for
the threat model. In short: uploads are validated and size-limited while
streaming, then preserved as original evidence in the case store under their
SHA-256 (never under the uploaded filename). Evidence is never executed.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __tool_name__, __version__
from ..acquisition import EvidenceParseError, load_bytes
from ..cases import CaseError, CaseStore, validate_case_id
from ..pipeline import BECPipeline
from .security import (
    MAX_FILES_PER_REQUEST,
    MAX_TOTAL_BYTES,
    UploadRejected,
    read_limited,
    validate_upload,
)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(
    title=f"{__tool_name__} {__version__}",
    description="FORENSIBEC - Business Email Compromise detection and digital investigation.",
)

# DNS-rebinding defence: a hostile page that re-points its own hostname at
# 127.0.0.1 would otherwise be same-origin with this app and could read case
# data. Only requests addressed to a known local host name are served.
ALLOWED_HOSTS = [h.strip() for h in os.environ.get(
    "FORENSIBEC_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def reject_cross_site_writes(request: Request, call_next):
    """Cross-site request forgery defence for state-changing requests.

    There is no login, so without this any web page the investigator visits
    could POST to /analyse and plant fabricated evidence into an existing case.
    Browsers label cross-site requests with Sec-Fetch-Site and Origin; either
    one identifying a different origin causes a refusal. Non-browser clients
    (the CLI, scripts, tests) send neither and are unaffected.
    """
    if request.method in UNSAFE_METHODS:
        fetch_site = request.headers.get("sec-fetch-site", "")
        origin = request.headers.get("origin", "")
        host = request.headers.get("host", "")
        cross = fetch_site == "cross-site"
        if origin and origin != "null":
            from urllib.parse import urlsplit
            cross = cross or urlsplit(origin).netloc.lower() != host.lower()
        elif origin == "null":
            cross = True
        if cross:
            return JSONResponse(
                {"error": "Cross-site request refused."}, status_code=403)
    return await call_next(request)


# No page uses scripts, external resources or frames, so the policy can be
# strict: injected markup cannot run script or load anything, and no other site
# can frame the dashboard (clickjacking an investigator into recording a
# determination would pass the Sec-Fetch-Site check, being same-origin).
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
# FastAPI's interactive API docs load Swagger UI from a CDN; they keep the
# framing and sniffing protections but not the script ban.
DOCS_PATHS = ("/docs", "/redoc")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    # "same-origin", not "no-referrer": under no-referrer browsers send
    # "Origin: null" on the dashboard's own form POSTs, which the CSRF check
    # (correctly) refuses. same-origin still sends nothing to other sites.
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if not request.url.path.startswith(DOCS_PATHS):
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    else:
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    return response


RECENT_CASES = 8


def _page(request: Request, template: str, active: str, **context):
    return TEMPLATES.TemplateResponse(
        request, template,
        {"version": __version__, "active": active, "query": "", **context},
    )


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def index(request: Request):
    cases = sorted(CaseStore().list(), key=lambda c: c.updated_utc, reverse=True)
    return _page(
        request, "index.html", "intake",
        nlp=BECPipeline.nlp_status(),
        suggested_case=f"CASE-{uuid.uuid4().hex[:6].upper()}",
        cases=cases[:RECENT_CASES],
        more_cases=len(cases) > RECENT_CASES,
        total_cases=len(cases),
    )


async def _collect(files: list[UploadFile]) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Validate and read uploads. Returns (payloads, rejection messages)."""
    if len(files) > MAX_FILES_PER_REQUEST:
        raise UploadRejected(
            f"Too many files: {len(files)}. Limit is {MAX_FILES_PER_REQUEST} per submission."
        )

    payloads: list[tuple[str, bytes]] = []
    rejected: list[str] = []
    total = 0

    for upload in files:
        try:
            raw = await read_limited(upload)
            label = validate_upload(upload.filename, upload.content_type, len(raw))
            # Parse before accepting, so evidence that cannot be analysed is
            # reported at intake rather than stored and then failing later.
            load_bytes(raw, label)
        except UploadRejected as exc:
            rejected.append(str(exc))
            continue
        except EvidenceParseError as exc:
            rejected.append(f"{label}: cannot be parsed safely - {exc}")
            continue

        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise UploadRejected(
                f"Submission exceeds the {MAX_TOTAL_BYTES // (1024 * 1024)} MB total limit."
            )
        payloads.append((label, raw))

    return payloads, rejected


def _analyse_into_case(payloads: list[tuple[str, bytes]], case: str,
                       examiner: str) -> dict:
    """Preserve the uploads in the case store, then analyse the whole case.

    The case ID is validated before it touches the filesystem; evidence is
    stored under its SHA-256, never under the uploaded filename.
    """
    store = CaseStore()
    case_id = validate_case_id(case)
    store.open_or_create(case_id, examiner or "", case_id)
    for label, raw in payloads:
        store.add_evidence(case_id, raw, label, examiner or "")
    return store.analyse(case_id, examiner or "")


@app.post("/analyse", response_class=HTMLResponse)
async def analyse(
    request: Request,
    files: list[UploadFile] = File(...),
    case: str = Form("CASE-000"),
    examiner: str = Form(""),
):
    """Analyse uploaded messages and render the investigator report."""
    try:
        payloads, rejected = await _collect(files)
    except UploadRejected as exc:
        return HTMLResponse(_error_page(str(exc)), status_code=400)

    if not payloads:
        detail = "No valid files were uploaded."
        if rejected:
            detail += " " + " ".join(rejected)
        return HTMLResponse(_error_page(detail), status_code=400)

    try:
        report = _analyse_into_case(payloads, case, examiner)
    except CaseError as exc:
        return HTMLResponse(_error_page(str(exc)), status_code=400)

    case_id = report["case"]["case_id"]
    if rejected:
        # Show the rejections now rather than lose them across a redirect.
        return _case_page(request, case_id, rejected=rejected)
    # Post/redirect/get: refreshing the result page must not resubmit evidence.
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.post("/api/analyse")
async def analyse_api(
    files: list[UploadFile] = File(...),
    case: str = Form("CASE-000"),
    examiner: str = Form(""),
):
    """Machine-readable endpoint returning the full JSON case report."""
    try:
        payloads, rejected = await _collect(files)
    except UploadRejected as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    if not payloads:
        return JSONResponse(
            {"error": "No valid files were uploaded.", "rejected": rejected},
            status_code=400,
        )

    try:
        report = _analyse_into_case(payloads, case, examiner)
    except CaseError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if rejected:
        report["case"]["rejected_uploads"] = rejected

    return JSONResponse(report)


# ---------------------------------------------------------------------------
# Case retrieval (read-only)
# ---------------------------------------------------------------------------

def _load_case_or_error(case_id: str):
    store = CaseStore()
    try:
        return store, store.load(case_id)
    except CaseError:
        return store, None


@app.get("/api/cases")
async def api_cases():
    return {"cases": [
        {"case_id": c.case_id, "title": c.title, "examiner": c.examiner,
         "created_utc": c.created_utc, "evidence_count": len(c.evidence),
         "summary": c.summary}
        for c in CaseStore().list()
    ]}


@app.get("/api/cases/{case_id}")
async def api_case(case_id: str):
    store, case = _load_case_or_error(case_id)
    if case is None:
        return JSONResponse({"error": "Case not found."}, status_code=404)
    return {"case": case.to_dict(), "related_cases": store.related_cases(case.case_id)}


@app.get("/api/cases/{case_id}/verify")
async def api_case_verify(case_id: str):
    store, case = _load_case_or_error(case_id)
    if case is None:
        return JSONResponse({"error": "Case not found."}, status_code=404)
    return store.verify(case.case_id)


@app.get("/api/cases/{case_id}/analysis")
async def api_case_analysis(case_id: str):
    store, case = _load_case_or_error(case_id)
    if case is None:
        return JSONResponse({"error": "Case not found."}, status_code=404)
    analysis = store.load_analysis(case.case_id)
    if analysis is None:
        return JSONResponse({"error": "Case has not been analysed."}, status_code=404)
    return analysis


@app.get("/api/search")
async def api_search(q: str = ""):
    if len(q) > 200:
        return JSONResponse({"error": "Query too long."}, status_code=400)
    return {"query": q, "results": CaseStore().search(q)}


@app.get("/cases/{case_id}/report", response_class=HTMLResponse)
async def case_report(case_id: str):
    store, case = _load_case_or_error(case_id)
    if case is None:
        return HTMLResponse(_error_page("Case not found."), status_code=404)
    path = store.report_path(case.case_id)
    if not path.exists():
        return HTMLResponse(_error_page("This case has not been analysed yet."),
                            status_code=404)
    return HTMLResponse(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Investigator dashboard pages
# ---------------------------------------------------------------------------

FLAGGED_BANDS = {"LIKELY_BEC", "CONFIRMED_BEC"}


def _case_page(request: Request, case_id: str, integrity: dict | None = None,
               rejected: list[str] | None = None):
    store = CaseStore()
    try:
        case = store.load(case_id)
    except CaseError:
        return HTMLResponse(_error_page("Case not found."), status_code=404)

    analysis = store.load_analysis(case.case_id)
    from ..feedback import ASSESSMENTS, FeedbackStore
    current_feedback = {k: v.to_dict() for k, v in FeedbackStore(store, case.case_id).current().items()}
    context = {"case": case, "analysis": analysis, "integrity": integrity,
               "feedback": current_feedback, "assessments": ASSESSMENTS,
               "rejected": rejected or [], "related": store.related_cases(case.case_id),
               "audit": store.audit_entries(case.case_id)}

    if analysis:
        flagged = [a for a in analysis["assessments"] if a["risk_band"] in FLAGGED_BANDS]
        recommendations: dict[str, list[str]] = {}
        iocs: dict[str, set[str]] = {}
        for item in flagged:
            for ind in item["indicators"]:
                rec = (ind.get("recommendation") or "").strip()
                if rec and ind["severity"] in ("CRITICAL", "HIGH"):
                    codes = recommendations.setdefault(rec, [])
                    if ind["code"] not in codes:
                        codes.append(ind["code"])
            for kind, values in (item.get("iocs") or {}).items():
                iocs.setdefault(kind, set()).update(values)
        context.update(
            recommendations=list(recommendations.items()),
            iocs=[(k.replace("_", " "), sorted(v)) for k, v in sorted(iocs.items()) if v],
            timeline=analysis.get("timeline") or [],
            graph=analysis.get("evidence_graph") or {"node_count": 0, "edge_count": 0},
            # Generated by EvidenceGraph.to_svg with every label escaped.
            graph_svg=analysis.get("evidence_graph_svg") or "",
        )
    return _page(request, "case.html", "cases", **context)


@app.post("/cases/{case_id}/feedback", response_class=HTMLResponse)
async def feedback_form(request: Request, case_id: str,
                        evidence_id: str = Form(...), assessment: str = Form(...),
                        examiner: str = Form(""), notes: str = Form("")):
    """Record an investigator assessment from the case page."""
    from ..feedback import FeedbackError
    try:
        CaseStore().record_feedback(case_id, evidence_id, assessment, examiner, notes)
    except (CaseError, FeedbackError) as exc:
        return HTMLResponse(_error_page(str(exc)), status_code=400)
    return RedirectResponse(f"/cases/{case_id}#feedback", status_code=303)


@app.post("/api/cases/{case_id}/feedback")
async def feedback_api(case_id: str, payload: dict):
    from ..feedback import FeedbackError
    try:
        record = CaseStore().record_feedback(
            case_id, str(payload.get("evidence_id", "")), str(payload.get("assessment", "")),
            str(payload.get("examiner", "")), str(payload.get("notes", "")))
    except (CaseError, FeedbackError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return record.to_dict()


@app.get("/api/cases/{case_id}/feedback")
async def feedback_list(case_id: str):
    from ..feedback import FeedbackStore
    store, case = _load_case_or_error(case_id)
    if case is None:
        return JSONResponse({"error": "Case not found."}, status_code=404)
    fb = FeedbackStore(store, case.case_id)
    return {"history": [r.to_dict() for r in fb.history()], "integrity": fb.verify()}


def _ask(case_id: str, question: str, evidence_id: str | None):
    from ..assistant import ask
    store, case = _load_case_or_error(case_id)
    if case is None:
        return None, "Case not found."
    analysis = store.load_analysis(case.case_id)
    if analysis is None:
        return None, "This case has not been analysed yet."
    return ask(question, analysis, evidence_id or None), None


@app.post("/api/cases/{case_id}/assistant")
async def assistant_api(case_id: str, payload: dict):
    question = str(payload.get("question", ""))[:500]
    answer, error = _ask(case_id, question, payload.get("evidence_id"))
    if error:
        return JSONResponse({"error": error}, status_code=404)
    return answer.to_dict()


@app.get("/cases/{case_id}/ask", response_class=HTMLResponse)
async def assistant_page(request: Request, case_id: str, q: str = "", evidence_id: str = ""):
    answer, error = _ask(case_id, q[:500], evidence_id)
    if error:
        return HTMLResponse(_error_page(error), status_code=404)
    return _page(request, "ask.html", "cases", case_id=case_id, question=q[:500],
                 answer=answer)


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    cases = sorted(CaseStore().list(), key=lambda c: c.created_utc, reverse=True)
    return _page(request, "cases.html", "cases", cases=cases)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_page(request: Request, case_id: str):
    return _case_page(request, case_id)


@app.get("/cases/{case_id}/verify", response_class=HTMLResponse)
async def case_verify_page(request: Request, case_id: str):
    store = CaseStore()
    try:
        case = store.load(case_id)
    except CaseError:
        return HTMLResponse(_error_page("Case not found."), status_code=404)
    result = store.verify(case.case_id)
    # Verification is itself an investigative action, so it is logged - after
    # the chain has been checked, so the entry cannot mask a break.
    from ..forensics import AuditLog
    with store.lock(case.case_id):
        AuditLog(store.audit_path(case.case_id)).record(
            "integrity_verified", "intact" if result["intact"] else "INTEGRITY FAILURE")
    return _case_page(request, case.case_id, integrity=result)


@app.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = ""):
    if len(q) > 200:
        return _page(request, "search.html", "", query=q[:200], results=[],
                     error="Query too long (200 characters maximum).")
    results = CaseStore().search(q) if q.strip() else []
    return _page(request, "search.html", "", query=q, results=results, error="")


@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    from ..report.assemble import LIMITATIONS
    return _page(request, "about.html", "about", limitations=LIMITATIONS)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Browsers request this on every page; answer rather than log a 404."""
    return Response(status_code=204)


@app.api_route("/api/health", methods=["GET", "HEAD"])
async def health():
    return {
        "status": "ok",
        "tool": __tool_name__,
        "version": __version__,
        "nlp_backends": BECPipeline.nlp_status(),
    }


def _error_page(message: str) -> str:
    """Client-safe error page. Never discloses internal state or paths."""
    import html as _html

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FORENSIBEC - submission rejected</title>
<style>
 body{{margin:0;padding:48px 24px;background:#f1f5f9;color:#0f172a;
      font:15px/1.6 "Segoe UI",system-ui,sans-serif}}
 .box{{max-width:620px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;
      border-left:4px solid #b91c1c;border-radius:10px;padding:26px}}
 h1{{font-size:19px;margin:0 0 10px;color:#b91c1c}}
 a{{color:#1d4ed8}}
</style></head><body><div class="box">
<h1>Submission rejected</h1>
<p>{_html.escape(message)}</p>
<p><a href="/">Return to evidence intake</a></p>
</div></body></html>"""
