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

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .. import __tool_name__, __version__
from ..cases import CaseError, CaseStore, validate_case_id
from ..pipeline import BECPipeline
from ..report import render_html
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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return TEMPLATES.TemplateResponse(
        request, "index.html",
        {
            "version": __version__,
            "nlp": BECPipeline.nlp_status(),
            "suggested_case": f"CASE-{uuid.uuid4().hex[:6].upper()}",
        },
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
        except UploadRejected as exc:
            rejected.append(str(exc))
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
    if rejected:
        report["case"]["rejected_uploads"] = rejected

    return HTMLResponse(render_html(report))


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


@app.get("/api/health")
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
