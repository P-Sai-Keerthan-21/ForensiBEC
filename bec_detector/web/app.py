"""FastAPI front end - FORENSIBEC investigator dashboard.

Thin by design: the web layer acquires bytes and renders what the pipeline
returns. Every detection decision lives in the engine, so the CLI and the web
UI can never disagree about a verdict.

Security posture is enforced in `security.py`; see that module's docstring for
the threat model. In short: uploads are validated, size-limited while
streaming, never written to disk and never executed.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .. import __tool_name__, __version__
from ..forensics import CommunicationGraph, build_case_timeline
from ..pipeline import BECPipeline
from ..report import build_case_report, render_html
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


def _analyse(payloads: list[tuple[str, bytes]], case: str, examiner: str):
    """Acquire, baseline across the upload set, then assess each message."""
    pipeline = BECPipeline(
        examiner=examiner or None,
        case_id=case or "CASE-000",
        audit_path=Path("output") / "audit.jsonl",
    )
    emails = [pipeline.acquire_bytes(raw, label) for label, raw in payloads]
    pipeline.fit(emails)
    assessments = [pipeline.assess(email) for email in emails]
    pipeline._finalise(assessments)
    return pipeline, assessments


def _build_report(pipeline: BECPipeline, assessments, case: str, examiner: str) -> dict:
    graph = CommunicationGraph()
    graph.add_all(assessments)

    report = build_case_report(
        assessments, case_name=case, examiner=examiner or None,
        nlp_status=pipeline.nlp_status(),
    )
    report["case"]["case_id"] = pipeline.case_id
    report["timeline"] = [e.to_dict() for e in build_case_timeline(assessments)]
    report["graph"] = graph.to_dict()
    evidence_graph = pipeline.evidence_graph(assessments)
    report["evidence_graph"] = evidence_graph.to_dict()
    report["evidence_graph_svg"] = evidence_graph.to_svg()
    report["audit"] = {
        "entries": pipeline.audit.to_list(),
        "integrity": pipeline.integrity(),
    }
    report["intelligence"] = {
        "provider": pipeline.intel.name,
        "status": pipeline.intel.status(),
        "external_configured": pipeline.intel.is_external,
    }
    report["correlation"] = {
        "matches": pipeline.correlation_matches,
        "store": str(pipeline.ioc_store.path) if pipeline.ioc_store else None,
        "note": (
            "Correlation reflects only cases previously analysed by this "
            "installation. It is not external threat intelligence."
        ),
    }
    return report


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

    pipeline, assessments = _analyse(payloads, case, examiner)
    report = _build_report(pipeline, assessments, case, examiner)
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

    pipeline, assessments = _analyse(payloads, case, examiner)
    report = _build_report(pipeline, assessments, case, examiner)
    if rejected:
        report["case"]["rejected_uploads"] = rejected

    return JSONResponse(report)


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
