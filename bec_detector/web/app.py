"""FastAPI front end for interactive analysis.

Thin by design: the web layer only acquires bytes and renders what the pipeline
returns. Every detection decision lives in the engine, so the CLI and the web UI
can never disagree about a verdict.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .. import __tool_name__, __version__
from ..pipeline import BECPipeline
from ..report import build_case_report, render_html

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Upload guard: BEC evidence is text; anything larger is not a single message.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = FastAPI(
    title=f"{__tool_name__} {__version__}",
    description="Business Email Compromise detector - forensic email analysis.",
)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return TEMPLATES.TemplateResponse(
        request, "index.html",
        {"version": __version__, "nlp": BECPipeline.nlp_status()},
    )


async def _read_uploads(files: list[UploadFile]) -> list[tuple[str, bytes]]:
    payloads: list[tuple[str, bytes]] = []
    for upload in files:
        raw = await upload.read()
        if not raw:
            continue
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{upload.filename} exceeds the {MAX_UPLOAD_BYTES // 1024 // 1024} MB limit",
            )
        payloads.append((upload.filename or "upload.eml", raw))
    if not payloads:
        raise HTTPException(status_code=400, detail="No readable files were uploaded.")
    return payloads


def _analyse(payloads: list[tuple[str, bytes]], case: str, examiner: str):
    """Acquire, baseline across the upload set, then assess each message."""
    pipeline = BECPipeline(examiner=examiner or None)
    emails = [pipeline.acquire_bytes(raw, label) for label, raw in payloads]
    pipeline.fit(emails)
    assessments = [pipeline.assess(email) for email in emails]
    return pipeline, assessments


@app.post("/analyse", response_class=HTMLResponse)
async def analyse(
    request: Request,
    files: list[UploadFile] = File(...),
    case: str = Form("Web submission"),
    examiner: str = Form(""),
):
    """Analyse uploaded .eml files and render the report inline."""
    payloads = await _read_uploads(files)
    pipeline, assessments = _analyse(payloads, case, examiner)

    report = build_case_report(
        assessments, case_name=case, examiner=examiner or None,
        nlp_status=pipeline.nlp_status(),
    )
    return HTMLResponse(render_html(report))


@app.post("/api/analyse")
async def analyse_api(
    files: list[UploadFile] = File(...),
    case: str = Form("API submission"),
    examiner: str = Form(""),
):
    """Machine-readable endpoint returning the JSON case report."""
    payloads = await _read_uploads(files)
    pipeline, assessments = _analyse(payloads, case, examiner)

    report = build_case_report(
        assessments, case_name=case, examiner=examiner or None,
        nlp_status=pipeline.nlp_status(),
    )
    return JSONResponse(report)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "tool": __tool_name__,
        "version": __version__,
        "nlp_backends": BECPipeline.nlp_status(),
    }
