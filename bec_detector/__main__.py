"""Command-line interface.

    python -m bec_detector scan data/samples --case "Capstone demo" --examiner "K. Guthala"
    python -m bec_detector scan suspect.eml --json out.json --html out.html
    python -m bec_detector status
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __tool_name__, __version__
from .models import RiskBand
from .pipeline import BECPipeline
from .report import render_html, write_json
from .report.assemble import assemble_report

BAND_MARK = {
    RiskBand.CONFIRMED_BEC: "[!!]",
    RiskBand.LIKELY_BEC: "[! ]",
    RiskBand.SUSPICIOUS: "[? ]",
    RiskBand.BENIGN: "[ok]",
}


def _cmd_scan(args: argparse.Namespace) -> int:
    source = Path(args.path)
    if not source.exists():
        print(f"error: evidence path not found: {source}", file=sys.stderr)
        return 2

    pipeline = BECPipeline(
        examiner=args.examiner,
        case_id=args.case_id,
        audit_path=args.audit,
        correlate=not args.no_correlate,
    )
    assessments = pipeline.run(source)

    for skipped_path, reason in getattr(pipeline, "skipped", []):
        print(f"warning: skipped {skipped_path}: {reason}", file=sys.stderr)

    if not assessments:
        print(f"error: no parsable messages found at {source}", file=sys.stderr)
        return 2

    ordered = sorted(assessments, key=lambda a: -a.score)

    print()
    print(f"{__tool_name__} {__version__} - analysed {len(assessments)} message(s) from {source}")
    print("=" * 78)
    for assessment in ordered:
        email = assessment.artifact
        subject = (email.subject or "(no subject)")[:52]
        print(
            f"{BAND_MARK[assessment.band]} {assessment.score:5.1f}  "
            f"{assessment.band.value:<14} {subject}"
        )
        print(f"         from: {email.from_display} <{email.from_address}>")
        if args.verbose:
            for indicator in assessment.indicators:
                print(f"           - [{indicator.severity.value:<8}] {indicator.title}")
                print(f"             {indicator.evidence}")
        print()

    flagged = sum(1 for a in assessments if a.band is not RiskBand.BENIGN)
    print("=" * 78)
    print(f"flagged {flagged} of {len(assessments)} message(s)")

    integrity = pipeline.integrity()
    print(f"audit chain : {'VERIFIED' if integrity['valid'] else 'BROKEN'} "
          f"({integrity['entries']} entries)")
    print(f"intel       : {pipeline.intel.name}")
    if pipeline.correlation_matches:
        print(f"correlation : {len(pipeline.correlation_matches)} indicator(s) "
              "previously seen in other local cases")

    report = assemble_report(pipeline, assessments, case_name=args.case,
                             examiner=args.examiner)

    if args.json:
        written = write_json(report, args.json)
        print(f"JSON report : {written}")
    if args.html:
        render_html(report, args.html)
        print(f"HTML report : {Path(args.html)}")

    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify the hash chain of an existing audit log."""
    from .forensics import AuditLog

    path = Path(args.path)
    if not path.exists():
        print(f"error: audit log not found: {path}", file=sys.stderr)
        return 2

    result = AuditLog(path).verify()
    print(f"audit log   : {path}")
    print(f"entries     : {result['entries']}")
    print(f"integrity   : {'VERIFIED' if result['valid'] else 'BROKEN'}")
    print(f"reason      : {result['reason']}")
    if not result["valid"]:
        print(f"broken at   : entry {result['broken_at']}", file=sys.stderr)
        return 1
    return 0


def _cmd_status(_: argparse.Namespace) -> int:
    print(f"{__tool_name__} {__version__}")
    for backend, ok in BECPipeline.nlp_status().items():
        print(f"  {backend:<18} {'available' if ok else 'UNAVAILABLE (fallback active)'}")
    return 0


# ---------------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------------

def _store():
    from .cases import CaseStore
    return CaseStore()


def _case_fail(exc: Exception) -> int:
    print(f"error: {exc}", file=sys.stderr)
    return 2


def _cmd_case_create(args: argparse.Namespace) -> int:
    from .cases import CaseError
    try:
        case = _store().create(args.case_id, args.examiner or "", args.title or "")
    except CaseError as exc:
        return _case_fail(exc)
    print(f"created {case.case_id} (examiner {case.examiner}) at {case.created_utc}")
    return 0


def _cmd_case_add(args: argparse.Namespace) -> int:
    from .cases import CaseError
    store = _store()
    source = Path(args.path)
    files = sorted(p for p in source.rglob("*.eml")) if source.is_dir() else [source]
    if not files or not all(f.is_file() for f in files):
        print(f"error: no .eml evidence found at {source}", file=sys.stderr)
        return 2
    try:
        store.load(args.case_id)
    except CaseError as exc:
        return _case_fail(exc)
    added = duplicates = 0
    rejected: list[str] = []
    for path in files:
        try:
            known = {e.sha256 for e in store.load(args.case_id).evidence}
            record = store.add_evidence(args.case_id, path.read_bytes(), path.name,
                                        args.examiner or "")
        except CaseError as exc:
            # One unusable file must not stop the rest of a directory, and
            # must never be preserved (it would block every later analysis).
            rejected.append(f"{path.name}: {exc}")
            print(f"  REJECTED  {path.name}: {exc}", file=sys.stderr)
            continue
        if record.sha256 in known:
            duplicates += 1
            note = "  (already preserved - identical bytes, not added again)"
        else:
            added += 1
            note = ""
        print(f"  {record.evidence_id}  sha256={record.sha256}  {path.name}{note}")
    print(f"{added} new item(s) registered in {args.case_id}"
          + (f"; {duplicates} already present" if duplicates else "")
          + (f"; {len(rejected)} rejected (not preserved)" if rejected else ""))
    return 2 if rejected else 0


def _cmd_case_analyse(args: argparse.Namespace) -> int:
    from .cases import CaseError
    store = _store()
    try:
        report = store.analyse(args.case_id, args.examiner or "")
    except CaseError as exc:
        return _case_fail(exc)
    for item in report["assessments"]:
        email = item["email"]
        print(f"{BAND_MARK[RiskBand(item['risk_band'])]} {item['risk_score']:5.1f}  "
              f"{item['risk_band']:<14} {item['evidence_id']}  {(email['subject'] or '')[:40]}")
    case = store.load(args.case_id)
    print(f"highest risk: {case.summary['highest_risk_band']} "
          f"({case.summary['highest_risk_score']}) in {case.summary['highest_risk_evidence']}")
    print(f"audit chain : {'VERIFIED' if report['audit']['integrity']['valid'] else 'BROKEN'}")
    print(f"report      : {store.report_path(args.case_id)}")
    return 0


def _cmd_case_show(args: argparse.Namespace) -> int:
    from .cases import CaseError
    store = _store()
    try:
        case = store.load(args.case_id)
    except CaseError as exc:
        return _case_fail(exc)
    print(f"case      : {case.case_id}  ({case.title})")
    print(f"examiner  : {case.examiner}")
    print(f"created   : {case.created_utc}   updated: {case.updated_utc}")
    print(f"evidence  : {len(case.evidence)} item(s)")
    for e in case.evidence:
        print(f"  {e.evidence_id}  {e.size_bytes:>7} bytes  sha256={e.sha256}  {e.original_filename}")
    if case.summary:
        s = case.summary
        print(f"analysed  : {s['analysed_utc']}")
        print(f"risk      : highest {s['highest_risk_band']} ({s['highest_risk_score']})")
        print(f"bands     : {s['band_counts']}")
        print(f"iocs      : {s['ioc_counts']}")
    else:
        print("analysed  : not yet")
    related = store.related_cases(case.case_id)
    print(f"related   : {', '.join(r['case_id'] for r in related) or 'none recorded'}")
    return 0


def _cmd_case_list(_: argparse.Namespace) -> int:
    cases = _store().list()
    if not cases:
        print("no cases")
        return 0
    for case in cases:
        risk = case.summary.get("highest_risk_band", "not analysed")
        print(f"{case.case_id:<20} {len(case.evidence):>3} evidence  {risk:<14} {case.title}")
    return 0


def _cmd_case_search(args: argparse.Namespace) -> int:
    hits = _store().search(args.query)
    if not hits:
        print("no matches")
        return 0
    for hit in hits:
        print(f"{hit['case_id']:<20} {', '.join(hit['matched_on'])}")
    return 0


def _cmd_case_feedback(args: argparse.Namespace) -> int:
    from .cases import CaseError
    from .feedback import FeedbackError
    try:
        record = _store().record_feedback(args.case_id, args.evidence_id, args.assessment,
                                          args.examiner, args.notes or "")
    except (CaseError, FeedbackError) as exc:
        return _case_fail(exc)
    print(f"recorded: {record.evidence_id} -> {record.assessment_label} "
          f"(system said {record.system_band} {record.system_score}; {record.agreement})")
    return 0


def _cmd_case_export_feedback(args: argparse.Namespace) -> int:
    import json as _json
    from .feedback import export_training_candidates
    data = export_training_candidates(_store(), args.case_id or None)
    Path(args.output).write_text(_json.dumps(data, indent=2), encoding="utf-8")
    print(f"{len(data['rows'])} candidate label(s), {len(data['withheld'])} withheld -> {args.output}")
    print("Not used for training by this application.")
    return 0


def _cmd_case_ask(args: argparse.Namespace) -> int:
    from .assistant import ask
    store = _store()
    analysis = store.load_analysis(args.case_id) if store.exists(args.case_id) else None
    if analysis is None:
        print("error: case not found or not analysed", file=sys.stderr)
        return 2
    answer = ask(args.question, analysis, args.evidence)
    print(f"[{answer.provider}; intent={answer.intent}; "
          f"grounded={'yes' if answer.grounded else 'NO'}]")
    print()
    print(answer.text())
    return 0 if answer.grounded else 1


def _cmd_case_verify(args: argparse.Namespace) -> int:
    from .cases import CaseError
    try:
        result = _store().verify(args.case_id)
    except CaseError as exc:
        return _case_fail(exc)
    for item in result["evidence"]:
        print(f"  {item['evidence_id']}  {item['status']}")
    print(f"audit chain : {'VERIFIED' if result['audit']['valid'] else 'BROKEN'} "
          f"({result['audit']['entries']} entries)")
    print(f"case        : {'INTACT' if result['intact'] else 'INTEGRITY FAILURE'}")
    return 0 if result["intact"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bec_detector",
        description="Business Email Compromise detector - forensic analysis of email evidence.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse an .eml file, .mbox archive or directory")
    scan.add_argument("path", help="evidence path")
    scan.add_argument("--case", default="Untitled case", help="case name for the report")
    scan.add_argument("--examiner", default=None, help="examiner name for chain of custody")
    scan.add_argument("--json", metavar="FILE", help="write the JSON case report here")
    scan.add_argument("--html", metavar="FILE", help="write the HTML case report here")
    scan.add_argument("-v", "--verbose", action="store_true", help="list every indicator")
    scan.add_argument("--case-id", default="CASE-000",
                      help="case identifier used for cross-case IOC correlation")
    scan.add_argument("--audit", metavar="FILE", default=None,
                      help="append the tamper-evident audit log to this file")
    scan.add_argument("--no-correlate", action="store_true",
                      help="disable local cross-case IOC correlation")
    scan.set_defaults(func=_cmd_scan)

    verify = sub.add_parser("verify-audit", help="verify a tamper-evident audit log")
    verify.add_argument("path", help="audit log file (.jsonl)")
    verify.set_defaults(func=_cmd_verify)

    case = sub.add_parser("case", help="case management: create, add, analyse, show, ...")
    case_sub = case.add_subparsers(dest="case_command", required=True)

    c = case_sub.add_parser("create", help="open a new case")
    c.add_argument("case_id")
    c.add_argument("--examiner", default=None)
    c.add_argument("--title", default=None)
    c.set_defaults(func=_cmd_case_create)

    c = case_sub.add_parser("add", help="preserve evidence (.eml file or directory) in a case")
    c.add_argument("case_id")
    c.add_argument("path")
    c.add_argument("--examiner", default=None)
    c.set_defaults(func=_cmd_case_add)

    c = case_sub.add_parser("analyse", help="analyse all evidence in a case and write its report")
    c.add_argument("case_id")
    c.add_argument("--examiner", default=None)
    c.set_defaults(func=_cmd_case_analyse)

    c = case_sub.add_parser("show", help="case summary")
    c.add_argument("case_id")
    c.set_defaults(func=_cmd_case_show)

    c = case_sub.add_parser("list", help="list cases")
    c.set_defaults(func=_cmd_case_list)

    c = case_sub.add_parser("search", help="search cases by ID, evidence, IOC, sender or subject")
    c.add_argument("query")
    c.set_defaults(func=_cmd_case_search)

    c = case_sub.add_parser("feedback", help="record an investigator assessment")
    c.add_argument("case_id")
    c.add_argument("evidence_id")
    c.add_argument("assessment", choices=["confirmed_suspicious", "confirmed_benign", "needs_review"])
    c.add_argument("--examiner", required=True)
    c.add_argument("--notes", default="")
    c.set_defaults(func=_cmd_case_feedback)

    c = case_sub.add_parser("export-feedback",
                            help="export candidate labels for a future, deliberate retraining step")
    c.add_argument("output")
    c.add_argument("case_id", nargs="*")
    c.set_defaults(func=_cmd_case_export_feedback)

    c = case_sub.add_parser("ask", help="ask the grounded assistant about an analysed case")
    c.add_argument("case_id")
    c.add_argument("question")
    c.add_argument("--evidence", default=None, help="evidence ID to focus on")
    c.set_defaults(func=_cmd_case_ask)

    c = case_sub.add_parser("verify", help="re-hash evidence and verify the case audit chain")
    c.add_argument("case_id")
    c.set_defaults(func=_cmd_case_verify)

    status = sub.add_parser("status", help="report which NLP backends are available")
    status.set_defaults(func=_cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
