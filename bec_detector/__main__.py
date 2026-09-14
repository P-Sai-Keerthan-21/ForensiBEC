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
from .forensics import CommunicationGraph, build_case_timeline
from .models import RiskBand
from .pipeline import BECPipeline
from .report import build_case_report, render_html, write_json

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

    graph = CommunicationGraph()
    graph.add_all(assessments)

    report = build_case_report(
        assessments,
        case_name=args.case,
        examiner=args.examiner,
        nlp_status=pipeline.nlp_status(),
    )
    report["case"]["case_id"] = pipeline.case_id
    report["timeline"] = [e.to_dict() for e in build_case_timeline(assessments)]
    report["graph"] = graph.to_dict()
    report["audit"] = {"entries": pipeline.audit.to_list(), "integrity": integrity}
    report["intelligence"] = {
        "provider": pipeline.intel.name,
        "status": pipeline.intel.status(),
        "external_configured": pipeline.intel.is_external,
    }
    report["correlation"] = {
        "matches": pipeline.correlation_matches,
        "store": str(pipeline.ioc_store.path) if pipeline.ioc_store else None,
        "note": ("Correlation reflects only cases previously analysed by this "
                 "installation. It is not external threat intelligence."),
    }

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

    status = sub.add_parser("status", help="report which NLP backends are available")
    status.set_defaults(func=_cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
