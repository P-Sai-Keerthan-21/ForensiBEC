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

    pipeline = BECPipeline(examiner=args.examiner)
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

    report = build_case_report(
        assessments,
        case_name=args.case,
        examiner=args.examiner,
        nlp_status=pipeline.nlp_status(),
    )

    if args.json:
        written = write_json(report, args.json)
        print(f"JSON report : {written}")
    if args.html:
        render_html(report, args.html)
        print(f"HTML report : {Path(args.html)}")

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
    scan.set_defaults(func=_cmd_scan)

    status = sub.add_parser("status", help="report which NLP backends are available")
    status.set_defaults(func=_cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
