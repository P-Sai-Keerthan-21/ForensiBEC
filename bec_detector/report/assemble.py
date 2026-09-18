"""Single assembly point for the full case report.

The CLI, the web application and case analysis previously each rebuilt the
report dictionary by hand, which let them drift apart. Everything that goes
into a report is gathered here, once.
"""

from __future__ import annotations

from typing import Any

from ..forensics import CommunicationGraph, build_case_timeline
from ..models import Assessment
from .builder import build_case_report

LIMITATIONS = [
    "Findings are technical indicators. The tool does not determine whether a "
    "criminal offence occurred; that is a decision for the investigator.",
    "Risk scores come from a transparent weighted-rule model. They are not "
    "calibrated probabilities and should not be read as a percentage chance "
    "of fraud.",
    "Behavioural, thread and stylometric findings are relative to the evidence "
    "acquired in this case. A small or partial collection weakens them.",
    "Stylometry draws no conclusion with fewer than three prior messages from "
    "the same sender.",
    "Unicode confusable detection uses a curated subset of the Unicode TR39 "
    "table; scripts beyond Latin, Cyrillic, Greek and Armenian are only "
    "partially covered.",
    "URLs are analysed lexically and never contacted; attachments are hashed "
    "and type-checked but never opened, and archives are not extracted.",
    "Threat intelligence is a local operator-maintained list only. No external "
    "service is consulted.",
    "Cross-case correlation reflects only cases previously analysed by this "
    "installation.",
    "All detection performance figures quoted for this project come from "
    "synthetic corpora and are not real-world accuracy estimates.",
]


def assemble_report(pipeline: Any, assessments: list[Assessment],
                    case_name: str = "Untitled case",
                    examiner: str | None = None) -> dict[str, Any]:
    """Build the complete report dictionary for one analysed case."""
    report = build_case_report(
        assessments, case_name=case_name, examiner=examiner,
        nlp_status=pipeline.nlp_status(),
    )
    report["case"]["case_id"] = pipeline.case_id

    communication = CommunicationGraph()
    communication.add_all(assessments)
    evidence_graph = pipeline.evidence_graph(assessments)

    report["timeline"] = [e.to_dict() for e in build_case_timeline(assessments)]
    report["graph"] = communication.to_dict()
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
    report["limitations"] = list(LIMITATIONS)
    return report
