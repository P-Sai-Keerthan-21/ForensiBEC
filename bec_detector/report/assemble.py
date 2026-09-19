"""Single assembly point for the full case report.

The CLI, the web application and case analysis previously each rebuilt the
report dictionary by hand, which let them drift apart. Everything that goes
into a report is gathered here, once.
"""

from __future__ import annotations

from typing import Any

from ..config import display_path
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


def config_fingerprint() -> dict[str, Any]:
    """SHA-256 over every parameter that affects a score.

    Two reports with the same fingerprint were scored under identical rules;
    a different fingerprint means the weights, caps, thresholds or trusted
    domains changed between them.
    """
    import hashlib
    import json

    from .. import config

    material = {
        "weights": config.WEIGHTS,
        "category_caps": config.CATEGORY_CAPS,
        "band_thresholds": config.BAND_THRESHOLDS,
        "score_normaliser": config.SCORE_NORMALISER,
        "business_hours": config.BUSINESS_HOURS,
        "trusted_domains": sorted(config.TRUSTED_DOMAINS),
        "trusted_relay_ips": sorted(config.TRUSTED_RELAY_IPS),
        "freemail_domains": sorted(config.FREEMAIL_DOMAINS),
    }
    blob = json.dumps(material, sort_keys=True, default=str).encode("utf-8")
    return {"sha256": hashlib.sha256(blob).hexdigest(),
            "covers": sorted(material)}


def reproducibility(pipeline: Any, assessments: list[Assessment]) -> dict[str, Any]:
    import platform
    import sys

    from .. import __tool_name__, __version__

    record: dict[str, Any] = {
        "tool": f"{__tool_name__} {__version__}",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "nlp_backends": pipeline.nlp_status(),
        "configuration": config_fingerprint(),
        "evidence_sha256": sorted(a.artifact.custody.sha256 for a in assessments),
        "deterministic": (
            "Scoring is rule-based and deterministic: the same evidence under the "
            "same configuration fingerprint produces the same findings and scores. "
            "Behavioural, thread and stylometric findings also depend on the other "
            "messages analysed alongside, so re-analyse the same evidence set."
        ),
    }
    try:
        import spacy
        record["spacy"] = spacy.__version__
    except Exception:
        record["spacy"] = None
    return record


def domain_analyses(assessment: Assessment) -> list[dict[str, Any]]:
    """Confusable analysis of every domain the message presents to a reader."""
    from ..analysis.confusables import analyse_domain
    from ..config import TRUSTED_DOMAINS

    email = assessment.artifact
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []

    candidates = [("From", email.from_domain), ("Reply-To", email.reply_to_domain)]
    if email.return_path and "@" in email.return_path:
        candidates.append(("Return-Path", email.return_path.rsplit("@", 1)[1].lower()))
    candidates += [("Link host", u.host) for u in email.urls if u.host and not u.is_ip_literal]

    for role, domain in candidates:
        if not domain or (role, domain) in seen:
            continue
        seen.add((role, domain))
        analysis = analyse_domain(domain, TRUSTED_DOMAINS)
        data = analysis.to_dict()
        data["role"] = role
        data["trusted"] = domain in TRUSTED_DOMAINS
        rows.append(data)
    return rows


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
        "store": display_path(pipeline.ioc_store.path) if pipeline.ioc_store else None,
        "note": (
            "Correlation reflects only cases previously analysed by this "
            "installation. It is not external threat intelligence."
        ),
    }
    report["limitations"] = list(LIMITATIONS)
    report["reproducibility"] = reproducibility(pipeline, assessments)

    by_id = {a.artifact.evidence_id: a for a in assessments}
    for item in report["assessments"]:
        source = by_id.get(item["evidence_id"])
        item["domain_analysis"] = domain_analyses(source) if source else []

    # Filled from the investigator feedback store when one exists for the case.
    # Kept separate from system inference by design.
    report.setdefault("investigator_assessments", [])
    return report
