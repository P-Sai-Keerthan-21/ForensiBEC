"""Canonical data structures shared by every stage of the forensic pipeline.

The pipeline is deliberately staged to mirror the standard forensic workflow:

    Acquisition  ->  Analysis  ->  Validation  ->  Report

Each stage consumes and enriches the objects defined here.  Keeping them in one
module means the stages stay decoupled and independently testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How much weight a single indicator carries on its own."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskBand(str, Enum):
    """Final classification returned to the examiner."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_BEC = "LIKELY_BEC"
    CONFIRMED_BEC = "CONFIRMED_BEC"


class Category(str, Enum):
    """Which analysis family produced an indicator.

    Used by the report to group evidence, and by the fusion engine to apply
    per-category caps so that one noisy family cannot dominate the score.
    """

    SENDER = "SENDER"
    AUTHENTICATION = "AUTHENTICATION"
    BEHAVIOR = "BEHAVIOR"
    CONTENT = "CONTENT"
    ANOMALY = "ANOMALY"
    THREAD = "THREAD"
    URL = "URL"
    ATTACHMENT = "ATTACHMENT"
    STYLOMETRY = "STYLOMETRY"
    INTELLIGENCE = "INTELLIGENCE"


class Confidence(str, Enum):
    """How firmly the evidence supports the inference drawn from it.

    Reported alongside every indicator so an investigator can separate a
    header fact from a behavioural inference.
    """

    OBSERVED = "OBSERVED"       # a fact read directly from the artifact
    INFERRED = "INFERRED"       # a conclusion drawn from observed facts
    INSUFFICIENT = "INSUFFICIENT"  # not enough data to judge


@dataclass
class CustodyRecord:
    """Chain-of-custody metadata captured at acquisition time.

    A forensic tool must be able to prove that the artifact it reported on is
    the artifact it ingested.  `sha256` is computed over the raw source bytes
    before any parsing occurs.
    """

    source_path: str
    sha256: str
    size_bytes: int
    acquired_utc: str
    examiner: str
    tool_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attachment:
    """A message attachment, described but never executed.

    `sha256` is computed over the decoded attachment bytes so the file can be
    recognised across cases without retaining the payload itself.
    """

    filename: str
    declared_mime: str
    detected_type: str
    extension: str
    size_bytes: int
    sha256: str
    type_mismatch: bool
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UrlArtifact:
    """A URL extracted from the message body, analysed statically only.

    The tool never resolves, requests or follows a URL it finds in evidence.
    """

    raw: str
    scheme: str
    host: str
    path: str
    is_ip_literal: bool
    is_punycode: bool
    uses_https: bool
    length: int
    display_mismatch: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EmailArtifact:
    """A single parsed email, normalised into the fields the analysers need.

    Raw header values are preserved in `headers` so that any indicator can
    quote the exact bytes it fired on -- this is what makes the assessment
    explainable rather than merely a score.
    """

    message_id: str
    from_display: str
    from_address: str
    reply_to_address: str
    return_path: str
    to_addresses: list[str]
    cc_addresses: list[str]
    subject: str
    body_text: str
    date_utc: datetime | None
    headers: dict[str, str]
    received_chain: list[str]
    auth_results: str
    attachments: list[Attachment]
    custody: CustodyRecord

    # Threading headers, kept as first-class fields because conversation
    # analysis depends on them rather than on body text.
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)

    urls: list[UrlArtifact] = field(default_factory=list)

    @property
    def attachment_names(self) -> list[str]:
        return [a.filename for a in self.attachments]

    @property
    def evidence_id(self) -> str:
        """Stable short identifier derived from the evidence hash.

        Derived rather than random so the same bytes always yield the same id,
        which is what makes cross-case correlation reproducible.
        """
        return f"EV-{self.custody.sha256[:12].upper()}"

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""

    @property
    def reply_to_domain(self) -> str:
        if "@" not in self.reply_to_address:
            return ""
        return self.reply_to_address.rsplit("@", 1)[-1].lower()

    def summary(self) -> dict[str, Any]:
        """Compact form used in report headers and API responses."""
        return {
            "evidence_id": self.evidence_id,
            "message_id": self.message_id,
            "from_display": self.from_display,
            "from_address": self.from_address,
            "reply_to_address": self.reply_to_address,
            "return_path": self.return_path,
            "subject": self.subject,
            "date_utc": self.date_utc.isoformat() if self.date_utc else None,
            "to_addresses": self.to_addresses,
            "cc_addresses": self.cc_addresses,
            "in_reply_to": self.in_reply_to,
            "references": self.references,
            "attachments": self.attachment_names,
            "attachment_detail": [a.to_dict() for a in self.attachments],
            "urls": [u.to_dict() for u in self.urls],
            "sha256": self.custody.sha256,
        }


@dataclass
class Indicator:
    """One piece of evidence, with the observation that produced it.

    `evidence` must always quote the concrete artifact content that triggered
    the rule.  An indicator that cannot explain itself is not admissible.
    """

    code: str
    title: str
    category: Category
    severity: Severity
    weight: float
    confidence: float
    evidence: str
    explanation: str
    # Separating what was seen from what was concluded keeps the report
    # defensible: an investigator can accept an observation while disputing
    # the inference drawn from it.
    basis: Confidence = Confidence.OBSERVED
    recommendation: str = ""
    mitre: list[str] = field(default_factory=list)

    @property
    def contribution(self) -> float:
        """Score actually contributed, discounted by the rule's confidence."""
        return round(self.weight * self.confidence, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "contribution": self.contribution,
            "basis": self.basis.value,
            "observed_evidence": self.evidence,
            "inference": self.explanation,
            "recommendation": self.recommendation,
            "mitre": self.mitre,
            # Retained under the original keys so existing consumers of the
            # JSON report keep working.
            "evidence": self.evidence,
            "explanation": self.explanation,
        }


@dataclass
class TimelineEvent:
    """One dated event in the investigation timeline.

    `source` records where the timestamp came from, so a derived analysis time
    is never mistaken for an observed message time.
    """

    timestamp: str
    kind: str
    description: str
    source: str
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Assessment:
    """The final explainable verdict for one email."""

    artifact: EmailArtifact
    indicators: list[Indicator] = field(default_factory=list)
    score: float = 0.0
    band: RiskBand = RiskBand.BENIGN
    category_scores: dict[str, float] = field(default_factory=dict)
    narrative: str = ""
    iocs: dict[str, list[str]] = field(default_factory=dict)
    timeline: list[TimelineEvent] = field(default_factory=list)
    mitre: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.artifact.evidence_id,
            "email": self.artifact.summary(),
            "custody": self.artifact.custody.to_dict(),
            "risk_score": self.score,
            "risk_band": self.band.value,
            "category_scores": self.category_scores,
            "narrative": self.narrative,
            "indicator_count": len(self.indicators),
            "indicators": [i.to_dict() for i in self.indicators],
            "iocs": self.iocs,
            "timeline": [e.to_dict() for e in self.timeline],
            "mitre": self.mitre,
            "analysis_notes": self.notes,
        }
