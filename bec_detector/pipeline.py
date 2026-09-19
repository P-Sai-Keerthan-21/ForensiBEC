"""End-to-end orchestration of the four forensic stages.

    Acquisition  ->  Analysis  ->  Validation  ->  Report

The two-pass structure matters: the whole corpus is acquired and observed
before any message is scored, because the behavioural, thread, stylometric and
statistical stages can only describe "unusual" relative to a baseline.

Every stage is additive. A failure in an optional forensic component (local
intelligence, cross-case correlation) degrades that component only -- it never
prevents the core assessment from being produced.
"""

from __future__ import annotations

from pathlib import Path

from .acquisition import load_bytes, load_path
from .config import display_path
from .analysis import (
    BehaviorBaseline,
    StyleBaseline,
    ThreadIndex,
    analyse_attachments,
    analyse_sender,
    analyse_text,
    analyse_urls,
    get_nlp_status,
)
from .forensics import (
    AuditLog,
    EvidenceGraph,
    IOCStore,
    LocalThreatIntelProvider,
    ThreatIntelProvider,
    build_case_timeline,
    build_message_timeline,
    correlation_indicators,
    extract_iocs,
    intel_indicators,
    map_indicators,
)
from .models import Assessment, EmailArtifact, Indicator
from .validation import AnomalyModel, fuse


class BECPipeline:
    """Runs the detector over a corpus of acquired messages."""

    def __init__(
        self,
        examiner: str | None = None,
        case_id: str = "CASE-000",
        audit_path: str | Path | None = None,
        intel: ThreatIntelProvider | None = None,
        ioc_store: IOCStore | None = None,
        correlate: bool = True,
    ) -> None:
        self.examiner = examiner
        self.case_id = case_id

        self.baseline = BehaviorBaseline()
        self.threads = ThreadIndex()
        self.style = StyleBaseline()
        self.anomaly = AnomalyModel()

        self.audit = AuditLog(audit_path, actor=examiner or "system")
        self.intel = intel if intel is not None else LocalThreatIntelProvider()
        self.correlate = correlate
        self.ioc_store = ioc_store if ioc_store is not None else (IOCStore() if correlate else None)

        self._fitted = False
        self.correlation_matches: list[dict] = []

        self.audit.record(
            "case_opened",
            f"case={case_id}; intel={self.intel.name}; correlation={'on' if correlate else 'off'}",
        )

    # -- Stage 1 -------------------------------------------------------------

    def acquire(self, path: str | Path) -> list[EmailArtifact]:
        """Load evidence from a file, directory or mbox archive."""
        self.skipped: list[tuple[str, str]] = []
        emails = load_path(path, examiner=self.examiner, errors=self.skipped)
        for source, reason in self.skipped:
            self.audit.record("evidence_skipped", f"source={source}; reason={reason}")
        for email in emails:
            self.audit.record(
                "evidence_acquired",
                f"sha256={email.custody.sha256}; source={email.custody.source_path}",
                evidence_id=email.evidence_id,
            )
        return emails

    def acquire_bytes(self, raw: bytes, label: str) -> EmailArtifact:
        """Acquire a single in-memory message (used by the web upload route)."""
        email = load_bytes(raw, label, examiner=self.examiner)
        self.audit.record(
            "evidence_acquired",
            f"sha256={email.custody.sha256}; source={label}",
            evidence_id=email.evidence_id,
        )
        return email

    # -- Baseline ------------------------------------------------------------

    def fit(self, emails: list[EmailArtifact]) -> None:
        """Observe the corpus so deviation becomes measurable."""
        self.baseline.observe_all(emails)
        self.threads.observe_all(emails)
        self.style.observe_all(emails)
        self.anomaly.fit(emails)
        self._fitted = True
        self.audit.record("baseline_established", f"messages_observed={len(emails)}")

    # -- Stages 2 and 3 ------------------------------------------------------

    def assess(self, email: EmailArtifact) -> Assessment:
        """Analyse and validate a single message against the current baseline."""
        indicators: list[Indicator] = []
        notes: list[str] = []

        # Core detection (unchanged from the working milestone).
        indicators.extend(analyse_sender(email))
        indicators.extend(analyse_text(email))
        indicators.extend(self.baseline.analyse(email))
        indicators.extend(self.anomaly.analyse(email))

        # Extended forensic analysis.
        indicators.extend(self.threads.analyse(email))
        indicators.extend(analyse_urls(email))
        indicators.extend(analyse_attachments(email))

        style_indicators, style_notes = self.style.analyse(email)
        indicators.extend(style_indicators)
        notes.extend(style_notes)

        # IOC extraction, local intelligence and local cross-case correlation.
        iocs = extract_iocs(email)

        try:
            matches = self.intel.lookup(iocs)
            indicators.extend(intel_indicators(matches))
        except Exception as exc:
            notes.append(f"Threat intelligence lookup unavailable: {type(exc).__name__}.")
        notes.append(self.intel.status())

        if self.ioc_store is not None:
            try:
                found = self.ioc_store.lookup(iocs, self.case_id)
                if found:
                    self.correlation_matches.extend(found)
                    indicators.extend(correlation_indicators(found))
            except Exception as exc:
                notes.append(f"Cross-case correlation unavailable: {type(exc).__name__}.")
        else:
            notes.append("Cross-case correlation disabled for this run.")

        assessment = fuse(email, indicators)
        assessment.iocs = iocs
        assessment.notes = notes
        assessment.mitre = map_indicators(assessment.indicators)
        assessment.timeline = build_message_timeline(assessment)

        self.audit.record(
            "message_assessed",
            f"score={assessment.score}; band={assessment.band.value}; "
            f"indicators={len(assessment.indicators)}",
            evidence_id=email.evidence_id,
        )
        return assessment

    def run(self, path: str | Path) -> list[Assessment]:
        """Acquire a corpus, baseline it, then assess every message."""
        emails = self.acquire(path)
        if not emails:
            return []
        self.fit(emails)
        assessments = [self.assess(email) for email in emails]
        self._finalise(assessments)
        return assessments

    def run_single(self, raw: bytes, label: str) -> Assessment:
        """Assess one uploaded message with no corpus context.

        Behavioural, thread and stylometric indicators are necessarily weaker
        here - there is no history to deviate from - so only the sender,
        content, URL and attachment stages carry real weight.
        """
        email = self.acquire_bytes(raw, label)
        self.baseline.observe(email)
        self.threads.observe(email)
        self.style.observe(email)
        assessment = self.assess(email)
        self._finalise([assessment])
        return assessment

    # -- Case finalisation ---------------------------------------------------

    # Only these bands contribute indicators of COMPROMISE to the store.
    IOC_RECORDING_BANDS = frozenset({"LIKELY_BEC", "CONFIRMED_BEC"})

    def _finalise(self, assessments: list[Assessment]) -> None:
        """Record this case's IOCs so future cases can correlate against them.

        Only messages assessed LIKELY_BEC or CONFIRMED_BEC contribute. Recording
        every message made legitimate correspondents' domains into "indicators
        of compromise", so that each later benign message from a regular partner
        was scored for "IOC reuse".
        """
        if self.ioc_store is None:
            return
        try:
            recorded = [a for a in assessments if a.band.value in self.IOC_RECORDING_BANDS]
            for assessment in recorded:
                self.ioc_store.record(assessment.iocs, self.case_id)
            self.ioc_store.save()
            self.audit.record(
                "iocs_recorded",
                f"case={self.case_id}; from {len(recorded)} of {len(assessments)} "
                f"message(s) assessed LIKELY_BEC or above; store={display_path(self.ioc_store.path)}",
            )
        except Exception as exc:
            self.audit.record("ioc_store_error", f"{type(exc).__name__}: {exc}")

    def case_timeline(self, assessments: list[Assessment]):
        return build_case_timeline(assessments)

    def evidence_graph(self, assessments: list[Assessment]) -> EvidenceGraph:
        """Provenance-carrying entity graph for this case.

        Cross-case links are added only for IOC reuse the local correlation
        store actually reported during this run.
        """
        graph = EvidenceGraph()
        graph.add_all(assessments, self.case_id)
        if self.correlation_matches:
            graph.add_cross_case_links(self.correlation_matches, self.case_id)
        return graph

    def integrity(self) -> dict:
        """Verify the audit chain for this run."""
        return self.audit.verify()

    # -- Diagnostics ---------------------------------------------------------

    @staticmethod
    def nlp_status() -> dict[str, bool]:
        """Which NLP backends loaded - recorded in the report footer."""
        return get_nlp_status()
