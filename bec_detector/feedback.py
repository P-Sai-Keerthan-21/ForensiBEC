"""Investigator feedback: human determinations recorded against a case.

The system produces risk assessments; investigators make determinations. This
module records the latter, alongside - never in place of - the former.

Each record captures
    case and evidence (ID and SHA-256), examiner, UTC timestamp,
    the SYSTEM assessment at the moment of review (score, band, and the scoring
    configuration fingerprint, so a later rule change cannot blur what the
    system actually said), and the INVESTIGATOR assessment with notes.

Integrity
    Records are appended to a hash-chained log (the same construction as the
    audit trail) and mirrored as an entry in the case audit log. They are never
    edited: a correction is a new record, and the latest record per evidence
    item is the current determination.

No automatic retraining
    Nothing in this application trains on feedback. `export_training_candidates`
    produces a controlled dataset for a FUTURE, deliberate retraining step, with
    poisoning-resistance rules applied (see docs/feedback.md):
      * only cases whose evidence and audit chain verify intact;
      * "needs review" is never exported as a label;
      * evidence on which examiners disagree is withheld, not resolved;
      * every label is bound to the evidence SHA-256 it was given against.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .forensics import AuditLog

ASSESSMENTS = {
    "confirmed_suspicious": "Confirmed suspicious",
    "confirmed_benign": "Confirmed benign",
    "needs_review": "Needs review",
}
FLAGGED_BANDS = {"LIKELY_BEC", "CONFIRMED_BEC"}
MAX_NOTES = 2000


class FeedbackError(ValueError):
    """Invalid feedback. Message is safe to show a user."""


@dataclass
class FeedbackRecord:
    case_id: str
    evidence_id: str
    evidence_sha256: str
    examiner: str
    timestamp_utc: str
    system_score: float
    system_band: str
    system_config_sha256: str
    assessment: str
    assessment_label: str
    notes: str
    agreement: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def agreement_of(system_band: str, assessment: str) -> str:
    """Derived comparison between system output and human determination."""
    flagged = system_band in FLAGGED_BANDS
    if assessment == "needs_review":
        return "undetermined"
    if assessment == "confirmed_suspicious":
        return "agrees" if flagged else "system false negative"
    return "system false positive" if flagged else "agrees"


class FeedbackStore:
    """Hash-chained, append-only feedback for one case."""

    def __init__(self, case_store, case_id: str) -> None:
        self.cases = case_store
        self.case_id = case_id
        self.path = case_store._dir(case_id) / "feedback.jsonl"

    def _log(self) -> AuditLog:
        return AuditLog(self.path, actor="feedback")

    def record(self, evidence_id: str, assessment: str, examiner: str,
               notes: str = "") -> FeedbackRecord:
        assessment = (assessment or "").strip().lower()
        if assessment not in ASSESSMENTS:
            raise FeedbackError(f"Assessment must be one of: {', '.join(ASSESSMENTS)}.")
        examiner = (examiner or "").strip()
        if not examiner:
            raise FeedbackError("Examiner is required for an investigator assessment.")
        if len(notes or "") > MAX_NOTES:
            raise FeedbackError(f"Notes are limited to {MAX_NOTES} characters.")

        case = self.cases.load(self.case_id)
        register = {e.evidence_id: e for e in case.evidence}
        if evidence_id not in register:
            raise FeedbackError(f"Evidence {evidence_id} is not part of case {self.case_id}.")

        analysis = self.cases.load_analysis(self.case_id)
        if not analysis:
            raise FeedbackError("The case must be analysed before it can be assessed.")
        system = next((a for a in analysis["assessments"] if a["evidence_id"] == evidence_id), None)
        if system is None:
            raise FeedbackError(f"Evidence {evidence_id} has no system assessment yet.")

        record = FeedbackRecord(
            case_id=self.case_id,
            evidence_id=evidence_id,
            evidence_sha256=register[evidence_id].sha256,
            examiner=examiner[:120],
            timestamp_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            system_score=system["risk_score"],
            system_band=system["risk_band"],
            system_config_sha256=(analysis.get("reproducibility") or {})
                                 .get("configuration", {}).get("sha256", ""),
            assessment=assessment,
            assessment_label=ASSESSMENTS[assessment],
            notes=(notes or "").strip(),
            agreement=agreement_of(system["risk_band"], assessment),
        )
        entry = self._log().record("investigator_assessment",
                                   json.dumps(record.to_dict(), sort_keys=True),
                                   evidence_id=evidence_id, actor=record.examiner)
        AuditLog(self.cases.audit_path(self.case_id)).record(
            "investigator_assessment",
            f"{record.assessment_label} ({record.agreement}); feedback entry "
            f"{entry.sequence} hash {entry.entry_hash[:16]}",
            evidence_id=evidence_id, actor=record.examiner)
        return record

    def history(self) -> list[FeedbackRecord]:
        """Every record, oldest first."""
        out = []
        for entry in self._log().entries:
            try:
                out.append(FeedbackRecord(**json.loads(entry.detail)))
            except (TypeError, ValueError):
                continue
        return out

    def current(self) -> dict[str, FeedbackRecord]:
        """Latest determination per evidence item."""
        latest: dict[str, FeedbackRecord] = {}
        for record in self.history():
            latest[record.evidence_id] = record
        return latest

    def verify(self) -> dict[str, Any]:
        return self._log().verify()


def export_training_candidates(case_store, case_ids: list[str] | None = None) -> dict[str, Any]:
    """Controlled dataset for a future, deliberate retraining step.

    Nothing in the application consumes this. It exists so that retraining,
    if ever done, starts from labels that passed explicit safeguards.
    """
    rows: list[dict[str, Any]] = []
    withheld: list[dict[str, str]] = []
    cases = case_ids or [c.case_id for c in case_store.list()]

    for case_id in cases:
        integrity = case_store.verify(case_id)
        store = FeedbackStore(case_store, case_id)
        feedback_chain = store.verify()
        if not (integrity["intact"] and feedback_chain["valid"]):
            withheld.append({"case_id": case_id, "reason": "integrity verification failed"})
            continue

        by_evidence: dict[str, set[str]] = {}
        for record in store.history():
            if record.assessment != "needs_review":
                by_evidence.setdefault(record.evidence_id, set()).add(record.assessment)

        for evidence_id, record in store.current().items():
            if record.assessment == "needs_review":
                withheld.append({"case_id": case_id, "evidence_id": evidence_id,
                                 "reason": "needs review - not a label"})
                continue
            if len(by_evidence.get(evidence_id, set())) > 1:
                withheld.append({"case_id": case_id, "evidence_id": evidence_id,
                                 "reason": "examiners disagree - withheld, not resolved"})
                continue
            rows.append({
                "evidence_sha256": record.evidence_sha256,
                "label": "MALICIOUS" if record.assessment == "confirmed_suspicious" else "BENIGN",
                "case_id": case_id, "evidence_id": evidence_id,
                "examiner": record.examiner, "timestamp_utc": record.timestamp_utc,
                "system_band_at_review": record.system_band,
                "system_config_sha256": record.system_config_sha256,
            })

    return {
        "purpose": "Candidate labels for a FUTURE, deliberate retraining step. "
                   "Not consumed by this application.",
        "safeguards": [
            "only cases whose evidence and audit chains verify intact",
            "needs-review determinations are never exported as labels",
            "evidence on which examiners disagree is withheld",
            "each label is bound to the SHA-256 of the evidence it was given against",
        ],
        "rows": rows,
        "withheld": withheld,
    }
