"""Case-level investigation management.

A case groups the evidence items of one investigation and retains everything
the analysis produced, so that findings can be reopened, re-verified and
reported on later rather than existing only for the lifetime of one request.

    <data dir>/cases/<CASE-ID>/
        case.json            metadata, evidence register, latest summary
        evidence/<sha256>.eml ORIGINAL bytes, write-once, named by hash
        audit.jsonl          hash-chained audit trail for this case
        analysis.json        full structured result of the latest analysis
        report.html          rendered forensic report of the latest analysis

Evidence handling
-----------------
Preserving original evidence is a forensic requirement, so a case store writes
uploaded messages to disk. It does so under these rules:

  * The stored file is named ONLY by its SHA-256. The submitter's filename is
    recorded as metadata and never used to build a path.
  * Evidence files are write-once. Re-adding identical bytes is a no-op;
    nothing is ever overwritten.
  * Every read re-hashes the file and refuses to use it if the hash no longer
    matches the register (see `verify`).
  * Stored evidence is never executed, opened by a handler, or served back
    raw by the web interface.

Case identifiers are validated against a strict pattern before they are used
as a directory name, which rules out path traversal through the case ID.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .acquisition import EvidenceParseError
from .forensics import AuditLog

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

BAND_RANK = {"BENIGN": 0, "SUSPICIOUS": 1, "LIKELY_BEC": 2, "CONFIRMED_BEC": 3}


class CaseError(ValueError):
    """Raised for invalid case operations. Message is safe to show a user."""


def data_dir() -> Path:
    """Root for all persisted state. Overridable so tests never touch output/."""
    return Path(os.environ.get("FORENSIBEC_DATA_DIR", "output"))


def validate_case_id(case_id: str) -> str:
    case_id = (case_id or "").strip()
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise CaseError(
            "Case reference must be 1-64 characters: letters, digits, '-' or '_', "
            "starting with a letter or digit."
        )
    return case_id


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EvidenceRecord:
    evidence_id: str
    sha256: str
    original_filename: str
    size_bytes: int
    added_utc: str
    added_by: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    case_id: str
    title: str
    examiner: str
    created_utc: str
    updated_utc: str
    status: str = "open"
    evidence: list[EvidenceRecord] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Case":
        evidence = [EvidenceRecord(**e) for e in data.get("evidence", [])]
        return cls(
            case_id=data["case_id"], title=data.get("title", ""),
            examiner=data.get("examiner", ""), created_utc=data["created_utc"],
            updated_utc=data.get("updated_utc", data["created_utc"]),
            status=data.get("status", "open"), evidence=evidence,
            summary=data.get("summary", {}),
        )


class CaseStore:
    """Filesystem-backed case repository."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root is not None else data_dir() / "cases"

    # -- paths ---------------------------------------------------------------

    def _dir(self, case_id: str) -> Path:
        path = (self.root / validate_case_id(case_id)).resolve()
        # Defence in depth: even a valid-looking ID must resolve inside root.
        if self.root.resolve() not in path.parents:
            raise CaseError("Case path escapes the case store.")
        return path

    def audit_path(self, case_id: str) -> Path:
        return self._dir(case_id) / "audit.jsonl"

    def evidence_path(self, case_id: str, sha256: str) -> Path:
        if not SHA256_PATTERN.fullmatch(sha256):
            raise CaseError("Invalid evidence hash.")
        return self._dir(case_id) / "evidence" / f"{sha256}.eml"

    def report_path(self, case_id: str) -> Path:
        return self._dir(case_id) / "report.html"

    def analysis_path(self, case_id: str) -> Path:
        return self._dir(case_id) / "analysis.json"

    # -- lifecycle -----------------------------------------------------------

    def exists(self, case_id: str) -> bool:
        try:
            return (self._dir(case_id) / "case.json").exists()
        except CaseError:
            return False

    def create(self, case_id: str, examiner: str = "", title: str = "") -> Case:
        case_id = validate_case_id(case_id)
        if self.exists(case_id):
            raise CaseError(f"Case {case_id} already exists.")
        directory = self._dir(case_id)
        (directory / "evidence").mkdir(parents=True, exist_ok=True)
        now = _now()
        case = Case(case_id=case_id, title=title or case_id,
                    examiner=examiner or "unspecified-examiner",
                    created_utc=now, updated_utc=now)
        self._save(case)
        AuditLog(self.audit_path(case_id), actor=case.examiner).record(
            "case_created", f"title={case.title!r}")
        return case

    def open_or_create(self, case_id: str, examiner: str = "", title: str = "") -> Case:
        if self.exists(case_id):
            return self.load(case_id)
        return self.create(case_id, examiner, title)

    def load(self, case_id: str) -> Case:
        path = self._dir(case_id) / "case.json"
        if not path.exists():
            raise CaseError(f"Case {case_id} does not exist.")
        return Case.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def _save(self, case: Case) -> None:
        case.updated_utc = _now()
        path = self._dir(case.case_id) / "case.json"
        path.write_text(json.dumps(case.to_dict(), indent=2, ensure_ascii=False),
                        encoding="utf-8")

    def list(self) -> list[Case]:
        if not self.root.exists():
            return []
        cases = []
        for entry in sorted(self.root.iterdir()):
            if entry.is_dir() and (entry / "case.json").exists():
                try:
                    cases.append(self.load(entry.name))
                except (CaseError, ValueError, KeyError):
                    continue
        return cases

    # -- evidence ------------------------------------------------------------

    def add_evidence(self, case_id: str, raw: bytes, original_filename: str,
                     examiner: str = "") -> EvidenceRecord:
        """Preserve one evidence item. Write-once; identical bytes are a no-op."""
        if not raw:
            raise CaseError("Evidence is empty.")
        case = self.load(case_id)
        sha256 = hashlib.sha256(raw).hexdigest()

        for existing in case.evidence:
            if existing.sha256 == sha256:
                return existing

        target = self.evidence_path(case_id, sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != sha256:
                raise CaseError("Stored evidence does not match its hash; refusing to overwrite.")
        else:
            # "xb": exclusive create in binary mode - never overwrites.
            with open(target, "xb") as fh:
                fh.write(raw)
            try:
                os.chmod(target, 0o444)
            except OSError:
                pass

        record = EvidenceRecord(
            evidence_id=f"EV-{sha256[:12].upper()}", sha256=sha256,
            original_filename=original_filename[:200], size_bytes=len(raw),
            added_utc=_now(), added_by=examiner or case.examiner,
        )
        case.evidence.append(record)
        self._save(case)
        AuditLog(self.audit_path(case_id), actor=record.added_by).record(
            "evidence_added",
            f"sha256={sha256}; size={len(raw)}; original_filename={record.original_filename!r}",
            evidence_id=record.evidence_id,
        )
        return record

    def read_evidence(self, case_id: str, record: EvidenceRecord) -> bytes:
        """Return stored bytes only if they still match the registered hash."""
        raw = self.evidence_path(case_id, record.sha256).read_bytes()
        if hashlib.sha256(raw).hexdigest() != record.sha256:
            raise CaseError(f"Evidence {record.evidence_id} fails integrity verification.")
        return raw

    # -- integrity -----------------------------------------------------------

    def verify(self, case_id: str) -> dict[str, Any]:
        """Re-hash every evidence item and verify the case audit chain."""
        case = self.load(case_id)
        items = []
        for record in case.evidence:
            path = self.evidence_path(case_id, record.sha256)
            if not path.exists():
                items.append({"evidence_id": record.evidence_id, "status": "MISSING"})
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            items.append({
                "evidence_id": record.evidence_id,
                "status": "VERIFIED" if actual == record.sha256 else "HASH MISMATCH",
                "expected_sha256": record.sha256,
                "actual_sha256": actual,
            })
        audit = AuditLog(self.audit_path(case_id)).verify()
        return {
            "case_id": case_id,
            "evidence": items,
            "evidence_intact": all(i["status"] == "VERIFIED" for i in items),
            "audit": audit,
            "intact": audit["valid"] and all(i["status"] == "VERIFIED" for i in items),
        }

    # -- analysis ------------------------------------------------------------

    def analyse(self, case_id: str, examiner: str = "",
                ioc_store=None, intel=None) -> dict[str, Any]:
        """Analyse every evidence item in the case and retain the results."""
        from .pipeline import BECPipeline
        from .report import render_html
        from .report.assemble import assemble_report

        case = self.load(case_id)
        if not case.evidence:
            raise CaseError(f"Case {case_id} has no evidence to analyse.")

        pipeline = BECPipeline(
            examiner=examiner or case.examiner, case_id=case_id,
            audit_path=self.audit_path(case_id), ioc_store=ioc_store, intel=intel,
        )
        emails = []
        for record in case.evidence:
            raw = self.read_evidence(case_id, record)  # integrity checked here
            # Slash-free by design: the custody source names the stored item
            # (case + hash) without ever looking like a filesystem path.
            label = f"{case_id}:evidence:{record.sha256}.eml [{record.original_filename}]"
            try:
                emails.append(pipeline.acquire_bytes(raw, label))
            except EvidenceParseError as exc:
                raise CaseError(f"Evidence {record.evidence_id} cannot be parsed safely: {exc}") from exc

        pipeline.fit(emails)
        assessments = [pipeline.assess(email) for email in emails]
        pipeline._finalise(assessments)

        report = assemble_report(pipeline, assessments, case_name=case.title,
                                 examiner=examiner or case.examiner)
        report["case"]["evidence_register"] = [e.to_dict() for e in case.evidence]
        report["case"]["related_cases"] = self.related_cases(case_id, report)

        self.analysis_path(case_id).write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        render_html(report, self.report_path(case_id))

        worst = max(assessments, key=lambda a: (BAND_RANK[a.band.value], a.score))
        case.summary = {
            "analysed_utc": _now(),
            "messages": len(assessments),
            "highest_risk_score": worst.score,
            "highest_risk_band": worst.band.value,
            "highest_risk_evidence": worst.artifact.evidence_id,
            "band_counts": report["summary"]["band_counts"],
            "indicator_total": sum(len(a.indicators) for a in assessments),
            "ioc_counts": {
                kind: len({v for a in assessments for v in a.iocs.get(kind, [])})
                for kind in ("email_addresses", "domains", "urls", "ipv4", "attachment_sha256")
            },
        }
        self._save(case)
        pipeline.audit.record("case_report_generated",
                              f"messages={len(assessments)}; highest={worst.band.value}")
        report["audit"]["integrity"] = pipeline.integrity()
        return report

    def load_analysis(self, case_id: str) -> dict[str, Any] | None:
        path = self.analysis_path(case_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    # -- search and linkage --------------------------------------------------

    def search(self, query: str) -> list[dict[str, Any]]:
        """Find cases by ID, title, examiner, evidence ID/hash, or any IOC,
        sender or subject recorded in the latest analysis."""
        needle = (query or "").strip().lower()
        if not needle:
            return []
        hits = []
        for case in self.list():
            reasons = []
            if needle in case.case_id.lower() or needle in case.title.lower():
                reasons.append("case reference/title")
            if needle in case.examiner.lower():
                reasons.append("examiner")
            for e in case.evidence:
                if needle in e.evidence_id.lower() or needle in e.sha256 \
                        or needle in e.original_filename.lower():
                    reasons.append(f"evidence {e.evidence_id}")
            analysis = self.load_analysis(case.case_id) or {}
            for item in analysis.get("assessments", []):
                email = item.get("email", {})
                if needle in (email.get("subject") or "").lower():
                    reasons.append(f"subject in {item.get('evidence_id')}")
                if needle in (email.get("from_address") or "").lower():
                    reasons.append(f"sender in {item.get('evidence_id')}")
                for kind, values in (item.get("iocs") or {}).items():
                    if any(needle in v.lower() for v in values):
                        reasons.append(f"IOC ({kind}) in {item.get('evidence_id')}")
            if reasons:
                hits.append({"case_id": case.case_id, "title": case.title,
                             "matched_on": sorted(set(reasons))})
        return hits

    def related_cases(self, case_id: str, report: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Cases sharing an indicator with this one, per the correlation results."""
        report = report or self.load_analysis(case_id) or {}
        related: dict[str, list[str]] = {}
        for match in (report.get("correlation") or {}).get("matches", []):
            for other in match.get("seen_in_cases", []):
                if other != case_id:
                    related.setdefault(other, []).append(f"{match['kind']}={match['value']}")
        return [{"case_id": k, "shared_indicators": sorted(set(v))}
                for k, v in sorted(related.items())]

    def audit_entries(self, case_id: str) -> list[dict[str, Any]]:
        return AuditLog(self.audit_path(case_id)).to_list()
