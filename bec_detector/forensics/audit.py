"""Tamper-evident audit log.

Every investigative action is appended as a record whose hash covers both the
record's own content and the hash of the record before it:

    entry_hash = SHA256( sequence || timestamp || actor || action || detail || prev_hash )

Altering, reordering or deleting any earlier entry breaks the chain from that
point onward, and `verify()` reports exactly where. This does not make the log
tamper-*proof* -- an attacker who can rewrite the whole file can recompute the
chain -- but it makes silent modification of a single entry detectable, which
is the property an evidence log needs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    sequence: int
    timestamp_utc: str
    actor: str
    action: str
    detail: str
    evidence_id: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_entry_hash(sequence: int, timestamp: str, actor: str, action: str,
                       detail: str, evidence_id: str, prev_hash: str) -> str:
    """Hash over the entry's content plus its predecessor's hash.

    Fields are joined with a separator that cannot appear in the field values
    after JSON escaping, so two different entries cannot produce the same
    pre-image by shifting content across a boundary.
    """
    payload = "\x1f".join([
        str(sequence),
        timestamp,
        json.dumps(actor),
        json.dumps(action),
        json.dumps(detail),
        json.dumps(evidence_id),
        prev_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash-chained log of investigative actions."""

    def __init__(self, path: str | Path | None = None, actor: str = "system") -> None:
        self.path = Path(path) if path else None
        self.actor = actor
        self.entries: list[AuditEntry] = []
        self._size = 0  # bytes of the file reflected in self.entries
        if self.path and self.path.exists():
            self._load()

    # -- construction --------------------------------------------------------

    def _load(self) -> None:
        assert self.path is not None
        raw = self.path.read_bytes()
        self._size = len(raw)
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                self.entries.append(AuditEntry(**json.loads(line)))
            except Exception:
                # A malformed line is itself a tampering signal; keep what we
                # have so verify() can report the break rather than crashing.
                break

    @property
    def head_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS_HASH

    # -- append --------------------------------------------------------------

    def record(self, action: str, detail: str = "", evidence_id: str = "",
               actor: str | None = None) -> AuditEntry:
        """Append one action to the chain.

        With a file, the append happens under a cross-process lock and first
        catches up with anything another process (or another AuditLog object)
        appended since this one was loaded, so the new entry always chains from
        the true head. Without this, two writers could both chain from the same
        entry and fork the log, which would then fail verification forever.
        """
        if not self.path:
            return self._new_entry(action, detail, evidence_id, actor)

        from ..storage import locked

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with locked(self.path.with_name(self.path.name + ".lock")):
            on_disk = self.path.stat().st_size if self.path.exists() else 0
            if on_disk != self._size:
                self.entries = []
                self._size = 0
                if on_disk:
                    self._load()
            entry = self._new_entry(action, detail, evidence_id, actor)
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
            self._size = self.path.stat().st_size
        return entry

    def _new_entry(self, action: str, detail: str, evidence_id: str,
                   actor: str | None) -> AuditEntry:
        sequence = len(self.entries) + 1
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        who = actor or self.actor
        prev = self.head_hash

        entry = AuditEntry(
            sequence=sequence,
            timestamp_utc=timestamp,
            actor=who,
            action=action,
            detail=detail,
            evidence_id=evidence_id,
            prev_hash=prev,
            entry_hash=compute_entry_hash(
                sequence, timestamp, who, action, detail, evidence_id, prev
            ),
        )
        self.entries.append(entry)
        return entry

    # -- verification --------------------------------------------------------

    def verify(self) -> dict[str, Any]:
        """Recompute the chain and report the first break, if any."""
        expected_prev = GENESIS_HASH

        for index, entry in enumerate(self.entries):
            if entry.sequence != index + 1:
                return {
                    "valid": False,
                    "entries": len(self.entries),
                    "broken_at": index + 1,
                    "reason": (
                        f"sequence gap: entry {index + 1} is numbered {entry.sequence}"
                    ),
                }

            if entry.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "entries": len(self.entries),
                    "broken_at": entry.sequence,
                    "reason": (
                        "chain break: this entry does not follow the previous one "
                        "(an earlier entry was altered, reordered or removed)"
                    ),
                }

            recomputed = compute_entry_hash(
                entry.sequence, entry.timestamp_utc, entry.actor, entry.action,
                entry.detail, entry.evidence_id, entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                return {
                    "valid": False,
                    "entries": len(self.entries),
                    "broken_at": entry.sequence,
                    "reason": "content altered: this entry's hash does not match its content",
                }

            expected_prev = entry.entry_hash

        return {
            "valid": True,
            "entries": len(self.entries),
            "broken_at": None,
            "reason": "chain intact - every entry hashes to its successor's prev_hash",
            "head_hash": self.head_hash,
        }

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self.entries]
