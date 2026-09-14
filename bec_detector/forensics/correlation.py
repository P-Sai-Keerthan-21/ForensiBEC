"""Local cross-case IOC correlation.

A small JSON-backed store recording which IOCs were seen in which case. When a
new case contains an indicator already recorded against a different case, that
reuse is reported.

Scope and honesty
-----------------
This correlates ONLY what this application has previously stored locally. It is
not threat intelligence, it makes no claim about the wider world, and an IOC
absent from the store means only "not seen by this installation before".

The store is a foundation for future cyber-crime case linkage, deliberately
kept to a simple, inspectable file format.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import FREEMAIL_DOMAINS, TRUSTED_DOMAINS, TRUSTED_RELAY_IPS, WEIGHTS
from ..models import Category, Confidence, Indicator, Severity

DEFAULT_STORE = Path("output") / "ioc_store.json"

# Indicator kinds too common to be interesting on their own. Correlating on an
# internal recipient address would link every case to every other case.
LOW_VALUE_KINDS = {"email_addresses"}


def _is_linkable(kind: str, value: str) -> bool:
    """Whether an indicator is specific enough to link two cases.

    The organisation's own domains appear in every case by definition, and
    consumer mail providers are shared by millions of unrelated senders.
    Correlating on either would manufacture links between cases that have
    nothing to do with each other.
    """
    if kind == "ipv4" and value in TRUSTED_RELAY_IPS:
        return False
    if kind == "domains":
        if value in TRUSTED_DOMAINS or value in FREEMAIL_DOMAINS:
            return False
        # A subdomain of our own estate is equally uninformative.
        if any(value.endswith("." + trusted) for trusted in TRUSTED_DOMAINS):
            return False
    return True


class IOCStore:
    """JSON-backed record of IOC -> cases seen in."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_STORE
        # {kind: {value: {"cases": [...], "first_seen": ..., "last_seen": ...}}}
        self.data: dict[str, dict[str, dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data = loaded
        except Exception:
            # A corrupt store must not abort an investigation; start clean and
            # let the caller see an empty correlation result.
            self.data = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # -- query ---------------------------------------------------------------

    def cases_for(self, kind: str, value: str) -> list[str]:
        return list(self.data.get(kind, {}).get(value, {}).get("cases", []))

    def lookup(self, iocs: dict[str, list[str]], current_case: str) -> list[dict[str, Any]]:
        """Return IOCs from this case previously seen in a *different* case."""
        matches: list[dict[str, Any]] = []
        for kind, values in iocs.items():
            if kind in LOW_VALUE_KINDS:
                continue
            for value in values:
                if not _is_linkable(kind, value):
                    continue
                others = [c for c in self.cases_for(kind, value) if c != current_case]
                if others:
                    matches.append({
                        "kind": kind,
                        "value": value,
                        "seen_in_cases": sorted(others),
                        "first_seen": self.data[kind][value].get("first_seen", ""),
                    })
        return matches

    # -- update --------------------------------------------------------------

    def record(self, iocs: dict[str, list[str]], case_id: str) -> int:
        """Store this case's IOCs. Returns how many values were recorded."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        count = 0
        for kind, values in iocs.items():
            bucket = self.data.setdefault(kind, {})
            for value in values:
                record = bucket.setdefault(value, {"cases": [], "first_seen": now})
                if case_id not in record["cases"]:
                    record["cases"].append(case_id)
                record["last_seen"] = now
                count += 1
        return count

    def stats(self) -> dict[str, int]:
        return {kind: len(values) for kind, values in self.data.items()}


def correlation_indicators(matches: list[dict[str, Any]]) -> list[Indicator]:
    """Turn cross-case matches into indicators."""
    if not matches:
        return []

    # One indicator summarising the reuse, rather than one per value, so a
    # noisy case cannot inflate its own score through correlation alone.
    shown = matches[:5]
    detail = "; ".join(
        f"{m['kind']}={m['value']} (also in {', '.join(m['seen_in_cases'])})"
        for m in shown
    )
    return [Indicator(
        code="INTEL_IOC_REUSE",
        title="Indicator reuse across previously analysed cases",
        category=Category.INTELLIGENCE,
        severity=Severity.HIGH if len(matches) > 2 else Severity.MEDIUM,
        weight=WEIGHTS.get("INTEL_IOC_REUSE", 16.0),
        confidence=0.8,
        evidence=f"{len(matches)} indicator(s) previously recorded locally: {detail}",
        explanation=(
            "One or more indicators in this message were recorded by this "
            "installation in an earlier case. Reuse of infrastructure across "
            "cases suggests a common actor or campaign. This reflects only "
            "local history, not external threat intelligence."
        ),
        basis=Confidence.OBSERVED,
        recommendation=(
            "Review the linked cases together and consider a combined report. "
            "Block the shared indicators at the gateway."
        ),
        mitre=["T1583"],
    )]
