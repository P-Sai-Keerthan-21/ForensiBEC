"""Threat-intelligence adapter interface.

No external intelligence service is contacted. `LocalThreatIntelProvider` reads
a local, operator-maintained indicator list and every result it returns is
labelled as local.

The abstract `ThreatIntelProvider` exists so a real provider can be added later
without touching the analysis code. Until one is configured, the report states
"External intelligence not configured" rather than implying a lookup occurred.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import LOCAL_INTEL_FILE, WEIGHTS, display_path
from ..models import Category, Confidence, Indicator, Severity

DEFAULT_INTEL_FILE = LOCAL_INTEL_FILE


@dataclass
class IntelMatch:
    """One indicator matched against an intelligence source."""

    kind: str
    value: str
    verdict: str
    note: str
    source: str
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "value": self.value, "verdict": self.verdict,
            "note": self.note, "source": self.source, "confidence": self.confidence,
        }


class ThreatIntelProvider(ABC):
    """Interface every intelligence source must implement."""

    #: Shown verbatim in the report so the reader knows what was consulted.
    name: str = "unnamed"
    is_external: bool = False

    @abstractmethod
    def lookup(self, iocs: dict[str, list[str]]) -> list[IntelMatch]:
        """Return matches for the supplied indicators."""

    @abstractmethod
    def status(self) -> str:
        """Human-readable availability statement for the report."""


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Matches indicators against a local operator-maintained list.

    The file format is deliberately simple:

        {
          "domains":  {"bad.example":  "known BEC infrastructure"},
          "email_addresses": {"x@y.example": "reported in prior fraud"},
          "urls":     {},
          "ipv4":     {},
          "attachment_sha256": {}
        }
    """

    name = "Local intelligence"
    is_external = False

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_INTEL_FILE
        self.indicators: dict[str, dict[str, str]] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.indicators = {
                    k: v for k, v in loaded.items() if isinstance(v, dict)
                }
                self._loaded = True
        except Exception:
            self.indicators = {}

    def lookup(self, iocs: dict[str, list[str]]) -> list[IntelMatch]:
        matches: list[IntelMatch] = []
        for kind, values in iocs.items():
            known = self.indicators.get(kind, {})
            if not known:
                continue
            for value in values:
                note = known.get(value)
                if note:
                    matches.append(IntelMatch(
                        kind=kind, value=value, verdict="known-bad",
                        note=note, source=self.name,
                    ))
        return matches

    def status(self) -> str:
        if not self.path.exists():
            return (
                f"Local intelligence: no indicator file at {display_path(self.path)} "
                "- no local intelligence applied. External intelligence not configured."
            )
        if not self._loaded:
            return (
                f"Local intelligence: {display_path(self.path)} could not be parsed "
                "- no local intelligence applied. External intelligence not configured."
            )
        total = sum(len(v) for v in self.indicators.values())
        return (
            f"Local intelligence: {total} indicator(s) loaded from {display_path(self.path)}. "
            "External intelligence not configured - no external service was contacted."
        )


@dataclass
class NullThreatIntelProvider(ThreatIntelProvider):
    """Used when intelligence is disabled entirely."""

    name: str = "None"
    is_external: bool = False
    _unused: list[str] = field(default_factory=list)

    def lookup(self, iocs: dict[str, list[str]]) -> list[IntelMatch]:
        return []

    def status(self) -> str:
        return "Threat intelligence disabled. External intelligence not configured."


def intel_indicators(matches: list[IntelMatch]) -> list[Indicator]:
    """Convert intelligence matches into scored indicators."""
    indicators: list[Indicator] = []

    for match in matches:
        code = (
            "INTEL_KNOWN_BAD_ADDRESS"
            if match.kind == "email_addresses"
            else "INTEL_KNOWN_BAD_DOMAIN"
        )
        indicators.append(Indicator(
            code=code,
            title=f"Indicator listed in {match.source.lower()}",
            category=Category.INTELLIGENCE,
            severity=Severity.CRITICAL,
            weight=WEIGHTS.get(code, 30.0),
            confidence=match.confidence,
            evidence=f"{match.kind}={match.value} - {match.note} [source: {match.source}]",
            explanation=(
                f"This indicator appears in the {match.source.lower()} list held "
                "by this installation. No external intelligence service was "
                "contacted; the verdict reflects locally recorded knowledge only."
            ),
            basis=Confidence.OBSERVED,
            recommendation=(
                "Block the indicator at the gateway and review any prior contact "
                "with it in mail logs."
            ),
            mitre=["T1583"],
        ))

    return indicators
