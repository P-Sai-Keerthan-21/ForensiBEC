"""Stylometric comparison against a sender's own prior messages.

The question this answers is narrow: does this message read like the other
messages from the same address in the evidence set?

Evidence discipline
-------------------
Stylometry is only meaningful against a baseline. This module refuses to
produce a verdict without one:

  * Fewer than MIN_BASELINE_MESSAGES prior messages from the same sender
    produces an explicit "Insufficient historical data" note and NO indicator.
  * A baseline is never synthesised, borrowed from a different sender, or
    inferred from the corpus at large.

A style deviation is evidence that an account may be writing differently, not
proof of compromise. Every indicator here is labelled INFERRED.
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict

from ..config import WEIGHTS
from ..models import Category, Confidence, EmailArtifact, Indicator, Severity

# Below this, a "baseline" would be noise rather than a profile.
MIN_BASELINE_MESSAGES = 3

GREETING = re.compile(
    r"^\s*(hi|hello|hey|dear|good\s+(morning|afternoon|evening)|greetings|team)\b[^\n]*",
    re.I,
)

SENTENCE_SPLIT = re.compile(r"[.!?]+\s+")


def _signature_block(body: str) -> str:
    """Approximate the sign-off: the last few non-empty lines."""
    lines = [ln.strip() for ln in (body or "").splitlines() if ln.strip()]
    return " | ".join(lines[-3:]).lower() if lines else ""


def _greeting(body: str) -> str:
    for line in (body or "").splitlines():
        if line.strip():
            match = GREETING.match(line)
            return match.group(0).strip().lower() if match else ""
    return ""


def style_features(email: EmailArtifact) -> dict[str, float]:
    """Numeric style profile of one message."""
    body = email.body_text or ""
    words = re.findall(r"[A-Za-z']+", body)
    sentences = [s for s in SENTENCE_SPLIT.split(body) if s.strip()]

    word_count = len(words) or 1
    unique = len({w.lower() for w in words})

    return {
        "mean_sentence_length": (
            statistics.fmean([len(s.split()) for s in sentences]) if sentences else 0.0
        ),
        "type_token_ratio": unique / word_count,
        "exclamation_rate": body.count("!") / word_count,
        "comma_rate": body.count(",") / word_count,
        "uppercase_ratio": sum(1 for w in words if len(w) > 3 and w.isupper()) / word_count,
        "mean_word_length": statistics.fmean([len(w) for w in words]) if words else 0.0,
    }


class StyleBaseline:
    """Per-sender writing profile built only from that sender's own messages."""

    def __init__(self) -> None:
        self._features: dict[str, list[dict[str, float]]] = defaultdict(list)
        self._greetings: dict[str, list[str]] = defaultdict(list)
        self._signatures: dict[str, list[str]] = defaultdict(list)

    def observe(self, email: EmailArtifact) -> None:
        address = email.from_address
        if not address or not (email.body_text or "").strip():
            return
        self._features[address].append(style_features(email))
        self._greetings[address].append(_greeting(email.body_text))
        self._signatures[address].append(_signature_block(email.body_text))

    def observe_all(self, emails: list[EmailArtifact]) -> None:
        for email in emails:
            self.observe(email)

    def baseline_size(self, address: str) -> int:
        """Prior messages available for this sender, excluding the one analysed."""
        return max(0, len(self._features.get(address, [])) - 1)

    def has_baseline(self, address: str) -> bool:
        return self.baseline_size(address) >= MIN_BASELINE_MESSAGES

    def analyse(self, email: EmailArtifact) -> tuple[list[Indicator], list[str]]:
        """Return (indicators, notes).

        `notes` carries the explicit insufficient-data statement so the report
        can show why no stylometric finding was made.
        """
        address = email.from_address
        if not address:
            return [], ["Stylometry: no sender address available."]

        size = self.baseline_size(address)
        if size < MIN_BASELINE_MESSAGES:
            return [], [
                f"Stylometry: insufficient historical data for {address} "
                f"({size} prior message(s) in evidence, {MIN_BASELINE_MESSAGES} required). "
                "No stylometric conclusion drawn."
            ]

        current = style_features(email)
        history = [f for f in self._features[address] if f != current] or self._features[address]

        deviations: list[str] = []
        for feature, value in current.items():
            values = [f[feature] for f in history]
            if len(values) < 2:
                continue
            mean = statistics.fmean(values)
            stdev = statistics.pstdev(values)
            if stdev == 0:
                continue
            z = (value - mean) / stdev
            if abs(z) >= 2.0:
                deviations.append(
                    f"{feature.replace('_', ' ')}: {value:.2f} vs baseline "
                    f"{mean:.2f} (z={z:+.1f})"
                )

        indicators: list[Indicator] = []

        if deviations:
            indicators.append(Indicator(
                code="STYLE_DEVIATION",
                title="Writing style departs from this sender's own baseline",
                category=Category.STYLOMETRY,
                severity=Severity.MEDIUM,
                weight=WEIGHTS.get("STYLE_DEVIATION", 18.0),
                confidence=0.7,
                evidence=f"baseline of {size} prior message(s); " + "; ".join(deviations[:3]),
                explanation=(
                    "Measurable writing features differ from this sender's "
                    "established pattern. This is consistent with a different "
                    "person composing the message, but ordinary causes exist "
                    "(dictation, haste, a different device or a genuine change "
                    "of circumstance)."
                ),
                basis=Confidence.INFERRED,
                recommendation=(
                    "Treat as corroboration only. Confirm authorship out of band "
                    "before relying on it."
                ),
                mitre=["T1586.002"],
            ))

        # -- Greeting change -----------------------------------------------
        greetings = [g for g in self._greetings[address] if g]
        current_greeting = _greeting(email.body_text)
        if greetings and current_greeting:
            others = [g for g in greetings if g != current_greeting]
            if len(others) >= MIN_BASELINE_MESSAGES and current_greeting not in others:
                indicators.append(Indicator(
                    code="STYLE_GREETING_CHANGE",
                    title="Unfamiliar greeting for this sender",
                    category=Category.STYLOMETRY,
                    severity=Severity.LOW,
                    weight=WEIGHTS.get("STYLE_GREETING_CHANGE", 12.0),
                    confidence=0.6,
                    evidence=f"this message opens {current_greeting!r}; "
                             f"prior messages used {sorted(set(others))[:3]}",
                    explanation="The opening salutation differs from the form this "
                                "sender has used previously in the evidence set.",
                    basis=Confidence.INFERRED,
                    recommendation="Weak signal; use only alongside stronger indicators.",
                ))

        # -- Signature change ------------------------------------------------
        signatures = [s for s in self._signatures[address] if s]
        current_signature = _signature_block(email.body_text)
        if len(signatures) > MIN_BASELINE_MESSAGES and current_signature:
            others = [s for s in signatures if s != current_signature]
            if len(others) >= MIN_BASELINE_MESSAGES and current_signature not in others:
                indicators.append(Indicator(
                    code="STYLE_SIGNATURE_CHANGE",
                    title="Sign-off differs from this sender's usual block",
                    category=Category.STYLOMETRY,
                    severity=Severity.LOW,
                    weight=WEIGHTS.get("STYLE_SIGNATURE_CHANGE", 14.0),
                    confidence=0.6,
                    evidence=f"sign-off {current_signature[:90]!r} not seen in "
                             f"{len(others)} prior message(s)",
                    explanation="The closing block differs from this sender's "
                                "established sign-off.",
                    basis=Confidence.INFERRED,
                    recommendation="Weak signal; corroborate before acting.",
                ))

        note = (f"Stylometry: compared against {size} prior message(s) from {address}.")
        return indicators, [note]
