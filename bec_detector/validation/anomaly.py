"""Statistical anomaly identification across the acquired corpus.

The rule engine asks "does this message match a known fraud pattern?".  This
module asks the complementary question: "does this message look unlike the
rest of the evidence set?" - which catches campaigns whose wording the
lexicons do not yet cover.

Features are deliberately simple and explainable; a modified z-score (median /
MAD based) is used because it stays meaningful on the small, skewed corpora a
forensic examiner actually works with.
"""

from __future__ import annotations

from ..config import WEIGHTS
from ..models import Category, EmailArtifact, Indicator, Severity

# Magic constant relating MAD to the standard deviation of a normal sample.
MAD_SCALE = 0.6745

# |modified z| above this is reported as an outlier.
Z_THRESHOLD = 3.5


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def extract_features(email: EmailArtifact) -> dict[str, float]:
    """Numeric profile of one message, used for corpus-relative comparison."""
    body = email.body_text or ""
    words = body.split()
    recipients = len(email.to_addresses) + len(email.cc_addresses)

    exclamations = body.count("!")
    uppercase_words = sum(1 for w in words if len(w) > 3 and w.isupper())

    return {
        "body_length": float(len(body)),
        "word_count": float(len(words)),
        "recipient_count": float(recipients),
        "received_hops": float(len(email.received_chain)),
        "exclamation_count": float(exclamations),
        "uppercase_word_count": float(uppercase_words),
        "attachment_count": float(len(email.attachments)),
    }


class AnomalyModel:
    """Corpus-fitted modified-z-score model over the extracted features."""

    def __init__(self) -> None:
        self.medians: dict[str, float] = {}
        self.mads: dict[str, float] = {}
        self.fitted = False
        self.sample_size = 0

    def fit(self, emails: list[EmailArtifact]) -> None:
        """Learn the central tendency and spread of each feature."""
        if len(emails) < 4:
            # Too few samples for a defensible statistical statement.
            self.fitted = False
            self.sample_size = len(emails)
            return

        rows = [extract_features(e) for e in emails]
        self.sample_size = len(rows)

        for feature in rows[0]:
            values = [row[feature] for row in rows]
            median = _median(values)
            mad = _median([abs(v - median) for v in values])
            self.medians[feature] = median
            self.mads[feature] = mad

        self.fitted = True

    def score(self, email: EmailArtifact) -> dict[str, float]:
        """Modified z-score per feature for one message."""
        if not self.fitted:
            return {}

        features = extract_features(email)
        scores: dict[str, float] = {}
        for name, value in features.items():
            mad = self.mads.get(name, 0.0)
            median = self.medians.get(name, 0.0)
            if mad == 0:
                # No spread in the corpus: only an exact mismatch is notable,
                # and we cannot quantify it, so skip rather than divide by zero.
                continue
            scores[name] = MAD_SCALE * (value - median) / mad
        return scores

    def analyse(self, email: EmailArtifact) -> list[Indicator]:
        """Emit an indicator for each feature that deviates from the corpus."""
        indicators: list[Indicator] = []
        for name, z in self.score(email).items():
            if abs(z) < Z_THRESHOLD:
                continue
            direction = "above" if z > 0 else "below"
            indicators.append(Indicator(
                code="STATISTICAL_OUTLIER",
                title=f"Corpus outlier on {name.replace('_', ' ')}",
                category=Category.ANOMALY,
                severity=Severity.LOW,
                weight=WEIGHTS.get("STATISTICAL_OUTLIER", 12.0),
                confidence=0.6,
                evidence=(
                    f"{name}={extract_features(email)[name]:.0f}, corpus median="
                    f"{self.medians[name]:.0f} (modified z={z:+.2f}, n={self.sample_size})"
                ),
                explanation=(
                    f"This message sits well {direction} the rest of the acquired "
                    f"corpus on {name.replace('_', ' ')}. Statistical deviation is "
                    "weak evidence alone but corroborates pattern-based findings."
                ),
            ))
        return indicators
