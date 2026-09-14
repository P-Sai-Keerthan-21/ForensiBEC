"""End-to-end orchestration of the four forensic stages.

    Acquisition  ->  Analysis  ->  Validation  ->  Report

The two-pass structure matters: the whole corpus is acquired and observed
before any message is scored, because the behavioural and statistical stages
can only describe "unusual" relative to a baseline.
"""

from __future__ import annotations

from pathlib import Path

from .acquisition import load_bytes, load_path
from .analysis import BehaviorBaseline, analyse_sender, analyse_text, get_nlp_status
from .models import Assessment, EmailArtifact, Indicator
from .validation import AnomalyModel, fuse


class BECPipeline:
    """Runs the detector over a corpus of acquired messages."""

    def __init__(self, examiner: str | None = None) -> None:
        self.examiner = examiner
        self.baseline = BehaviorBaseline()
        self.anomaly = AnomalyModel()
        self._fitted = False

    # -- Stage 1 -------------------------------------------------------------

    def acquire(self, path: str | Path) -> list[EmailArtifact]:
        """Load evidence from a file, directory or mbox archive."""
        return load_path(path, examiner=self.examiner)

    def acquire_bytes(self, raw: bytes, label: str) -> EmailArtifact:
        """Acquire a single in-memory message (used by the web upload route)."""
        return load_bytes(raw, label, examiner=self.examiner)

    # -- Baseline ------------------------------------------------------------

    def fit(self, emails: list[EmailArtifact]) -> None:
        """Observe the corpus so behavioural deviation becomes measurable."""
        self.baseline.observe_all(emails)
        self.anomaly.fit(emails)
        self._fitted = True

    # -- Stages 2 and 3 ------------------------------------------------------

    def assess(self, email: EmailArtifact) -> Assessment:
        """Analyse and validate a single message against the current baseline."""
        indicators: list[Indicator] = []
        indicators.extend(analyse_sender(email))
        indicators.extend(analyse_text(email))
        indicators.extend(self.baseline.analyse(email))
        indicators.extend(self.anomaly.analyse(email))
        return fuse(email, indicators)

    def run(self, path: str | Path) -> list[Assessment]:
        """Acquire a corpus, baseline it, then assess every message."""
        emails = self.acquire(path)
        if not emails:
            return []
        self.fit(emails)
        return [self.assess(email) for email in emails]

    def run_single(self, raw: bytes, label: str) -> Assessment:
        """Assess one uploaded message with no corpus context.

        Behavioural indicators are necessarily weaker here - there is no history
        to deviate from - so only the sender, content and header stages carry
        real weight.
        """
        email = self.acquire_bytes(raw, label)
        self.baseline.observe(email)
        return self.assess(email)

    # -- Diagnostics ---------------------------------------------------------

    @staticmethod
    def nlp_status() -> dict[str, bool]:
        """Which NLP backends loaded - recorded in the report footer."""
        return get_nlp_status()
