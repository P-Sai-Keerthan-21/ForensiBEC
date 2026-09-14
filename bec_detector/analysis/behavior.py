"""Sending-behaviour analysis.

A single email carries no behavioural context on its own, so the baseline is
built from the corpus being examined: every message is first observed, then
each message is scored against what the corpus says is normal for that sender.

This is the milestone-scope version of behavioural profiling. It detects the
deviations that matter most in BEC - a known correspondent suddenly writing
from a new domain, or a familiar display name attached to an unfamiliar
address - without needing months of live mailbox history.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import BUSINESS_HOURS, WEIGHTS
from ..models import Category, EmailArtifact, Indicator, Severity


def _indicator(code: str, title: str, severity: Severity, evidence: str,
               explanation: str, confidence: float = 1.0) -> Indicator:
    return Indicator(
        code=code, title=title, category=Category.BEHAVIOR, severity=severity,
        weight=WEIGHTS.get(code, 5.0), confidence=confidence,
        evidence=evidence, explanation=explanation,
    )


def _name_key(display: str) -> str:
    """Normalised person key so 'Ravi Menon' and 'ravi menon (CFO)' unify."""
    import re

    cleaned = re.sub(r"\(.*?\)|\[.*?\]", " ", display or "")
    cleaned = re.sub(r"[^a-z ]", " ", cleaned.lower())
    return " ".join(sorted(cleaned.split()))


class BehaviorBaseline:
    """Corpus-derived profile of what each sender normally looks like.

    Populate with `observe()` over the whole corpus, then call `analyse()` per
    message. Observing before analysing is what makes "first time we have seen
    this address" a meaningful statement.
    """

    def __init__(self) -> None:
        self.addresses_seen: dict[str, int] = defaultdict(int)
        self.domains_for_name: dict[str, set[str]] = defaultdict(set)
        # How often each (display name -> domain) pairing occurs. Used to tell
        # the impersonator apart from the party being impersonated.
        self.domain_counts_for_name: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.displays_for_address: dict[str, set[str]] = defaultdict(set)
        self.send_hours: dict[str, list[int]] = defaultdict(list)
        self.recipients_for_address: dict[str, set[str]] = defaultdict(set)
        self._observed = 0

    # -- population ---------------------------------------------------------

    def observe(self, email: EmailArtifact) -> None:
        address = email.from_address
        if not address:
            return

        self.addresses_seen[address] += 1
        self._observed += 1

        name = _name_key(email.from_display)
        if name:
            self.domains_for_name[name].add(email.from_domain)
            self.domain_counts_for_name[name][email.from_domain] += 1
        if email.from_display:
            self.displays_for_address[address].add(email.from_display.strip())
        if email.date_utc:
            self.send_hours[address].append(email.date_utc.hour)
        for recipient in email.to_addresses:
            self.recipients_for_address[address].add(recipient)

    def observe_all(self, emails: list[EmailArtifact]) -> None:
        for email in emails:
            self.observe(email)

    @property
    def corpus_size(self) -> int:
        return self._observed

    # -- scoring ------------------------------------------------------------

    def analyse(self, email: EmailArtifact) -> list[Indicator]:
        """Score one message against the baseline."""
        indicators: list[Indicator] = []
        address = email.from_address
        if not address:
            return indicators

        name = _name_key(email.from_display)

        # -- Known person, new domain: the strongest behavioural BEC signal --
        #
        # When one display name spans several domains, exactly one side of that
        # pair is normally the impersonator. Firing at full weight on both would
        # penalise the genuine correspondent for having been impersonated, so
        # the established domain (the one this name uses most often) is reported
        # at reduced weight as context rather than as an accusation.
        if name:
            known_domains = self.domains_for_name.get(name, set())
            other_domains = known_domains - {email.from_domain}
            if other_domains and email.from_domain:
                counts = self.domain_counts_for_name.get(name, {})
                this_count = counts.get(email.from_domain, 0)
                established = max(counts.values()) if counts else 0
                is_established = this_count >= established and this_count > 1

                if is_established:
                    indicators.append(_indicator(
                        "DISPLAY_NAME_CHANGED",
                        "This correspondent is being impersonated elsewhere in the corpus",
                        Severity.LOW,
                        evidence=(
                            f"{email.from_display!r} is established at "
                            f"{email.from_domain!r} ({this_count} messages); a "
                            f"variant also appears at {sorted(other_domains)}"
                        ),
                        explanation=(
                            "This message is on the domain the sender normally uses, "
                            "so it is most likely the genuine party. It is flagged "
                            "only because a lookalike of this identity exists in the "
                            "same evidence set and the pair should be reviewed together."
                        ),
                        confidence=0.3,
                    ))
                else:
                    indicators.append(_indicator(
                        "NEW_DOMAIN_FOR_KNOWN_NAME",
                        "Known correspondent writing from an unfamiliar domain",
                        Severity.CRITICAL,
                        evidence=(
                            f"{email.from_display!r} is normally seen at "
                            f"{sorted(other_domains)}, but this message was sent "
                            f"from {email.from_domain!r}"
                        ),
                        explanation=(
                            "The same display name is established on a different "
                            "domain in this corpus. This message uses the less "
                            "established domain, which is the pattern of an "
                            "impersonation of that correspondent."
                        ),
                    ))

        # -- Same address, changed display name ------------------------------
        displays = self.displays_for_address.get(address, set())
        if len(displays) > 1:
            indicators.append(_indicator(
                "DISPLAY_NAME_CHANGED",
                "Sending address has used multiple display names",
                Severity.HIGH,
                evidence=f"{address} seen as: {sorted(displays)}",
                explanation=(
                    "One address presenting several identities suggests either a "
                    "compromised mailbox being repurposed or deliberate identity "
                    "rotation."
                ),
                confidence=0.85,
            ))

        # -- First contact ----------------------------------------------------
        if self.addresses_seen.get(address, 0) <= 1:
            indicators.append(_indicator(
                "FIRST_TIME_SENDER", "No prior correspondence with this address",
                Severity.LOW,
                evidence=f"{address} appears once in the acquired corpus",
                explanation=(
                    "First contact is not suspicious alone, but a first-time "
                    "sender issuing a financial instruction warrants verification."
                ),
                confidence=0.6,
            ))

        # -- Off-hours send ---------------------------------------------------
        if email.date_utc:
            hour = email.date_utc.hour
            start, end = BUSINESS_HOURS
            if not (start <= hour < end):
                indicators.append(_indicator(
                    "OFF_HOURS_SEND", "Sent outside normal business hours",
                    Severity.LOW,
                    evidence=f"sent at {email.date_utc.isoformat()} (hour {hour:02d} UTC)",
                    explanation=(
                        f"Delivery falls outside the {start:02d}:00-{end:02d}:00 "
                        "business window. Attackers commonly send when finance "
                        "staff cannot easily verify a request in person."
                    ),
                    confidence=0.6,
                ))

        # -- Recipient-set deviation -----------------------------------------
        known_recipients = self.recipients_for_address.get(address, set())
        current = set(email.to_addresses)
        if len(known_recipients) > len(current) and current and not (current & known_recipients):
            indicators.append(_indicator(
                "UNUSUAL_RECIPIENT_SET", "Message targets an unfamiliar recipient set",
                Severity.LOW,
                evidence=f"recipients {sorted(current)} not previously contacted by {address}",
                explanation=(
                    "This sender has corresponded with a different group in the "
                    "corpus. Sudden narrow targeting of finance staff is a common "
                    "BEC pattern."
                ),
                confidence=0.6,
            ))

        return indicators


def analyse_behavior(email: EmailArtifact, baseline: BehaviorBaseline) -> list[Indicator]:
    """Convenience wrapper mirroring the other analyser signatures."""
    return baseline.analyse(email)
