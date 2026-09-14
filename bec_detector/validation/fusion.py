"""Indicator fusion - combining independent signals into one verdict.

Design decision, and the reason this is not a machine-learning classifier: the
brief requires an *explainable* risk assessment. A weighted-additive model with
per-category caps produces a score whose every point can be traced back to a
named rule and the header or sentence that triggered it. That traceability is
what makes a finding defensible in a report.

Fusion proceeds in four steps:

  1. Deduplicate - the same rule firing twice must not double-count.
  2. Sum contributions per category (weight x confidence).
  3. Cap each category, so one verbose family cannot dominate.
  4. Apply corroboration bonuses, then normalise to 0-100 and band.
"""

from __future__ import annotations

from ..config import BAND_THRESHOLDS, CATEGORY_CAPS, SCORE_NORMALISER
from ..models import Assessment, Category, EmailArtifact, Indicator, RiskBand, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def deduplicate(indicators: list[Indicator]) -> list[Indicator]:
    """Keep the strongest instance of each rule code.

    Several analysers can legitimately raise the same code (for example a
    payment request detected both by vocabulary and by an inline IBAN). The
    finding is one finding; we keep the highest-contribution instance.
    """
    best: dict[str, Indicator] = {}
    for indicator in indicators:
        current = best.get(indicator.code)
        if current is None or indicator.contribution > current.contribution:
            best[indicator.code] = indicator
    return list(best.values())


def _corroboration_bonus(indicators: list[Indicator]) -> tuple[float, list[str]]:
    """Reward combinations that are far more damning together than apart.

    A payment instruction is ordinary. An unverified sender is ordinary. A
    payment instruction *from* an unverified sender under time pressure is the
    BEC pattern itself, and the score should reflect that interaction.
    """
    codes = {i.code for i in indicators}
    bonus = 0.0
    reasons: list[str] = []

    identity_compromised = bool(codes & {
        "DISPLAY_NAME_IMPERSONATION", "LOOKALIKE_DOMAIN",
        "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS", "FREEMAIL_EXEC_CLAIM",
        "NEW_DOMAIN_FOR_KNOWN_NAME",
    })
    financial_ask = bool(codes & {
        "PAYMENT_REQUEST", "BANKING_CHANGE_REQUEST", "GIFT_CARD_REQUEST",
    })
    pressure = bool(codes & {"URGENCY_LANGUAGE", "AUTHORITY_PRESSURE", "SECRECY_REQUEST"})
    auth_failed = bool(codes & {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"})

    if identity_compromised and financial_ask:
        bonus += 15.0
        reasons.append(
            "sender identity is questionable AND a financial action is requested"
        )
    if financial_ask and pressure:
        bonus += 10.0
        reasons.append("a financial request is combined with pressure tactics")
    if identity_compromised and auth_failed:
        bonus += 10.0
        reasons.append(
            "spoofing indicators are corroborated by failed sender authentication"
        )
    if identity_compromised and financial_ask and pressure:
        bonus += 10.0
        reasons.append(
            "all three legs of the BEC pattern are present together "
            "(identity, financial ask, pressure)"
        )

    return bonus, reasons


def _band_for(score: float) -> RiskBand:
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return RiskBand(band)
    return RiskBand.BENIGN


def _narrative(email: EmailArtifact, indicators: list[Indicator],
               band: RiskBand, score: float, bonus_reasons: list[str]) -> str:
    """Plain-language summary an examiner can paste into a report."""
    if not indicators:
        return (
            f"No BEC indicators were raised for this message. Sender "
            f"{email.from_address or 'unknown'} produced no identity, "
            "authentication, behavioural or linguistic findings."
        )

    ranked = sorted(indicators, key=lambda i: (-i.contribution, SEVERITY_ORDER[i.severity]))
    top = ranked[:3]

    verdict = {
        RiskBand.CONFIRMED_BEC: (
            "This message exhibits the full Business Email Compromise pattern and "
            "should be treated as a confirmed attempt."
        ),
        RiskBand.LIKELY_BEC: (
            "This message is likely a Business Email Compromise attempt and "
            "should not be actioned without out-of-band verification."
        ),
        RiskBand.SUSPICIOUS: (
            "This message carries suspicious traits that warrant analyst review "
            "before any financial action is taken."
        ),
        RiskBand.BENIGN: (
            "This message shows no meaningful BEC characteristics."
        ),
    }[band]

    lines = [
        f"{verdict} Risk score {score:.1f}/100 ({band.value}), derived from "
        f"{len(indicators)} indicator(s).",
        "",
        f"Sender presents as {email.from_display or '(no display name)'!r} at "
        f"{email.from_address or '(no address)'}"
        + (f", with replies directed to {email.reply_to_address}." if email.reply_to_address
           else "."),
        "",
        "Principal findings:",
    ]
    for indicator in top:
        lines.append(f"  - {indicator.title} [{indicator.severity.value}] - {indicator.evidence}")

    if bonus_reasons:
        lines.append("")
        lines.append("Score escalated because " + "; ".join(bonus_reasons) + ".")

    if band in {RiskBand.LIKELY_BEC, RiskBand.CONFIRMED_BEC}:
        lines.append("")
        lines.append(
            "Recommended action: do not reply or action any payment. Verify the "
            "request with the purported sender using a phone number already on "
            "file - never one supplied in this message - and preserve the "
            "original message with full headers for the case file."
        )

    return "\n".join(lines)


def fuse(email: EmailArtifact, indicators: list[Indicator]) -> Assessment:
    """Combine indicators into a scored, banded, explained assessment."""
    unique = deduplicate(indicators)

    # Step 2 - accumulate per category.
    raw_by_category: dict[str, float] = {c.value: 0.0 for c in Category}
    for indicator in unique:
        raw_by_category[indicator.category.value] += indicator.contribution

    # Step 3 - cap each category.
    capped: dict[str, float] = {}
    for category, raw in raw_by_category.items():
        cap = CATEGORY_CAPS.get(category, 100.0)
        capped[category] = round(min(raw, cap), 2)

    subtotal = sum(capped.values())

    # Step 4 - corroboration, normalise, band.
    bonus, bonus_reasons = _corroboration_bonus(unique)
    total = subtotal + bonus

    score = round(min(100.0, (total / SCORE_NORMALISER) * 100.0), 1)
    band = _band_for(score)

    ordered = sorted(
        unique,
        key=lambda i: (SEVERITY_ORDER[i.severity], -i.contribution),
    )

    return Assessment(
        artifact=email,
        indicators=ordered,
        score=score,
        band=band,
        category_scores=capped,
        narrative=_narrative(email, ordered, band, score, bonus_reasons),
    )
