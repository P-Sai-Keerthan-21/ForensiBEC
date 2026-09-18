"""Sender identity and header-authentication analysis.

This module answers two forensic questions:

  1. Does the person the message *claims* to be from match the address it was
     actually sent from?  (display-name spoofing, lookalike domains)
  2. Do the receiving infrastructure's own verdicts corroborate the sender?
     (SPF / DKIM / DMARC in Authentication-Results)
"""

from __future__ import annotations

import re

from ..config import (
    EXECUTIVE_TITLES,
    FREEMAIL_DOMAINS,
    TRUSTED_DOMAINS,
    WEIGHTS,
)
from ..models import Category, EmailArtifact, Indicator, Severity
from .confusables import analyse_domain, core_label, decode_idna, describe, skeleton

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")



def _indicator(code: str, title: str, category: Category, severity: Severity,
               evidence: str, explanation: str, confidence: float = 1.0) -> Indicator:
    return Indicator(
        code=code,
        title=title,
        category=category,
        severity=severity,
        weight=WEIGHTS.get(code, 5.0),
        confidence=confidence,
        evidence=evidence,
        explanation=explanation,
    )


def _normalise_domain(domain: str) -> str:
    """Collapse a domain to the Latin letters its brand label visually presents.

    Punycode labels are decoded first, then Cyrillic/Greek/fullwidth confusables
    are mapped to the Latin letters they imitate (see confusables.py). On a
    pure-ASCII domain the result is identical to the original comparer:
    "nOrthwind-l0gistics.com" and "northwind-logistics.com" both give
    "northwindlogistics".
    """
    unicode_form, _ = decode_idna((domain or "").strip().strip("."))
    return skeleton(core_label(unicode_form.lower()))


def _levenshtein(a: str, b: str) -> int:
    """Edit distance, used to catch single-character domain substitutions."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,               # deletion
                current[j - 1] + 1,            # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        previous = current
    return previous[-1]


def _extract_person_name(display: str) -> str:
    """Strip titles and parenthetical role suffixes from a display name."""
    cleaned = re.sub(r"\(.*?\)|\[.*?\]", " ", display)
    cleaned = re.sub(r"[^A-Za-z .'-]", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _claims_executive(display: str, subject: str, body: str) -> str | None:
    """Return the executive title claimed, if any."""
    haystack = f"{display} {subject} {body[:400]}".lower()
    for title in sorted(EXECUTIVE_TITLES, key=len, reverse=True):
        if re.search(rf"\b{re.escape(title)}\b", haystack):
            return title
    return None


def _parse_auth_results(raw: str) -> dict[str, str]:
    """Pull spf/dkim/dmarc verdicts out of an Authentication-Results header."""
    verdicts: dict[str, str] = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}\s*=\s*(\w+)", raw, re.I)
        if match:
            verdicts[mechanism] = match.group(1).lower()
    return verdicts


def analyse_sender(email: EmailArtifact) -> list[Indicator]:
    """Extract every sender-identity and authentication indicator."""
    indicators: list[Indicator] = []

    display = email.from_display
    address = email.from_address
    domain = email.from_domain

    # -- Display name embeds a *different* address than the real sender -------
    for found in EMAIL_IN_TEXT.findall(display):
        if found.lower() != address:
            indicators.append(_indicator(
                "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS",
                "Display name contains a different email address",
                Category.SENDER, Severity.HIGH,
                evidence=f'From: "{display}" <{address}>',
                explanation=(
                    f"The display name advertises {found!r} but the message was "
                    f"actually sent from {address!r}. Mail clients show the display "
                    "name, so the recipient sees an address that never sent this mail."
                ),
            ))
            break

    # -- Display name is itself a bare address (low-grade obfuscation) --------
    if display and EMAIL_IN_TEXT.fullmatch(display.strip()) and display.strip().lower() != address:
        indicators.append(_indicator(
            "DISPLAY_NAME_IS_EMAIL", "Display name is a bare email address",
            Category.SENDER, Severity.LOW,
            evidence=f'From: "{display}" <{address}>',
            explanation="Using an address as the display name is a common way to "
                        "make a spoofed identity look like a real mail header.",
        ))

    # -- Impersonation: external address claiming an internal identity -------
    claimed_title = _claims_executive(display, email.subject, email.body_text)
    person = _extract_person_name(display)
    external = bool(domain) and domain not in TRUSTED_DOMAINS

    if external and person and claimed_title:
        indicators.append(_indicator(
            "DISPLAY_NAME_IMPERSONATION",
            "External sender presents as an internal executive",
            Category.SENDER, Severity.CRITICAL,
            evidence=f'From: "{display}" <{address}>  |  claimed role: {claimed_title!r}',
            explanation=(
                f"The display name presents {person!r} in the role of "
                f"{claimed_title!r}, but {domain!r} is not a trusted internal domain. "
                "This is the signature pattern of CEO-fraud display-name spoofing."
            ),
        ))

    # -- Freemail address asserting an executive role ------------------------
    if domain in FREEMAIL_DOMAINS and claimed_title:
        indicators.append(_indicator(
            "FREEMAIL_EXEC_CLAIM",
            "Executive identity asserted from a consumer mailbox",
            Category.SENDER, Severity.HIGH,
            evidence=f'From: "{display}" <{address}>',
            explanation=(
                f"{domain!r} is a free consumer mail provider, yet the message "
                f"claims the authority of a {claimed_title!r}. Corporate officers "
                "do not issue payment instructions from personal webmail."
            ),
        ))

    # -- Lookalike domain ----------------------------------------------------
    if domain and domain not in TRUSTED_DOMAINS:
        analysis = analyse_domain(domain, TRUSTED_DOMAINS)
        normalised = _normalise_domain(domain)
        for trusted in sorted(TRUSTED_DOMAINS):
            trusted_norm = _normalise_domain(trusted)
            distance = _levenshtein(normalised, trusted_norm)
            if normalised == trusted_norm or 0 < distance <= 2:
                identical = normalised == trusted_norm
                if analysis.confusable_chars:
                    detail = (f"{len(analysis.confusable_chars)} non-Latin character(s) "
                              "render as Latin letters")
                elif identical:
                    detail = "identical once homoglyph substitutions are reversed"
                else:
                    detail = f"edit distance {distance}"
                indicators.append(_indicator(
                    "LOOKALIKE_DOMAIN", "Sender domain imitates a trusted domain",
                    Category.SENDER, Severity.CRITICAL,
                    evidence=(f"sender domain {domain!r} vs trusted domain {trusted!r} | "
                              + describe(analysis)),
                    explanation=(
                        f"{domain!r} is visually confusable with the legitimate "
                        f"{trusted!r} ({detail}). Registering a near-identical "
                        "domain is the standard way to defeat a recipient's "
                        "visual check."
                    ),
                    confidence=1.0 if identical else 0.85,
                ))
                break

        # A single label mixing Latin with Cyrillic/Greek has essentially no
        # legitimate use. Genuine internationalised domains are single-script,
        # so they are never flagged here.
        if analysis.is_mixed_script:
            indicators.append(_indicator(
                "MIXED_SCRIPT_DOMAIN", "Domain label mixes writing systems",
                Category.SENDER, Severity.HIGH,
                evidence=describe(analysis)
                         + f" | mixed-script label(s): {analysis.mixed_script_labels}"
                         + f" | scripts present: {analysis.scripts}",
                explanation=(
                    "A single domain label combines Latin letters with Cyrillic or "
                    "Greek letters. Legitimate internationalised domains are "
                    "written in one script; mixing scripts is the construction "
                    "used in IDN homograph attacks."
                ),
            ))

    # -- Reply-To divergence -------------------------------------------------
    if email.reply_to_address and email.reply_to_address != address:
        reply_domain = email.reply_to_domain
        indicators.append(_indicator(
            "REPLY_TO_MISMATCH", "Reply-To differs from the sending address",
            Category.SENDER, Severity.HIGH,
            evidence=f"From: {address}  |  Reply-To: {email.reply_to_address}",
            explanation=(
                "Replies will be routed to an address the sender did not send "
                "from. In BEC this silently redirects the victim's response to "
                "an attacker-controlled mailbox."
            ),
        ))
        if reply_domain in FREEMAIL_DOMAINS and domain not in FREEMAIL_DOMAINS:
            indicators.append(_indicator(
                "REPLY_TO_FREEMAIL", "Reply-To points at a consumer mailbox",
                Category.SENDER, Severity.HIGH,
                evidence=f"Reply-To: {email.reply_to_address}",
                explanation=(
                    f"A business message from {domain!r} diverts replies to "
                    f"{reply_domain!r}, a free consumer provider."
                ),
            ))

    # -- Return-Path divergence (envelope vs header sender) ------------------
    if email.return_path and email.return_path != address:
        indicators.append(_indicator(
            "RETURN_PATH_MISMATCH", "Envelope sender differs from header From",
            Category.SENDER, Severity.MEDIUM,
            evidence=f"Return-Path: {email.return_path}  |  From: {address}",
            explanation=(
                "The SMTP envelope sender does not match the From header. Benign "
                "causes exist (mailing lists, relays), so this corroborates rather "
                "than proves spoofing."
            ),
            confidence=0.7,
        ))

    # -- Authentication verdicts --------------------------------------------
    if email.auth_results:
        verdicts = _parse_auth_results(email.auth_results)
        excerpt = email.auth_results[:200]

        for mechanism, code, title, severity, meaning in (
            ("spf", "SPF_FAIL", "SPF validation failed", Severity.HIGH,
             "the sending server is not authorised to send for that domain"),
            ("dkim", "DKIM_FAIL", "DKIM signature failed", Severity.HIGH,
             "the message body or headers were not signed by the claimed domain"),
            ("dmarc", "DMARC_FAIL", "DMARC alignment failed", Severity.CRITICAL,
             "the domain owner's own published policy rejects this message"),
        ):
            verdict = verdicts.get(mechanism)
            if verdict in {"fail", "softfail", "permerror", "temperror"}:
                indicators.append(_indicator(
                    code, title, Category.AUTHENTICATION, severity,
                    evidence=f"Authentication-Results: {excerpt}",
                    explanation=(
                        f"{mechanism.upper()} returned {verdict!r} - {meaning}. "
                        "The receiving infrastructure could not confirm the sender."
                    ),
                    confidence=1.0 if verdict == "fail" else 0.6,
                ))
    else:
        indicators.append(_indicator(
            "NO_AUTH_RESULTS", "No Authentication-Results header present",
            Category.AUTHENTICATION, Severity.LOW,
            evidence="Authentication-Results header absent",
            explanation="Sender authentication could not be verified from the "
                        "message alone; SPF/DKIM/DMARC evidence is unavailable.",
            confidence=0.6,
        ))

    # -- Relay chain ---------------------------------------------------------
    hops = len(email.received_chain)
    if hops > 8:
        indicators.append(_indicator(
            "SUSPICIOUS_HOP_COUNT", "Unusually long relay chain",
            Category.AUTHENTICATION, Severity.LOW,
            evidence=f"{hops} Received headers in the delivery chain",
            explanation="Long relay chains can indicate laundering through open "
                        "relays or compromised intermediate hosts.",
            confidence=0.5,
        ))

    return indicators
