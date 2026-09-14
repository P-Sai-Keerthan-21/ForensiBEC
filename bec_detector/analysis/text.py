"""Linguistic analysis of the message body and subject.

Two NLP layers are used, and both degrade gracefully:

  * NLTK   - tokenisation and lemmatisation, so that "urgently" and "urgent"
             collapse to the same lexicon hit.
  * spaCy  - named-entity recognition, used to confirm that a payment request
             actually names a MONEY / ORG / PERSON entity rather than merely
             using finance vocabulary.

If either model is unavailable the analyser falls back to regex matching and
records that fact, so a missing model degrades precision but never crashes a
forensic run.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from ..config import WEIGHTS
from ..models import Category, EmailArtifact, Indicator, Severity
from .lexicons import (
    AUTHORITY_TERMS,
    BANKING_CHANGE_TERMS,
    CREDENTIAL_TERMS,
    FAKE_THREAD_PREFIXES,
    GIFT_CARD_TERMS,
    PAYMENT_TERMS,
    SECRECY_TERMS,
    THREAD_HIJACK_TERMS,
    URGENCY_TERMS,
)

# Currency amounts: $12,500.00 / EUR 40000 / 25,000 USD / £3k
MONEY_PATTERN = re.compile(
    r"(?:[$€£₹]\s?\d[\d,.]*(?:\s?[kKmM])?)"
    r"|(?:\b(?:usd|eur|gbp|inr|aud|cad)\s?\d[\d,.]*)"
    r"|(?:\b\d[\d,.]*\s?(?:usd|eur|gbp|inr|dollars|euros|pounds)\b)",
    re.I,
)

IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
ACCOUNT_PATTERN = re.compile(r"\b(?:a/c|acct|account)\s*(?:no\.?|number|#)?\s*:?\s*\d{6,}\b", re.I)


# ---------------------------------------------------------------------------
# NLP backend loading (cached - models are expensive to initialise)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_spacy() -> Any | None:
    try:
        import spacy

        return spacy.load("en_core_web_sm")
    except Exception:
        return None


@lru_cache(maxsize=1)
def _load_nltk() -> Any | None:
    """Return a lemmatiser-like callable, or None if NLTK data is missing."""
    try:
        import nltk
        from nltk.stem import WordNetLemmatizer

        lemmatiser = WordNetLemmatizer()
        lemmatiser.lemmatize("testing", "v")  # force the corpus load to fail fast
        return lemmatiser
    except Exception:
        return None


def get_nlp_status() -> dict[str, bool]:
    """Report which NLP backends are live - surfaced in the report footer."""
    return {
        "spacy_ner": _load_spacy() is not None,
        "nltk_lemmatiser": _load_nltk() is not None,
    }


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _normalise(text: str) -> str:
    """Lower-case and collapse whitespace so multi-word phrases match."""
    return re.sub(r"\s+", " ", text.lower())


def _lemma_expand(text: str) -> str:
    """Append verb/noun lemmas so inflected forms still hit the lexicons."""
    lemmatiser = _load_nltk()
    if lemmatiser is None:
        return text
    try:
        tokens = re.findall(r"[a-z']+", text)
        lemmas = {lemmatiser.lemmatize(t, "v") for t in tokens}
        lemmas |= {lemmatiser.lemmatize(t, "n") for t in tokens}
        return text + " " + " ".join(sorted(lemmas))
    except Exception:
        return text


def _find_terms(haystack: str, terms: set[str], limit: int = 4) -> list[str]:
    """Return matched lexicon terms, whole-word where the term is a single word."""
    hits: list[str] = []
    for term in sorted(terms, key=len, reverse=True):
        pattern = rf"\b{re.escape(term)}\b" if " " not in term else re.escape(term)
        if re.search(pattern, haystack):
            hits.append(term)
        if len(hits) >= limit:
            break
    return hits


def _quote(body: str, term: str, width: int = 90) -> str:
    """Pull the sentence fragment around a hit, for the evidence field."""
    match = re.search(re.escape(term), body, re.I)
    if not match:
        return term
    start = max(0, match.start() - width // 2)
    end = min(len(body), match.end() + width // 2)
    fragment = re.sub(r"\s+", " ", body[start:end]).strip()
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(body) else ""
    return f"{prefix}{fragment}{suffix}"


def _indicator(code: str, title: str, severity: Severity, evidence: str,
               explanation: str, confidence: float = 1.0) -> Indicator:
    return Indicator(
        code=code, title=title, category=Category.CONTENT, severity=severity,
        weight=WEIGHTS.get(code, 5.0), confidence=confidence,
        evidence=evidence, explanation=explanation,
    )


def _entities(text: str) -> dict[str, list[str]]:
    """spaCy NER, limited to the entity types relevant to payment fraud."""
    nlp = _load_spacy()
    if nlp is None:
        return {}
    try:
        doc = nlp(text[:5000])
    except Exception:
        return {}

    found: dict[str, list[str]] = {}
    for ent in doc.ents:
        if ent.label_ in {"MONEY", "ORG", "PERSON", "DATE", "GPE"}:
            bucket = found.setdefault(ent.label_, [])
            if ent.text not in bucket and len(bucket) < 6:
                bucket.append(ent.text)
    return found


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyse_text(email: EmailArtifact) -> list[Indicator]:
    """Extract every content/linguistic indicator from subject and body."""
    indicators: list[Indicator] = []

    body = email.body_text or ""
    subject = email.subject or ""
    combined = f"{subject}\n{body}"
    haystack = _lemma_expand(_normalise(combined))

    entities = _entities(combined)
    money_entities = entities.get("MONEY", [])
    money_regex = MONEY_PATTERN.findall(combined)

    # -- Urgency -------------------------------------------------------------
    urgency_hits = _find_terms(haystack, URGENCY_TERMS)
    if urgency_hits:
        # Two or more independent urgency cues is meaningfully stronger than one.
        confidence = 1.0 if len(urgency_hits) >= 2 else 0.7
        indicators.append(_indicator(
            "URGENCY_LANGUAGE", "Manufactured time pressure",
            Severity.MEDIUM if len(urgency_hits) < 2 else Severity.HIGH,
            evidence=f"terms: {', '.join(urgency_hits)}  |  {_quote(combined, urgency_hits[0])}",
            explanation=(
                f"{len(urgency_hits)} urgency cue(s) detected. BEC relies on time "
                "pressure to stop the recipient from verifying the request through "
                "a second channel."
            ),
            confidence=confidence,
        ))

    # -- Banking change (highest-signal BEC pattern) -------------------------
    banking_hits = _find_terms(haystack, BANKING_CHANGE_TERMS)
    if banking_hits:
        indicators.append(_indicator(
            "BANKING_CHANGE_REQUEST", "Request to change payment destination",
            Severity.CRITICAL,
            evidence=_quote(combined, banking_hits[0]),
            explanation=(
                "The message asks for banking or beneficiary details to be "
                "changed. Redirecting an established payment relationship is the "
                "core objective of vendor-invoice BEC."
            ),
        ))

    # -- Payment instruction -------------------------------------------------
    payment_hits = _find_terms(haystack, PAYMENT_TERMS)
    if payment_hits:
        has_amount = bool(money_entities or money_regex)
        indicators.append(_indicator(
            "PAYMENT_REQUEST", "Financial transaction requested",
            Severity.HIGH if has_amount else Severity.MEDIUM,
            evidence=f"terms: {', '.join(payment_hits)}  |  {_quote(combined, payment_hits[0])}",
            explanation=(
                "The message contains a payment or transfer instruction"
                + (", corroborated by a named monetary amount." if has_amount
                   else ", though no explicit amount was found.")
            ),
            confidence=1.0 if has_amount else 0.65,
        ))

    # -- Monetary amount named ----------------------------------------------
    if money_entities or money_regex:
        shown = money_entities or [str(m) for m in money_regex[:4]]
        source = "spaCy MONEY entity" if money_entities else "currency pattern"
        indicators.append(_indicator(
            "MONEY_ENTITY_PRESENT", "Specific monetary amount named",
            Severity.MEDIUM,
            evidence=f"{source}: {', '.join(shown[:4])}",
            explanation=(
                "A concrete sum is stated. Combined with an urgent instruction "
                "and an unverified sender, this is the classic fraudulent "
                "transfer request shape."
            ),
            confidence=0.9 if money_entities else 0.75,
        ))

    # -- Bank account artefacts ---------------------------------------------
    iban_hits = IBAN_PATTERN.findall(combined)
    account_hits = ACCOUNT_PATTERN.findall(combined)
    if iban_hits or account_hits:
        indicators.append(_indicator(
            "PAYMENT_REQUEST", "Bank account identifiers supplied in message body",
            Severity.HIGH,
            evidence=f"IBAN/account artefacts: {', '.join((iban_hits + account_hits)[:3])}",
            explanation=(
                "Raw account or IBAN details appear inline. Legitimate finance "
                "processes rarely transmit new account details unsolicited by email."
            ),
            confidence=0.85,
        ))

    # -- Gift-card variant ---------------------------------------------------
    gift_hits = _find_terms(haystack, GIFT_CARD_TERMS)
    if gift_hits:
        indicators.append(_indicator(
            "GIFT_CARD_REQUEST", "Gift-card purchase solicited",
            Severity.CRITICAL,
            evidence=_quote(combined, gift_hits[0]),
            explanation=(
                "A request to buy gift cards and return the codes is an "
                "untraceable-value BEC variant with essentially no legitimate "
                "business equivalent."
            ),
        ))

    # -- Secrecy -------------------------------------------------------------
    secrecy_hits = _find_terms(haystack, SECRECY_TERMS)
    if secrecy_hits:
        indicators.append(_indicator(
            "SECRECY_REQUEST", "Request to bypass normal verification",
            Severity.HIGH,
            evidence=_quote(combined, secrecy_hits[0]),
            explanation=(
                "The sender asks the recipient to keep the request private or "
                "avoid involving colleagues, which defeats the segregation-of-"
                "duties control that would otherwise catch the fraud."
            ),
        ))

    # -- Authority pressure --------------------------------------------------
    authority_hits = _find_terms(haystack, AUTHORITY_TERMS)
    if authority_hits:
        indicators.append(_indicator(
            "AUTHORITY_PRESSURE", "Appeal to hierarchical authority",
            Severity.MEDIUM,
            evidence=_quote(combined, authority_hits[0]),
            explanation=(
                "The message leans on rank, or claims the sender is unreachable "
                "by phone. Both discourage the out-of-band check that would "
                "expose the impersonation."
            ),
            confidence=0.8,
        ))

    # -- Credential harvesting ----------------------------------------------
    credential_hits = _find_terms(haystack, CREDENTIAL_TERMS)
    if credential_hits:
        indicators.append(_indicator(
            "CREDENTIAL_SOLICITATION", "Credential harvesting language",
            Severity.HIGH,
            evidence=_quote(combined, credential_hits[0]),
            explanation=(
                "The message solicits account credentials or password action, "
                "the typical initial-access step preceding a mailbox takeover."
            ),
        ))

    # -- Fabricated thread continuity ---------------------------------------
    hijack_hits = _find_terms(haystack, THREAD_HIJACK_TERMS)
    fake_reply = (
        subject.lower().startswith(FAKE_THREAD_PREFIXES)
        and not email.headers.get("in-reply-to")
        and not email.headers.get("references")
    )
    if hijack_hits or fake_reply:
        if fake_reply:
            evidence = f"Subject: {subject!r} with no In-Reply-To or References header"
            detail = ("The subject claims to continue a thread, but the message "
                      "carries no threading headers - the conversation it refers "
                      "to does not exist in this mailbox.")
        else:
            evidence = _quote(combined, hijack_hits[0])
            detail = ("The body asserts a prior conversation, a technique used to "
                      "borrow trust from an exchange that may never have happened.")
        indicators.append(_indicator(
            "THREAD_HIJACK_MARKERS", "Fabricated conversation continuity",
            Severity.MEDIUM, evidence=evidence, explanation=detail,
            confidence=0.9 if fake_reply else 0.7,
        ))

    return indicators
