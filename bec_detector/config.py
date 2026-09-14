"""Tunable detection parameters.

Everything a grader or examiner might want to adjust lives here rather than
being scattered through the rule code: scoring weights, the risk-band cut-offs
and the corporate context the detector is defending.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Organisational context
# ---------------------------------------------------------------------------
# Domains considered "internal".  Display-name impersonation is scored far more
# harshly when an external address claims to be one of our own people.
TRUSTED_DOMAINS: set[str] = {
    "northwind-logistics.com",
    "northwind-logistics.co.uk",
}

# Consumer mailbox providers.  Legitimate for personal mail, highly suspicious
# as the Reply-To on an invoice or payroll request.
FREEMAIL_DOMAINS: set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com", "proton.me",
    "mail.com", "gmx.com", "zoho.com", "yandex.com", "icloud.com",
    "rediffmail.com", "inbox.com", "fastmail.com",
}

# Executive / authority roles commonly impersonated in CEO-fraud.
EXECUTIVE_TITLES: set[str] = {
    "ceo", "cfo", "coo", "cto", "chairman", "chairperson", "president",
    "vice president", "vp", "managing director", "director", "head of finance",
    "finance director", "financial controller", "controller", "treasurer",
    "general manager", "owner", "founder", "partner",
}

# ---------------------------------------------------------------------------
# Scoring weights (points added to the raw score when the rule fires)
# ---------------------------------------------------------------------------
WEIGHTS: dict[str, float] = {
    # --- Sender / identity -------------------------------------------------
    "DISPLAY_NAME_IMPERSONATION": 30.0,
    "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS": 25.0,
    "LOOKALIKE_DOMAIN": 28.0,
    "FREEMAIL_EXEC_CLAIM": 22.0,
    "REPLY_TO_MISMATCH": 20.0,
    "REPLY_TO_FREEMAIL": 18.0,
    "RETURN_PATH_MISMATCH": 12.0,
    "DISPLAY_NAME_IS_EMAIL": 8.0,
    # --- Authentication ----------------------------------------------------
    "SPF_FAIL": 18.0,
    "DKIM_FAIL": 16.0,
    "DMARC_FAIL": 20.0,
    "NO_AUTH_RESULTS": 6.0,
    "SUSPICIOUS_HOP_COUNT": 6.0,
    # --- Behaviour ---------------------------------------------------------
    "FIRST_TIME_SENDER": 10.0,
    "DISPLAY_NAME_CHANGED": 22.0,
    "OFF_HOURS_SEND": 8.0,
    "UNUSUAL_RECIPIENT_SET": 8.0,
    "NEW_DOMAIN_FOR_KNOWN_NAME": 24.0,
    # --- Content / NLP -----------------------------------------------------
    "URGENCY_LANGUAGE": 14.0,
    "PAYMENT_REQUEST": 20.0,
    "BANKING_CHANGE_REQUEST": 30.0,
    "SECRECY_REQUEST": 18.0,
    "AUTHORITY_PRESSURE": 12.0,
    "GIFT_CARD_REQUEST": 26.0,
    "MONEY_ENTITY_PRESENT": 10.0,
    "CREDENTIAL_SOLICITATION": 16.0,
    "THREAD_HIJACK_MARKERS": 10.0,
    # --- Statistical anomaly ----------------------------------------------
    "STATISTICAL_OUTLIER": 12.0,
}

# Per-category ceilings.  Without these, a single verbose phishing body could
# stack a dozen content rules and outweigh hard header evidence.
CATEGORY_CAPS: dict[str, float] = {
    "SENDER": 60.0,
    "AUTHENTICATION": 40.0,
    "BEHAVIOR": 40.0,
    "CONTENT": 70.0,
    "ANOMALY": 15.0,
}

# ---------------------------------------------------------------------------
# Risk bands - lower bound of each band on the normalised 0-100 score
# ---------------------------------------------------------------------------
BAND_THRESHOLDS: list[tuple[float, str]] = [
    (75.0, "CONFIRMED_BEC"),
    (50.0, "LIKELY_BEC"),
    (25.0, "SUSPICIOUS"),
    (0.0, "BENIGN"),
]

# Normalisation divisor: raw score is scaled against this then clamped to 100.
SCORE_NORMALISER: float = 140.0

# Business hours (local 24h clock) used by the off-hours behaviour rule.
BUSINESS_HOURS: tuple[int, int] = (7, 20)

# Default examiner recorded in the chain of custody when none is supplied.
DEFAULT_EXAMINER = "unspecified-examiner"
