"""Tunable detection parameters.

Everything a grader or examiner might want to adjust lives here rather than
being scattered through the rule code: scoring weights, the risk-band cut-offs
and the corporate context the detector is defending.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------
# Anchored to the project, not the current working directory, so the CLI and
# the web server find the same cases, IOC store and intelligence list however
# they are launched. FORENSIBEC_DATA_DIR overrides the data location.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR: Path = PROJECT_ROOT / "output"
LOCAL_INTEL_FILE: Path = PROJECT_ROOT / "data" / "local_intel.json"


def display_path(path: str | Path) -> str:
    """How a local file is named in reports and logs.

    Paths inside the project are shown relative to it, so reports and the API
    do not disclose the install location or the Windows user name.
    """
    path = Path(path)
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def data_dir() -> Path:
    """Root for all persisted state (cases, IOC store)."""
    override = os.environ.get("FORENSIBEC_DATA_DIR")
    return Path(override) if override else DEFAULT_DATA_DIR

# ---------------------------------------------------------------------------
# Organisational context
# ---------------------------------------------------------------------------
# Domains considered "internal".  Display-name impersonation is scored far more
# harshly when an external address claims to be one of our own people.
TRUSTED_DOMAINS: set[str] = {
    "northwind-logistics.com",
    "northwind-logistics.co.uk",
}

# The organisation's own mail infrastructure. These appear in the Received
# chain of every legitimate message, so correlating cases on them would link
# every case to every other case. Operators should list their own relays here.
TRUSTED_RELAY_IPS: set[str] = {
    "198.51.100.24",  # sample internal relay used by the synthetic corpus
}

# Known legitimate external correspondents. Never used as cross-case links:
# a genuine partner domain that was SPOOFED in one confirmed BEC would otherwise
# become an "indicator" that penalises every later benign message from that
# partner. Operators should list their established suppliers and customers.
CORRELATION_ALLOWLIST: set[str] = {
    # Legitimate partners of the fictional organisation in the synthetic corpus.
    "delaney-freight.co", "harborline-supplies.com", "bergindustrial.se",
    "castellan-pack.eu", "orrinmarine.co.uk",
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
    "MIXED_SCRIPT_DOMAIN": 24.0,
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
    # --- Thread / conversation --------------------------------------------
    "THREAD_FABRICATED_REPLY": 18.0,
    "THREAD_UNKNOWN_PARENT": 12.0,
    "THREAD_NEW_PARTICIPANT": 14.0,
    "THREAD_REPLYTO_INTRODUCED": 26.0,
    "THREAD_SENDER_DIVERGENCE": 28.0,
    "THREAD_PAYMENT_PIVOT": 30.0,
    # --- URL (static analysis only) ----------------------------------------
    "URL_DISPLAY_MISMATCH": 26.0,
    "URL_IP_LITERAL": 20.0,
    "URL_PUNYCODE": 20.0,
    "URL_SHORTENER": 12.0,
    "URL_SUSPICIOUS_PATH": 14.0,
    "URL_NO_TLS": 6.0,
    "URL_ODD_HOST": 12.0,
    "URL_LOOKALIKE_HOST": 22.0,
    "URL_HIGH_VOLUME": 5.0,
    # --- Attachment (static analysis only) ---------------------------------
    "ATTACHMENT_TYPE_MISMATCH": 28.0,
    "ATTACHMENT_EXECUTABLE": 30.0,
    "ATTACHMENT_MACRO_CAPABLE": 20.0,
    "ATTACHMENT_ARCHIVE": 10.0,
    "ATTACHMENT_DOUBLE_EXTENSION": 30.0,
    "ATTACHMENT_EMPTY": 4.0,
    # --- Stylometry ---------------------------------------------------------
    "STYLE_DEVIATION": 18.0,
    "STYLE_GREETING_CHANGE": 12.0,
    "STYLE_SIGNATURE_CHANGE": 14.0,
    # --- Local threat intelligence -----------------------------------------
    "INTEL_KNOWN_BAD_DOMAIN": 30.0,
    "INTEL_KNOWN_BAD_ADDRESS": 30.0,
    "INTEL_IOC_REUSE": 16.0,
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
    "THREAD": 45.0,
    "URL": 45.0,
    "ATTACHMENT": 50.0,
    "STYLOMETRY": 25.0,
    "INTELLIGENCE": 40.0,
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
