"""Lightweight MITRE ATT&CK evidence mapping.

This maps *observed indicator codes* to techniques that such behaviour is
commonly associated with. It is a reading aid for the investigator, not
attribution.

Every mapping surfaced by this module is labelled:

    "Potential technique mapping based on observed evidence."

No claim is made that a technique was definitively used, and no actor or group
attribution is ever produced.
"""

from __future__ import annotations

from typing import Any

DISCLAIMER = "Potential technique mapping based on observed evidence."

# technique id -> (name, tactic, one-line relevance)
TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "T1566": (
        "Phishing", "Initial Access",
        "Message solicits action through deceptive email content.",
    ),
    "T1566.001": (
        "Spearphishing Attachment", "Initial Access",
        "Message carries an attachment capable of delivering code.",
    ),
    "T1566.002": (
        "Spearphishing Link", "Initial Access",
        "Message contains a link to attacker-controlled content.",
    ),
    "T1534": (
        "Internal Spearphishing", "Lateral Movement",
        "Message uses an existing conversation or internal trust relationship.",
    ),
    "T1656": (
        "Impersonation", "Defense Evasion",
        "Sender presents as a trusted person or organisation.",
    ),
    "T1585.002": (
        "Establish Accounts: Email Accounts", "Resource Development",
        "Attacker-controlled mailbox used to receive victim replies.",
    ),
    "T1586.002": (
        "Compromise Accounts: Email Accounts", "Resource Development",
        "Message may originate from a legitimate but compromised mailbox.",
    ),
    "T1583": (
        "Acquire Infrastructure", "Resource Development",
        "Domain, host or address registered or reused for the operation.",
    ),
    "T1583.001": (
        "Acquire Infrastructure: Domains", "Resource Development",
        "Lookalike domain registered to imitate a trusted party.",
    ),
    "T1036.007": (
        "Masquerading: Double File Extension", "Defense Evasion",
        "Filename constructed to misrepresent the file type.",
    ),
    "T1036.008": (
        "Masquerading: Masquerade File Type", "Defense Evasion",
        "File content does not match its declared type.",
    ),
    "T1598": (
        "Phishing for Information", "Reconnaissance",
        "Message solicits credentials or sensitive detail.",
    ),
    "T1657": (
        "Financial Theft", "Impact",
        "Message seeks to cause an unauthorised transfer of funds.",
    ),
}

# Indicator code -> techniques, for codes that do not carry their own mapping.
CODE_MAP: dict[str, list[str]] = {
    "DISPLAY_NAME_IMPERSONATION": ["T1656", "T1566"],
    "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS": ["T1656"],
    "FREEMAIL_EXEC_CLAIM": ["T1656", "T1585.002"],
    "LOOKALIKE_DOMAIN": ["T1583.001", "T1656"],
    "REPLY_TO_MISMATCH": ["T1585.002"],
    "REPLY_TO_FREEMAIL": ["T1585.002"],
    "SPF_FAIL": ["T1566"],
    "DKIM_FAIL": ["T1566"],
    "DMARC_FAIL": ["T1566"],
    "URGENCY_LANGUAGE": ["T1566"],
    "AUTHORITY_PRESSURE": ["T1656"],
    "SECRECY_REQUEST": ["T1566"],
    "PAYMENT_REQUEST": ["T1657"],
    "BANKING_CHANGE_REQUEST": ["T1657"],
    "GIFT_CARD_REQUEST": ["T1657"],
    "CREDENTIAL_SOLICITATION": ["T1598"],
    "THREAD_FABRICATED_REPLY": ["T1566", "T1534"],
    "THREAD_PAYMENT_PIVOT": ["T1534", "T1657"],
    "THREAD_SENDER_DIVERGENCE": ["T1534"],
    "THREAD_REPLYTO_INTRODUCED": ["T1585.002"],
    "NEW_DOMAIN_FOR_KNOWN_NAME": ["T1583.001", "T1656"],
    "DISPLAY_NAME_CHANGED": ["T1586.002"],
    "STYLE_DEVIATION": ["T1586.002"],
    "ATTACHMENT_EXECUTABLE": ["T1566.001"],
    "ATTACHMENT_MACRO_CAPABLE": ["T1566.001"],
    "ATTACHMENT_TYPE_MISMATCH": ["T1036.008"],
    "ATTACHMENT_DOUBLE_EXTENSION": ["T1036.007"],
    "URL_DISPLAY_MISMATCH": ["T1566.002"],
    "URL_IP_LITERAL": ["T1566.002"],
    "URL_PUNYCODE": ["T1566.002", "T1583.001"],
    "URL_LOOKALIKE_HOST": ["T1583.001"],
    "INTEL_KNOWN_BAD_DOMAIN": ["T1583"],
    "INTEL_IOC_REUSE": ["T1583"],
}


def map_indicators(indicators: list[Any]) -> list[dict[str, str]]:
    """Map fired indicators to potential ATT&CK techniques.

    Returns one entry per distinct technique, listing which indicators
    suggested it, so the investigator can trace the mapping back to evidence.
    """
    suggested: dict[str, set[str]] = {}

    for indicator in indicators:
        codes = list(getattr(indicator, "mitre", []) or [])
        codes.extend(CODE_MAP.get(indicator.code, []))
        for technique in codes:
            if technique in TECHNIQUES:
                suggested.setdefault(technique, set()).add(indicator.code)

    mapped: list[dict[str, str]] = []
    for technique, sources in sorted(suggested.items()):
        name, tactic, relevance = TECHNIQUES[technique]
        mapped.append({
            "technique_id": technique,
            "technique": name,
            "tactic": tactic,
            "relevance": relevance,
            "suggested_by": ", ".join(sorted(sources)),
            "disclaimer": DISCLAIMER,
        })
    return mapped
