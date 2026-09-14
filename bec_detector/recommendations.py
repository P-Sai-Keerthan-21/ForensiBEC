"""Investigator guidance per indicator code.

Kept separate from the analysers so that guidance can be reviewed and edited by
an investigations lead without touching detection logic, and so the original
core analysers did not need rewriting when the recommendation field was added.

`fuse()` backfills any indicator that does not carry its own recommendation.
Wording is deliberately procedural -- what to do next -- and never asserts that
a crime occurred.
"""

from __future__ import annotations

VERIFY_OUT_OF_BAND = (
    "Verify the request by telephone using a number already held on file, "
    "never one supplied in this message."
)

RECOMMENDATIONS: dict[str, str] = {
    # -- Identity ----------------------------------------------------------
    "DISPLAY_NAME_IMPERSONATION": (
        "Do not action the request. " + VERIFY_OUT_OF_BAND
        + " Record the sending domain as an IOC."
    ),
    "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS": (
        "Inspect the full From header in the original message source and "
        "confirm the true sending address with the purported sender."
    ),
    "DISPLAY_NAME_IS_EMAIL": (
        "Treat as a weak signal; confirm the true sending address in the raw headers."
    ),
    "LOOKALIKE_DOMAIN": (
        "Block the lookalike domain at the mail gateway and add it to the IOC "
        "list. Check mail logs for other messages from the same domain."
    ),
    "FREEMAIL_EXEC_CLAIM": (
        "Do not action. Executives do not issue payment instructions from "
        "personal webmail. " + VERIFY_OUT_OF_BAND
    ),
    "REPLY_TO_MISMATCH": (
        "Do not reply. Confirm the correct reply address with the sender "
        "through a known-good channel."
    ),
    "REPLY_TO_FREEMAIL": (
        "Do not reply. Record the consumer address as an IOC and block it."
    ),
    "RETURN_PATH_MISMATCH": (
        "Corroborate with the authentication results before drawing a "
        "conclusion; mailing lists and relays produce this legitimately."
    ),
    # -- Authentication ------------------------------------------------------
    "SPF_FAIL": (
        "Treat the sender as unverified. Check whether the sending IP appears "
        "in other recent mail, and review the gateway's SPF enforcement policy."
    ),
    "DKIM_FAIL": (
        "Treat message integrity as unverified. Preserve the original message "
        "with full headers before any further handling."
    ),
    "DMARC_FAIL": (
        "The domain owner's own policy rejects this message. Quarantine it and "
        "review why it was delivered."
    ),
    "NO_AUTH_RESULTS": (
        "Acquire the message from the receiving gateway instead, so that "
        "authentication results are available for analysis."
    ),
    "SUSPICIOUS_HOP_COUNT": (
        "Review the Received chain for relays outside expected mail routing."
    ),
    # -- Behaviour -----------------------------------------------------------
    "FIRST_TIME_SENDER": (
        "Apply new-supplier or new-contact verification procedure before "
        "actioning any request."
    ),
    "DISPLAY_NAME_CHANGED": (
        "Review the sender's recent mail for signs of mailbox compromise, and "
        "confirm identity with the correspondent directly."
    ),
    "OFF_HOURS_SEND": (
        "Note the send time; corroborate with other indicators before acting."
    ),
    "UNUSUAL_RECIPIENT_SET": (
        "Confirm why this sender is now addressing this group."
    ),
    "NEW_DOMAIN_FOR_KNOWN_NAME": (
        "Do not action. Contact the correspondent on their established address "
        "and confirm whether they changed domain."
    ),
    # -- Content -------------------------------------------------------------
    "URGENCY_LANGUAGE": (
        "Do not let stated deadlines bypass the normal approval workflow. "
        "Time pressure is the mechanism, not the justification."
    ),
    "PAYMENT_REQUEST": (
        "Route through the standard payment approval process. " + VERIFY_OUT_OF_BAND
    ),
    "BANKING_CHANGE_REQUEST": (
        "Halt any payment. Bank detail changes must be confirmed by telephone "
        "with a known contact and re-verified against supplier records."
    ),
    "SECRECY_REQUEST": (
        "Escalate to a manager regardless of the request for confidentiality. "
        "A legitimate instruction never requires bypassing controls."
    ),
    "AUTHORITY_PRESSURE": (
        "Confirm the instruction directly with the named individual through an "
        "established channel."
    ),
    "GIFT_CARD_REQUEST": (
        "Do not purchase. Report to the security team; this pattern has no "
        "legitimate business equivalent."
    ),
    "MONEY_ENTITY_PRESENT": (
        "Record the amount and beneficiary details in the case file as "
        "potential transaction indicators."
    ),
    "CREDENTIAL_SOLICITATION": (
        "Do not enter credentials. If any were submitted, reset them "
        "immediately and review account sign-in logs."
    ),
    "THREAD_HIJACK_MARKERS": (
        "Confirm the referenced prior conversation actually exists in the "
        "mailbox before trusting the continuity."
    ),
    # -- Statistical ---------------------------------------------------------
    "STATISTICAL_OUTLIER": (
        "Weak corroborating signal only. Review alongside stronger indicators."
    ),
}

DEFAULT_RECOMMENDATION = (
    "Review this finding alongside the other indicators before deciding on action."
)


def recommendation_for(code: str) -> str:
    return RECOMMENDATIONS.get(code, DEFAULT_RECOMMENDATION)
