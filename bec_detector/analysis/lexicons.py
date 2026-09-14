"""Linguistic signal lists for the content analyser.

These are the BEC social-engineering patterns documented in the FBI IC3 BEC
advisories and the common vendor-fraud / CEO-fraud playbooks: manufactured
urgency, appeal to authority, enforced secrecy, and a payment instruction.
"""

from __future__ import annotations

# Manufactured time pressure.
URGENCY_TERMS: set[str] = {
    "urgent", "urgently", "immediate", "immediately", "asap", "right away",
    "as soon as possible", "time sensitive", "time-sensitive", "deadline",
    "expires", "expiring", "today", "within the hour", "before close of business",
    "cob", "eod", "end of day", "quickly", "promptly", "no delay", "without delay",
    "last chance", "final notice", "act now", "critical", "emergency", "rush",
}

# Appeal to hierarchy / pressure from a superior.
AUTHORITY_TERMS: set[str] = {
    "i need you to", "i want you to", "i am counting on you", "do this for me",
    "as your", "on my behalf", "i am currently", "i'm currently", "i am in a meeting",
    "i'm in a meeting", "i am travelling", "i'm travelling", "i am traveling",
    "cannot talk", "can't talk", "unable to talk", "do not call me", "don't call me",
    "trust you", "handle this personally", "my authority", "approved by me",
    "i authorise", "i authorize", "board approved",
}

# Requests to bypass normal controls.
SECRECY_TERMS: set[str] = {
    "confidential", "strictly confidential", "keep this between us",
    "do not discuss", "don't discuss", "do not share", "don't share",
    "discreet", "discretion", "private matter", "not inform", "without informing",
    "no one else", "nobody else", "internal only", "off the record",
    "do not copy", "don't copy", "do not cc", "don't cc",
}

# A financial instruction is the payload of nearly every real BEC.
PAYMENT_TERMS: set[str] = {
    "wire transfer", "wire the", "bank transfer", "transfer the funds",
    "transfer funds", "remit", "remittance", "payment", "invoice", "outstanding balance",
    "make a payment", "process the payment", "release the payment", "settle the invoice",
    "purchase order", "swift", "iban", "sort code", "routing number",
    "account number", "beneficiary", "bank details",
    # NOTE: bare "payable" is deliberately absent - it matches the department
    # name "accounts payable" and produced false positives on routine mail.
}

# The single highest-signal BEC phrase family: changing where money goes.
BANKING_CHANGE_TERMS: set[str] = {
    "change the bank", "change our bank", "changed our bank", "new bank details",
    "updated bank details", "update the bank details", "update our banking",
    "new account details", "updated account details", "change of account",
    "new beneficiary", "different account", "alternate account", "revised bank",
    "banking details have changed", "our banking has changed", "new remittance",
    "update your records", "amend the bank",
}

# Gift-card fraud is a distinct, easily-recognised BEC variant.
GIFT_CARD_TERMS: set[str] = {
    "gift card", "gift cards", "itunes card", "google play card", "steam card",
    "amazon card", "voucher code", "scratch the back", "scratch off the back",
    "card codes", "redeem code",
}

# Credential harvesting overlaps with BEC as the initial access step.
CREDENTIAL_TERMS: set[str] = {
    "verify your account", "confirm your password", "your password will expire",
    "re-enter your credentials", "reconfirm your login", "sign in to verify",
    "validate your mailbox", "session expired", "unusual sign-in",
    "click here to verify", "update your password", "mailbox full",
}

# Markers suggesting an attacker has grafted onto an existing conversation.
THREAD_HIJACK_TERMS: set[str] = {
    "as per our previous", "further to our conversation", "following up on my last",
    "per my last email", "as discussed earlier", "regarding the attached invoice",
}

# Subject-line prefixes an attacker fakes to imply an existing thread.
FAKE_THREAD_PREFIXES: tuple[str, ...] = ("re:", "fw:", "fwd:")
