"""Conversation / thread analysis.

Reconstructs conversations from Message-ID, In-Reply-To and References, then
looks for the ways a BEC actor grafts onto or fabricates a thread.

Evidence discipline
-------------------
Thread hijacking is a serious allegation, so this module only reports what the
headers actually support:

  * A subject starting "Re:" with NO threading headers is a *fabricated* reply
    -- stated as observed fact, because the headers are simply absent.
  * A reply whose parent Message-ID is not in the acquired corpus is reported
    as an unknown parent, NOT as hijacking -- the parent may simply not have
    been collected.
  * Sender or Reply-To divergence *within a reconstructed thread* is the only
    case where hijacking is offered, and it is labelled INFERRED.

If the corpus contains no thread for a message, no thread indicator is raised
at all rather than guessing.
"""

from __future__ import annotations

import re

from ..config import WEIGHTS
from ..models import Category, Confidence, EmailArtifact, Indicator, Severity
from .lexicons import BANKING_CHANGE_TERMS, PAYMENT_TERMS

REPLY_PREFIX = re.compile(r"^\s*((re|fw|fwd|aw|sv)\s*:\s*)+", re.I)


def normalise_subject(subject: str) -> str:
    """Strip reply/forward prefixes so a thread can be keyed by base subject."""
    return REPLY_PREFIX.sub("", subject or "").strip().lower()


def _indicator(code: str, title: str, severity: Severity, evidence: str,
               explanation: str, recommendation: str, confidence: float = 1.0,
               basis: Confidence = Confidence.OBSERVED,
               mitre: list[str] | None = None) -> Indicator:
    return Indicator(
        code=code, title=title, category=Category.THREAD, severity=severity,
        weight=WEIGHTS.get(code, 5.0), confidence=confidence,
        evidence=evidence, explanation=explanation,
        basis=basis, recommendation=recommendation, mitre=mitre or [],
    )


def _mentions(text: str, terms: set[str]) -> bool:
    lowered = re.sub(r"\s+", " ", (text or "").lower())
    return any(term in lowered for term in terms)


class ThreadIndex:
    """Reconstructs conversations across the acquired corpus from HEADERS.

    A conversation is identified by its root Message-ID: the first entry of
    References, otherwise the earliest ancestor reachable through In-Reply-To,
    otherwise the message's own Message-ID.

    An earlier version grouped messages by normalised subject, contrary to this
    module's documented design. Unrelated messages that happened to share a
    generic subject ("Invoice attached") were then treated as one conversation
    and the second sender was reported as an intruder. Subject similarity is
    not evidence that two messages belong together; threading headers are.
    """

    def __init__(self) -> None:
        self.by_message_id: dict[str, EmailArtifact] = {}
        self._members: list[EmailArtifact] = []
        self._roots: dict[int, str] | None = None

    def observe(self, email: EmailArtifact) -> None:
        if email.message_id:
            self.by_message_id[email.message_id.strip()] = email
        self._members.append(email)
        self._roots = None  # a new message may complete an ancestor chain

    def observe_all(self, emails: list[EmailArtifact]) -> None:
        for email in emails:
            self.observe(email)

    def root_of(self, email: EmailArtifact) -> str:
        """Root Message-ID of the conversation this message belongs to."""
        refs = [r.strip() for r in email.references if r.strip()]
        if refs:
            return refs[0]
        parent = (email.in_reply_to or "").strip()
        seen: set[str] = set()
        while parent and parent in self.by_message_id and parent not in seen:
            seen.add(parent)
            ancestor = self.by_message_id[parent]
            ancestor_refs = [r.strip() for r in ancestor.references if r.strip()]
            if ancestor_refs:
                return ancestor_refs[0]
            if not (ancestor.in_reply_to or "").strip():
                return parent
            parent = ancestor.in_reply_to.strip()
        if parent:
            return parent
        own = (email.message_id or "").strip()
        return own or f"sha256:{email.custody.sha256}"

    def thread_for(self, email: EmailArtifact) -> list[EmailArtifact]:
        """Every acquired message in the same header-defined conversation."""
        if self._roots is None:
            self._roots = {id(m): self.root_of(m) for m in self._members}
        root = self.root_of(email)
        members = [m for m in self._members if self._roots.get(id(m)) == root]
        members.sort(key=lambda e: (e.date_utc is None, e.date_utc))
        return members

    def analyse(self, email: EmailArtifact) -> list[Indicator]:
        indicators: list[Indicator] = []

        claims_reply = bool(REPLY_PREFIX.match(email.subject or ""))
        has_threading = bool(email.in_reply_to or email.references)

        # -- Fabricated continuity: claims to be a reply, carries no headers --
        if claims_reply and not has_threading:
            indicators.append(_indicator(
                "THREAD_FABRICATED_REPLY", "Reply prefix with no threading headers",
                Severity.HIGH,
                evidence=(
                    f"Subject: {email.subject!r}; In-Reply-To: absent; References: absent"
                ),
                explanation=(
                    "The subject presents this as a continuation of an existing "
                    "conversation, but the message carries neither In-Reply-To "
                    "nor References. A genuine reply generated by a mail client "
                    "would carry at least one."
                ),
                recommendation=(
                    "Ask the purported sender, through a known-good channel, "
                    "whether the referenced conversation exists."
                ),
                mitre=["T1566"],
            ))

        # -- Reply to a parent that is not in the evidence set ---------------
        if email.in_reply_to and email.in_reply_to not in self.by_message_id:
            indicators.append(_indicator(
                "THREAD_UNKNOWN_PARENT", "Referenced parent message not in evidence set",
                Severity.LOW,
                evidence=f"In-Reply-To: {email.in_reply_to}",
                explanation=(
                    "The parent message is not present in the acquired corpus. "
                    "This is expected when only part of a mailbox was collected, "
                    "so it is recorded as a collection gap rather than as a finding "
                    "against the message."
                ),
                recommendation=(
                    "Acquire the referenced message before drawing any conclusion "
                    "about this conversation."
                ),
                basis=Confidence.INSUFFICIENT,
                confidence=0.4,
            ))

        # -- Everything below needs a reconstructed thread -------------------
        thread = [m for m in self.thread_for(email) if m.custody.sha256 != email.custody.sha256]
        if not thread:
            return indicators

        earlier = [m for m in thread
                   if m.date_utc and email.date_utc and m.date_utc < email.date_utc]
        if not earlier:
            return indicators

        prior_senders = {m.from_address for m in earlier if m.from_address}

        # Everyone already party to this conversation in any role. A recipient
        # who later replies is a normal participant, not a new sender -- keying
        # this off prior *senders* alone would flag every ordinary two-party
        # exchange, since the second party is always a first-time sender.
        prior_participants: set[str] = set(prior_senders)
        for m in earlier:
            prior_participants |= set(m.to_addresses) | set(m.cc_addresses)
            if m.reply_to_address:
                prior_participants.add(m.reply_to_address)

        # -- An address never party to this conversation joins it -------------
        if email.from_address and email.from_address not in prior_participants:
            indicators.append(_indicator(
                "THREAD_SENDER_DIVERGENCE", "Message from an address not party to this conversation",
                Severity.HIGH,
                evidence=(
                    f"thread rooted at {self.root_of(email)!r} involved "
                    f"{sorted(prior_participants)}; this message is from "
                    f"{email.from_address!r}, which appears in no earlier message"
                ),
                explanation=(
                    "This sender was neither an author nor a recipient of any "
                    "earlier message in the conversation, yet is writing into it. "
                    "That is consistent with an outsider inserting themselves "
                    "into an existing exchange."
                ),
                recommendation=(
                    "Confirm with an established participant that this sender is "
                    "a legitimate party to the conversation."
                ),
                basis=Confidence.INFERRED,
                confidence=0.85,
                mitre=["T1566", "T1534"],
            ))

        # -- Reply-To introduced partway through -----------------------------
        prior_reply_to = {m.reply_to_address for m in earlier if m.reply_to_address}
        if email.reply_to_address and email.reply_to_address not in prior_reply_to:
            if not any(m.reply_to_address for m in earlier):
                indicators.append(_indicator(
                    "THREAD_REPLYTO_INTRODUCED", "Reply-To introduced partway through a conversation",
                    Severity.HIGH,
                    evidence=(
                        f"no earlier message in this thread set Reply-To; "
                        f"this message sets Reply-To: {email.reply_to_address}"
                    ),
                    explanation=(
                        "Replies to this conversation will now go somewhere they "
                        "did not go before. Redirecting an established thread is a "
                        "direct mechanism for intercepting the victim's response."
                    ),
                    recommendation=(
                        "Do not reply. Verify the change with the original "
                        "correspondent using contact details held on file."
                    ),
                    basis=Confidence.INFERRED,
                    confidence=0.9,
                    mitre=["T1566"],
                ))

        # -- New participants appearing --------------------------------------
        current = set(email.to_addresses) | set(email.cc_addresses)
        added = current - prior_participants
        removed = prior_participants - current - {email.from_address}

        if added and prior_participants:
            indicators.append(_indicator(
                "THREAD_NEW_PARTICIPANT", "New recipients added to an existing conversation",
                Severity.LOW,
                evidence=f"added to thread: {sorted(added)}",
                explanation=(
                    "Recipients not previously party to this conversation now "
                    "appear on it. This is often benign, but narrowing a thread "
                    "onto finance staff is a common BEC manoeuvre."
                ),
                recommendation="Confirm the new recipients were added deliberately.",
                basis=Confidence.INFERRED,
                confidence=0.5,
            ))

        # -- The pivot that matters: thread turns into a payment instruction --
        now_financial = _mentions(f"{email.subject} {email.body_text}",
                                  BANKING_CHANGE_TERMS | PAYMENT_TERMS)
        was_financial = any(
            _mentions(f"{m.subject} {m.body_text}", BANKING_CHANGE_TERMS | PAYMENT_TERMS)
            for m in earlier
        )
        identity_changed = bool(
            (email.from_address and email.from_address not in prior_senders)
            or (email.reply_to_address and email.reply_to_address not in prior_reply_to)
        )

        if now_financial and not was_financial and identity_changed:
            indicators.append(_indicator(
                "THREAD_PAYMENT_PIVOT", "Conversation pivots to a payment instruction as identity changes",
                Severity.CRITICAL,
                evidence=(
                    f"no earlier message in thread rooted at {self.root_of(email)!r} "
                    f"discussed payment; this message does, and the sender or "
                    f"Reply-To also changed"
                ),
                explanation=(
                    "A previously non-financial conversation has become a payment "
                    "instruction at the same moment the participating identity "
                    "changed. The combination is the defining shape of "
                    "conversation-hijacking BEC."
                ),
                recommendation=(
                    "Halt any payment arising from this thread. Verify by "
                    "telephone using a number held on file, never one supplied "
                    "in this conversation. Preserve the whole thread for the case file."
                ),
                basis=Confidence.INFERRED,
                confidence=0.9,
                mitre=["T1566", "T1534"],
            ))

        if removed and prior_participants and now_financial:
            indicators.append(_indicator(
                "THREAD_NEW_PARTICIPANT", "Participants dropped as the thread turns financial",
                Severity.MEDIUM,
                evidence=f"no longer addressed: {sorted(removed)}",
                explanation=(
                    "Recipients who were part of this conversation have been "
                    "removed at the point it became financial, which reduces the "
                    "number of people able to challenge the request."
                ),
                recommendation="Re-include the original participants before actioning anything.",
                basis=Confidence.INFERRED,
                confidence=0.7,
            ))

        return indicators


def analyse_thread(email: EmailArtifact, index: ThreadIndex) -> list[Indicator]:
    """Convenience wrapper mirroring the other analyser signatures."""
    return index.analyse(email)
