"""Investigation timeline construction.

Timestamps are only ever taken from something that actually carries one:

  * the message Date header            -> "email sent/received"
  * the chain-of-custody acquisition   -> "evidence acquired"
  * the analysis run                   -> "analysis performed"

Content events (payment request, account change, suspicious URL, attachment)
are attached to the timestamp of the message that contains them, and their
`source` field says so. No event is ever given an invented time, and a message
with no parsable Date contributes no message-time event at all.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Assessment, EmailArtifact, TimelineEvent

# Indicator codes that represent a meaningful investigative moment.
EVENT_CODES: dict[str, tuple[str, str]] = {
    "PAYMENT_REQUEST": ("payment_request", "Payment or transfer requested"),
    "BANKING_CHANGE_REQUEST": ("account_change", "Change of payment destination requested"),
    "GIFT_CARD_REQUEST": ("payment_request", "Gift-card purchase solicited"),
    "CREDENTIAL_SOLICITATION": ("credential_request", "Credentials solicited"),
    "THREAD_PAYMENT_PIVOT": ("account_change", "Conversation pivoted to payment instruction"),
    "THREAD_REPLYTO_INTRODUCED": ("reply_to_change", "Reply-To introduced mid-conversation"),
    "REPLY_TO_MISMATCH": ("reply_to_change", "Reply-To differs from sending address"),
}


def _iso(dt: datetime | None) -> str:
    return dt.isoformat(timespec="seconds") if dt else ""


def build_message_timeline(assessment: Assessment) -> list[TimelineEvent]:
    """Timeline for a single assessed message."""
    email: EmailArtifact = assessment.artifact
    events: list[TimelineEvent] = []
    evidence_id = email.evidence_id

    if email.date_utc:
        events.append(TimelineEvent(
            timestamp=_iso(email.date_utc),
            kind="email_sent",
            description=(
                f"Message {email.subject!r} sent by {email.from_address or 'unknown sender'}"
            ),
            source="Date header",
            evidence_id=evidence_id,
        ))

        # Content events share the message timestamp; the source field makes
        # clear they are derived from that message rather than independently dated.
        seen: set[str] = set()
        for indicator in assessment.indicators:
            mapped = EVENT_CODES.get(indicator.code)
            if not mapped or mapped[0] in seen:
                continue
            seen.add(mapped[0])
            events.append(TimelineEvent(
                timestamp=_iso(email.date_utc),
                kind=mapped[0],
                description=mapped[1],
                source=f"derived from {indicator.code} in this message",
                evidence_id=evidence_id,
            ))

        for url in email.urls[:5]:
            if url.is_ip_literal or url.is_punycode or url.display_mismatch:
                events.append(TimelineEvent(
                    timestamp=_iso(email.date_utc),
                    kind="suspicious_url",
                    description=f"Suspicious link present: {url.raw[:100]}",
                    source="URL extracted from message body",
                    evidence_id=evidence_id,
                ))
                break

        for item in email.attachments:
            events.append(TimelineEvent(
                timestamp=_iso(email.date_utc),
                kind="attachment",
                description=(
                    f"Attachment {item.filename!r} ({item.detected_type}, "
                    f"{item.size_bytes} bytes)"
                ),
                source="MIME part in this message",
                evidence_id=evidence_id,
            ))
    else:
        # Explicitly record the gap rather than silently omitting the message.
        events.append(TimelineEvent(
            timestamp="",
            kind="undated",
            description=(
                f"Message {email.subject!r} carries no parsable Date header; "
                "it cannot be placed on the timeline"
            ),
            source="absent Date header",
            evidence_id=evidence_id,
        ))

    events.append(TimelineEvent(
        timestamp=email.custody.acquired_utc,
        kind="evidence_acquired",
        description=f"Evidence {evidence_id} acquired by {email.custody.examiner}",
        source="chain-of-custody record",
        evidence_id=evidence_id,
    ))

    return events


def build_case_timeline(assessments: list[Assessment]) -> list[TimelineEvent]:
    """Merge per-message timelines into one chronological case view.

    Undated events are kept and sorted to the end rather than discarded, so a
    collection gap stays visible in the report.
    """
    events: list[TimelineEvent] = []
    for assessment in assessments:
        events.extend(assessment.timeline or build_message_timeline(assessment))

    events.append(TimelineEvent(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        kind="analysis",
        description=f"Automated BEC analysis completed over {len(assessments)} message(s)",
        source="this analysis run",
    ))

    events.sort(key=lambda e: (e.timestamp == "", e.timestamp))
    return events
