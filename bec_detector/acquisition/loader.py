"""Parse acquired bytes into `EmailArtifact` objects.

Uses the standard library `email` package with the modern default policy, which
handles MIME decoding, RFC 2047 encoded-word headers, and multipart traversal
without any third-party dependency.
"""

from __future__ import annotations

import email
import mailbox
import re
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from ..models import Attachment, CustodyRecord, EmailArtifact
from .custody import build_custody_record

# Header fields preserved verbatim so indicators can quote them as evidence.
PRESERVED_HEADERS = (
    "from", "to", "cc", "bcc", "reply-to", "return-path", "subject", "date",
    "message-id", "in-reply-to", "references", "authentication-results",
    "received-spf", "dkim-signature", "x-mailer", "x-originating-ip",
    "x-priority", "importance", "sender", "x-forwarded-for",
)


def _decode(value: str | None) -> str:
    """Decode RFC 2047 encoded-words, tolerating malformed input."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return str(value).strip()


def _split_address(raw: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a From/Reply-To header."""
    if not raw:
        return "", ""
    parsed = getaddresses([raw])
    if not parsed:
        return "", ""
    name, addr = parsed[0]
    return _decode(name), addr.strip().lower()


def _all_addresses(raw: str) -> list[str]:
    if not raw:
        return []
    return [a.strip().lower() for _, a in getaddresses([raw]) if a.strip()]


def _extract_body(msg: EmailMessage) -> str:
    """Prefer text/plain; fall back to stripped HTML when that is all we have."""
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            return part.get_content()
    except Exception:
        pass

    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            import re

            html = part.get_content()
            text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
            text = re.sub(r"<br\s*/?>|</p>", "\n", text, flags=re.I)
            text = re.sub(r"<[^>]+>", " ", text)
            return re.sub(r"[ \t]+", " ", text)
    except Exception:
        pass

    # Last resort for non-conforming messages.
    payload = msg.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return str(msg.get_payload() or "")


def _raw_html(msg: EmailMessage) -> str:
    """Return the raw HTML part, if the message has one.

    URL analysis must run against the HTML source rather than the rendered
    text: the anchor href and its visible text only differ in the markup, and
    a plain-text alternative often omits the links entirely.
    """
    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            return part.get_content()
    except Exception:
        pass
    return ""


def _attachments(msg: EmailMessage) -> list[Attachment]:
    """Describe each attachment without ever executing or writing it to disk.

    The payload is decoded in memory only long enough to hash it and sniff its
    real type from the leading magic bytes.
    """
    from ..analysis.attachments import describe_attachment

    found: list[Attachment] = []
    try:
        parts = list(msg.iter_attachments())
    except Exception:
        return found

    for part in parts:
        raw_name = part.get_filename()
        name = _decode(raw_name) if raw_name else ""
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        found.append(describe_attachment(
            filename=name,
            declared_mime=part.get_content_type(),
            payload=payload,
        ))
    return found


def _parse_date(msg: EmailMessage) -> datetime | None:
    raw = msg.get("date")
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except Exception:
        return None
    if dt is None:
        return None
    # Normalise to UTC so behaviour rules compare like with like.
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_artifact(msg: EmailMessage, custody: CustodyRecord) -> EmailArtifact:
    from ..analysis.urls import extract_urls

    from_display, from_address = _split_address(msg.get("from", ""))
    _, reply_to_address = _split_address(msg.get("reply-to", ""))
    _, return_path = _split_address(msg.get("return-path", ""))

    headers: dict[str, str] = {}
    for key in PRESERVED_HEADERS:
        value = msg.get(key)
        if value:
            headers[key] = _decode(value)

    references_raw = msg.get("references") or ""
    references = re.findall(r"<[^>]+>", references_raw) if references_raw else []

    body = _extract_body(msg)
    html_source = _raw_html(msg)

    return EmailArtifact(
        message_id=(msg.get("message-id") or "").strip(),
        from_display=from_display,
        from_address=from_address,
        reply_to_address=reply_to_address,
        return_path=return_path,
        to_addresses=_all_addresses(msg.get("to", "")),
        cc_addresses=_all_addresses(msg.get("cc", "")),
        subject=_decode(msg.get("subject", "")),
        body_text=body,
        date_utc=_parse_date(msg),
        headers=headers,
        received_chain=[_decode(v) for v in msg.get_all("received", [])],
        auth_results=_decode(msg.get("authentication-results", "")),
        attachments=_attachments(msg),
        custody=custody,
        in_reply_to=(msg.get("in-reply-to") or "").strip(),
        references=references,
        urls=extract_urls(html_source or body, bool(html_source)),
    )


def load_bytes(raw: bytes, source_label: str, examiner: str | None = None) -> EmailArtifact:
    """Parse an in-memory message (e.g. an HTTP upload)."""
    custody = build_custody_record(source_label, raw, examiner)
    msg = email.message_from_bytes(raw, policy=default_policy)
    return _to_artifact(msg, custody)


def load_eml(path: str | Path, examiner: str | None = None) -> EmailArtifact:
    """Parse a single .eml file from disk."""
    path = Path(path)
    raw = path.read_bytes()
    custody = build_custody_record(str(path), raw, examiner)
    msg = email.message_from_bytes(raw, policy=default_policy)
    return _to_artifact(msg, custody)


def load_mbox(path: str | Path, examiner: str | None = None) -> list[EmailArtifact]:
    """Parse every message in an mbox archive."""
    path = Path(path)
    artifacts: list[EmailArtifact] = []
    box = mailbox.mbox(str(path), factory=None)
    try:
        for index, message in enumerate(box):
            raw = message.as_bytes()
            custody = build_custody_record(f"{path}#msg{index}", raw, examiner)
            msg = email.message_from_bytes(raw, policy=default_policy)
            artifacts.append(_to_artifact(msg, custody))
    finally:
        box.close()
    return artifacts


def load_path(path: str | Path, examiner: str | None = None) -> list[EmailArtifact]:
    """Acquire from a file or a directory of evidence.

    Accepts a single .eml, an .mbox archive, or a directory scanned recursively
    for .eml files.  Unreadable files are skipped rather than aborting the run.
    """
    path = Path(path)

    if path.is_dir():
        artifacts: list[EmailArtifact] = []
        for candidate in sorted(path.rglob("*")):
            if candidate.suffix.lower() in {".eml", ".txt", ".msg-text"} and candidate.is_file():
                try:
                    artifacts.append(load_eml(candidate, examiner))
                except Exception:
                    continue
        return artifacts

    if path.suffix.lower() == ".mbox":
        return load_mbox(path, examiner)

    return [load_eml(path, examiner)]
