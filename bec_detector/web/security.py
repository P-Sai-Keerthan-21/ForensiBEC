"""Upload validation and application security helpers.

Threat model for this application
---------------------------------
The tool ingests hostile input by design: every uploaded file is, by
assumption, attacker-authored. The defences below follow from that.

  * Uploads are never executed. Accepted messages are preserved in the case
    store as original evidence, named only by their SHA-256; attachments are
    never extracted to separate files, so a malicious attachment never
    exists on disk as a file that could be opened or executed.
  * Upload filenames are treated as untrusted data. They are sanitised before
    being used as a label and are never joined to a filesystem path, which
    removes the path-traversal class entirely.
  * Size is enforced while streaming, so an oversized upload is abandoned
    before it is fully read into memory.
  * Only message formats are accepted; other content types are rejected.
  * Errors returned to the client are generic. Stack traces, filesystem paths
    and internal state are not disclosed.

This module intentionally contains no credential handling. Authentication is
out of scope for this milestone; see docs/security.md for the intended design.
"""

from __future__ import annotations

import re
import unicodedata

# 10 MB is far above any legitimate .eml and well below a memory-pressure risk.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FILES_PER_REQUEST = 100
MAX_TOTAL_BYTES = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {".eml", ".msg-text", ".txt", ".mbox"}

ALLOWED_CONTENT_TYPES = {
    "message/rfc822", "text/plain", "application/octet-stream",
    "application/mbox", "",
}

# Anything that could traverse a path or inject control characters.
UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class UploadRejected(ValueError):
    """Raised when an upload fails validation. Message is client-safe."""


def sanitise_filename(raw: str | None) -> str:
    """Reduce an untrusted filename to a safe display label.

    The result is used only as a label in the report and the chain-of-custody
    record. It is never used to open, create or locate a file.
    """
    if not raw:
        return "upload.eml"

    # Strip any directory component from every platform's separator.
    name = raw.replace("\\", "/").split("/")[-1]

    # Normalise so visually-identical Unicode cannot smuggle a different name.
    name = unicodedata.normalize("NFKC", name)

    # Remove control characters, then anything outside the safe set.
    name = "".join(ch for ch in name if ch.isprintable())
    name = UNSAFE_NAME.sub("_", name)

    # Reject names that are only dots after sanitisation (".", "..").
    if not name.strip("._") :
        return "upload.eml"

    return name[:120]


def validate_upload(filename: str | None, content_type: str | None, size: int) -> str:
    """Validate one upload. Returns the sanitised label, or raises."""
    safe = sanitise_filename(filename)

    if size <= 0:
        raise UploadRejected(f"{safe}: file is empty.")

    if size > MAX_UPLOAD_BYTES:
        raise UploadRejected(
            f"{safe}: exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB per-file limit."
        )

    extension = ""
    if "." in safe:
        extension = "." + safe.rsplit(".", 1)[-1].lower()

    if extension and extension not in ALLOWED_EXTENSIONS:
        raise UploadRejected(
            f"{safe}: unsupported file type. Accepted: "
            f"{', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    declared = (content_type or "").split(";")[0].strip().lower()
    if declared and declared not in ALLOWED_CONTENT_TYPES:
        raise UploadRejected(f"{safe}: unsupported content type {declared!r}.")

    return safe


async def read_limited(upload, limit: int = MAX_UPLOAD_BYTES) -> bytes:
    """Read an upload in chunks, aborting as soon as the limit is exceeded.

    Reading the whole body first and checking afterwards would let an oversized
    upload occupy memory before being rejected.
    """
    chunks: list[bytes] = []
    total = 0

    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise UploadRejected(
                f"{sanitise_filename(upload.filename)}: exceeds the "
                f"{limit // (1024 * 1024)} MB per-file limit."
            )
        chunks.append(chunk)

    return b"".join(chunks)
