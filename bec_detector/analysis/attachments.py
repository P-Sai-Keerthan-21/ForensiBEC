"""Static attachment analysis.

Attachments are described, hashed and type-checked. They are NEVER executed,
never extracted to a separate file, and never opened by any external handler.
The payload is held in memory only long enough to hash it and read its leading
magic bytes.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

from ..config import WEIGHTS
from ..models import Attachment, Category, Confidence, EmailArtifact, Indicator, Severity

# Leading magic bytes -> real file type. Enough to catch the mismatches that
# matter in BEC without pulling in a binary signature database.
MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip-container"),   # also .docx/.xlsx/.pptx/.jar
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),  # legacy .doc/.xls/.msg
    (b"MZ", "pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"\xca\xfe\xba\xbe", "java-class"),
    (b"GIF8", "gif"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
)

# Extensions that can execute code on open, directly or via script host.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "cpl", "jar", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "ps1", "hta", "lnk", "reg", "dll",
    "app", "iso", "img", "one",
}

# Office formats that can carry macros.
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"}

# Archive formats commonly used to smuggle the above past a gateway.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}

# What each extension is expected to look like on disk.
EXPECTED_TYPE: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "docx": {"zip-container"}, "xlsx": {"zip-container"}, "pptx": {"zip-container"},
    "docm": {"zip-container"}, "xlsm": {"zip-container"},
    "doc": {"ole2"}, "xls": {"ole2"}, "ppt": {"ole2"}, "msg": {"ole2"},
    "zip": {"zip-container"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "exe": {"pe-executable"}, "dll": {"pe-executable"},
    "rtf": {"rtf"},
}

# Declared MIME -> expected sniffed type, for the declared-vs-actual check.
MIME_EXPECTED: dict[str, set[str]] = {
    "application/pdf": {"pdf"},
    "image/png": {"png"},
    "image/jpeg": {"jpeg"},
    "image/gif": {"gif"},
    "application/zip": {"zip-container"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {"zip-container"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {"zip-container"},
    "application/msword": {"ole2"},
    "application/vnd.ms-excel": {"ole2"},
}


def sniff_type(payload: bytes) -> str:
    """Identify a file from its leading bytes. Returns 'unknown' if unmatched."""
    if not payload:
        return "empty"
    for signature, name in MAGIC_SIGNATURES:
        if payload.startswith(signature):
            return name
    # Heuristic: mostly-printable content with no known signature is text.
    sample = payload[:512]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if sample and printable / len(sample) > 0.9:
        return "text"
    return "unknown"


def _extension(filename: str) -> str:
    """Final extension, lower-cased, with no leading dot."""
    if not filename:
        return ""
    return PurePosixPath(filename).suffix.lstrip(".").lower()


def _double_extension(filename: str) -> str:
    """Return the inner extension when a name has a deceptive double suffix.

    'invoice.pdf.exe' returns 'pdf' - the extension the recipient is meant to
    read while the file is actually the outer one.
    """
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        inner = parts[-2]
        if inner in EXPECTED_TYPE or inner in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg"}:
            return inner
    return ""


def describe_attachment(filename: str, declared_mime: str, payload: bytes) -> Attachment:
    """Build the static description of one attachment. Never executes it."""
    extension = _extension(filename)
    detected = sniff_type(payload)

    expected = EXPECTED_TYPE.get(extension)
    mime_expected = MIME_EXPECTED.get((declared_mime or "").lower())

    mismatch = False
    notes: list[str] = []

    if expected and detected not in expected and detected not in {"empty", "unknown"}:
        mismatch = True
        notes.append(f"extension .{extension} expects {sorted(expected)}, content is {detected}")

    if mime_expected and detected not in mime_expected and detected not in {"empty", "unknown"}:
        mismatch = True
        notes.append(f"declared {declared_mime} but content is {detected}")

    inner = _double_extension(filename)
    if inner:
        notes.append(f"double extension: appears as .{inner} but is .{extension}")

    return Attachment(
        filename=filename or "<unnamed>",
        declared_mime=declared_mime or "application/octet-stream",
        detected_type=detected,
        extension=extension,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest() if payload else "",
        type_mismatch=mismatch,
        notes="; ".join(notes),
    )


def _indicator(code: str, title: str, severity: Severity, evidence: str,
               explanation: str, recommendation: str, confidence: float = 1.0,
               basis: Confidence = Confidence.OBSERVED,
               mitre: list[str] | None = None) -> Indicator:
    return Indicator(
        code=code, title=title, category=Category.ATTACHMENT, severity=severity,
        weight=WEIGHTS.get(code, 5.0), confidence=confidence,
        evidence=evidence, explanation=explanation,
        basis=basis, recommendation=recommendation, mitre=mitre or [],
    )


def analyse_attachments(email: EmailArtifact) -> list[Indicator]:
    """Raise indicators for statically suspicious attachments."""
    indicators: list[Indicator] = []

    for item in email.attachments:
        label = f"{item.filename} ({item.size_bytes} bytes, sha256 {item.sha256[:16]}...)"

        if item.type_mismatch:
            indicators.append(_indicator(
                "ATTACHMENT_TYPE_MISMATCH", "Attachment content does not match its name or MIME type",
                Severity.CRITICAL,
                evidence=f"{label} - {item.notes}",
                explanation=(
                    "The file's real format, read from its magic bytes, differs "
                    "from what its extension or declared MIME type claims. This "
                    "is a deliberate technique to get past filtering and to "
                    "mislead the recipient about what they are opening."
                ),
                recommendation=(
                    "Do not open. Preserve the hash as an IOC and submit the file "
                    "to an isolated malware analysis environment."
                ),
                mitre=["T1036.008"],
            ))

        if item.extension in EXECUTABLE_EXTENSIONS:
            indicators.append(_indicator(
                "ATTACHMENT_EXECUTABLE", "Executable or scriptable attachment",
                Severity.CRITICAL,
                evidence=label,
                explanation=(
                    f"A .{item.extension} file can execute code when opened. "
                    "Business correspondence does not normally carry one."
                ),
                recommendation="Do not open under any circumstances. Quarantine and hand to malware analysis.",
                mitre=["T1566.001"],
            ))

        if item.extension in MACRO_EXTENSIONS:
            indicators.append(_indicator(
                "ATTACHMENT_MACRO_CAPABLE", "Macro-enabled office document",
                Severity.HIGH,
                evidence=label,
                explanation=(
                    f"A .{item.extension} file can carry executable macros, a "
                    "long-standing initial-access technique."
                ),
                recommendation="Open only in a sandboxed viewer with macros disabled, if at all.",
                mitre=["T1566.001"],
            ))

        if item.extension in ARCHIVE_EXTENSIONS:
            indicators.append(_indicator(
                "ATTACHMENT_ARCHIVE", "Archive attachment",
                Severity.MEDIUM,
                evidence=label,
                explanation=(
                    "Archives conceal their contents from many mail gateways. "
                    "This tool does not extract archives, so the contents are "
                    "unexamined."
                ),
                recommendation="Extract and inspect only in an isolated environment.",
                basis=Confidence.INFERRED,
                confidence=0.7,
            ))

        if _double_extension(item.filename):
            indicators.append(_indicator(
                "ATTACHMENT_DOUBLE_EXTENSION", "Deceptive double file extension",
                Severity.CRITICAL,
                evidence=f"{item.filename!r} - {item.notes}",
                explanation=(
                    "The filename is constructed so a recipient reads a harmless "
                    "document type while the operating system uses the final, "
                    "executable extension."
                ),
                recommendation="Do not open. Treat as a deliberate deception attempt.",
                mitre=["T1036.007"],
            ))

        if item.detected_type == "empty" and item.size_bytes == 0:
            indicators.append(_indicator(
                "ATTACHMENT_EMPTY", "Zero-byte attachment",
                Severity.LOW,
                evidence=item.filename,
                explanation="An empty attachment may be a lure to prompt a reply, "
                            "or an artefact of a malformed message.",
                recommendation="Note but do not action; corroborate with other indicators.",
                basis=Confidence.INFERRED,
                confidence=0.5,
            ))

    return indicators
