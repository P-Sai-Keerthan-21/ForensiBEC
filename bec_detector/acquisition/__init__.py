"""Stage 1 - Acquisition.

Reads evidence from disk, records chain of custody, and normalises each message
into an `EmailArtifact`.  Nothing in this package makes a judgement about the
content; it only preserves and structures it.
"""

from .custody import build_custody_record, sha256_file, sha256_bytes
from .loader import EvidenceParseError, load_bytes, load_eml, load_mbox, load_path

__all__ = [
    "build_custody_record",
    "sha256_file",
    "sha256_bytes",
    "load_eml",
    "load_bytes",
    "load_mbox",
    "load_path",
    "EvidenceParseError",
]
