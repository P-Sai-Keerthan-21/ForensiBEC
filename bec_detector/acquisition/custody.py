"""Chain-of-custody helpers.

The hash is taken over the raw bytes as they were read from the evidence
source, before parsing.  That way the report can assert exactly which byte
sequence produced the findings.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .. import __tool_name__, __version__
from ..config import DEFAULT_EXAMINER
from ..models import CustodyRecord


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_custody_record(
    source_path: str,
    raw: bytes,
    examiner: str | None = None,
) -> CustodyRecord:
    """Create the custody record for one acquired message."""
    return CustodyRecord(
        source_path=str(source_path),
        sha256=sha256_bytes(raw),
        size_bytes=len(raw),
        acquired_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        examiner=examiner or DEFAULT_EXAMINER,
        tool_version=f"{__tool_name__} {__version__}",
    )
