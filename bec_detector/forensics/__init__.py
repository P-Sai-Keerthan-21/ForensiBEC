"""Forensic support layer: integrity, provenance, intelligence and correlation.

These modules surround the detection engine rather than participating in it,
providing the evidence-handling properties a DFIR tool needs: tamper-evident
logging, IOC extraction and local correlation, timeline construction, an
intelligence adapter and ATT&CK mapping.
"""

from .audit import AuditEntry, AuditLog, compute_entry_hash
from .correlation import IOCStore, correlation_indicators
from .evidence_graph import EvidenceGraph, Provenance
from .graph import HAS_NETWORKX, CommunicationGraph
from .intel import (
    IntelMatch,
    LocalThreatIntelProvider,
    NullThreatIntelProvider,
    ThreatIntelProvider,
    intel_indicators,
)
from .ioc import extract_iocs, flatten, normalise_domain, normalise_url
from .mitre import DISCLAIMER, TECHNIQUES, map_indicators
from .timeline import build_case_timeline, build_message_timeline

__all__ = [
    "AuditEntry", "AuditLog", "compute_entry_hash",
    "IOCStore", "correlation_indicators",
    "CommunicationGraph", "HAS_NETWORKX", "EvidenceGraph", "Provenance",
    "ThreatIntelProvider", "LocalThreatIntelProvider", "NullThreatIntelProvider",
    "IntelMatch", "intel_indicators",
    "extract_iocs", "flatten", "normalise_domain", "normalise_url",
    "map_indicators", "TECHNIQUES", "DISCLAIMER",
    "build_message_timeline", "build_case_timeline",
]
