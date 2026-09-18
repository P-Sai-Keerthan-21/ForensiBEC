"""Forensic evidence graph with per-relationship provenance.

The communication graph (graph.py) answers "who wrote to whom". This graph
answers the investigator's question: "why are these two things connected?".

Every edge carries one or more PROVENANCE records naming the evidence item and
the exact header or body location that established the relationship. An edge
with no provenance cannot be created - `_link` refuses it - so the graph never
contains a relationship that the evidence does not support.

Entities
--------
    case        a case under investigation
    email       one acquired message, keyed by evidence id
    address     an email address
    domain      a mail or web domain
    url         a URL found in a message body (never visited)
    ip          a routable IPv4 address from the Received chain or a URL
    attachment  an attachment, keyed by SHA-256 (never executed)
    payment     a bank-account identifier found in a message body
    message_ref a Message-ID referenced by In-Reply-To/References
    thread      a conversation, keyed by the root Message-ID of its
                References chain

Relationships
-------------
    contains          case -> email, email -> url/attachment/payment
    sent_by           email -> address        (From header)
    sent_to           email -> address        (To / Cc headers)
    replies_to        email -> address        (Reply-To header)
    envelope_from     email -> address        (Return-Path header)
    belongs_to        address -> domain, email -> thread
    resolves_to       url -> domain / url -> ip   (lexical parse only)
    received_from     email -> ip             (Received header)
    references        email -> message_ref / email
    associated_with   (reserved for cross-case links supplied by correlation)

Thread identity is taken from threading HEADERS, never from subject-line
similarity, so thread membership is an observation rather than an inference.
"""

from __future__ import annotations

import html
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..config import TRUSTED_DOMAINS
from ..models import Assessment, EmailArtifact
from .ioc import IPV4_RE, _is_routable, normalise_url

try:  # pragma: no cover - whichever path is installed is exercised
    import networkx as nx

    HAS_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAS_NETWORKX = False

NODE_TYPES = (
    "case", "email", "address", "domain", "url", "ip",
    "attachment", "payment", "message_ref", "thread",
)

RELATIONS = (
    "contains", "sent_by", "sent_to", "replies_to", "envelope_from",
    "belongs_to", "resolves_to", "received_from", "references", "associated_with",
)

IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
ACCOUNT_RE = re.compile(r"\b(?:account(?: number)?|a/c)\s*[:#]?\s*(\d{6,12})\b", re.I)


@dataclass(frozen=True)
class Provenance:
    """Where in the evidence a relationship was observed."""

    evidence_id: str
    source: str        # e.g. "From header", "Received header #2", "message body"
    detail: str = ""   # the observed value, quoted

    def to_dict(self) -> dict[str, str]:
        return {"evidence_id": self.evidence_id, "source": self.source, "detail": self.detail}


@dataclass
class Node:
    id: str
    type: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence_ids: set[str] = field(default_factory=set)
    cases: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "label": self.label,
            "attrs": self.attrs,
            "evidence_ids": sorted(self.evidence_ids),
            "cases": sorted(self.cases),
        }


@dataclass
class Edge:
    source: str
    target: str
    relation: str
    provenance: list[Provenance] = field(default_factory=list)
    cases: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "target": self.target, "relation": self.relation,
            "provenance": [p.to_dict() for p in self.provenance],
            "cases": sorted(self.cases),
        }


def node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


class EvidenceGraph:
    """Typed entity graph in which every edge is traceable to evidence."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self._adjacent: dict[str, set[tuple[str, str, str]]] = defaultdict(set)

    # -- construction --------------------------------------------------------

    def _node(self, kind: str, value: str, label: str | None = None,
              case_id: str = "", evidence_id: str = "", **attrs: Any) -> str:
        if kind not in NODE_TYPES:
            raise ValueError(f"unknown node type {kind!r}")
        if not value:
            raise ValueError("node value must be non-empty")
        key = node_id(kind, value)
        node = self.nodes.get(key)
        if node is None:
            node = Node(id=key, type=kind, label=label or value)
            self.nodes[key] = node
        node.attrs.update({k: v for k, v in attrs.items() if v is not None})
        if case_id:
            node.cases.add(case_id)
        if evidence_id:
            node.evidence_ids.add(evidence_id)
        return key

    def _link(self, source: str, target: str, relation: str,
              provenance: Provenance, case_id: str = "") -> None:
        """Add or reinforce an edge. Refuses any edge without provenance."""
        if relation not in RELATIONS:
            raise ValueError(f"unknown relation {relation!r}")
        if not provenance or not provenance.evidence_id or not provenance.source:
            raise ValueError("an edge requires provenance naming its evidence")
        if source not in self.nodes or target not in self.nodes:
            raise ValueError("both endpoints must exist before they can be linked")
        if source == target:
            return
        key = (source, target, relation)
        edge = self.edges.get(key)
        if edge is None:
            edge = Edge(source=source, target=target, relation=relation)
            self.edges[key] = edge
            self._adjacent[source].add(key)
            self._adjacent[target].add(key)
        if provenance not in edge.provenance:
            edge.provenance.append(provenance)
        if case_id:
            edge.cases.add(case_id)

    def _address(self, address: str, case_id: str, evidence_id: str,
                 display: str = "") -> str:
        """An address node, linked to its domain."""
        addr = address.strip().lower()
        a = self._node("address", addr, case_id=case_id, evidence_id=evidence_id)
        if display:
            names = self.nodes[a].attrs.setdefault("display_names", [])
            if display not in names:
                names.append(display)
        if "@" in addr:
            domain = addr.rsplit("@", 1)[1]
            d = self._node("domain", domain, case_id=case_id, evidence_id=evidence_id,
                           trusted=domain in TRUSTED_DOMAINS)
            self._link(a, d, "belongs_to",
                       Provenance(evidence_id, "address syntax", addr), case_id)
        return a

    def add_assessment(self, assessment: Assessment, case_id: str = "") -> str:
        """Add every entity and relationship observable in one assessed message."""
        email: EmailArtifact = assessment.artifact
        ev = email.evidence_id

        e = self._node(
            "email", ev, label=email.subject or "(no subject)",
            case_id=case_id, evidence_id=ev,
            subject=email.subject, sha256=email.custody.sha256,
            date_utc=email.date_utc.isoformat() if email.date_utc else None,
            risk_score=assessment.score, risk_band=assessment.band.value,
            message_id=email.message_id or None,
        )

        if case_id:
            c = self._node("case", case_id, case_id=case_id)
            self._link(c, e, "contains",
                       Provenance(ev, "chain-of-custody record",
                                  f"acquired {email.custody.acquired_utc}"), case_id)

        # -- header relationships ---------------------------------------------
        if email.from_address:
            a = self._address(email.from_address, case_id, ev, email.from_display)
            self._link(e, a, "sent_by", Provenance(
                ev, "From header", f'"{email.from_display}" <{email.from_address}>'), case_id)

        for header, values in (("To header", email.to_addresses),
                               ("Cc header", email.cc_addresses)):
            for value in values:
                a = self._address(value, case_id, ev)
                self._link(e, a, "sent_to", Provenance(ev, header, value), case_id)

        if email.reply_to_address:
            a = self._address(email.reply_to_address, case_id, ev)
            self._link(e, a, "replies_to",
                       Provenance(ev, "Reply-To header", email.reply_to_address), case_id)

        if email.return_path:
            a = self._address(email.return_path, case_id, ev)
            self._link(e, a, "envelope_from",
                       Provenance(ev, "Return-Path header", email.return_path), case_id)

        for index, hop in enumerate(email.received_chain, 1):
            for ip in IPV4_RE.findall(hop):
                if _is_routable(ip):
                    i = self._node("ip", ip, case_id=case_id, evidence_id=ev)
                    self._link(e, i, "received_from", Provenance(
                        ev, f"Received header #{index}", hop[:160]), case_id)

        # -- threading (headers only, never subject similarity) ---------------
        refs = [r.strip() for r in email.references if r.strip()]
        parent = (email.in_reply_to or "").strip()
        for ref, source in [(r, "References header") for r in refs] + (
                [(parent, "In-Reply-To header")] if parent else []):
            target = self._email_by_message_id(ref)
            if target is None:
                target = self._node("message_ref", ref, case_id=case_id,
                                    evidence_id=ev, acquired=False)
            self._link(e, target, "references", Provenance(ev, source, ref), case_id)

        root = refs[0] if refs else (parent or (email.message_id or "").strip())
        if root:
            basis = ("References header (first entry)" if refs
                     else "In-Reply-To header" if parent else "own Message-ID")
            t = self._node("thread", root, label=f"thread {root}",
                           case_id=case_id, evidence_id=ev)
            self._link(e, t, "belongs_to", Provenance(ev, basis, root), case_id)

        # -- body artefacts ------------------------------------------------------
        for url in email.urls:
            u = self._node("url", normalise_url(url.raw), label=url.raw[:80],
                           case_id=case_id, evidence_id=ev,
                           https=url.uses_https, display_mismatch=url.display_mismatch or None)
            self._link(e, u, "contains", Provenance(ev, "message body", url.raw), case_id)
            if url.host:
                if url.is_ip_literal:
                    h = self._node("ip", url.host, case_id=case_id, evidence_id=ev)
                else:
                    h = self._node("domain", url.host, case_id=case_id, evidence_id=ev,
                                   trusted=url.host in TRUSTED_DOMAINS)
                self._link(u, h, "resolves_to", Provenance(
                    ev, "URL host (lexical parse, not resolved)", url.host), case_id)

        for item in email.attachments:
            if not item.sha256:
                continue
            t = self._node("attachment", item.sha256, label=item.filename,
                           case_id=case_id, evidence_id=ev,
                           filename=item.filename, detected_type=item.detected_type,
                           type_mismatch=item.type_mismatch, size_bytes=item.size_bytes)
            self._link(e, t, "contains", Provenance(
                ev, "MIME attachment part", f"{item.filename} sha256={item.sha256}"), case_id)

        body = email.body_text or ""
        for iban in IBAN_RE.findall(body):
            p = self._node("payment", iban, label=f"IBAN {iban}", case_id=case_id,
                           evidence_id=ev, payment_type="IBAN")
            self._link(e, p, "contains", Provenance(ev, "message body", iban), case_id)
        for account in ACCOUNT_RE.findall(body):
            p = self._node("payment", account, label=f"account {account}",
                           case_id=case_id, evidence_id=ev, payment_type="account number")
            self._link(e, p, "contains", Provenance(ev, "message body", account), case_id)

        return e

    def add_all(self, assessments: Iterable[Assessment], case_id: str = "") -> None:
        items = list(assessments)
        # Two passes, so a reply's In-Reply-To can link to a parent that was
        # acquired later in the batch rather than to a placeholder reference.
        for assessment in items:
            self._node("email", assessment.artifact.evidence_id,
                       message_id=assessment.artifact.message_id or None)
        for assessment in items:
            self.add_assessment(assessment, case_id)
        self._resolve_placeholders()

    def add_cross_case_links(self, matches: list[dict[str, Any]], case_id: str) -> None:
        """Record IOC reuse reported by the local correlation store.

        Only indicators already present as nodes are linked, and the provenance
        names the correlation store, not the message, as the source.
        """
        kind_to_node = {"domains": "domain", "ipv4": "ip", "urls": "url",
                        "attachment_sha256": "attachment"}
        for match in matches:
            kind = kind_to_node.get(match.get("kind", ""))
            if not kind:
                continue
            target = node_id(kind, match["value"])
            if target not in self.nodes:
                continue
            for other in match.get("seen_in_cases", []):
                c = self._node("case", other, case_id=other)
                self._link(target, c, "associated_with", Provenance(
                    f"CASE:{other}", "local IOC correlation store",
                    f"{match['kind']}={match['value']} also recorded in {other}"), case_id)

    def _email_by_message_id(self, message_id: str) -> str | None:
        for key, node in self.nodes.items():
            if node.type == "email" and node.attrs.get("message_id") == message_id:
                return key
        return None

    def _resolve_placeholders(self) -> None:
        """Re-point references at messages that have since been acquired.

        Each edge to the placeholder is recreated against the real email node
        with its provenance intact, then the placeholder is removed.
        """
        for key in [k for k, n in self.nodes.items() if n.type == "message_ref"]:
            real = self._email_by_message_id(key.split(":", 1)[1])
            if real is None:
                continue
            for edge_key in list(self._adjacent.get(key, ())):
                edge = self.edges.pop(edge_key)
                for end in edge_key[:2]:
                    self._adjacent[end].discard(edge_key)
                source = real if edge.source == key else edge.source
                target = real if edge.target == key else edge.target
                for provenance in edge.provenance:
                    for case in edge.cases or {""}:
                        self._link(source, target, edge.relation, provenance, case)
            self.nodes.pop(key, None)
            self._adjacent.pop(key, None)

    # -- queries -------------------------------------------------------------

    def node_details(self, key: str) -> dict[str, Any]:
        """A node plus every relationship touching it, with provenance."""
        if key not in self.nodes:
            raise KeyError(key)
        relations = [self.edges[k].to_dict() for k in sorted(self._adjacent.get(key, ()))]
        return {"node": self.nodes[key].to_dict(), "relationships": relations}

    def explain_connection(self, a: str, b: str, max_hops: int = 6) -> dict[str, Any]:
        """Shortest evidence path between two entities, edge by edge.

        Answers "why are these two entities connected?" with the provenance of
        every hop. Returns connected=False rather than inventing a link.
        """
        if a not in self.nodes or b not in self.nodes:
            return {"connected": False, "reason": "one or both entities are not in the graph",
                    "path": []}
        previous: dict[str, tuple[str, tuple[str, str, str]] | None] = {a: None}
        queue = deque([(a, 0)])
        while queue:
            current, depth = queue.popleft()
            if current == b:
                break
            if depth >= max_hops:
                continue
            for edge_key in sorted(self._adjacent.get(current, ())):
                src, dst, _ = edge_key
                nxt = dst if src == current else src
                if nxt not in previous:
                    previous[nxt] = (current, edge_key)
                    queue.append((nxt, depth + 1))

        if b not in previous:
            return {"connected": False,
                    "reason": f"no evidence path within {max_hops} hops", "path": []}

        path: list[dict[str, Any]] = []
        cursor = b
        while previous[cursor] is not None:
            parent, edge_key = previous[cursor]  # type: ignore[misc]
            path.append(self.edges[edge_key].to_dict())
            cursor = parent
        path.reverse()
        return {"connected": True, "hops": len(path), "path": path}

    def filter_case(self, case_id: str) -> "EvidenceGraph":
        """A copy containing only entities and edges observed in one case."""
        sub = EvidenceGraph()
        for key, node in self.nodes.items():
            if case_id in node.cases:
                sub.nodes[key] = Node(node.id, node.type, node.label, dict(node.attrs),
                                      set(node.evidence_ids), set(node.cases))
        for key, edge in self.edges.items():
            if case_id in edge.cases and edge.source in sub.nodes and edge.target in sub.nodes:
                sub.edges[key] = Edge(edge.source, edge.target, edge.relation,
                                      list(edge.provenance), set(edge.cases))
                sub._adjacent[edge.source].add(key)
                sub._adjacent[edge.target].add(key)
        return sub

    def neighbourhood(self, key: str, depth: int = 1) -> "EvidenceGraph":
        """Entities within `depth` hops of one node, for focused display."""
        keep = {key}
        frontier = {key}
        for _ in range(depth):
            nxt = set()
            for current in frontier:
                for src, dst, _ in self._adjacent.get(current, ()):
                    nxt.add(dst if src == current else src)
            frontier = nxt - keep
            keep |= nxt
        sub = EvidenceGraph()
        for k in keep:
            if k in self.nodes:
                sub.nodes[k] = self.nodes[k]
        for edge_key, edge in self.edges.items():
            if edge.source in keep and edge.target in keep:
                sub.edges[edge_key] = edge
                sub._adjacent[edge.source].add(edge_key)
                sub._adjacent[edge.target].add(edge_key)
        return sub

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            by_type[node.type] += 1
        by_relation: dict[str, int] = defaultdict(int)
        for edge in self.edges.values():
            by_relation[edge.relation] += 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes_by_type": dict(sorted(by_type.items())),
            "edges_by_relation": dict(sorted(by_relation.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.summary(),
            "backend": "networkx" if HAS_NETWORKX else "builtin",
            "nodes": [n.to_dict() for n in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [e.to_dict() for _, e in sorted(self.edges.items())],
        }

    def to_networkx(self):  # pragma: no cover - thin adapter
        if not HAS_NETWORKX:
            raise RuntimeError("networkx is not installed")
        graph = nx.MultiDiGraph()
        for node in self.nodes.values():
            graph.add_node(node.id, type=node.type, label=node.label)
        for edge in self.edges.values():
            graph.add_edge(edge.source, edge.target, relation=edge.relation,
                           provenance=[p.to_dict() for p in edge.provenance])
        return graph

    # -- visualisation -------------------------------------------------------

    def to_svg(self, width: int = 900, height: int = 560, seed: int = 20260918) -> str:
        """Self-contained SVG of the graph. Deterministic layout; all labels escaped."""
        if not self.nodes:
            return '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>'

        keys = sorted(self.nodes)
        if HAS_NETWORKX and len(keys) > 1:
            g = nx.Graph()
            g.add_nodes_from(keys)
            g.add_edges_from((e.source, e.target) for e in self.edges.values())
            pos = nx.spring_layout(g, seed=seed)
        else:
            pos = {k: (math.cos(2 * math.pi * i / len(keys)),
                       math.sin(2 * math.pi * i / len(keys))) for i, k in enumerate(keys)}

        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        span_x = (max(xs) - min(xs)) or 1.0
        span_y = (max(ys) - min(ys)) or 1.0
        pad = 60

        def at(k: str) -> tuple[float, float]:
            x, y = pos[k]
            return (pad + (x - min(xs)) / span_x * (width - 2 * pad),
                    pad + (y - min(ys)) / span_y * (height - 2 * pad))

        colours = {
            "case": "#334155", "email": "#1d4ed8", "address": "#0f766e",
            "domain": "#7c3aed", "url": "#c2410c", "ip": "#b91c1c",
            "attachment": "#a16207", "payment": "#be123c",
            "message_ref": "#64748b", "thread": "#475569",
        }

        parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
                 f'role="img" aria-label="Evidence graph" '
                 f'style="width:100%;height:auto;background:#fff;border:1px solid #e2e8f0;'
                 f'border-radius:8px">']
        for edge in sorted(self.edges.values(), key=lambda e: (e.source, e.target, e.relation)):
            x1, y1 = at(edge.source)
            x2, y2 = at(edge.target)
            flagged = edge.relation in {"replies_to", "envelope_from"}
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                f'stroke="{"#dc2626" if flagged else "#cbd5e1"}" stroke-width="1.2">'
                f'<title>{html.escape(edge.relation)}: '
                f'{html.escape("; ".join(p.source for p in edge.provenance))}</title></line>'
            )
        for k in keys:
            node = self.nodes[k]
            x, y = at(k)
            risky = node.type == "email" and node.attrs.get("risk_band") in {
                "LIKELY_BEC", "CONFIRMED_BEC"}
            radius = 9 if node.type in {"email", "case"} else 6
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" '
                f'fill="{colours.get(node.type, "#64748b")}" '
                f'stroke="{"#dc2626" if risky else "#fff"}" stroke-width="{3 if risky else 1.5}">'
                f'<title>{html.escape(node.type)}: {html.escape(node.label)}</title></circle>'
            )
            parts.append(
                f'<text x="{x + 11:.1f}" y="{y + 4:.1f}" font-size="9" '
                f'font-family="Segoe UI, sans-serif" fill="#334155">'
                f'{html.escape(node.label[:28])}</text>'
            )
        parts.append("</svg>")
        return "".join(parts)
