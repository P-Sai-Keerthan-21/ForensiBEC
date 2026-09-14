"""Communication graph.

Builds a relationship graph around the correspondents in a case so an
investigator can see who talks to whom, and which relationships are new.

NetworkX is optional. If it is not installed the graph is still built and
queried through the same interface using plain dictionaries -- only the
centrality metric is skipped. This keeps the dependency from destabilising
the rest of the application.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..config import TRUSTED_DOMAINS
from ..models import Assessment, EmailArtifact, RiskBand

try:  # pragma: no cover - exercised implicitly by whichever path is installed
    import networkx as nx

    HAS_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAS_NETWORKX = False


class CommunicationGraph:
    """Addresses and domains as nodes; observed communication as edges."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str], dict[str, Any]] = {}
        self._adjacency: dict[str, set[str]] = defaultdict(set)

    # -- construction --------------------------------------------------------

    def _add_node(self, address: str, **attrs: Any) -> None:
        if not address:
            return
        domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
        node = self.nodes.setdefault(address, {
            "id": address,
            "kind": "address",
            "domain": domain,
            "internal": domain in TRUSTED_DOMAINS,
            "messages_sent": 0,
            "messages_received": 0,
            "max_risk": 0.0,
            "flagged": False,
        })
        for key, value in attrs.items():
            node[key] = value

    def _add_edge(self, source: str, target: str, kind: str, risk: float,
                  flagged: bool) -> None:
        if not source or not target or source == target:
            return
        key = (source, target)
        edge = self.edges.setdefault(key, {
            "source": source, "target": target, "kinds": set(),
            "count": 0, "max_risk": 0.0, "flagged": False,
        })
        edge["kinds"].add(kind)
        edge["count"] += 1
        edge["max_risk"] = max(edge["max_risk"], risk)
        edge["flagged"] = edge["flagged"] or flagged
        self._adjacency[source].add(target)
        self._adjacency[target].add(source)

    def add_assessment(self, assessment: Assessment) -> None:
        email: EmailArtifact = assessment.artifact
        risk = assessment.score
        flagged = assessment.band in {RiskBand.LIKELY_BEC, RiskBand.CONFIRMED_BEC}

        sender = email.from_address
        if sender:
            self._add_node(sender)
            self.nodes[sender]["messages_sent"] += 1
            self.nodes[sender]["max_risk"] = max(self.nodes[sender]["max_risk"], risk)
            self.nodes[sender]["flagged"] = self.nodes[sender]["flagged"] or flagged

        for recipient in list(email.to_addresses) + list(email.cc_addresses):
            self._add_node(recipient)
            self.nodes[recipient]["messages_received"] += 1
            self._add_edge(sender, recipient, "sent_to", risk, flagged)

        # A Reply-To pointing somewhere other than the sender is itself a
        # relationship worth drawing - it is where the victim's reply would go.
        if email.reply_to_address and email.reply_to_address != sender:
            self._add_node(email.reply_to_address)
            self._add_edge(sender, email.reply_to_address, "replies_diverted_to", risk, flagged)

    def add_all(self, assessments: list[Assessment]) -> None:
        for assessment in assessments:
            self.add_assessment(assessment)

    # -- queries -------------------------------------------------------------

    def neighbours(self, address: str) -> list[str]:
        return sorted(self._adjacency.get(address, set()))

    def suspicious_relationships(self) -> list[dict[str, Any]]:
        """Edges that crossed from an internal address to an external one on a
        flagged message -- the relationships an investigator should look at first."""
        found = []
        for (source, target), edge in self.edges.items():
            if not edge["flagged"]:
                continue
            source_internal = self.nodes.get(source, {}).get("internal", False)
            target_internal = self.nodes.get(target, {}).get("internal", False)
            if source_internal != target_internal:
                found.append({
                    "source": source,
                    "target": target,
                    "kinds": sorted(edge["kinds"]),
                    "max_risk": edge["max_risk"],
                    "crosses_boundary": True,
                })
        return sorted(found, key=lambda e: -e["max_risk"])

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the report and the dashboard."""
        summary: dict[str, Any] = {
            "backend": "networkx" if HAS_NETWORKX else "builtin",
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": sorted(self.nodes.values(), key=lambda n: -n["max_risk"]),
            "edges": [
                {**edge, "kinds": sorted(edge["kinds"])}
                for edge in self.edges.values()
            ],
            "suspicious_relationships": self.suspicious_relationships(),
        }

        if HAS_NETWORKX and self.nodes:
            graph = self.to_networkx()
            try:
                centrality = nx.degree_centrality(graph)
                summary["most_connected"] = sorted(
                    ({"address": k, "centrality": round(v, 3)} for k, v in centrality.items()),
                    key=lambda item: -item["centrality"],
                )[:8]
            except Exception:
                summary["most_connected"] = []
        else:
            summary["most_connected"] = []

        return summary

    def to_networkx(self):  # pragma: no cover - trivial adapter
        """Return a NetworkX DiGraph. Raises if NetworkX is unavailable."""
        if not HAS_NETWORKX:
            raise RuntimeError("networkx is not installed")
        graph = nx.DiGraph()
        for address, attrs in self.nodes.items():
            graph.add_node(address, **{k: v for k, v in attrs.items() if k != "id"})
        for (source, target), edge in self.edges.items():
            graph.add_edge(
                source, target,
                kinds=sorted(edge["kinds"]),
                count=edge["count"],
                max_risk=edge["max_risk"],
            )
        return graph
