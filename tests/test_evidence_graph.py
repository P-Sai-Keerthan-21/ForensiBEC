"""Evidence graph tests.

The central property: no relationship exists without evidence. Every edge must
carry provenance naming a real evidence item and the header or body location
that established it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bec_detector.forensics import EvidenceGraph, IOCStore, Provenance
from bec_detector.forensics.evidence_graph import NODE_TYPES, RELATIONS, node_id
from bec_detector.pipeline import BECPipeline

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    pipeline = BECPipeline(
        examiner="pytest-graph", case_id="CASE-GRAPH",
        ioc_store=IOCStore(tmp_path_factory.mktemp("ioc") / "s.json"),
    )
    assessments = pipeline.run(SAMPLES)
    return pipeline, assessments, pipeline.evidence_graph(assessments)


def _email_node(assessments, filename):
    for a in assessments:
        if Path(a.artifact.custody.source_path).name == filename:
            return node_id("email", a.artifact.evidence_id), a
    raise AssertionError(filename)


# ---------------------------------------------------------------------------
# No relationship without evidence
# ---------------------------------------------------------------------------

def test_every_edge_has_provenance(case):
    _, _, graph = case
    assert graph.edges
    for edge in graph.edges.values():
        assert edge.provenance, f"{edge.relation} {edge.source}->{edge.target} has no provenance"
        for p in edge.provenance:
            assert p.evidence_id and p.source


def test_every_message_provenance_points_at_acquired_evidence(case):
    """Provenance evidence ids must be real acquired messages (or the
    correlation store, which is labelled as such)."""
    _, assessments, graph = case
    acquired = {a.artifact.evidence_id for a in assessments}
    for edge in graph.edges.values():
        for p in edge.provenance:
            assert p.evidence_id in acquired or p.evidence_id.startswith("CASE:"), p


def test_link_refuses_edge_without_provenance():
    graph = EvidenceGraph()
    a = graph._node("address", "a@x.test")
    b = graph._node("domain", "x.test")
    with pytest.raises(ValueError):
        graph._link(a, b, "belongs_to", Provenance("", "somewhere"))
    with pytest.raises(ValueError):
        graph._link(a, b, "belongs_to", None)  # type: ignore[arg-type]
    assert not graph.edges


def test_link_refuses_unknown_relation_or_missing_endpoint():
    graph = EvidenceGraph()
    a = graph._node("address", "a@x.test")
    with pytest.raises(ValueError):
        graph._link(a, a, "invented_relation", Provenance("EV-1", "From header"))
    with pytest.raises(ValueError):
        graph._link(a, "domain:missing.test", "belongs_to", Provenance("EV-1", "x"))


def test_only_declared_types_and_relations_appear(case):
    _, _, graph = case
    assert {n.type for n in graph.nodes.values()} <= set(NODE_TYPES)
    assert {e.relation for e in graph.edges.values()} <= set(RELATIONS)


# ---------------------------------------------------------------------------
# Entities are extracted from the evidence
# ---------------------------------------------------------------------------

def test_header_relationships_quote_the_header(case):
    _, assessments, graph = case
    email_key, assessment = _email_node(assessments, "bec_01_ceo_wire_urgent.eml")
    details = graph.node_details(email_key)
    by_relation = {r["relation"]: r for r in details["relationships"]}

    assert by_relation["sent_by"]["target"] == node_id("address", "r.menon@northwind-l0gistics.com")
    assert by_relation["sent_by"]["provenance"][0]["source"] == "From header"
    assert by_relation["replies_to"]["target"] == node_id("address", "ravi.menon.exec@gmail.com")
    assert by_relation["replies_to"]["provenance"][0]["source"] == "Reply-To header"
    assert "envelope_from" in by_relation


def test_payment_entities_come_from_the_body(case):
    _, assessments, graph = case
    email_key, assessment = _email_node(assessments, "bec_01_ceo_wire_urgent.eml")
    payments = [e for e in graph.edges.values()
                if e.source == email_key and graph.nodes[e.target].type == "payment"]
    assert payments
    body = assessment.artifact.body_text
    for edge in payments:
        value = graph.nodes[edge.target].id.split(":", 1)[1]
        assert value in body, "payment entity must be quoted verbatim from the body"


def test_attachment_node_keyed_by_hash(case):
    _, assessments, graph = case
    _, assessment = _email_node(assessments, "bec_08_link_and_attachment.eml")
    sha = assessment.artifact.attachments[0].sha256
    node = graph.nodes[node_id("attachment", sha)]
    assert node.attrs["filename"] == "Payslip_September.pdf.exe"
    assert node.attrs["type_mismatch"] is True


def test_url_resolves_lexically_to_its_ip(case):
    _, _, graph = case
    url_edges = [e for e in graph.edges.values() if e.relation == "resolves_to"
                 and e.target == node_id("ip", "203.0.113.45")]
    assert url_edges
    assert "not resolved" in url_edges[0].provenance[0].source


def test_received_ips_are_routable_only(case):
    _, _, graph = case
    for node in graph.nodes.values():
        if node.type == "ip":
            assert not node.id.split(":", 1)[1].startswith(("10.", "127.", "192.168."))


# ---------------------------------------------------------------------------
# Threads come from headers, not subject similarity
# ---------------------------------------------------------------------------

def test_reply_references_its_real_parent(case):
    _, assessments, graph = case
    reply_key, _ = _email_node(assessments, "thread_02_genuine_reply.eml")
    parent_key, _ = _email_node(assessments, "thread_01_genuine_opening.eml")
    refs = [e for e in graph.edges.values()
            if e.source == reply_key and e.relation == "references"]
    assert any(e.target == parent_key for e in refs), "reply must link to the acquired parent"


def test_thread_members_share_one_thread_node(case):
    _, assessments, graph = case
    keys = [_email_node(assessments, f)[0] for f in
            ("thread_01_genuine_opening.eml", "thread_02_genuine_reply.eml",
             "thread_03_hijack.eml")]
    threads = []
    for key in keys:
        t = [e.target for e in graph.edges.values()
             if e.source == key and e.relation == "belongs_to"
             and graph.nodes[e.target].type == "thread"]
        threads.append(t[0])
    assert len(set(threads)) == 1


def test_same_subject_without_headers_is_not_threaded():
    """Subject similarity alone must never create a thread link."""
    from bec_detector.acquisition import load_bytes
    from bec_detector.pipeline import BECPipeline as P

    def msg(mid: str) -> bytes:
        return (f"From: a@x.test\r\nTo: b@y.test\r\nSubject: Re: Invoice 12\r\n"
                f"Message-ID: <{mid}@x.test>\r\nDate: Mon, 01 Sep 2026 09:00:00 +0000\r\n"
                "\r\nbody\r\n").encode()

    p = P(case_id="CASE-T", correlate=False)
    emails = [load_bytes(msg("one"), "1"), load_bytes(msg("two"), "2")]
    p.fit(emails)
    graph = p.evidence_graph([p.assess(e) for e in emails])
    thread_nodes = [n for n in graph.nodes.values() if n.type == "thread"]
    assert len(thread_nodes) == 2, "two unrelated messages must not share a thread"


def test_unacquired_parent_is_a_labelled_placeholder():
    graph = EvidenceGraph()
    from bec_detector.acquisition import load_bytes
    from bec_detector.validation import fuse

    raw = (b"From: a@x.test\r\nTo: b@y.test\r\nSubject: Re: x\r\n"
           b"Message-ID: <child@x.test>\r\nIn-Reply-To: <missing@x.test>\r\n\r\nhi\r\n")
    email = load_bytes(raw, "c")
    graph.add_all([fuse(email, [])])
    ref = graph.nodes[node_id("message_ref", "<missing@x.test>")]
    assert ref.attrs["acquired"] is False


def test_placeholder_is_repointed_when_parent_arrives():
    from bec_detector.acquisition import load_bytes
    from bec_detector.validation import fuse

    graph = EvidenceGraph()
    child = load_bytes(b"From: a@x.test\r\nTo: b@y.test\r\nSubject: Re: x\r\n"
                       b"Message-ID: <c@x.test>\r\nIn-Reply-To: <p@x.test>\r\n\r\nhi\r\n", "c")
    parent = load_bytes(b"From: b@y.test\r\nTo: a@x.test\r\nSubject: x\r\n"
                        b"Message-ID: <p@x.test>\r\n\r\nhello\r\n", "p")
    graph.add_assessment(fuse(child, []))
    graph.add_assessment(fuse(parent, []))
    graph._resolve_placeholders()

    child_key = node_id("email", child.evidence_id)
    parent_key = node_id("email", parent.evidence_id)
    assert node_id("message_ref", "<p@x.test>") not in graph.nodes
    edge = graph.edges[(child_key, parent_key, "references")]
    assert edge.provenance[0].source == "In-Reply-To header"


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def test_explain_connection_returns_evidence_path(case):
    """'Why are these two entities connected?'"""
    _, _, graph = case
    victim = node_id("address", "priya.sharma@northwind-logistics.com")
    attacker_reply = node_id("address", "ravi.menon.exec@gmail.com")
    result = graph.explain_connection(victim, attacker_reply)

    assert result["connected"]
    assert result["hops"] >= 2
    relations = [hop["relation"] for hop in result["path"]]
    assert "replies_to" in relations
    for hop in result["path"]:
        assert hop["provenance"], "every hop must say why"


def test_explain_connection_does_not_invent_links(case):
    _, _, graph = case
    graph._node("domain", "isolated.example")
    result = graph.explain_connection(node_id("domain", "isolated.example"),
                                      node_id("address", "priya.sharma@northwind-logistics.com"))
    assert result["connected"] is False
    assert result["path"] == []


def test_filter_case_keeps_only_that_case(case):
    _, _, graph = case
    other = EvidenceGraph()
    other.nodes.update(graph.nodes)
    other.edges.update(graph.edges)
    other._node("domain", "elsewhere.example", case_id="CASE-OTHER")

    sub = other.filter_case("CASE-GRAPH")
    assert node_id("domain", "elsewhere.example") not in sub.nodes
    assert all("CASE-GRAPH" in n.cases for n in sub.nodes.values())


def test_neighbourhood_is_bounded(case):
    _, assessments, graph = case
    key, _ = _email_node(assessments, "bec_01_ceo_wire_urgent.eml")
    one_hop = graph.neighbourhood(key, 1)
    assert key in one_hop.nodes
    assert len(one_hop.nodes) < len(graph.nodes)
    for edge in one_hop.edges.values():
        assert edge.source in one_hop.nodes and edge.target in one_hop.nodes


def test_cross_case_links_only_for_existing_nodes():
    graph = EvidenceGraph()
    graph.add_cross_case_links(
        [{"kind": "domains", "value": "not-in-graph.example", "seen_in_cases": ["CASE-9"]}],
        "CASE-1",
    )
    assert not graph.edges and not graph.nodes


# ---------------------------------------------------------------------------
# Serialisation and visualisation
# ---------------------------------------------------------------------------

def test_serialisation_round_trips_to_json(case):
    import json

    _, _, graph = case
    data = json.loads(json.dumps(graph.to_dict()))
    assert data["node_count"] == len(data["nodes"])
    assert data["edge_count"] == len(data["edges"])
    assert set(data["nodes_by_type"]) <= set(NODE_TYPES)


def test_svg_escapes_hostile_labels():
    from bec_detector.acquisition import load_bytes
    from bec_detector.validation import fuse

    raw = (b'From: "<script>alert(1)</script>" <a@x.test>\r\nTo: b@y.test\r\n'
           b"Subject: <img src=x onerror=alert(1)>\r\n\r\nhi\r\n")
    graph = EvidenceGraph()
    graph.add_all([fuse(load_bytes(raw, "x"), [])])
    svg = graph.to_svg()
    assert "<script>" not in svg
    assert "<img" not in svg
    assert svg.startswith("<svg")


def test_svg_is_deterministic(case):
    _, _, graph = case
    assert graph.to_svg() == graph.to_svg()


def test_report_carries_evidence_graph(tmp_path):
    from fastapi.testclient import TestClient

    from bec_detector.web.app import app

    files = [("files", (p.name, p.read_bytes(), "message/rfc822"))
             for p in sorted(SAMPLES.glob("thread_*.eml"))]
    data = TestClient(app).post("/api/analyse", files=files,
                                data={"case": "CASE-EG"}).json()
    assert data["evidence_graph"]["edge_count"] > 0
    assert re.match(r"<svg", data["evidence_graph_svg"])
