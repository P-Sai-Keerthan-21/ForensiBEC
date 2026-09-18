"""Grounded investigation assistant.

Architecture
------------
    Forensic engine -> structured evidence (the case analysis) -> assistant
    -> human-readable explanation

The assistant never analyses mail. It explains what the forensic engine already
found, using only the structured case analysis.

Grounding
---------
Every statement is a `Claim` carrying citations: indicator codes, evidence IDs,
header names or timeline entries. `validate_grounding` rejects any answer that
cites something absent from the case's structured evidence. Template answers
are built from that evidence, so they pass by construction; the validator
exists so that any future model-backed provider has to pass the same gate.

Providers
---------
`TemplateProvider` (default) is deterministic and local. It is reported as
"deterministic evidence templates" and never presented as an AI model.
`ExternalProviderNotConfigured` documents the extension point: no external
model is called, and no evidence leaves the machine, unless a provider is
deliberately implemented and configured.

Prompt injection
----------------
Email content is attacker-controlled. Text such as "ignore previous
instructions" inside a message is evidence, not instruction. The template
provider never interprets evidence text: questions are matched against a fixed
set of intents, and evidence appears in answers only as quoted data. An email
therefore cannot change which answer is produced or what it says about risk.

Language discipline
-------------------
Answers never claim certainty, attribution or criminality. `FORBIDDEN_PHRASES`
is enforced on every answer.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

FLAGGED = {"LIKELY_BEC", "CONFIRMED_BEC"}

FORBIDDEN_PHRASES = (
    "definitely", "certainly", "proves", "proven", "guaranteed", "100%",
    "the attacker is", "attributed to", "is a criminal", "committed fraud",
    "is guilty", "confirmed attacker",
)

CAVEATS = [
    "Risk scores are produced by a transparent rule-based model; they are not "
    "probabilities.",
    "These are technical indicators. Whether an offence occurred is a "
    "determination for the investigator.",
    "No actor is identified or attributed.",
]


# ---------------------------------------------------------------------------
# Answer structures
# ---------------------------------------------------------------------------

@dataclass
class Claim:
    text: str
    citations: list[str] = field(default_factory=list)


@dataclass
class Section:
    heading: str
    claims: list[Claim] = field(default_factory=list)


@dataclass
class Answer:
    question: str
    intent: str
    provider: str
    sections: list[Section] = field(default_factory=list)
    caveats: list[str] = field(default_factory=lambda: list(CAVEATS))
    grounded: bool = False
    grounding_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def text(self) -> str:
        lines = []
        for section in self.sections:
            lines.append(section.heading.upper())
            for claim in section.claims:
                cite = f"  [{', '.join(claim.citations)}]" if claim.citations else ""
                lines.append(f"  - {claim.text}{cite}")
            lines.append("")
        lines.extend(f"Note: {c}" for c in self.caveats)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------

def citable(analysis: dict[str, Any]) -> set[str]:
    """Every identifier an answer may legitimately cite for this case."""
    refs: set[str] = {"case", "timeline", "evidence_graph", "audit", "fusion"}
    case = analysis.get("case") or {}
    if case.get("case_id"):
        refs.add(case["case_id"])
    for item in analysis.get("assessments") or []:
        refs.add(item["evidence_id"])
        for ind in item.get("indicators") or []:
            refs.add(ind["code"])
            refs.add(f"{item['evidence_id']}:{ind['code']}")
        for header in (item.get("email") or {}).get("headers") or {}:
            refs.add(f"header:{header}")
        for entry in item.get("mitre") or []:
            refs.add(entry["technique_id"])
    for entry in analysis.get("investigator_assessments") or []:
        refs.add(f"investigator:{entry.get('evidence_id')}")
    return refs


def validate_grounding(answer: Answer, analysis: dict[str, Any]) -> Answer:
    """Reject citations to evidence the case does not contain, and banned language."""
    allowed = citable(analysis)
    errors: list[str] = []
    for section in answer.sections:
        for claim in section.claims:
            for citation in claim.citations:
                if citation not in allowed:
                    errors.append(f"citation {citation!r} is not in the case evidence")
            if not claim.citations:
                errors.append(f"uncited claim: {claim.text[:60]!r}")
    # The phrase check polices the assistant's own language. Quoted evidence is
    # excluded: an email saying "I will certainly pay" is evidence, and quoting
    # it is not the assistant claiming certainty.
    body = re.sub("“[^”]*”", " ", answer.text()).lower()
    for phrase in FORBIDDEN_PHRASES:
        if phrase in body:
            errors.append(f"forbidden phrase {phrase!r}")
    answer.grounding_errors = errors
    answer.grounded = not errors
    return answer


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

class AssistantProvider(ABC):
    name = "unnamed"

    @abstractmethod
    def answer(self, question: str, analysis: dict[str, Any],
               evidence_id: str | None = None) -> Answer:
        ...


class ExternalProviderNotConfigured(AssistantProvider):
    """Extension point for a model-backed provider. Deliberately inert.

    Implementing one requires: explicit operator configuration, a statement of
    where evidence is sent, passing structured evidence only (never raw
    message bodies as instructions), and running every answer through
    `validate_grounding` before display.
    """

    name = "external model (not configured)"

    def answer(self, question, analysis, evidence_id=None) -> Answer:
        raise RuntimeError("No external model is configured. Evidence is never sent "
                           "off this machine by default.")


# Order matters: specific intents are checked before generic ones, so that
# "explain the evidence graph" reaches the graph intent, not the evidence one.
INTENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("why_flagged", ("why", "flagged", "high risk", "risk score", "score", "suspicious")),
    ("graph", ("graph", "connected", "relationship", "linked", "entities")),
    ("timeline", ("timeline", "when", "sequence", "order of events", "chronolog")),
    ("next_steps", ("next", "should i", "recommend", "what to do", "review")),
    ("evidence", ("evidence", "support", "based on", "prove", "show")),
    ("feedback", ("investigator", "human", "determination", "agree", "false positive",
                  "false negative")),
    ("summary", ("summar", "overview", "case", "what happened")),
)

SUPPORTED = ("why was this email flagged", "what evidence supports the assessment",
             "what should I review next", "summarise this case", "explain the timeline",
             "explain the evidence graph", "how do investigator assessments compare")


def classify(question: str) -> str:
    """Map a question to a fixed intent. Deterministic keyword matching only."""
    q = (question or "").lower()
    for intent, keywords in INTENTS:
        if any(k in q for k in keywords):
            return intent
    return "unsupported"


def _quote(value: Any, limit: int = 140) -> str:
    """Evidence is quoted as data, never interpreted."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return f"“{text[:limit]}{'...' if len(text) > limit else ''}”"


class TemplateProvider(AssistantProvider):
    name = "deterministic evidence templates (no language model)"

    def answer(self, question, analysis, evidence_id=None) -> Answer:
        intent = classify(question)
        handler = getattr(self, f"_{intent}", self._unsupported)
        answer = Answer(question=question, intent=intent, provider=self.name)
        answer.sections = handler(analysis, evidence_id)
        return validate_grounding(answer, analysis)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _target(analysis, evidence_id):
        items = analysis.get("assessments") or []
        if evidence_id:
            for item in items:
                if item["evidence_id"] == evidence_id:
                    return item
            return None
        return max(items, key=lambda a: a["risk_score"]) if items else None

    # -- intents -------------------------------------------------------------

    def _why_flagged(self, analysis, evidence_id):
        item = self._target(analysis, evidence_id)
        if item is None:
            return [Section("Not available", [Claim(
                "That evidence item is not part of this case's analysis.", ["case"])])]
        ev = item["evidence_id"]
        ranked = sorted(item["indicators"], key=lambda i: -i["contribution"])[:5]
        evidence = [Claim(f"{i['title']}: {_quote(i['observed_evidence'])} ({i['basis'].lower()})",
                          [ev, f"{ev}:{i['code']}"]) for i in ranked]
        inference = [Claim(i["inference"], [f"{ev}:{i['code']}"]) for i in ranked[:3]]
        fusion = item.get("fusion") or {}
        risk = [Claim(
            f"Scored {item['risk_score']:.1f}/100, band {item['risk_band']}. The largest "
            f"contributions were " + ", ".join(f"{i['code']} (+{i['contribution']:.1f})"
                                                for i in ranked[:3]) + ".",
            [ev] + [f"{ev}:{i['code']}" for i in ranked[:3]])]
        if fusion.get("corroboration_reasons"):
            risk.append(Claim("Corroboration added +{:g} because {}.".format(
                fusion["corroboration_bonus"], "; ".join(fusion["corroboration_reasons"])),
                [ev, "fusion"]))
        recs, seen = [], set()
        for i in ranked:
            if i.get("recommendation") and i["recommendation"] not in seen:
                seen.add(i["recommendation"])
                recs.append(Claim(i["recommendation"], [f"{ev}:{i['code']}"]))
        if not ranked:
            return [Section("Assessment", [Claim(
                f"{ev} raised no indicators and scored {item['risk_score']:.1f} "
                f"({item['risk_band']}).", [ev])])]
        return [Section(f"Evidence ({ev})", evidence), Section("Inference", inference),
                Section("Risk", risk), Section("Recommendation", recs[:4])]

    def _evidence(self, analysis, evidence_id):
        item = self._target(analysis, evidence_id)
        if item is None:
            return [Section("Not available", [Claim("No such evidence in this case.", ["case"])])]
        ev = item["evidence_id"]
        observed = [i for i in item["indicators"] if i["basis"] == "OBSERVED"]
        inferred = [i for i in item["indicators"] if i["basis"] != "OBSERVED"]
        sections = [Section("Observed directly in the message", [
            Claim(f"{i['title']}: {_quote(i['observed_evidence'])}", [f"{ev}:{i['code']}"])
            for i in observed] or [Claim("No directly observed findings.", [ev])])]
        if inferred:
            sections.append(Section("Inferred from observations (weaker)", [
                Claim(f"{i['title']} ({i['basis'].lower()})", [f"{ev}:{i['code']}"])
                for i in inferred]))
        return sections

    def _next_steps(self, analysis, evidence_id):
        claims, seen = [], set()
        for item in analysis.get("assessments") or []:
            if item["risk_band"] not in FLAGGED:
                continue
            for i in item["indicators"]:
                rec = i.get("recommendation")
                if rec and i["severity"] in ("CRITICAL", "HIGH") and rec not in seen:
                    seen.add(rec)
                    claims.append(Claim(rec, [item["evidence_id"], f"{item['evidence_id']}:{i['code']}"]))
        gaps = []
        for item in analysis.get("assessments") or []:
            for i in item["indicators"]:
                if i["code"] == "THREAD_UNKNOWN_PARENT":
                    gaps.append(Claim(
                        f"Acquire the parent message referenced by {item['evidence_id']}; "
                        "it is not in the evidence set.", [f"{item['evidence_id']}:{i['code']}"]))
        integrity = (analysis.get("audit") or {}).get("integrity") or {}
        verify = [Claim("Re-verify evidence integrity before relying on these findings"
                        + ("" if integrity.get("valid") else "; the audit chain did NOT verify") + ".",
                        ["audit"])]
        sections = [Section("From findings on messages scored LIKELY_BEC or above",
                            claims[:8] or [Claim("No message was scored LIKELY_BEC or above.", ["case"])])]
        if gaps:
            sections.append(Section("Collection gaps", gaps))
        sections.append(Section("Evidence handling", verify))
        return sections

    def _summary(self, analysis, evidence_id):
        s = analysis.get("summary") or {}
        items = analysis.get("assessments") or []
        case_id = (analysis.get("case") or {}).get("case_id") or "case"
        claims = [Claim(f"{s.get('messages_analysed', 0)} message(s) analysed; "
                        f"band counts {s.get('band_counts', {})}.", [case_id])]
        for item in sorted(items, key=lambda a: -a["risk_score"])[:3]:
            top = sorted(item["indicators"], key=lambda i: -i["contribution"])[:2]
            claims.append(Claim(
                f"{item['evidence_id']} {_quote(item['email'].get('subject'), 60)} scored "
                f"{item['risk_score']:.1f} ({item['risk_band']})"
                + (": " + "; ".join(i["title"] for i in top) if top else ""),
                [item["evidence_id"]] + [f"{item['evidence_id']}:{i['code']}" for i in top]))
        integrity = (analysis.get("audit") or {}).get("integrity") or {}
        claims.append(Claim("Audit chain " + ("verified." if integrity.get("valid") else "NOT verified."),
                            ["audit"]))
        return [Section("Case summary", claims)]

    def _timeline(self, analysis, evidence_id):
        events = [e for e in (analysis.get("timeline") or []) if e.get("timestamp")]
        claims = [Claim(f"{e['timestamp']}: {e['kind']} - {_quote(e['description'], 100)} "
                        f"(timestamp source: {e['source']})",
                        [e["evidence_id"]] if e.get("evidence_id") else ["timeline"])
                  for e in events[:15]]
        undated = [e for e in (analysis.get("timeline") or []) if not e.get("timestamp")]
        if undated:
            claims.append(Claim(f"{len(undated)} event(s) have no usable timestamp and are not "
                                "placed on the timeline.", ["timeline"]))
        return [Section("Timeline (only real timestamps are used)",
                        claims or [Claim("No dated events.", ["timeline"])])]

    def _graph(self, analysis, evidence_id):
        g = analysis.get("evidence_graph") or {}
        claims = [Claim(f"{g.get('node_count', 0)} entities and {g.get('edge_count', 0)} "
                        f"relationships; entity types {g.get('nodes_by_type', {})}.",
                        ["evidence_graph"])]
        for edge in (g.get("edges") or []):
            if edge["relation"] in ("replies_to", "envelope_from"):
                prov = edge["provenance"][0]
                claims.append(Claim(
                    f"{edge['source'].split(':', 1)[1]} {edge['relation'].replace('_', ' ')} "
                    f"{edge['target'].split(':', 1)[1]}, established by the {prov['source']}.",
                    [prov["evidence_id"]]))
                if len(claims) >= 8:
                    break
        return [Section("Evidence graph", claims)]

    def _feedback(self, analysis, evidence_id):
        entries = analysis.get("investigator_assessments") or []
        if not entries:
            return [Section("Investigator assessments", [Claim(
                "No investigator assessment has been recorded for this case.", ["case"])])]
        return [Section("Investigator assessments (human determinations)", [
            Claim(f"{e['evidence_id']}: {e['examiner']} recorded {e['assessment']} "
                  f"({e['agreement']}); the system had scored {e['system_band']} "
                  f"{e['system_score']}.", [e["evidence_id"], f"investigator:{e['evidence_id']}"])
            for e in entries])]

    def _unsupported(self, analysis, evidence_id):
        return [Section("Question not recognised", [Claim(
            "I can only explain this case's recorded evidence. Supported questions: "
            + "; ".join(SUPPORTED) + ".", ["case"])])]


def ask(question: str, analysis: dict[str, Any], evidence_id: str | None = None,
        provider: AssistantProvider | None = None) -> Answer:
    """Answer a question about one analysed case, grounded in its evidence."""
    return (provider or TemplateProvider()).answer(question[:500], analysis, evidence_id)
