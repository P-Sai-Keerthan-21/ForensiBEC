"""Render a case report as a self-contained HTML document.

No external assets are referenced, so the report can be archived alongside the
evidence and still render years later from the case file.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

BAND_COLOURS = {
    "CONFIRMED_BEC": ("#7f1d1d", "#fee2e2"),
    "LIKELY_BEC": ("#9a3412", "#ffedd5"),
    "SUSPICIOUS": ("#854d0e", "#fef9c3"),
    "BENIGN": ("#166534", "#dcfce7"),
}

SEVERITY_COLOURS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#4d7c0f",
    "INFO": "#475569",
}

STYLE = """
:root {
  --bg: #f8fafc; --panel: #ffffff; --ink: #0f172a; --muted: #64748b;
  --line: #e2e8f0;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 32px; background: var(--bg); color: var(--ink);
  font: 14px/1.6 "Segoe UI", system-ui, -apple-system, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 32px 0 12px; padding-bottom: 6px;
     border-bottom: 2px solid var(--line); }
h3 { font-size: 15px; margin: 0 0 6px; }
.sub { color: var(--muted); margin: 0 0 24px; }
.panel { background: var(--panel); border: 1px solid var(--line);
         border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 12px; margin-bottom: 20px; }
.stat { background: var(--panel); border: 1px solid var(--line);
        border-radius: 10px; padding: 14px 16px; }
.stat .n { font-size: 26px; font-weight: 650; }
.stat .l { color: var(--muted); font-size: 12px; text-transform: uppercase;
           letter-spacing: .04em; }
.band { display: inline-block; padding: 3px 11px; border-radius: 999px;
        font-weight: 650; font-size: 12px; letter-spacing: .03em; }
.msg-head { display: flex; justify-content: space-between; align-items: flex-start;
            gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }
.score { font-size: 28px; font-weight: 700; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
     color: var(--muted); }
code, .mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; }
.evidence { background: #f1f5f9; border-left: 3px solid #94a3b8; padding: 6px 10px;
            border-radius: 4px; word-break: break-word; }
.sev { font-weight: 650; font-size: 12px; white-space: nowrap; }
.narrative { white-space: pre-wrap; background: #f8fafc; border: 1px solid var(--line);
             border-radius: 8px; padding: 14px 16px; }
.custody { font-size: 12px; color: var(--muted); }
.custody .mono { color: var(--ink); }
.kv { display: grid; grid-template-columns: 150px 1fr; gap: 4px 14px; font-size: 13px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; word-break: break-word; }
footer { color: var(--muted); font-size: 12px; margin-top: 36px;
         border-top: 1px solid var(--line); padding-top: 14px; }
.table-wrap { overflow-x: auto; }
.lbl { font-size:10px; text-transform:uppercase; letter-spacing:.06em;
       color:var(--muted); margin:8px 0 3px; font-weight:700; }
.lbl:first-child { margin-top:0; }
.rec { background:#eff6ff; border-left:3px solid #1d4ed8; padding:6px 10px;
       border-radius:4px; }
.basis { display:inline-block; margin-top:5px; font-size:10px; padding:1px 7px;
         border-radius:999px; letter-spacing:.05em; font-weight:700; }
.basis-observed { background:#dcfce7; color:#166534; }
.basis-inferred { background:#fef9c3; color:#854d0e; }
.basis-insufficient { background:#e2e8f0; color:#475569; }
.conf { color:var(--muted); font-size:11px; }
.pill { display:inline-block; background:#f1f5f9; border:1px solid var(--line);
        border-radius:5px; padding:2px 8px; margin:2px 3px 2px 0;
        font-family:Consolas, monospace; font-size:11.5px; word-break:break-all; }
.tl { border-left:2px solid var(--line); padding-left:16px; margin-left:6px; }
.tl-item { position:relative; padding:7px 0; font-size:13px; }
.tl-item::before { content:""; position:absolute; left:-21px; top:14px;
        width:8px; height:8px; border-radius:50%; background:#94a3b8; }
.tl-time { font-family:Consolas, monospace; font-size:11.5px; color:var(--muted); }
.tl-src { color:var(--muted); font-size:11.5px; font-style:italic; }
.integrity-ok { background:#f0fdf4; border:1px solid #bbf7d0; color:#14532d;
        padding:11px 14px; border-radius:7px; }
.integrity-bad { background:#fef2f2; border:1px solid #fecaca; color:#7f1d1d;
        padding:11px 14px; border-radius:7px; }
.disclaim { background:#fefce8; border:1px solid #fde68a; color:#713f12;
        padding:10px 13px; border-radius:7px; font-size:12.5px; margin-top:10px; }
.small { font-size:12.5px; color:var(--muted); }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _band_chip(band: str) -> str:
    fg, bg = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))
    return f'<span class="band" style="color:{fg};background:{bg}">{_esc(band)}</span>'



def _pills(values: list[str], empty: str = "none") -> str:
    if not values:
        return f'<span class="small">{_esc(empty)}</span>'
    return "".join(f'<span class="pill">{_esc(v)}</span>' for v in values)


def _render_iocs(iocs: dict[str, list[str]]) -> str:
    """Extracted indicators, grouped by kind."""
    if not iocs or not any(iocs.values()):
        return '<p class="small">No indicators extracted.</p>'
    rows = []
    for kind, values in iocs.items():
        if not values:
            continue
        label = kind.replace("_", " ").title()
        rows.append(f"<tr><td><strong>{_esc(label)}</strong></td><td>{_pills(values)}</td></tr>")
    return '<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"


def _render_attachments(items: list[dict]) -> str:
    if not items:
        return '<p class="small">No attachments.</p>'
    rows = ["<tr><th>Filename</th><th>Declared</th><th>Actual</th>"
            "<th>Size</th><th>SHA-256</th><th>Mismatch</th></tr>"]
    for a in items:
        flag = ('<span style="color:#b91c1c;font-weight:700">YES</span>'
                if a.get("type_mismatch") else "no")
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(a.get("filename"))}</td>'
            f'<td class="mono">{_esc(a.get("declared_mime"))}</td>'
            f'<td class="mono">{_esc(a.get("detected_type"))}</td>'
            f'<td class="mono">{a.get("size_bytes", 0)}</td>'
            f'<td class="mono">{_esc((a.get("sha256") or "")[:24])}...</td>'
            f"<td>{flag}</td></tr>"
        )
        if a.get("notes"):
            rows.append(f'<tr><td colspan="6" class="small">{_esc(a["notes"])}</td></tr>')
    return '<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"


def _render_urls(items: list[dict]) -> str:
    if not items:
        return '<p class="small">No URLs found in the message body.</p>'
    rows = ["<tr><th>URL</th><th>Host</th><th>TLS</th><th>Notes</th></tr>"]
    for u in items:
        notes = []
        if u.get("is_ip_literal"):
            notes.append("IP literal")
        if u.get("is_punycode"):
            notes.append("punycode")
        if u.get("display_mismatch"):
            notes.append(f'displayed as {u["display_mismatch"]}')
        rows.append(
            "<tr>"
            f'<td class="mono" style="word-break:break-all">{_esc(u.get("raw"))}</td>'
            f'<td class="mono">{_esc(u.get("host"))}</td>'
            f'<td>{"https" if u.get("uses_https") else "<strong>http</strong>"}</td>'
            f'<td class="small">{_esc("; ".join(notes)) or "-"}</td></tr>'
        )
    return ('<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"
            '<p class="small">URLs are analysed statically. This tool never '
            'contacts a URL found in evidence.</p>')


def _render_mitre(entries: list[dict]) -> str:
    if not entries:
        return '<p class="small">No technique mapping suggested.</p>'
    rows = ["<tr><th>Technique</th><th>Tactic</th><th>Relevance</th><th>Suggested by</th></tr>"]
    for e in entries:
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(e["technique_id"])}<br>{_esc(e["technique"])}</td>'
            f'<td>{_esc(e["tactic"])}</td>'
            f'<td class="small">{_esc(e["relevance"])}</td>'
            f'<td class="mono small">{_esc(e["suggested_by"])}</td></tr>'
        )
    return ('<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"
            '<div class="disclaim">Potential technique mapping based on observed '
            'evidence. This is not attribution and does not identify any actor.</div>')


def _render_timeline(events: list[dict]) -> str:
    if not events:
        return '<p class="small">No timeline events.</p>'
    items = []
    for e in events:
        when = e.get("timestamp") or "undated"
        items.append(
            '<div class="tl-item">'
            f'<span class="tl-time">{_esc(when)}</span> &mdash; '
            f'<strong>{_esc(e.get("kind"))}</strong>: {_esc(e.get("description"))}'
            f'<br><span class="tl-src">source: {_esc(e.get("source"))}'
            + (f' &middot; {_esc(e["evidence_id"])}' if e.get("evidence_id") else "")
            + "</span></div>"
        )
    return '<div class="tl">' + "".join(items) + "</div>"


def _render_notes(notes: list[str]) -> str:
    if not notes:
        return ""
    return ('<div class="lbl">Analysis notes</div><ul class="small">'
            + "".join(f"<li>{_esc(n)}</li>" for n in notes) + "</ul>")


def _render_assessment(item: dict[str, Any], index: int) -> str:
    email = item["email"]
    custody = item["custody"]
    band = item["risk_band"]
    fg, _ = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))

    rows = []
    for indicator in item["indicators"]:
        colour = SEVERITY_COLOURS.get(indicator["severity"], "#475569")
        recommendation = indicator.get("recommendation", "")
        basis = indicator.get("basis", "OBSERVED")
        rows.append(
            "<tr>"
            f'<td class="sev" style="color:{colour}">{_esc(indicator["severity"])}</td>'
            f'<td><strong>{_esc(indicator["title"])}</strong><br>'
            f'<code>{_esc(indicator["code"])}</code>'
            f'<div class="basis basis-{_esc(basis).lower()}">{_esc(basis)}</div></td>'
            f'<td>'
            f'<div class="lbl">Observed evidence</div>'
            f'<div class="evidence mono">{_esc(indicator["observed_evidence"])}</div>'
            f'<div class="lbl">Inference</div><div>{_esc(indicator["inference"])}</div>'
            + (f'<div class="lbl">Recommendation</div>'
               f'<div class="rec">{_esc(recommendation)}</div>' if recommendation else "")
            + (f'<div class="lbl">Potential ATT&amp;CK</div>'
               f'<div class="mono">{_esc(", ".join(indicator.get("mitre", [])))}</div>'
               if indicator.get("mitre") else "")
            + "</td>"
            f'<td class="mono">+{indicator["contribution"]:.1f}<br>'
            f'<span class="conf">conf {indicator["confidence"]:.2f}</span></td>'
            "</tr>"
        )

    indicator_table = (
        '<div class="table-wrap"><table>'
        "<tr><th>Severity</th><th>Indicator</th><th>Observation / inference / recommendation</th><th>Risk</th></tr>"
        + "".join(rows)
        + "</table></div>"
        if rows else "<p><em>No indicators raised.</em></p>"
    )

    categories = " &middot; ".join(
        f"{_esc(k)} {v:.1f}" for k, v in item["category_scores"].items() if v
    ) or "none"

    return f"""
<div class="panel">
  <div class="msg-head">
    <div>
      <h3>#{index}. {_esc(email["subject"]) or "(no subject)"}</h3>
      <div class="custody">
        From <span class="mono">{_esc(email["from_display"])} &lt;{_esc(email["from_address"])}&gt;</span>
        &middot; {_esc(email["date_utc"]) or "no date"}
      </div>
    </div>
    <div style="text-align:right">
      <div class="score" style="color:{fg}">{item["risk_score"]:.1f}</div>
      {_band_chip(band)}
    </div>
  </div>

  <dl class="kv">
    <dt>Reply-To</dt><dd class="mono">{_esc(email["reply_to_address"]) or "(none)"}</dd>
    <dt>Recipients</dt><dd class="mono">{_esc(", ".join(email["to_addresses"])) or "(none)"}</dd>
    <dt>Attachments</dt><dd class="mono">{_esc(", ".join(email["attachments"])) or "(none)"}</dd>
    <dt>Message-ID</dt><dd class="mono">{_esc(email["message_id"]) or "(none)"}</dd>
    <dt>Category scores</dt><dd>{categories}</dd>
  </dl>

  <h4>Assessment</h4>
  <div class="narrative">{_esc(item["narrative"])}</div>

  <h4>Indicators ({item["indicator_count"]})</h4>
  {indicator_table}

  <h4>Attachments</h4>
  {_render_attachments(email.get("attachment_detail", []))}

  <h4>URLs</h4>
  {_render_urls(email.get("urls", []))}

  <h4>Extracted IOCs</h4>
  {_render_iocs(item.get("iocs", {}))}

  <h4>Potential ATT&amp;CK mapping</h4>
  {_render_mitre(item.get("mitre", []))}

  <h4>Timeline for this message</h4>
  {_render_timeline(item.get("timeline", []))}

  {_render_notes(item.get("analysis_notes", []))}

  <p class="custody" style="margin-top:14px">
    <strong>Chain of custody</strong> &mdash;
    source <span class="mono">{_esc(custody["source_path"])}</span>,
    {custody["size_bytes"]} bytes,
    SHA-256 <span class="mono">{_esc(custody["sha256"])}</span>,
    acquired {_esc(custody["acquired_utc"])} by {_esc(custody["examiner"])}.
  </p>
</div>
"""


def render_html(report: dict[str, Any], path: str | Path | None = None) -> str:
    """Render the case report; write it to `path` when given."""
    case = report["case"]
    summary = report["summary"]

    stats = "".join(
        f'<div class="stat"><div class="n">{value}</div><div class="l">{label}</div></div>'
        for label, value in (
            ("Messages analysed", summary["messages_analysed"]),
            ("Flagged", summary["messages_flagged"]),
            ("Highest score", f'{summary["highest_score"]:.1f}'),
            ("Mean score", f'{summary["mean_score"]:.1f}'),
        )
    )

    band_rows = "".join(
        f"<tr><td>{_band_chip(band)}</td><td class='mono'>{count}</td></tr>"
        for band, count in summary["band_counts"].items()
    )

    top_rows = "".join(
        f"<tr><td><code>{_esc(code)}</code></td><td class='mono'>{count}</td></tr>"
        for code, count in summary["most_common_indicators"]
    ) or "<tr><td colspan='2'><em>none</em></td></tr>"

    bodies = "".join(
        _render_assessment(item, i)
        for i, item in enumerate(report["assessments"], start=1)
    )

    backends = ", ".join(
        f"{name}: {'available' if ok else 'unavailable (regex fallback in use)'}"
        for name, ok in (case.get("nlp_backends") or {}).items()
    ) or "not reported"

    # -- Case-level DFIR sections -------------------------------------------
    parts: list[str] = []

    timeline = report.get("timeline") or []
    if timeline:
        parts.append("<h2>Investigation timeline</h2><div class=\"panel\">"
                     + _render_timeline(timeline) + "</div>")

    graph = report.get("graph") or {}
    if graph.get("node_count"):
        suspicious = graph.get("suspicious_relationships") or []
        rows = ["<tr><th>From</th><th>To</th><th>Relationship</th><th>Max risk</th></tr>"]
        for rel in suspicious[:15]:
            rows.append(
                "<tr>"
                f'<td class="mono">{_esc(rel["source"])}</td>'
                f'<td class="mono">{_esc(rel["target"])}</td>'
                f'<td class="small">{_esc(", ".join(rel["kinds"]))}</td>'
                f'<td class="mono">{rel["max_risk"]:.1f}</td></tr>'
            )
        table = ('<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"
                 if suspicious else
                 '<p class="small">No boundary-crossing relationships on flagged messages.</p>')
        parts.append(
            "<h2>Communication graph</h2><div class=\"panel\">"
            f'<p class="small">{graph["node_count"]} addresses, {graph["edge_count"]} '
            f'relationships (backend: {_esc(graph.get("backend"))}).</p>'
            "<div class=\"lbl\">Relationships crossing the organisational boundary on flagged mail</div>"
            + table + "</div>"
        )

    corr = report.get("correlation") or {}
    if corr:
        matches = corr.get("matches") or []
        if matches:
            rows = ["<tr><th>Indicator</th><th>Kind</th><th>Also seen in</th></tr>"]
            for m in matches[:20]:
                rows.append(
                    "<tr>"
                    f'<td class="mono">{_esc(m["value"])}</td>'
                    f'<td class="small">{_esc(m["kind"])}</td>'
                    f'<td class="mono">{_esc(", ".join(m["seen_in_cases"]))}</td></tr>'
                )
            body = ('<p><strong>Potential IOC reuse across cases.</strong></p>'
                    '<div class="table-wrap"><table>' + "".join(rows) + "</table></div>")
        else:
            body = '<p class="small">No indicator from this case was previously recorded locally.</p>'
        parts.append(
            "<h2>Cross-case IOC correlation</h2><div class=\"panel\">"
            + body + f'<div class="disclaim">{_esc(corr.get("note", ""))}</div></div>'
        )

    intel = report.get("intelligence") or {}
    if intel:
        parts.append(
            "<h2>Threat intelligence</h2><div class=\"panel\">"
            f'<p>Provider: <strong>{_esc(intel.get("provider"))}</strong></p>'
            f'<p class="small">{_esc(intel.get("status"))}</p></div>'
        )

    audit = report.get("audit") or {}
    if audit:
        integrity = audit.get("integrity") or {}
        valid = integrity.get("valid")
        cls = "integrity-ok" if valid else "integrity-bad"
        headline = ("Audit chain verified - no tampering detected."
                    if valid else "AUDIT CHAIN BROKEN - the log has been altered.")
        entries = audit.get("entries") or []
        rows = ["<tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th>"
                "<th>Detail</th><th>Entry hash</th></tr>"]
        for e in entries[:60]:
            rows.append(
                "<tr>"
                f'<td class="mono">{e["sequence"]}</td>'
                f'<td class="mono">{_esc(e["timestamp_utc"])}</td>'
                f'<td>{_esc(e["actor"])}</td>'
                f'<td class="mono">{_esc(e["action"])}</td>'
                f'<td class="small" style="word-break:break-all">{_esc(e["detail"])}</td>'
                f'<td class="mono">{_esc(e["entry_hash"][:16])}...</td></tr>'
            )
        parts.append(
            "<h2>Evidence integrity &amp; audit log</h2><div class=\"panel\">"
            f'<div class="{cls}"><strong>{_esc(headline)}</strong><br>'
            f'<span class="small">{_esc(integrity.get("reason", ""))} '
            f'({integrity.get("entries", 0)} entries)</span></div>'
            '<div class="lbl" style="margin-top:14px">Hash-chained audit trail</div>'
            '<div class="table-wrap"><table>' + "".join(rows) + "</table></div>"
            '<p class="small">Each entry hashes its own content together with the '
            'previous entry\'s hash, so altering, reordering or deleting any entry '
            'breaks the chain from that point onward.</p></div>'
        )

    rejected = case.get("rejected_uploads") or []
    if rejected:
        parts.append(
            "<h2>Rejected uploads</h2><div class=\"panel\"><ul class=\"small\">"
            + "".join(f"<li>{_esc(r)}</li>" for r in rejected)
            + "</ul></div>"
        )

    case_sections = "".join(parts)

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FORENSIBEC - {_esc(case.get("case_id") or case["name"])}</title>
<style>{STYLE}</style></head>
<body><div class="wrap">
  <h1>FORENSIBEC &mdash; Business Email Compromise Investigation</h1>
  <p class="sub">
    Case <strong>{_esc(case.get("case_id") or case["name"])}</strong>
    ({_esc(case["name"])}) &middot;
    examiner {_esc(case["examiner"])} &middot;
    generated {_esc(case["generated_utc"])}
  </p>

  <div class="grid">{stats}</div>

  <h2>Risk distribution</h2>
  <div class="panel"><div class="table-wrap"><table>
    <tr><th>Band</th><th>Messages</th></tr>{band_rows}
  </table></div></div>

  <h2>Most frequent indicators</h2>
  <div class="panel"><div class="table-wrap"><table>
    <tr><th>Indicator code</th><th>Occurrences</th></tr>{top_rows}
  </table></div></div>

  {case_sections}

  <h2>Per-message assessments</h2>
  {bodies}

  <footer>
    Generated by {_esc(case["tool"])}. NLP backends &mdash; {_esc(backends)}.<br>
    Scores are produced by a transparent weighted-indicator model; every point
    is attributable to a named rule and the evidence quoted beside it.
  </footer>
</div></body></html>
"""

    if path is not None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding="utf-8")

    return document
