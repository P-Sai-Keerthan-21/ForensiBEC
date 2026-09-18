"""Render the forensic investigation report as a self-contained HTML document.

No external assets are referenced, so the report can be archived alongside the
evidence and still render years later from the case file.

Structure
---------
The report follows a fixed investigative order and keeps four things strictly
apart, because an investigator must be able to accept one while disputing
another:

    OBSERVED EVIDENCE      what the artifact actually contains, quoted
    SYSTEM INFERENCE       what the rules conclude from it
    RISK                   how much each conclusion contributes to the score
    RECOMMENDATION         what to do next

Investigator assessments are a fifth, separate category: human judgements
recorded against the case, never mixed into system output.

Every section renders an explicit "not present" statement when its evidence is
absent. Nothing is ever filled in by the renderer.

All values originate in attacker-controlled evidence and are HTML-escaped at
the point of output. The only unescaped markup is the evidence-graph SVG, which
this application generates itself with every label already escaped.
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
    "CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207",
    "LOW": "#4d7c0f", "INFO": "#475569",
}

# Report sections, in order, and which indicator codes/categories feed each.
DOMAIN_CODES = {"LOOKALIKE_DOMAIN", "MIXED_SCRIPT_DOMAIN"}
FINANCIAL_CODES = {"PAYMENT_REQUEST", "BANKING_CHANGE_REQUEST",
                   "GIFT_CARD_REQUEST", "MONEY_ENTITY_PRESENT"}

STYLE = """
:root { --bg:#f8fafc; --panel:#fff; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; }
* { box-sizing:border-box; }
body { margin:0; padding:32px; background:var(--bg); color:var(--ink);
       font:14px/1.6 "Segoe UI", system-ui, -apple-system, sans-serif; }
.wrap { max-width:1100px; margin:0 auto; }
h1 { font-size:24px; margin:0 0 4px; }
h2 { font-size:17px; margin:34px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--line); }
h2 .num { color:var(--muted); font-weight:500; margin-right:6px; }
h3 { font-size:15px; margin:0 0 6px; }
h4 { font-size:12.5px; margin:22px 0 6px; text-transform:uppercase; letter-spacing:.05em;
     color:#334155; border-left:3px solid #94a3b8; padding-left:8px; }
.sub { color:var(--muted); margin:0 0 20px; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:10px;
         padding:18px 20px; margin-bottom:16px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.stat .n { font-size:24px; font-weight:650; }
.stat .l { color:var(--muted); font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; }
.band { display:inline-block; padding:3px 11px; border-radius:999px; font-weight:650;
        font-size:12px; letter-spacing:.03em; }
.msg-head { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }
.score { font-size:28px; font-weight:700; }
table { width:100%; border-collapse:collapse; margin-top:8px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }
code, .mono { font-family:"Cascadia Code", Consolas, monospace; font-size:12px; word-break:break-word; }
.table-wrap { overflow-x:auto; }
.evidence { background:#f1f5f9; border-left:3px solid #64748b; padding:6px 10px; border-radius:4px;
            word-break:break-word; }
.inference { border-left:3px solid #ca8a04; padding:4px 10px; background:#fefce8; border-radius:4px; }
.rec { background:#eff6ff; border-left:3px solid #1d4ed8; padding:6px 10px; border-radius:4px; }
.lbl { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted);
       margin:8px 0 3px; font-weight:700; }
.lbl:first-child { margin-top:0; }
.sev { font-weight:650; font-size:12px; white-space:nowrap; }
.basis { display:inline-block; margin-top:5px; font-size:10px; padding:1px 7px; border-radius:999px;
         letter-spacing:.05em; font-weight:700; }
.basis-observed { background:#dcfce7; color:#166534; }
.basis-inferred { background:#fef9c3; color:#854d0e; }
.basis-insufficient { background:#e2e8f0; color:#475569; }
.absent { color:var(--muted); font-style:italic; }
.small { font-size:12.5px; color:var(--muted); }
.pill { display:inline-block; background:#f1f5f9; border:1px solid var(--line); border-radius:5px;
        padding:2px 8px; margin:2px 3px 2px 0; font-family:Consolas, monospace; font-size:11.5px;
        word-break:break-all; }
.kv { display:grid; grid-template-columns:170px 1fr; gap:4px 14px; font-size:13px; }
.kv dt { color:var(--muted); } .kv dd { margin:0; word-break:break-word; }
.ok { color:#166534; font-weight:650; } .bad { color:#b91c1c; font-weight:650; }
.warn { color:#a16207; font-weight:650; }
.tl { border-left:2px solid var(--line); padding-left:16px; margin-left:6px; }
.tl-item { position:relative; padding:6px 0; font-size:13px; }
.tl-item::before { content:""; position:absolute; left:-21px; top:13px; width:8px; height:8px;
                   border-radius:50%; background:#94a3b8; }
.tl-time { font-family:Consolas, monospace; font-size:11.5px; color:var(--muted); }
.tl-src { color:var(--muted); font-size:11.5px; font-style:italic; }
.integrity-ok { background:#f0fdf4; border:1px solid #bbf7d0; color:#14532d; padding:11px 14px; border-radius:7px; }
.integrity-bad { background:#fef2f2; border:1px solid #fecaca; color:#7f1d1d; padding:11px 14px; border-radius:7px; }
.disclaim { background:#fefce8; border:1px solid #fde68a; color:#713f12; padding:10px 13px;
            border-radius:7px; font-size:12.5px; margin-top:10px; }
.human { background:#f5f3ff; border:1px solid #ddd6fe; border-left:4px solid #6d28d9;
         padding:12px 14px; border-radius:7px; }
.legend span { display:inline-block; margin-right:14px; font-size:12px; }
.legend i { display:inline-block; width:12px; height:12px; border-radius:3px; margin-right:5px;
            vertical-align:-1px; }
.narrative { white-space:pre-wrap; background:#f8fafc; border:1px solid var(--line);
             border-radius:8px; padding:12px 14px; font-size:13px; }
nav.toc { columns:3; column-gap:24px; font-size:12.5px; }
nav.toc a { color:#1d4ed8; text-decoration:none; display:block; }
footer { color:var(--muted); font-size:12px; margin-top:36px; border-top:1px solid var(--line); padding-top:14px; }
@media print { body { padding:0; } .panel { break-inside:avoid; } }
"""


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _absent(text: str) -> str:
    return f'<p class="absent">{_esc(text)}</p>'


def _band_chip(band: str) -> str:
    fg, bg = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))
    return f'<span class="band" style="color:{fg};background:{bg}">{_esc(band)}</span>'


def _pills(values: list[str], empty: str = "none") -> str:
    if not values:
        return f'<span class="absent">{_esc(empty)}</span>'
    return "".join(f'<span class="pill">{_esc(v)}</span>' for v in values)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Rows are pre-escaped HTML fragments."""
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><tr>{head}</tr>{body}</table></div>'


def _section(number: int, anchor: str, title: str, body: str) -> str:
    return (f'<h2 id="{anchor}"><span class="num">{number}.</span>{_esc(title)}</h2>'
            f'<div class="panel">{body}</div>')


# ---------------------------------------------------------------------------
# Indicator rendering: EVIDENCE -> INFERENCE -> RISK -> RECOMMENDATION
# ---------------------------------------------------------------------------

def _indicator_rows(indicators: list[dict[str, Any]]) -> str:
    rows = []
    for ind in indicators:
        colour = SEVERITY_COLOURS.get(ind["severity"], "#475569")
        basis = ind.get("basis", "OBSERVED")
        mitre = ", ".join(ind.get("mitre") or [])
        rows.append(
            "<tr>"
            f'<td style="width:24%"><strong>{_esc(ind["title"])}</strong><br>'
            f'<code>{_esc(ind["code"])}</code><br>'
            f'<span class="sev" style="color:{colour}">{_esc(ind["severity"])}</span> '
            f'<span class="basis basis-{_esc(basis).lower()}">{_esc(basis)}</span></td>'
            f'<td style="width:28%"><div class="evidence mono">{_esc(ind["observed_evidence"])}</div></td>'
            f'<td style="width:26%"><div class="inference">{_esc(ind["inference"])}</div>'
            + (f'<div class="small" style="margin-top:4px">Potential ATT&amp;CK: '
               f'<code>{_esc(mitre)}</code></div>' if mitre else "")
            + "</td>"
            f'<td class="mono" style="width:8%">+{ind["contribution"]:.1f}<br>'
            f'<span class="small">w {ind["weight"]:g} &times; c {ind["confidence"]:.2f}</span></td>'
            f'<td style="width:14%"><div class="rec">{_esc(ind.get("recommendation", ""))}</div></td>'
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><tr>'
        "<th>Finding</th><th>Observed evidence</th><th>System inference</th>"
        "<th>Risk</th><th>Recommendation</th></tr>"
        + "".join(rows) + "</table></div>"
    )


def _findings(indicators: list[dict[str, Any]], empty: str) -> str:
    if not indicators:
        return _absent(empty)
    return _indicator_rows(indicators)


def _split(indicators: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Partition one message's indicators into report sections."""
    groups: dict[str, list[dict[str, Any]]] = {
        "identity": [], "domain": [], "auth": [], "behaviour": [], "nlp": [],
        "financial": [], "thread": [], "style": [], "url": [], "attachment": [],
        "intel": [],
    }
    for ind in indicators:
        code, cat = ind["code"], ind["category"]
        if code in DOMAIN_CODES:
            groups["domain"].append(ind)
        elif cat == "SENDER":
            groups["identity"].append(ind)
        elif cat == "AUTHENTICATION":
            groups["auth"].append(ind)
        elif cat in ("BEHAVIOR", "ANOMALY"):
            groups["behaviour"].append(ind)
        elif code in FINANCIAL_CODES:
            groups["financial"].append(ind)
        elif cat == "CONTENT":
            groups["nlp"].append(ind)
        elif cat == "THREAD":
            groups["thread"].append(ind)
        elif cat == "STYLOMETRY":
            groups["style"].append(ind)
        elif cat == "URL":
            groups["url"].append(ind)
        elif cat == "ATTACHMENT":
            groups["attachment"].append(ind)
        else:
            groups["intel"].append(ind)
    return groups


# ---------------------------------------------------------------------------
# Per-message blocks
# ---------------------------------------------------------------------------

def _metadata(email: dict[str, Any], item: dict[str, Any]) -> str:
    return (
        '<dl class="kv">'
        f'<dt>Evidence ID</dt><dd class="mono">{_esc(item["evidence_id"])}</dd>'
        f'<dt>Subject</dt><dd>{_esc(email.get("subject")) or "<span class=absent>(none)</span>"}</dd>'
        f'<dt>Date (UTC)</dt><dd class="mono">{_esc(email.get("date_utc")) or "<span class=absent>no parsable Date header</span>"}</dd>'
        f'<dt>Message-ID</dt><dd class="mono">{_esc(email.get("message_id")) or "<span class=absent>(none)</span>"}</dd>'
        f'<dt>To</dt><dd class="mono">{_esc(", ".join(email.get("to_addresses") or [])) or "<span class=absent>(none)</span>"}</dd>'
        f'<dt>Cc</dt><dd class="mono">{_esc(", ".join(email.get("cc_addresses") or [])) or "<span class=absent>(none)</span>"}</dd>'
        f'<dt>SHA-256</dt><dd class="mono">{_esc(email.get("sha256"))}</dd>'
        "</dl>"
    )


def _address_comparison(email: dict[str, Any]) -> str:
    """From / Reply-To / Return-Path side by side - observed values only."""
    sender = (email.get("from_address") or "").lower()
    rows = []
    for field, value in (("From", email.get("from_address")),
                         ("Reply-To", email.get("reply_to_address")),
                         ("Return-Path", email.get("return_path"))):
        if not value:
            status = '<span class="absent">header absent</span>'
        elif field == "From":
            status = '<span class="small">reference address</span>'
        elif value.lower() == sender:
            status = '<span class="ok">matches From</span>'
        else:
            status = '<span class="bad">differs from From</span>'
        display = email.get("from_display") if field == "From" else ""
        rows.append([_esc(field), f'<span class="mono">{_esc(value) or "-"}</span>',
                     _esc(display) or '<span class="absent">-</span>', status])
    return _table(["Header", "Address", "Display name", "Comparison"], rows)


def _header_forensics(email: dict[str, Any]) -> str:
    headers = email.get("headers") or {}
    raw_rows = [[f"<code>{_esc(k)}</code>", f'<span class="mono">{_esc(v)}</span>']
                for k, v in sorted(headers.items())]
    received = email.get("received_chain") or []
    hops = "".join(f"<li class='mono'>{_esc(h)}</li>" for h in received)
    return (
        "<h4>From / Reply-To / Return-Path</h4>" + _address_comparison(email)
        + "<h4>Received chain (as delivered, most recent first)</h4>"
        + (f"<ol>{hops}</ol>" if received else _absent("No Received headers present."))
        + "<h4>Preserved header values</h4>"
        + (_table(["Header", "Value"], raw_rows) if raw_rows else _absent("No headers preserved."))
    )


def _auth_block(email: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    import re

    raw = email.get("authentication_results") or ""
    verdicts = []
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", raw, re.I)
        verdict = m.group(1).lower() if m else None
        cls = "ok" if verdict == "pass" else ("bad" if verdict in {"fail", "softfail", "permerror"}
                                              else "absent")
        verdicts.append([mech.upper(), f'<span class="{cls}">{_esc(verdict or "not reported")}</span>'])
    return (
        (f'<div class="lbl">Authentication-Results (observed)</div>'
         f'<div class="evidence mono">{_esc(raw)}</div>' if raw
         else _absent("No Authentication-Results header: SPF/DKIM/DMARC cannot be assessed "
                      "from this message."))
        + _table(["Mechanism", "Verdict recorded by receiving server"], verdicts)
        + "<h4>Authentication findings</h4>"
        + _findings(findings, "No authentication findings.")
    )


def _domain_block(item: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    rows = []
    for d in item.get("domain_analysis") or []:
        chars = "; ".join(f"{c['char']} {c['codepoint']} {c['script']} -> {c['imitates']}"
                          for c in d.get("confusable_chars") or [])
        resembles = (f'{_esc(d["best_match"])} (similarity {d["similarity"]:.2f}, '
                     f'distance {d["edit_distance"]})' if d.get("resembles_trusted")
                     else ('<span class="ok">trusted domain</span>' if d.get("trusted")
                           else '<span class="absent">no resemblance</span>'))
        rows.append([
            _esc(d["role"]),
            f'<span class="mono">{_esc(d["original"])}</span>',
            f'<span class="mono">{_esc(d["ascii_form"])}</span>'
            + (' <span class="warn">IDN</span>' if d.get("is_idn") else ""),
            f'<span class="mono">{_esc(d["skeleton"])}</span>',
            _esc(", ".join(d.get("scripts") or [])) + (
                ' <span class="bad">MIXED</span>' if d.get("is_mixed_script") else ""),
            f'<span class="mono">{_esc(chars)}</span>' if chars else '<span class="absent">none</span>',
            resembles,
        ])
    table = (_table(["Role", "Original", "Punycode / ASCII", "Normalised skeleton",
                     "Scripts", "Confusable characters", "Potential impersonated domain"], rows)
             if rows else _absent("No domains to analyse."))
    return (table + "<h4>Domain and confusable findings</h4>"
            + _findings(findings, "No look-alike, homoglyph or mixed-script domain findings."))


def _url_block(email: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    urls = email.get("urls") or []
    rows = []
    for u in urls:
        notes = [n for n, on in (("IP literal", u.get("is_ip_literal")),
                                 ("punycode", u.get("is_punycode"))) if on]
        if u.get("display_mismatch"):
            notes.append(f"displayed as {u['display_mismatch']}")
        rows.append([f'<span class="mono">{_esc(u.get("raw"))}</span>',
                     f'<span class="mono">{_esc(u.get("host"))}</span>',
                     "https" if u.get("uses_https") else '<span class="warn">http</span>',
                     _esc("; ".join(notes)) or '<span class="absent">-</span>'])
    return ((_table(["URL", "Host", "Scheme", "Observations"], rows)
             + '<p class="small">Static analysis only. No URL found in evidence is ever '
               'resolved or contacted.</p>')
            if rows else _absent("No URLs in the message body.")) + (
        "<h4>URL findings</h4>" + _findings(findings, "No URL findings."))


def _attachment_block(email: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    items = email.get("attachment_detail") or []
    rows = [[f'<span class="mono">{_esc(a.get("filename"))}</span>',
             f'<span class="mono">{_esc(a.get("declared_mime"))}</span>',
             f'<span class="mono">{_esc(a.get("detected_type"))}</span>',
             f'<span class="mono">{a.get("size_bytes", 0)}</span>',
             f'<span class="mono">{_esc(a.get("sha256"))}</span>',
             '<span class="bad">YES</span>' if a.get("type_mismatch") else "no"]
            for a in items]
    return ((_table(["Filename", "Declared MIME", "Actual type (magic bytes)", "Bytes",
                     "SHA-256", "Mismatch"], rows)
             + '<p class="small">Attachments are hashed and type-checked in memory. They '
               'are never opened, executed or extracted.</p>')
            if rows else _absent("No attachments.")) + (
        "<h4>Attachment findings</h4>" + _findings(findings, "No attachment findings."))


def _thread_block(email: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    refs = email.get("references") or []
    return (
        '<dl class="kv">'
        f'<dt>In-Reply-To</dt><dd class="mono">{_esc(email.get("in_reply_to")) or "<span class=absent>absent</span>"}</dd>'
        f'<dt>References</dt><dd>{_pills(refs, "absent")}</dd>'
        "</dl><h4>Thread findings</h4>"
        + _findings(findings, "No thread findings. Thread analysis only reports what "
                              "the threading headers support.")
    )


def _style_block(item: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    notes = [n for n in item.get("analysis_notes") or [] if n.startswith("Stylometry")]
    return ("".join(f'<p class="small">{_esc(n)}</p>' for n in notes)
            + _findings(findings, "No stylometric findings."))


def _iocs(iocs: dict[str, list[str]]) -> str:
    if not iocs or not any(iocs.values()):
        return _absent("No indicators extracted.")
    rows = [[f"<strong>{_esc(k.replace('_', ' ').title())}</strong>", _pills(v)]
            for k, v in iocs.items() if v]
    return _table(["Kind", "Values (normalised)"], rows)


def _mitre(entries: list[dict[str, str]]) -> str:
    if not entries:
        return _absent("No technique mapping suggested.")
    rows = [[f'<code>{_esc(e["technique_id"])}</code><br>{_esc(e["technique"])}',
             _esc(e["tactic"]), _esc(e["relevance"]),
             f'<code>{_esc(e["suggested_by"])}</code>'] for e in entries]
    return (_table(["Technique", "Tactic", "Relevance", "Suggested by"], rows)
            + '<div class="disclaim">Potential technique mapping based on observed evidence. '
              'This is not attribution and identifies no actor.</div>')


def _fusion(item: dict[str, Any]) -> str:
    fusion = item.get("fusion") or {}
    if not fusion:
        return _absent("Fusion breakdown unavailable.")
    rows = [[_esc(cat), f'<span class="mono">{raw:.2f}</span>',
             f'<span class="mono">{fusion["category_caps"].get(cat, 100):g}</span>',
             f'<span class="mono">{fusion["capped_by_category"].get(cat, 0):.2f}</span>']
            for cat, raw in fusion.get("raw_by_category", {}).items()]
    reasons = fusion.get("corroboration_reasons") or []
    verified = fusion.get("identity_verified")
    return (
        (_table(["Evidence category", "Sum of contributions", "Category cap", "Counted"], rows)
         if rows else _absent("No indicator contributed to the score."))
        + '<dl class="kv" style="margin-top:10px">'
        f'<dt>Subtotal</dt><dd class="mono">{fusion.get("subtotal", 0):.2f}</dd>'
        f'<dt>Corroboration bonus</dt><dd class="mono">+{fusion.get("corroboration_bonus", 0):g}</dd>'
        f'<dt>Why</dt><dd>{_esc("; ".join(reasons)) or "<span class=absent>no corroborating combination present</span>"}</dd>'
        f'<dt>Identity verified</dt><dd>{"yes - pressure language earns no bonus" if verified else "no"}</dd>'
        f'<dt>Formula</dt><dd class="mono">{_esc(fusion.get("formula"))}</dd>'
        "</dl>"
    )


def _risk(item: dict[str, Any]) -> str:
    band = item["risk_band"]
    fg, _ = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))
    thresholds = (item.get("fusion") or {}).get("band_thresholds") or {}
    bands = ", ".join(f"{b} &ge; {t:g}" for b, t in sorted(thresholds.items(), key=lambda x: -x[1]))
    return (
        f'<div class="msg-head"><div><div class="score" style="color:{fg}">'
        f'{item["risk_score"]:.1f}<span class="small"> / 100</span></div>{_band_chip(band)}</div>'
        f'<div class="small" style="max-width:560px">This is a <strong>rule-based risk score</strong>, '
        "not a probability. It is the capped, corroboration-adjusted sum of the "
        "contributions listed above. Statistical confidence in a detection is a separate "
        "question this score does not answer."
        + (f"<br>Bands: {bands}." if bands else "") + "</div></div>"
        + f'<div class="lbl" style="margin-top:12px">System narrative</div>'
          f'<div class="narrative">{_esc(item.get("narrative"))}</div>'
    )


def _recommendations(indicators: list[dict[str, Any]]) -> str:
    seen: dict[str, list[str]] = {}
    for ind in indicators:
        rec = (ind.get("recommendation") or "").strip()
        if rec:
            seen.setdefault(rec, []).append(ind["code"])
    if not seen:
        return _absent("No action recommended beyond routine handling.")
    return "<ol>" + "".join(
        f'<li>{_esc(rec)} <span class="small">(from <code>{_esc(", ".join(codes))}</code>)</span></li>'
        for rec, codes in seen.items()) + "</ol>"


def _timeline(events: list[dict[str, Any]]) -> str:
    if not events:
        return _absent("No timeline events.")
    items = []
    for e in events:
        items.append(
            '<div class="tl-item">'
            f'<span class="tl-time">{_esc(e.get("timestamp") or "undated")}</span> &mdash; '
            f'<strong>{_esc(e.get("kind"))}</strong>: {_esc(e.get("description"))}'
            f'<br><span class="tl-src">source: {_esc(e.get("source"))}'
            + (f' &middot; {_esc(e["evidence_id"])}' if e.get("evidence_id") else "")
            + "</span></div>")
    return '<div class="tl">' + "".join(items) + "</div>"


def _render_message(item: dict[str, Any], index: int) -> str:
    email = item["email"]
    groups = _split(item["indicators"])
    custody = item["custody"]

    blocks = [
        ("Email metadata", _metadata(email, item)),
        ("Header forensics", _header_forensics(email)),
        ("Sender identity and display-name analysis",
         _findings(groups["identity"], "No identity or display-name findings.")),
        ("Domain and Unicode confusable analysis", _domain_block(item, groups["domain"])),
        ("SPF / DKIM / DMARC", _auth_block(email, groups["auth"])),
        ("Behavioural analysis",
         _findings(groups["behaviour"], "No behavioural or statistical findings.")),
        ("NLP and social-engineering indicators",
         _findings(groups["nlp"], "No urgency, authority, secrecy or credential language found.")),
        ("Financial intent",
         _findings(groups["financial"], "No payment, bank-change or monetary indicators.")),
        ("Thread reconstruction", _thread_block(email, groups["thread"])),
        ("Stylometry", _style_block(item, groups["style"])),
        ("URL analysis", _url_block(email, groups["url"])),
        ("Attachment analysis", _attachment_block(email, groups["attachment"])),
        ("Extracted IOCs", _iocs(item.get("iocs", {}))),
        ("Threat intelligence and correlation findings",
         _findings(groups["intel"], "No local intelligence or cross-case correlation findings.")),
        ("Potential ATT&CK mapping", _mitre(item.get("mitre", []))),
        ("Evidence fusion", _fusion(item)),
        ("Risk assessment", _risk(item)),
        ("Investigator recommendations", _recommendations(item["indicators"])),
        ("Message timeline", _timeline(item.get("timeline", []))),
    ]
    notes = [n for n in item.get("analysis_notes") or [] if not n.startswith("Stylometry")]
    body = "".join(f"<h4>{_esc(title)}</h4>{content}" for title, content in blocks)
    if notes:
        body += "<h4>Analysis notes</h4><ul class='small'>" + "".join(
            f"<li>{_esc(n)}</li>" for n in notes) + "</ul>"

    fg, _ = BAND_COLOURS.get(item["risk_band"], ("#334155", "#e2e8f0"))
    return (
        f'<div class="panel" id="msg-{index}">'
        f'<div class="msg-head"><div><h3>#{index}. {_esc(email.get("subject")) or "(no subject)"}</h3>'
        f'<div class="small">From <span class="mono">{_esc(email.get("from_display"))} '
        f'&lt;{_esc(email.get("from_address"))}&gt;</span> &middot; {_esc(item["evidence_id"])}</div></div>'
        f'<div style="text-align:right"><div class="score" style="color:{fg}">{item["risk_score"]:.1f}</div>'
        f'{_band_chip(item["risk_band"])}</div></div>'
        + body
        + f'<p class="small" style="margin-top:14px"><strong>Chain of custody</strong> &mdash; '
          f'source <span class="mono">{_esc(custody["source_path"])}</span>, '
          f'{custody["size_bytes"]} bytes, SHA-256 <span class="mono">{_esc(custody["sha256"])}</span>, '
          f'acquired {_esc(custody["acquired_utc"])} by {_esc(custody["examiner"])} '
          f'using {_esc(custody["tool_version"])}.</p>'
        "</div>"
    )


# ---------------------------------------------------------------------------
# Case-level sections
# ---------------------------------------------------------------------------

def _executive_summary(report: dict[str, Any]) -> str:
    summary = report["summary"]
    items = report["assessments"]
    stats = "".join(
        f'<div class="stat"><div class="n">{v}</div><div class="l">{_esc(k)}</div></div>'
        for k, v in (("Messages analysed", summary["messages_analysed"]),
                     ("Above BENIGN", summary["messages_flagged"]),
                     ("Highest risk score", f'{summary["highest_score"]:.1f}'),
                     ("Mean risk score", f'{summary["mean_score"]:.1f}')))
    bands = "".join(f"<li>{_band_chip(b)} {n}</li>" for b, n in summary["band_counts"].items())

    lines = []
    if items:
        top = items[0]
        principal = [i for i in top["indicators"] if i["severity"] in ("CRITICAL", "HIGH")][:4]
        lines.append(
            f"The highest-risk message is <strong>{_esc(top['evidence_id'])}</strong> "
            f"(“{_esc(top['email'].get('subject'))}”), scored "
            f"<strong>{top['risk_score']:.1f}</strong> ({_esc(top['risk_band'])}).")
        if principal:
            lines.append("Its principal observed findings are: " + "; ".join(
                f"<em>{_esc(i['title'])}</em>" for i in principal) + ".")
    lines.append("This summary reports technical indicators. Whether an offence occurred is "
                 "a determination for the investigator, recorded separately in "
                 "§ Investigator assessment.")
    return (f'<div class="grid">{stats}</div><ul style="list-style:none;padding:0;margin:14px 0">'
            f'{bands}</ul>' + "".join(f"<p>{line}</p>" for line in lines))


def _evidence_information(report: dict[str, Any]) -> str:
    register = report["case"].get("evidence_register")
    if register:
        rows = [[f'<span class="mono">{_esc(e["evidence_id"])}</span>',
                 _esc(e["original_filename"]),
                 f'<span class="mono">{e["size_bytes"]}</span>',
                 f'<span class="mono">{_esc(e["added_utc"])}</span>', _esc(e["added_by"])]
                for e in register]
        return _table(["Evidence ID", "Submitted as", "Bytes", "Added (UTC)", "Added by"], rows)
    rows = [[f'<span class="mono">{_esc(i["evidence_id"])}</span>',
             f'<span class="mono">{_esc(i["custody"]["source_path"])}</span>',
             f'<span class="mono">{i["custody"]["size_bytes"]}</span>']
            for i in report["assessments"]]
    return _table(["Evidence ID", "Source", "Bytes"], rows)


def _integrity(report: dict[str, Any]) -> str:
    rows = [[f'<span class="mono">{_esc(i["evidence_id"])}</span>',
             f'<span class="mono">{_esc(i["custody"]["sha256"])}</span>']
            for i in report["assessments"]]
    audit = (report.get("audit") or {}).get("integrity") or {}
    status = ""
    if audit:
        cls = "integrity-ok" if audit.get("valid") else "integrity-bad"
        status = (f'<div class="{cls}" style="margin-bottom:12px"><strong>'
                  + ("Audit chain verified." if audit.get("valid")
                     else "AUDIT CHAIN BROKEN - the log has been altered.")
                  + f'</strong> <span class="small">{_esc(audit.get("reason"))} '
                    f'({audit.get("entries", 0)} entries)</span></div>')
    return (status + '<p class="small">SHA-256 computed over the raw source bytes before '
            'any parsing. Each value identifies exactly the bytes this report describes.</p>'
            + _table(["Evidence ID", "SHA-256"], rows))


def _custody(report: dict[str, Any]) -> str:
    rows = [[f'<span class="mono">{_esc(i["evidence_id"])}</span>',
             f'<span class="mono">{_esc(i["custody"]["source_path"])}</span>',
             f'<span class="mono">{_esc(i["custody"]["acquired_utc"])}</span>',
             _esc(i["custody"]["examiner"]), _esc(i["custody"]["tool_version"])]
            for i in report["assessments"]]
    return _table(["Evidence ID", "Source", "Acquired (UTC)", "Examiner", "Tool"], rows)


def _graph(report: dict[str, Any]) -> str:
    eg = report.get("evidence_graph") or {}
    if not eg.get("node_count"):
        return _absent("No evidence graph available.")
    types = ", ".join(f"{k}: {v}" for k, v in eg.get("nodes_by_type", {}).items())
    relations = ", ".join(f"{k}: {v}" for k, v in eg.get("edges_by_relation", {}).items())
    svg = report.get("evidence_graph_svg") or ""
    boundary = (report.get("graph") or {}).get("suspicious_relationships") or []
    rows = [[f'<span class="mono">{_esc(r["source"])}</span>',
             f'<span class="mono">{_esc(r["target"])}</span>',
             _esc(", ".join(r["kinds"])), f'<span class="mono">{r["max_risk"]:.1f}</span>']
            for r in boundary[:15]]
    return (
        f'<p class="small">{eg["node_count"]} entities, {eg["edge_count"]} relationships. '
        f'Entities: {_esc(types)}. Relationships: {_esc(relations)}. Every relationship '
        "carries provenance naming the header or body location that established it "
        "(full detail in the JSON report).</p>"
        + '<div class="legend small">'
          '<span><i style="background:#1d4ed8"></i>email</span>'
          '<span><i style="background:#0f766e"></i>address</span>'
          '<span><i style="background:#7c3aed"></i>domain</span>'
          '<span><i style="background:#c2410c"></i>URL</span>'
          '<span><i style="background:#b91c1c"></i>IP</span>'
          '<span><i style="background:#a16207"></i>attachment</span>'
          '<span><i style="background:#be123c"></i>payment</span>'
          '<span><i style="background:#475569"></i>thread</span>'
          '<span>red ring = email scored LIKELY/CONFIRMED BEC; red line = Reply-To / Return-Path</span>'
          "</div>"
        + svg  # generated by EvidenceGraph.to_svg with every label escaped
        + "<h4>Relationships crossing the organisational boundary on flagged mail</h4>"
        + (_table(["From", "To", "Relationship", "Max risk"], rows) if rows
           else _absent("None."))
    )


def _correlation(report: dict[str, Any]) -> str:
    corr = report.get("correlation") or {}
    matches = corr.get("matches") or []
    related = report["case"].get("related_cases") or []
    body = ""
    if matches:
        rows = [[f'<span class="mono">{_esc(m["value"])}</span>', _esc(m["kind"]),
                 f'<span class="mono">{_esc(", ".join(m["seen_in_cases"]))}</span>']
                for m in matches[:25]]
        body += "<p><strong>Potential IOC reuse across cases.</strong></p>" + _table(
            ["Indicator", "Kind", "Also seen in"], rows)
    else:
        body += _absent("No indicator from this case was previously recorded locally.")
    if related:
        body += "<h4>Related cases</h4>" + _table(
            ["Case", "Shared indicators"],
            [[f'<span class="mono">{_esc(r["case_id"])}</span>',
              _pills(r["shared_indicators"])] for r in related])
    return body + f'<div class="disclaim">{_esc(corr.get("note", ""))}</div>'


def _intel(report: dict[str, Any]) -> str:
    intel = report.get("intelligence") or {}
    if not intel:
        return _absent("Threat intelligence not configured.")
    return (f'<p>Provider: <strong>{_esc(intel.get("provider"))}</strong> '
            f'({"external" if intel.get("external_configured") else "local only"})</p>'
            f'<p class="small">{_esc(intel.get("status"))}</p>')


def _case_mitre(report: dict[str, Any]) -> str:
    merged: dict[str, dict[str, Any]] = {}
    for item in report["assessments"]:
        for entry in item.get("mitre") or []:
            slot = merged.setdefault(entry["technique_id"], {**entry, "evidence": set()})
            slot["evidence"].add(item["evidence_id"])
    if not merged:
        return _absent("No technique mapping suggested.")
    rows = [[f'<code>{_esc(t)}</code> {_esc(e["technique"])}', _esc(e["tactic"]),
             _pills(sorted(e["evidence"]))] for t, e in sorted(merged.items())]
    return (_table(["Technique", "Tactic", "Suggested by evidence"], rows)
            + '<div class="disclaim">Potential technique mapping based on observed evidence. '
              "Not attribution.</div>")


def _investigator(report: dict[str, Any]) -> str:
    entries = report.get("investigator_assessments") or []
    if not entries:
        return ('<div class="human"><strong>No investigator assessment has been recorded '
                "for this case.</strong><br><span class='small'>Everything above is system "
                "output. A human determination, when recorded, appears here and is kept "
                "separate from system inference.</span></div>")
    rows = []
    for e in entries:
        rows.append([
            f'<span class="mono">{_esc(e.get("timestamp_utc"))}</span>',
            _esc(e.get("examiner")),
            f'<span class="mono">{_esc(e.get("evidence_id"))}</span>',
            _esc(f'{e.get("system_band")} ({e.get("system_score")})'),
            f"<strong>{_esc(e.get('assessment'))}</strong>",
            _esc(e.get("notes")),
        ])
    return ('<div class="human"><strong>Human determinations.</strong> '
            '<span class="small">Recorded by examiners; not produced by the system.</span></div>'
            + _table(["Recorded (UTC)", "Examiner", "Evidence", "System assessment at the time",
                      "Investigator assessment", "Notes"], rows))


def _audit(report: dict[str, Any]) -> str:
    audit = report.get("audit") or {}
    integrity = audit.get("integrity") or {}
    entries = audit.get("entries") or []
    cls = "integrity-ok" if integrity.get("valid") else "integrity-bad"
    head = ("Audit chain verified - no tampering detected." if integrity.get("valid")
            else "AUDIT CHAIN BROKEN - the log has been altered.")
    rows = [[f'<span class="mono">{e["sequence"]}</span>',
             f'<span class="mono">{_esc(e["timestamp_utc"])}</span>', _esc(e["actor"]),
             f'<span class="mono">{_esc(e["action"])}</span>',
             f'<span class="small">{_esc(e["detail"])}</span>',
             f'<span class="mono">{_esc(e["entry_hash"][:16])}&hellip;</span>']
            for e in entries[-80:]]
    return (f'<div class="{cls}"><strong>{_esc(head)}</strong><br><span class="small">'
            f'{_esc(integrity.get("reason", ""))} ({integrity.get("entries", 0)} entries)</span></div>'
            + '<p class="small">Each entry hashes its own content together with the previous '
              "entry's hash; altering, reordering or deleting any entry breaks the chain from "
              "that point onward.</p>"
            + (_table(["#", "Time (UTC)", "Actor", "Action", "Detail", "Entry hash"], rows)
               if rows else _absent("No audit entries.")))


def _limitations(report: dict[str, Any]) -> str:
    items = report.get("limitations") or []
    if not items:
        return _absent("No limitations recorded.")
    return "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in items) + "</ul>"


def _reproducibility(report: dict[str, Any]) -> str:
    r = report.get("reproducibility") or {}
    if not r:
        return _absent("Reproducibility record unavailable.")
    backends = ", ".join(f"{k}: {'available' if v else 'unavailable'}"
                         for k, v in (r.get("nlp_backends") or {}).items())
    return (
        '<dl class="kv">'
        f'<dt>Tool</dt><dd>{_esc(r.get("tool"))}</dd>'
        f'<dt>Python</dt><dd class="mono">{_esc(r.get("python"))}</dd>'
        f'<dt>Platform</dt><dd class="mono">{_esc(r.get("platform"))}</dd>'
        f'<dt>spaCy</dt><dd class="mono">{_esc(r.get("spacy"))}</dd>'
        f'<dt>NLP backends</dt><dd>{_esc(backends)}</dd>'
        f'<dt>Configuration SHA-256</dt><dd class="mono">{_esc((r.get("configuration") or {}).get("sha256"))}</dd>'
        f'<dt>Covers</dt><dd class="small">{_esc(", ".join((r.get("configuration") or {}).get("covers", [])))}</dd>'
        f'<dt>Evidence analysed</dt><dd>{len(r.get("evidence_sha256") or [])} item(s)</dd>'
        "</dl>"
        f'<p class="small">{_esc(r.get("deterministic"))}</p>'
    )


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------

def render_html(report: dict[str, Any], path: str | Path | None = None) -> str:
    """Render the full investigation report; write it to `path` when given."""
    case = report["case"]
    items = report["assessments"]

    sections: list[tuple[str, str, str]] = [
        ("case", "Case information", (
            '<dl class="kv">'
            f'<dt>Case reference</dt><dd class="mono">{_esc(case.get("case_id") or case["name"])}</dd>'
            f'<dt>Title</dt><dd>{_esc(case["name"])}</dd>'
            f'<dt>Examiner</dt><dd>{_esc(case["examiner"])}</dd>'
            f'<dt>Report generated (UTC)</dt><dd class="mono">{_esc(case["generated_utc"])}</dd>'
            f'<dt>Tool</dt><dd>{_esc(case["tool"])}</dd>'
            "</dl>"
            + ("<h4>Rejected uploads</h4><ul class='small'>" + "".join(
                f"<li>{_esc(r)}</li>" for r in case["rejected_uploads"]) + "</ul>"
               if case.get("rejected_uploads") else ""))),
        ("summary", "Executive summary", _executive_summary(report)),
        ("evidence", "Evidence information", _evidence_information(report)),
        ("integrity", "Evidence integrity", _integrity(report)),
        ("custody", "Chain of custody", _custody(report)),
        ("messages", "Per-message analysis",
         '<p class="small">Each message below is reported in a fixed order: metadata, '
         "headers, identity, domains, authentication, behaviour, NLP, financial intent, "
         "thread, stylometry, URLs, attachments, IOCs, intelligence, ATT&amp;CK mapping, "
         "evidence fusion, risk and recommendations. Findings separate "
         "<strong>observed evidence</strong>, <strong>system inference</strong>, "
         "<strong>risk contribution</strong> and <strong>recommendation</strong>.</p>"
         + ("".join(f'<a href="#msg-{i}">#{i} {_esc(it["email"].get("subject") or "(no subject)")} '
                    f"&mdash; {it['risk_score']:.1f} {_esc(it['risk_band'])}</a><br>"
                    for i, it in enumerate(items, 1)) if items else _absent("No messages."))),
    ]

    toc_titles = [t for _, t, _ in sections] + [
        "Messages", "Evidence graph", "Cross-case correlation", "Investigation timeline",
        "Threat intelligence", "Potential ATT&CK mapping (case)", "Investigator assessment",
        "Audit integrity", "Limitations", "Reproducibility"]
    anchors = [a for a, _, _ in sections] + [
        "msgs", "graph", "correlation", "timeline", "intel", "mitre", "investigator",
        "audit", "limitations", "repro"]
    toc = '<nav class="toc">' + "".join(
        f'<a href="#{a}">{n}. {_esc(t)}</a>' for n, (a, t) in enumerate(zip(anchors, toc_titles), 1)
    ) + "</nav>"

    body = "".join(_section(n, a, t, b) for n, (a, t, b) in enumerate(sections, 1))
    n = len(sections)
    body += f'<h2 id="msgs"><span class="num">{n + 1}.</span>Messages</h2>' + "".join(
        _render_message(item, i) for i, item in enumerate(items, 1))

    tail = [
        ("graph", "Evidence graph", _graph(report)),
        ("correlation", "Cross-case correlation", _correlation(report)),
        ("timeline", "Investigation timeline", _timeline(report.get("timeline") or [])),
        ("intel", "Threat intelligence", _intel(report)),
        ("mitre", "Potential ATT&CK mapping (case)", _case_mitre(report)),
        ("investigator", "Investigator assessment", _investigator(report)),
        ("audit", "Audit integrity", _audit(report)),
        ("limitations", "Limitations", _limitations(report)),
        ("repro", "Reproducibility", _reproducibility(report)),
    ]
    body += "".join(_section(n + 2 + i, a, t, b) for i, (a, t, b) in enumerate(tail))

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FORENSIBEC - {_esc(case.get("case_id") or case["name"])}</title>
<style>{STYLE}</style></head>
<body><div class="wrap">
  <h1>FORENSIBEC &mdash; Business Email Compromise Investigation Report</h1>
  <p class="sub">Case <strong>{_esc(case.get("case_id") or case["name"])}</strong>
    ({_esc(case["name"])}) &middot; examiner {_esc(case["examiner"])} &middot;
    generated {_esc(case["generated_utc"])}</p>
  <div class="panel"><strong>Contents</strong>{toc}</div>
  {body}
  <footer>
    Generated by {_esc(case["tool"])}. Findings are technical indicators produced by a
    transparent weighted-rule model; every point of every score is attributable to a
    named rule and the evidence quoted beside it. This report does not determine that
    an offence occurred.
  </footer>
</div></body></html>
"""
    if path is not None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding="utf-8")
    return document
