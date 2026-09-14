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
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _band_chip(band: str) -> str:
    fg, bg = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))
    return f'<span class="band" style="color:{fg};background:{bg}">{_esc(band)}</span>'


def _render_assessment(item: dict[str, Any], index: int) -> str:
    email = item["email"]
    custody = item["custody"]
    band = item["risk_band"]
    fg, _ = BAND_COLOURS.get(band, ("#334155", "#e2e8f0"))

    rows = []
    for indicator in item["indicators"]:
        colour = SEVERITY_COLOURS.get(indicator["severity"], "#475569")
        rows.append(
            "<tr>"
            f'<td class="sev" style="color:{colour}">{_esc(indicator["severity"])}</td>'
            f'<td><strong>{_esc(indicator["title"])}</strong><br>'
            f'<code>{_esc(indicator["code"])}</code></td>'
            f'<td>{_esc(indicator["explanation"])}'
            f'<div class="evidence mono">{_esc(indicator["evidence"])}</div></td>'
            f'<td class="mono">+{indicator["contribution"]:.1f}</td>'
            "</tr>"
        )

    indicator_table = (
        '<div class="table-wrap"><table>'
        "<tr><th>Severity</th><th>Indicator</th><th>Finding and evidence</th><th>Score</th></tr>"
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

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BEC Assessment - {_esc(case["name"])}</title>
<style>{STYLE}</style></head>
<body><div class="wrap">
  <h1>Business Email Compromise &mdash; Forensic Assessment</h1>
  <p class="sub">
    Case <strong>{_esc(case["name"])}</strong> &middot;
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
