"""Controlled adversarial robustness experiment for the forensic rule engine.

Question
--------
If an attacker rewords, reformats or re-dresses a BEC message, does the
forensic engine still flag it - and does harmless reformatting of benign mail
cause false alarms?

Scope and safety
----------------
* Target: the forensic rule engine (the system's decision path), not the ML
  baselines.
* Data: the local research TEST split only. Nothing is fetched, sent or
  executed. Transformations edit headers and body text of already-synthetic
  messages; none adds an attachment, link or payload.
* Intelligence and cross-case correlation are disabled, so the static local
  indicator list cannot mask or inflate the effect of a transformation.
* Deterministic: fixed seed, fixed transformation tables.

The engine was NOT tuned in response to these results. Whatever degradation
appears is reported as found (docs/adversarial_testing.md).
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import default as default_policy
from pathlib import Path
from typing import Any, Callable

import email as email_lib

from bec_detector.acquisition import load_bytes
from bec_detector.forensics import IOCStore, NullThreatIntelProvider
from bec_detector.pipeline import BECPipeline

SEED = 20260918
RESEARCH_TEST = Path("data") / "research" / "test"
RESULTS_DIR = Path("output") / "research"
FLAGGED = {"LIKELY_BEC", "CONFIRMED_BEC"}

PROVENANCE = (
    "SYNTHETIC research corpus, test split. Transformations are deterministic "
    "edits of synthetic messages. Results describe the robustness of this "
    "rule engine to these specific transformations; they are not a measure of "
    "resistance to a real, adaptive adversary."
)

# ---------------------------------------------------------------------------
# Transformation tables
# ---------------------------------------------------------------------------

# Lower-pressure paraphrases of the phrases the urgency lexicon targets.
URGENCY_SOFTENING = [
    (r"\bthis is urgent and must be completed today\b", "it would help to have this done soon"),
    (r"\bplease treat this as time sensitive\b", "please look at this when you can"),
    (r"\bit must clear before close of business\b", "ideally it clears later on"),
    (r"\bi need this processed immediately, without delay\b", "could you process this for me"),
    (r"\bthis is critical and cannot wait until tomorrow\b", "this is fairly important"),
    (r"\bplease action this right away\b", "please action this"),
    (r"\bthe deadline is this afternoon\b", "the timing is flexible"),
    (r"\burgent(ly)?\b", "important"),
    (r"\bimmediately\b", "at your earliest convenience"),
    (r"\bwithout delay\b", "when possible"),
    (r"\bas soon as possible\b", "when convenient"),
    (r"\basap\b", "soon"),
    (r"\btoday\b", "shortly"),
    (r"\bdeadline\b", "timing"),
    (r"\bcritical\b", "notable"),
    (r"\btime[- ]sensitive\b", "timely"),
]

# Paraphrases of the financial vocabulary.
PAYMENT_PARAPHRASE = [
    (r"\bbanking details have changed\b", "we now receive funds elsewhere"),
    (r"\bbank details\b", "remittance coordinates"),
    (r"\bnew beneficiary account\b", "updated receiving arrangement"),
    (r"\bbeneficiary\b", "recipient"),
    (r"\bwire transfer\b", "funds movement"),
    (r"\bupdate your records\b", "note our new arrangement"),
    (r"\bremitted\b", "sent over"),
    (r"\bremit\b", "send over"),
    (r"\boutstanding balance\b", "open amount"),
    (r"\bpayment\b", "settlement"),
    (r"\binvoice\b", "bill"),
    (r"\bgift cards?\b", "store vouchers"),
    (r"\bredeem codes\b", "voucher numbers"),
]

BENIGN_PADDING = (
    "Thanks again for the update at the depot review earlier this week. The team "
    "found the new schedule helpful and the Rotterdam arrangements are working well.\n\n"
    "On a separate note, the quarterly newsletter is now on the intranet, and the "
    "canteen will be closed on Friday for maintenance.\n\n"
)

TITLE_PATTERN = re.compile(
    r"\s*(\((CEO|CFO|COO|CTO|Finance Director|Operations Director)\)|"
    r"-\s*(CEO|CFO|Finance Director))\s*", re.I)

# Homoglyph substitution for the org's brand: Cyrillic o / a / i.
HOMOGLYPHS = {"o": "о", "a": "а", "i": "і"}


# ---------------------------------------------------------------------------
# Message editing
# ---------------------------------------------------------------------------

def _load(raw: bytes) -> EmailMessage:
    return email_lib.message_from_bytes(raw, policy=default_policy)


def _body(msg: EmailMessage) -> str:
    part = msg.get_body(preferencelist=("plain",))
    return part.get_content() if part is not None else ""


def _with_body(msg: EmailMessage, text: str) -> EmailMessage:
    msg.set_content(text)
    return msg


def _replace_all(text: str, table: list[tuple[str, str]]) -> tuple[str, int]:
    total = 0
    for pattern, repl in table:
        text, n = re.subn(pattern, repl, text, flags=re.I)
        total += n
    return text, total


def _sender(msg: EmailMessage) -> tuple[str, str]:
    from email.utils import parseaddr
    return parseaddr(str(msg.get("From", "")))


def _set_sender(msg: EmailMessage, display: str, address: str) -> None:
    from email.headerregistry import Address
    del msg["From"]
    local, _, domain = address.partition("@")
    msg["From"] = Address(display_name=display, username=local, domain=domain)


URL_TOKEN = re.compile(r"https?://\S+")


def _prose_only(text: str, edit) -> str:
    """Apply `edit` to the text between URLs, leaving every URL byte-identical.

    A transformation that alters a link (stripping its dots, upper-casing its
    case-sensitive path) breaks the link. A broken link is not an attack, so
    such edits would manufacture artificial evasions.
    """
    pieces, last = [], 0
    for match in URL_TOKEN.finditer(text):
        pieces.append(edit(text[last:match.start()]))
        pieces.append(match.group(0))
        last = match.end()
    pieces.append(edit(text[last:]))
    return "".join(pieces)


@dataclass
class Transformation:
    key: str
    description: str
    applies_to: str          # "malicious" | "benign" | "both"
    fn: Callable[[EmailMessage, random.Random], tuple[EmailMessage, str]]


def t_uppercase(msg, rng):
    return _with_body(msg, _prose_only(_body(msg), str.upper)),         "body upper-cased (URLs preserved)"


def t_lowercase(msg, rng):
    subject = str(msg.get("Subject", ""))
    del msg["Subject"]
    msg["Subject"] = subject.lower()
    return _with_body(msg, _prose_only(_body(msg), str.lower)),         "subject and body lower-cased (URLs preserved)"


def t_punctuation(msg, rng):
    """Strip punctuation from prose, leaving URLs intact.

    An earlier version also stripped the dots and colons inside URLs, which
    destroys the link and produced an artificial "evasion".
    """
    strip = lambda chunk: re.sub(r"[.,;:!?'\"()-]", "", chunk)
    return _with_body(msg, _prose_only(_body(msg), strip)),         "punctuation removed from prose (URLs preserved)"


def t_whitespace(msg, rng):
    text = re.sub(r" ", "  ", _body(msg))
    text = re.sub(r"\n", "\n\n", text)
    return _with_body(msg, "\t" + text), "spaces doubled, blank lines inserted, leading tab"


def t_padding(msg, rng):
    return _with_body(msg, BENIGN_PADDING + _body(msg) + "\n\n" + BENIGN_PADDING), \
        "benign paragraphs added before and after"


def t_soften(msg, rng):
    text, n = _replace_all(_body(msg), URGENCY_SOFTENING)
    subject, m = _replace_all(str(msg.get("Subject", "")), URGENCY_SOFTENING)
    del msg["Subject"]
    msg["Subject"] = subject
    return _with_body(msg, text), f"urgency wording softened ({n + m} replacements)"


def t_paraphrase(msg, rng):
    text, n = _replace_all(_body(msg), PAYMENT_PARAPHRASE)
    return _with_body(msg, text), f"financial wording paraphrased ({n} replacements)"


def t_display_name(msg, rng):
    display, address = _sender(msg)
    stripped = TITLE_PATTERN.sub(" ", display).strip()
    _set_sender(msg, stripped, address)
    return msg, f"display name {display!r} -> {stripped!r}"


def t_homoglyph_domain(msg, rng):
    display, address = _sender(msg)
    local, _, domain = address.partition("@")
    if "northwind" not in domain:
        return msg, "no brand domain to alter"
    brand = "northwind-logistics"
    swapped = "".join(HOMOGLYPHS.get(ch, ch) if i % 3 == 0 else ch
                      for i, ch in enumerate(brand))
    new_domain = f"{swapped}.com"
    _set_sender(msg, display, f"{local}@{new_domain}")
    return msg, f"sender domain {domain!r} -> Unicode homoglyph {new_domain!r}"


def t_combosquat(msg, rng):
    display, address = _sender(msg)
    local, _, domain = address.partition("@")
    if "northwind" not in domain:
        return msg, "no brand domain to alter"
    new_domain = "northwind-logistics-payments.com"
    _set_sender(msg, display, f"{local}@{new_domain}")
    return msg, f"sender domain {domain!r} -> combosquat {new_domain!r}"


def t_combined(msg, rng):
    msg, a = t_soften(msg, rng)
    msg, b = t_paraphrase(msg, rng)
    msg, c = t_padding(msg, rng)
    msg, d = t_display_name(msg, rng)
    return msg, "; ".join([a, b, c, d])


TRANSFORMATIONS: tuple[Transformation, ...] = (
    Transformation("uppercase", "Body in capitals", "both", t_uppercase),
    Transformation("lowercase", "Subject and body in lower case", "both", t_lowercase),
    Transformation("punctuation", "Punctuation stripped", "both", t_punctuation),
    Transformation("whitespace", "Whitespace inflated", "both", t_whitespace),
    Transformation("padding", "Benign text padding (dilution)", "both", t_padding),
    Transformation("soften_urgency", "Urgency wording softened", "malicious", t_soften),
    Transformation("paraphrase_financial", "Financial wording paraphrased", "malicious", t_paraphrase),
    Transformation("strip_title", "Executive title removed from display name", "malicious", t_display_name),
    Transformation("homoglyph_domain", "Brand domain rebuilt with Unicode homoglyphs", "malicious", t_homoglyph_domain),
    Transformation("combosquat_domain", "Brand domain replaced by a combosquat", "malicious", t_combosquat),
    Transformation("combined", "Soften + paraphrase + padding + strip title", "malicious", t_combined),
)


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------

def _labelled_messages(limit: int | None = None) -> list[tuple[str, str, str, bytes]]:
    labels = json.loads((RESEARCH_TEST / "labels.json").read_text(encoding="utf-8"))
    items = []
    for name in sorted(labels):
        meta = labels[name]
        items.append((name, meta["label"], meta["family"], (RESEARCH_TEST / name).read_bytes()))
    return items[:limit] if limit else items


def _engine(originals: list[bytes], tmp: Path) -> BECPipeline:
    """A pipeline baselined on the ORIGINAL messages, intel and correlation off."""
    pipeline = BECPipeline(case_id="CASE-ROBUSTNESS", intel=NullThreatIntelProvider(),
                           ioc_store=IOCStore(tmp / "ioc.json"), correlate=False)
    emails = [pipeline.acquire_bytes(raw, f"orig-{i}") for i, raw in enumerate(originals)]
    pipeline.fit(emails)
    return pipeline


def run_robustness(limit: int | None = None, output_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    import tempfile

    rng = random.Random(SEED)
    items = _labelled_messages(limit)

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = _engine([raw for *_, raw in items], Path(tmpdir))

        originals: dict[str, Any] = {}
        for name, label, family, raw in items:
            a = engine.assess(load_bytes(raw, name))
            originals[name] = (a.score, a.band.value, {i.code for i in a.indicators})

        per_transform = []
        examples = []
        for transform in TRANSFORMATIONS:
            rows = []
            for name, label, family, raw in items:
                kind = "malicious" if label == "MALICIOUS" else "benign"
                if transform.applies_to not in (kind, "both"):
                    continue
                edited, change = transform.fn(_load(raw), rng)
                variant = load_bytes(edited.as_bytes(), f"{name}+{transform.key}")
                after = engine.assess(variant)
                before_score, before_band, before_codes = originals[name]
                after_codes = {i.code for i in after.indicators}
                rows.append({
                    "message": name, "label": label, "family": family,
                    "change": change,
                    "original_score": before_score, "transformed_score": after.score,
                    "score_delta": round(after.score - before_score, 1),
                    "original_band": before_band, "transformed_band": after.band.value,
                    "verdict_changed": (before_band in FLAGGED) != (after.band.value in FLAGGED),
                    "lost_indicators": sorted(before_codes - after_codes),
                    "gained_indicators": sorted(after_codes - before_codes),
                })

            malicious = [r for r in rows if r["label"] == "MALICIOUS"]
            benign = [r for r in rows if r["label"] == "BENIGN"]
            summary = {"key": transform.key, "description": transform.description,
                       "applies_to": transform.applies_to}
            if malicious:
                before = sum(r["original_band"] in FLAGGED for r in malicious)
                after_ = sum(r["transformed_band"] in FLAGGED for r in malicious)
                summary["malicious"] = {
                    "n": len(malicious),
                    "detected_before": before,
                    "detected_after": after_,
                    "detection_rate_before": round(before / len(malicious), 4),
                    "detection_rate_after": round(after_ / len(malicious), 4),
                    "evaded": sum(r["original_band"] in FLAGGED and r["transformed_band"] not in FLAGGED
                                  for r in malicious),
                    "mean_score_delta": round(sum(r["score_delta"] for r in malicious) / len(malicious), 2),
                    "min_score_delta": min(r["score_delta"] for r in malicious),
                }
            if benign:
                fp_before = sum(r["original_band"] in FLAGGED for r in benign)
                fp_after = sum(r["transformed_band"] in FLAGGED for r in benign)
                summary["benign"] = {
                    "n": len(benign),
                    "false_positives_before": fp_before,
                    "false_positives_after": fp_after,
                    "induced_false_positives": sum(
                        r["original_band"] not in FLAGGED and r["transformed_band"] in FLAGGED
                        for r in benign),
                    "mean_score_delta": round(sum(r["score_delta"] for r in benign) / len(benign), 2),
                }
            lost = {}
            for r in malicious:
                for code in r["lost_indicators"]:
                    lost[code] = lost.get(code, 0) + 1
            summary["most_lost_indicators"] = sorted(lost.items(), key=lambda x: -x[1])[:6]
            per_transform.append(summary)

            evaders = [r for r in malicious
                       if r["original_band"] in FLAGGED and r["transformed_band"] not in FLAGGED]
            examples.extend(evaders[:2])

    results = {
        "result_type": "RESEARCH ADVERSARIAL ROBUSTNESS RESULTS",
        "provenance": PROVENANCE,
        "not_real_world_accuracy": True,
        "target": "forensic rule engine (bec_detector.pipeline.BECPipeline)",
        "configuration": {
            "data": str(RESEARCH_TEST),
            "messages": len(items),
            "seed": SEED,
            "threat_intelligence": "disabled",
            "cross_case_correlation": "disabled",
            "baseline": "behavioural/thread/style baselines fitted on the original messages",
            "flagged_bands": sorted(FLAGGED),
        },
        "engine_tuned_in_response": False,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "transformations": per_transform,
        "evasion_examples": examples[:12],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "robustness.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return results


def format_table(results: dict[str, Any]) -> str:
    lines = [f"{'Transformation':<44}{'Mal det before':>15}{'after':>8}{'evaded':>8}"
             f"{'mean dS':>9}{'Ben FP induced':>16}"]
    lines.append("-" * len(lines[0]))
    for t in results["transformations"]:
        m = t.get("malicious")
        b = t.get("benign")
        lines.append(
            f"{t['description'][:43]:<44}"
            + (f"{m['detected_before']:>9}/{m['n']:<5}{m['detected_after']:>8}{m['evaded']:>8}"
               f"{m['mean_score_delta']:>9.1f}" if m else f"{'-':>15}{'-':>8}{'-':>8}{'-':>9}")
            + (f"{b['induced_false_positives']:>10}/{b['n']:<5}" if b else f"{'-':>16}")
        )
    return "\n".join(lines)


def main() -> int:
    print("ADVERSARIAL ROBUSTNESS - forensic rule engine")
    print(f"  {PROVENANCE}\n")
    results = run_robustness()
    print(format_table(results))
    print(f"\nwritten: {RESULTS_DIR / 'robustness.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
