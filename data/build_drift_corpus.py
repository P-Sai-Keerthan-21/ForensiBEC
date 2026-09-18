"""Generate a SHIFTED second generation of the synthetic research corpus.

PROVENANCE
==========
Everything here is SYNTHETIC. This is a deliberately shifted variant of
data/build_research_corpus.py, built to test whether the system (a) notices
that incoming mail no longer resembles what it was built and trained on, and
(b) how its detection holds up when the attack pattern changes.

It does NOT reproduce real attacker evolution. The shift is a documented,
hand-chosen change of generator parameters, stated in full below and in the
metadata file. Real drift is gradual, multi-dimensional and adversarial.

What changes between generation 1 and generation 2
--------------------------------------------------
                          generation 1          generation 2
  compromised mailboxes   35% of attacks        80% of attacks
  lure vocabulary         bank-change, wire,    salary-deposit switch,
                          gift card, credential "route settlements to our new
                                                institution" - wording chosen to
                                                avoid the engine's lexicons
  pressure language       ~80% of attacks       ~25% of attacks
  dates                   Jan-Aug 2026          Mar-Oct 2027
  benign mail             generator unchanged   generator unchanged

The remaining 20% of generation-2 attacks are produced by the ORIGINAL
generator unchanged, so the shift is a change of mix plus a new lure, not a
wholesale replacement.

This builder imports the original generator rather than editing it, so the
canonical research corpus stays byte-identical.

    python data/build_drift_corpus.py
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_research_corpus as base  # noqa: E402

SEED = 20270301
DEFAULT_SIZE = 400
OUT = Path(__file__).resolve().parent / "research_drift" / "gen2"

COMPROMISED_SHARE = 0.80
PRESSURE_SHARE = 0.25

# A lure family absent from generation 1, phrased to avoid the vocabulary the
# rule engine's lexicons look for. That avoidance is the point of the test.
NOVEL_LURES = [
    "Please switch my salary deposit to the account below before the next run.",
    "We have migrated receivables to a new institution; kindly route upcoming "
    "settlements there from now on.",
    "Our finance team now works with a different receiving institution - please "
    "adjust your records before the next cycle.",
    "Could you move my pay to the new account listed here from this month?",
    "Going forward, please direct our remittances to the arrangement below.",
]
NOVEL_SUBJECTS = [
    "Payroll change for next run", "Remittance arrangement", "Quick admin change",
    "Supplier account housekeeping", "Change for this month", "Admin update",
]
SOFT_PRESSURE = [
    "It would be great to have this sorted before the next run.",
    "Appreciate you picking this up.",
]


def _account_line(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return f"  Account: {rng.randrange(10_000_000, 99_999_999)}  Sort: {rng.randrange(10, 99)}-{rng.randrange(10, 99)}-{rng.randrange(10, 99)}"
    return f"  {base._iban(rng)}"


def _make_compromised_novel(rng: random.Random, when: datetime) -> dict:
    """A genuine mailbox sending a novel-lure request. Identity is clean."""
    victim_name, victim_box = rng.choice(base.INTERNAL_PEOPLE)
    first = victim_name.split()[0]

    if rng.random() < 0.5:
        name, domain, box = rng.choice(base.PARTNERS)
        display, internal = f"{name} Accounts", False
    else:
        person, box = rng.choice(base.INTERNAL_PEOPLE)
        domain, display, internal = base.ORG, person, True
    addr = f"{box}@{domain}"

    lines = [rng.choice(NOVEL_LURES), _account_line(rng)]
    if rng.random() < PRESSURE_SHARE:
        lines.append(rng.choice(base.URGENCY))
    elif rng.random() < 0.6:
        lines.append(rng.choice(SOFT_PRESSURE))

    headers = {
        "From": f'"{display}" <{addr}>',
        "To": f"{rng.choice(['hr.payroll', 'accounts.payable', victim_box])}@{base.ORG}",
        "Subject": rng.choice(NOVEL_SUBJECTS),
        "Date": base.format_datetime(when),
        "Message-ID": f"<{rng.randrange(10**9, 10**10)}@{domain}>",
        "Authentication-Results": base.AUTH_PASS.format(d=domain),
        "Received": base._received(rng, internal, when),
    }
    return {"label": "MALICIOUS", "family": "novel_lure_compromised_gen2",
            "headers": headers, "body": base._body(rng, first, lines)}


def generate(size: int = DEFAULT_SIZE, seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    start = datetime(2027, 3, 1, 8, 0, tzinfo=timezone.utc)
    items: list[dict] = []
    for index in range(size):
        when = start + timedelta(days=rng.randrange(0, 240), hours=rng.randrange(0, 24),
                                 minutes=rng.randrange(0, 60))
        if rng.random() < 0.42:
            if rng.random() < COMPROMISED_SHARE:
                item = _make_compromised_novel(rng, when)
            else:
                item = base._make_malicious(rng, when)   # original generator, unchanged
                item["family"] += "_gen1style"
        else:
            item = base._make_benign(rng, when)          # original generator, unchanged
        item["name"] = f"g{index:04d}_{item['family']}"
        items.append(item)
    return items


def write(size: int = DEFAULT_SIZE, seed: int = SEED, root: Path = OUT) -> dict:
    items = generate(size, seed)
    root.mkdir(parents=True, exist_ok=True)
    for existing in root.glob("*.eml"):
        existing.unlink()

    digest = hashlib.sha256()
    labels: dict[str, dict[str, str]] = {}
    for item in items:
        raw = base._serialise(item)
        (root / f"{item['name']}.eml").write_bytes(raw)
        digest.update(raw)
        labels[f"{item['name']}.eml"] = {"label": item["label"], "family": item["family"]}
    (root / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for meta in labels.values():
        counts[meta["label"]] = counts.get(meta["label"], 0) + 1

    metadata = {
        "name": "ForensiBEC synthetic research corpus - generation 2 (shifted)",
        "provenance": "SYNTHETIC. A deliberately shifted variant of generation 1. "
                      "Does NOT reproduce real attacker evolution.",
        "generator": "data/build_drift_corpus.py",
        "seed": seed, "size": size, "counts": counts,
        "corpus_sha256": digest.hexdigest(),
        "shift": {
            "compromised_share_of_attacks": {"gen1": 0.35, "gen2": COMPROMISED_SHARE},
            "pressure_language_share": {"gen1": "~0.80", "gen2": PRESSURE_SHARE},
            "novel_lure": "salary-deposit switch / route settlements to a new "
                          "institution, worded to avoid the engine's lexicons",
            "dates": {"gen1": "2026-01 to 2026-08", "gen2": "2027-03 to 2027-10"},
            "benign_generator": "unchanged",
            "gen1_style_attacks": f"{1 - COMPROMISED_SHARE:.0%} of gen2 attacks use "
                                  "the original generator unchanged",
        },
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (root / "corpus.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    meta = write()
    print(f"SYNTHETIC generation-2 (shifted) corpus written to {OUT}")
    print(f"  size {meta['size']}  counts {meta['counts']}  sha256 {meta['corpus_sha256'][:24]}...")
    print("  This does NOT reproduce real attacker evolution; see the module docstring.")
