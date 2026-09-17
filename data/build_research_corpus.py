"""Generate the synthetic RESEARCH corpus for ML baselining and ablation.

PROVENANCE — READ BEFORE USING ANY RESULT FROM THIS CORPUS
==========================================================

Every message this script produces is SYNTHETIC. It is assembled from
parameterised templates by a seeded random process. No message here was
collected from a real mailbox, and no real person, organisation, domain or
bank detail is represented.

What results on this corpus DO mean
-----------------------------------
They measure whether the features the forensic engine extracts are *learnable*
and which evidence families carry separable signal. That is the question the
ablation study asks, and synthetic data can answer it.

What results on this corpus DO NOT mean
---------------------------------------
They are NOT an estimate of real-world accuracy, and must never be reported as
one. Data generated from templates has a learnable generative structure, so any
classifier trained on it enjoys a ceiling effect: it can learn the generator
rather than the phenomenon. Scores here are an OPTIMISTIC UPPER BOUND.

Design decisions that make the task non-trivial
-----------------------------------------------
A generator that emits cleanly separable classes would make every model look
perfect and every ablation look identical. Three mechanisms introduce genuine
difficulty:

1. CONFOUNDED BENIGNS - a proportion of benign messages legitimately carry
   urgency, money amounts, deadlines and payment vocabulary (a real finance
   department does this daily). These are the messages a text-only classifier
   should get wrong.
2. SUBTLE MALICIOUS - a proportion of malicious messages omit the loud signals
   (no urgency words, no explicit amount) and rely only on identity or thread
   evidence. These are the messages a header-only classifier should get wrong.
3. LEXICAL OVERLAP - both classes draw greetings, sign-offs and filler
   sentences from shared pools, so vocabulary alone is not decisive.

Regenerate deterministically with:

    python data/build_research_corpus.py

The seed is fixed, so the corpus is byte-reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260918
DEFAULT_SIZE = 900

ROOT = Path(__file__).resolve().parent
RESEARCH = ROOT / "research"

# ---------------------------------------------------------------------------
# Fictional organisation
# ---------------------------------------------------------------------------

ORG = "northwind-logistics.com"

INTERNAL_PEOPLE = [
    ("Priya Sharma", "priya.sharma"), ("Joseph Okafor", "j.okafor"),
    ("Sandra Whitlock", "sandra.whitlock"), ("Ravi Menon", "r.menon"),
    ("Daniel Osei", "d.osei"), ("Aisha Bello", "a.bello"),
    ("Tomasz Nowak", "t.nowak"), ("Mei Lin", "m.lin"),
    ("Callum Reid", "c.reid"), ("Fatima Haddad", "f.haddad"),
]

INTERNAL_BOXES = [
    "accounts.payable", "hr.payroll", "it", "sales", "scheduling",
    "warehouse.leads", "all.staff", "procurement",
]

PARTNERS = [
    ("Delaney Freight Solutions", "delaney-freight.co", "m.kalina"),
    ("Harborline Supplies", "harborline-supplies.com", "billing"),
    ("Berg Industrial AB", "bergindustrial.se", "t.berg"),
    ("Castellan Packaging", "castellan-pack.eu", "accounts"),
    ("Orrin Marine Ltd", "orrinmarine.co.uk", "finance"),
]

# Attacker infrastructure - all fictional, RFC 2606 / TEST-NET where applicable.
LOOKALIKE_DOMAINS = [
    "northwind-l0gistics.com", "northwind-logistlcs.com", "northwlnd-logistics.com",
    "northwind-logistics.support", "northwind-logistics.com.secure-mx.net",
    "n0rthwind-logistics.com", "northwind-logistic.com",
]
PARTNER_LOOKALIKES = [
    "delaney-freigth.co", "delaney-freight.co.inv-portal.net", "harborline-supplies.co",
    "castellan-pack.com", "orrin-marine.co.uk",
]
FREEMAIL = ["gmail.com", "outlook.com", "yandex.com", "protonmail.com", "mail.com", "aol.com"]
ATTACK_HOSTS = ["203.0.113.45", "198.51.100.77", "203.0.113.180"]

# Legitimate links that appear in ordinary business correspondence. Without
# these, "the message contains a URL" would perfectly predict the malicious
# class, which is an artifact of the generator rather than a property of BEC.
BENIGN_URLS = [
    f"https://intranet.{ORG}/policies/remote-working",
    f"https://portal.{ORG}/invoices/view",
    f"https://{ORG}/depot-schedule",
    "https://harborline-supplies.com/terms",
    "https://delaney-freight.co/contract-portal",
    f"https://intranet.{ORG}/hr/handbook",
]

AUTH_PASS = (f"mx.{ORG}; spf=pass smtp.mailfrom={{d}}; "
             f"dkim=pass header.d={{d}}; dmarc=pass")
AUTH_FAIL = f"mx.{ORG}; spf=fail smtp.mailfrom={{d}}; dkim=none; dmarc=fail"
AUTH_SOFT = f"mx.{ORG}; spf=softfail; dkim=none; dmarc=fail"

RECV_INTERNAL = (f"from mail.{ORG} (mail.{ORG} [198.51.100.24]) by mx.{ORG} "
                 "with ESMTPS id {rid}; {date}")
RECV_EXTERNAL = ("from unknown (vps-{n}.hostwind.example [203.0.113.{ip}]) "
                 f"by mx.{ORG} with ESMTP id {{rid}}; {{date}}")

# ---------------------------------------------------------------------------
# Shared language pools - deliberately used by BOTH classes
# ---------------------------------------------------------------------------

GREETINGS = ["Hello,", "Hi {first},", "Good morning,", "Dear {first},", "{first},", "Hi all,"]
SIGNOFFS = ["Regards,", "Best regards,", "Many thanks,", "Kind regards,", "Thanks,", "Best,"]

FILLER = [
    "Let me know if you need anything else.",
    "Happy to discuss if that helps.",
    "Apologies for the short notice.",
    "I have copied the relevant team.",
    "This follows on from our earlier discussion.",
    "Please treat this as routine unless you hear otherwise.",
    "Do check the attached schedule when you get a moment.",
]

# Loud malicious phrasing.
URGENCY = [
    "This is urgent and must be completed today.",
    "Please treat this as time sensitive - it must clear before close of business.",
    "I need this processed immediately, without delay.",
    "This is critical and cannot wait until tomorrow.",
    "Please action this right away - the deadline is this afternoon.",
]
SECRECY = [
    "Please keep this strictly between us until the announcement.",
    "Do not discuss this with anyone else in the team for now.",
    "This is confidential and should not be copied to the wider group.",
    "Please handle this discreetly and do not cc anyone.",
]
AUTHORITY = [
    "I am counting on you to handle this personally.",
    "I am currently in meetings and cannot take a call.",
    "I am travelling and unable to talk right now, so please just reply here.",
    "I need you to deal with this on my behalf.",
]
BANK_CHANGE = [
    "Please note our banking details have changed following a treasury restructure.",
    "Kindly update your records - we have moved to a new account.",
    "Our remittance details are now different; please amend the bank details on file.",
    "We have changed banks, so please use the new beneficiary account below.",
]
PAYMENT = [
    "Please process the wire transfer of {amount} to the beneficiary below.",
    "The outstanding balance of {amount} needs to be remitted today.",
    "Kindly release the payment of {amount} against the invoice attached.",
    "Please settle {amount} to the account details provided.",
]
GIFT_CARD = [
    "Could you purchase {n} gift cards and send me the redeem codes from the back?",
    "I need {n} gift cards bought today - just reply with the card codes.",
]
CREDENTIAL = [
    "Your password will expire in 2 hours - please click here to verify your account.",
    "Your mailbox is full. Re-enter your credentials to restore access.",
    "Unusual sign-in detected. Sign in to verify your account immediately.",
]

# Benign business language that SHARES vocabulary with the malicious class.
BENIGN_FINANCE = [
    "The invoice for {amount} is due at the end of the month through the usual process.",
    "Please process {amount} against the existing purchase order when convenient.",
    "The {amount} payment was approved at the last review; details are unchanged.",
    "Accounts payable have the invoice for {amount} - no action needed from you.",
]
BENIGN_URGENT = [
    "This is urgent - I need the stocktake figures before close of business.",
    "Time sensitive: the auditors arrive tomorrow and I need the schedule today.",
    "Please treat this as a priority; the depot review is this afternoon.",
    "Apologies for the rush, but the report deadline is end of day.",
]
BENIGN_ROUTINE = [
    "The maintenance window is confirmed for Saturday morning.",
    "The updated policy is now on the intranet for everyone to read.",
    "Could you confirm the pallet dimensions for the Rotterdam depot?",
    "The delivery window is confirmed for Friday afternoon.",
    "Notes from the depot review are attached for your records.",
    "The Q3 budget review has been scheduled for the 24th.",
]

SUBJECT_MAL = [
    "Urgent - confidential transfer required today", "Re: Invoice {inv} - updated bank details",
    "Quick favour - are you at your desk?", "Change of account for salary payment",
    "Action required: mailbox verification", "Fw: Completion funds - handle personally",
    "Re: outstanding remittance", "Payment instruction - {inv}",
    "Re: {inv} - revised remittance details", "Important: account update needed",
]
SUBJECT_BEN = [
    "Notes from the depot review", "Planned maintenance this Saturday",
    "Statement for {month}", "Updated remote working policy",
    "Question about pallet dimensions", "Invoice {inv} attached",
    "Q3 budget review scheduled", "Friday delivery window confirmed",
    "Stocktake figures needed before close of business", "Weekly operations summary",
    "Re: pallet contract renewal", "Purchase order {inv} confirmation",
]

MONTHS = ["August", "September", "October", "November"]
CURRENCIES = ["USD", "EUR", "GBP"]


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def _amount(rng: random.Random) -> str:
    return f"{rng.choice(CURRENCIES)} {rng.randrange(1500, 95000):,}.00"


def _inv(rng: random.Random) -> str:
    return f"INV-{rng.randrange(10000, 99999)}"


def _iban(rng: random.Random) -> str:
    country = rng.choice(["GB", "LT", "DE", "MT", "CY"])
    return f"{country}{rng.randrange(10, 99)}{rng.randrange(10**12, 10**13 - 1)}"


def _received(rng: random.Random, internal: bool, when: datetime) -> str:
    rid = f"{rng.randrange(0x1000, 0xffff):04x}{rng.randrange(0x10, 0xff):02x}"
    stamp = format_datetime(when)
    if internal:
        return RECV_INTERNAL.format(rid=rid, date=stamp)
    return RECV_EXTERNAL.format(
        n=rng.randrange(1000, 9999), ip=rng.randrange(2, 250), rid=rid, date=stamp
    )


def _body(rng: random.Random, first: str, lines: list[str]) -> str:
    greeting = rng.choice(GREETINGS).format(first=first)
    body = [greeting, ""]
    body.extend(lines)
    if rng.random() < 0.55:
        body.append(rng.choice(FILLER))
    body.extend(["", rng.choice(SIGNOFFS)])
    return "\n".join(body)


def _make_malicious(rng: random.Random, when: datetime) -> dict:
    """Build one malicious message.

    `subtle` variants deliberately omit urgency and explicit amounts so that a
    text-only model cannot catch them - they are carried by identity evidence
    only. Those are the cases the ablation should show header features
    recovering.
    """
    subtle = rng.random() < 0.30

    # A compromised account is the hard case: the mailbox is genuine, so every
    # identity and authentication check passes. Only behaviour, style and the
    # financial ask betray it. Without these the corpus would be separable on
    # the authentication header alone.
    compromised = rng.random() < 0.35

    variant = rng.choice([
        "ceo_fraud", "vendor_invoice", "payroll", "gift_card", "credential", "lookalike",
    ])
    if compromised:
        variant = rng.choice(["ceo_fraud", "vendor_invoice", "payroll"])

    victim_name, victim_box = rng.choice(INTERNAL_PEOPLE)
    victim = f"{victim_box}@{ORG}"
    first = victim_name.split()[0]

    display, addr, domain = "", "", ""
    if compromised:
        # Genuine mailbox, genuine domain - nothing wrong with the identity.
        if variant == "vendor_invoice":
            name, domain, box = rng.choice(PARTNERS)
            display = f"{name} Accounts"
        else:
            person, box = rng.choice(INTERNAL_PEOPLE)
            domain = ORG
            display = person
        addr = f"{box}@{domain}"
    elif variant in {"ceo_fraud", "lookalike", "payroll"}:
        person, box = rng.choice(INTERNAL_PEOPLE[:5])
        domain = rng.choice(LOOKALIKE_DOMAINS)
        title = rng.choice([" (CEO)", " (CFO)", " - Finance Director", ""])
        display = f"{person}{title}"
        addr = f"{box}@{domain}"
    elif variant == "vendor_invoice":
        name, real_domain, box = rng.choice(PARTNERS)
        domain = rng.choice(PARTNER_LOOKALIKES + [real_domain])
        display = f"{name} Accounts"
        addr = f"{box}@{domain}"
    else:
        person, box = rng.choice(INTERNAL_PEOPLE[:5])
        domain = rng.choice(FREEMAIL + LOOKALIKE_DOMAINS)
        display = f"{person}" + rng.choice([" - CFO", " (CEO)", ""])
        addr = f"{box}.{rng.randrange(1, 99)}@{domain}"

    amount = _amount(rng)
    lines: list[str] = []

    if variant == "gift_card":
        lines.append(rng.choice(GIFT_CARD).format(n=rng.randrange(5, 25)))
    elif variant == "credential":
        lines.append(rng.choice(CREDENTIAL))
    elif variant == "vendor_invoice":
        lines.append(rng.choice(BANK_CHANGE))
        if not subtle:
            lines.append(rng.choice(PAYMENT).format(amount=amount))
            lines.append(f"  IBAN: {_iban(rng)}")
    else:
        if not subtle:
            lines.append(rng.choice(PAYMENT).format(amount=amount))
            lines.append(f"  IBAN: {_iban(rng)}")
        else:
            lines.append(rng.choice([
                "Could you let me know when you are free to action a transfer?",
                "Are you at your desk? I need something handled.",
                rng.choice(BENIGN_ROUTINE),
            ]))

    if not subtle:
        if rng.random() < 0.8:
            lines.insert(0, rng.choice(URGENCY))
        if rng.random() < 0.6:
            lines.append(rng.choice(SECRECY))
        if rng.random() < 0.6:
            lines.append(rng.choice(AUTHORITY))

    headers = {
        "From": f'"{display}" <{addr}>',
        "To": victim,
        "Subject": rng.choice(SUBJECT_MAL).format(inv=_inv(rng)),
        "Date": format_datetime(when),
        "Message-ID": f"<{rng.randrange(10**9, 10**10)}@{domain}>",
        "Authentication-Results": (
            AUTH_PASS.format(d=domain) if compromised
            else rng.choice([AUTH_FAIL, AUTH_SOFT]).format(d=domain)
        ),
        "Received": _received(rng, compromised, when),
    }
    # A compromised mailbox rarely needs a Reply-To: the attacker already
    # receives the replies. Adding one would reintroduce an easy giveaway.
    if not compromised and rng.random() < 0.7:
        headers["Reply-To"] = f"{display.split()[0].lower()}.{rng.randrange(1, 99)}@{rng.choice(FREEMAIL)}"
    elif compromised and rng.random() < 0.12:
        headers["Reply-To"] = f"{display.split()[0].lower()}@{rng.choice(FREEMAIL)}"
    if not compromised and rng.random() < 0.25:
        headers["Return-Path"] = f"<bounce@{rng.choice(LOOKALIKE_DOMAINS)}>"
    elif rng.random() < 0.35:
        headers["Return-Path"] = f"<{addr}>"

    urls = []
    if variant == "credential" or rng.random() < 0.25:
        urls.append(f"http://{rng.choice(ATTACK_HOSTS)}/secure/login.php")
        lines.append(f"Verify here: {urls[0]}")

    family = variant
    if compromised:
        family += "_compromised"
    if subtle:
        family += "_subtle"

    return {
        "label": "MALICIOUS",
        "family": family,
        "headers": headers,
        "body": _body(rng, first, lines),
    }


def _make_benign(rng: random.Random, when: datetime) -> dict:
    """Build one benign message.

    `confounded` variants legitimately carry urgency and/or money language.
    These are the messages a text-only model should misclassify, and the reason
    the ablation can distinguish evidence families at all.
    """
    confounded = rng.random() < 0.50
    internal = rng.random() < 0.7

    victim_name, victim_box = rng.choice(INTERNAL_PEOPLE)
    first = victim_name.split()[0]

    if internal:
        person, box = rng.choice(INTERNAL_PEOPLE)
        domain = ORG
        # Real executives sign with their title. Treating a title as inherently
        # suspicious would be an artifact, so benign mail carries them too.
        title = rng.choice(["", "", "", " (CFO)", " (CEO)", " - Finance Director",
                            " (Operations Director)"])
        display, addr = f"{person}{title}", f"{box}@{domain}"
    elif rng.random() < 0.10:
        # A small supplier or contractor legitimately using consumer mail.
        person, box = rng.choice(INTERNAL_PEOPLE)
        domain = rng.choice(FREEMAIL)
        display = f"{person.split()[0]} {person.split()[1]} (Contractor)"
        addr = f"{box}.contract@{domain}"
    else:
        name, domain, box = rng.choice(PARTNERS)
        display, addr = f"{name} Accounts", f"{box}@{domain}"

    recipient = (f"{rng.choice(INTERNAL_BOXES)}@{ORG}"
                 if rng.random() < 0.5 else f"{victim_box}@{ORG}")

    lines: list[str] = []
    amount = _amount(rng)
    if confounded:
        # A legitimate finance request. It draws from the SAME urgency and
        # payment pools the malicious class uses, because in reality the two
        # read alike - the difference is the sender and the account, not the
        # wording. This is what stops the text channel from being decisive.
        if rng.random() < 0.7:
            lines.append(rng.choice(URGENCY if rng.random() < 0.5 else BENIGN_URGENT))
        lines.append(rng.choice(
            PAYMENT if rng.random() < 0.6 else BENIGN_FINANCE
        ).format(amount=amount))
        if rng.random() < 0.35:
            lines.append("Details are unchanged and already on file.")
        if rng.random() < 0.45:
            # A real invoice quotes the account it is to be paid into.
            lines.append(f"  Beneficiary account (unchanged): IBAN {_iban(rng)}")
        if rng.random() < 0.20:
            # Legitimate internal confidentiality, e.g. pre-announcement M&A.
            lines.append(rng.choice(SECRECY))
        if rng.random() < 0.20:
            lines.append(rng.choice(AUTHORITY))
    else:
        lines.append(rng.choice(BENIGN_ROUTINE))
        if rng.random() < 0.3:
            lines.append(rng.choice(BENIGN_ROUTINE))

    if rng.random() < 0.40:
        lines.append(f"Details are here: {rng.choice(BENIGN_URLS)}")

    # Legitimate mail forwarded through a list, or relayed by a partner with a
    # misconfigured SPF record, softfails authentication. Real estates produce
    # these constantly; without them, "auth failed" would perfectly predict the
    # malicious class.
    relayed = (not internal) and rng.random() < 0.30

    headers = {
        "From": f'"{display}" <{addr}>',
        "To": recipient,
        "Subject": rng.choice(SUBJECT_BEN).format(
            inv=_inv(rng), month=rng.choice(MONTHS)
        ),
        "Date": format_datetime(when),
        "Message-ID": f"<{rng.randrange(10**9, 10**10)}@{domain}>",
        "Authentication-Results": (
            AUTH_SOFT if relayed else AUTH_PASS.format(d=domain)
        ),
        "Received": _received(rng, internal and not relayed, when),
    }
    if rng.random() < 0.12:
        # Legitimate Reply-To: shared team mailbox on the same domain.
        headers["Reply-To"] = f"{rng.choice(INTERNAL_BOXES)}@{domain}"
    if rng.random() < 0.35:
        # Ordinary envelope sender. Its mere presence is not suspicious.
        headers["Return-Path"] = f"<{addr}>"

    return {
        "label": "BENIGN",
        "family": ("benign_confounded" if confounded else "benign_routine")
                  + ("_internal" if internal else "_external")
                  + ("_relayed" if relayed else ""),
        "headers": headers,
        "body": _body(rng, first, lines),
    }


def _serialise(item: dict) -> bytes:
    msg = EmailMessage()
    for key, value in item["headers"].items():
        msg[key] = value
    msg.set_content(item["body"])
    return msg.as_bytes()


def generate(size: int, seed: int) -> list[dict]:
    """Produce `size` messages with a deterministic seed."""
    rng = random.Random(seed)
    start = datetime(2026, 1, 5, 8, 0, tzinfo=timezone.utc)

    items: list[dict] = []
    for index in range(size):
        # Malicious mail skews to out-of-hours; benign to the working day.
        when = start + timedelta(
            days=rng.randrange(0, 240),
            hours=rng.randrange(0, 24),
            minutes=rng.randrange(0, 60),
        )
        if rng.random() < 0.42:
            item = _make_malicious(rng, when)
        else:
            item = _make_benign(rng, when)
        item["name"] = f"r{index:04d}_{item['family']}"
        items.append(item)
    return items


def split(items: list[dict], seed: int) -> dict[str, list[dict]]:
    """Stratified 60/20/20 split, deterministic under `seed`.

    Stratification keeps the class ratio stable across splits so that a metric
    computed on the test set is comparable to one computed on validation.
    """
    rng = random.Random(seed + 1)
    by_label: dict[str, list[dict]] = {}
    for item in items:
        by_label.setdefault(item["label"], []).append(item)

    out: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    for label, group in sorted(by_label.items()):
        group = sorted(group, key=lambda i: i["name"])
        rng.shuffle(group)
        n = len(group)
        n_train, n_val = int(n * 0.6), int(n * 0.2)
        out["train"].extend(group[:n_train])
        out["validation"].extend(group[n_train:n_train + n_val])
        out["test"].extend(group[n_train + n_val:])

    for key in out:
        out[key].sort(key=lambda i: i["name"])
    return out


def write(size: int = DEFAULT_SIZE, seed: int = SEED, root: Path = RESEARCH) -> dict:
    items = generate(size, seed)
    splits = split(items, seed)

    digest = hashlib.sha256()
    counts: dict[str, dict[str, int]] = {}

    for split_name, group in splits.items():
        target = root / split_name
        target.mkdir(parents=True, exist_ok=True)
        for existing in target.glob("*.eml"):
            existing.unlink()

        labels: dict[str, dict[str, str]] = {}
        for item in group:
            raw = _serialise(item)
            filename = f"{item['name']}.eml"
            (target / filename).write_bytes(raw)
            digest.update(raw)
            labels[filename] = {"label": item["label"], "family": item["family"]}

        (target / "labels.json").write_text(
            json.dumps(labels, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        tally: dict[str, int] = {}
        for meta in labels.values():
            tally[meta["label"]] = tally.get(meta["label"], 0) + 1
        counts[split_name] = tally

    metadata = {
        "name": "ForensiBEC synthetic research corpus",
        "provenance": "SYNTHETIC - generated from parameterised templates by "
                      "data/build_research_corpus.py. No real mailbox, person, "
                      "organisation or financial detail is represented.",
        "generator": "data/build_research_corpus.py",
        "seed": seed,
        "size": size,
        "corpus_sha256": digest.hexdigest(),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "split_strategy": "stratified 60/20/20 by label, deterministic under seed",
        "counts": counts,
        "interpretation": {
            "valid_use": "Measuring whether engineered features are learnable and "
                         "which evidence families carry separable signal (ablation).",
            "invalid_use": "Estimating real-world detection accuracy. Template-"
                           "generated data has learnable generative structure, so "
                           "results are an OPTIMISTIC UPPER BOUND, not a performance "
                           "estimate.",
        },
        "difficulty_controls": [
            "~40% of benign messages carry legitimate urgency and/or payment "
            "language (confounded benigns)",
            "~30% of malicious messages omit urgency and explicit amounts, "
            "relying on identity evidence only (subtle malicious)",
            "~28% of malicious messages are sent from a COMPROMISED but genuine "
            "mailbox: real domain, SPF/DKIM/DMARC all pass, no lookalike. Only "
            "behavioural, stylometric and financial evidence can reach these",
            "~30% of external benign messages are relayed or forwarded and "
            "SOFTFAIL SPF, so authentication failure does not imply malicious",
            "greetings, sign-offs and filler are drawn from pools shared by both "
            "classes",
            "the URGENCY, PAYMENT, SECRECY and AUTHORITY sentence pools are "
            "SHARED between classes: a legitimate finance request and a "
            "fraudulent one are worded alike, so the text channel alone cannot "
            "decide the label",
            "benign mail carries the LEGITIMATE form of properties that would "
            "otherwise be artifacts: IBANs on invoices, links to portals and "
            "intranets, Return-Path headers, executive titles in display names, "
            "and occasional consumer-mail contractors",
        ],
        "deliberately_discriminative": [
            "BANKING_CHANGE_REQUEST - unsolicited bank-detail changes are the "
            "BEC payload and are genuinely rare in benign mail",
            "GIFT_CARD_REQUEST - no legitimate business equivalent",
            "CREDENTIAL_SOLICITATION - not routine business correspondence",
            "LOOKALIKE_DOMAIN - a confusable domain has no benign explanation",
        ],
        "why_these_controls": (
            "An earlier generation separated the classes perfectly on the "
            "authentication header alone, so every model and every ablation "
            "configuration scored 1.000 and the experiment could not "
            "distinguish evidence families. The compromised-account and "
            "relayed-benign controls model real phenomena that break that "
            "shortcut. A later generation additionally SHARED the urgency and "
            "payment sentence pools between classes, because drawing the two "
            "classes from disjoint vocabularies let a TF-IDF model recover the "
            "label from wording alone."
        ),
    }

    meta_dir = root / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "corpus.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    meta = write(args.size, args.seed)
    print(f"SYNTHETIC research corpus written to {RESEARCH}")
    print(f"  seed        : {meta['seed']}")
    print(f"  size        : {meta['size']}")
    print(f"  corpus hash : {meta['corpus_sha256'][:32]}...")
    for split_name, tally in meta["counts"].items():
        total = sum(tally.values())
        detail = ", ".join(f"{k}={v}" for k, v in sorted(tally.items()))
        print(f"  {split_name:<11} {total:>4}  ({detail})")
    print()
    print("  Results on this corpus are an OPTIMISTIC UPPER BOUND.")
    print("  They are NOT an estimate of real-world accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
