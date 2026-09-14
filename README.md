# FORENSIBEC — Business Email Compromise Detector

Cyber Forensics capstone project — an explainable BEC detection and digital
investigation tool, built around the standard forensic workflow:

```
Acquisition  ->  Analysis  ->  Validation  ->  Report
```

The detector ingests email evidence under chain of custody, extracts sender,
behavioural, linguistic, conversational, URL and attachment features,
identifies anomalies, fuses the indicators into a single risk score, and
produces an assessment in which **every point of the score is attributable to a
named rule and the exact header or sentence that triggered it**.

Findings separate **observed evidence** from **inference** from
**recommendation**, so an investigator can accept an observation while
disputing the conclusion drawn from it.

---

## Quick start

```bash
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m spacy download en_core_web_sm
venv\Scripts\python.exe -c "import nltk; nltk.download('wordnet'); nltk.download('punkt_tab')"
```

Generate the labelled corpus, then run a case:

```bash
venv\Scripts\python.exe data/build_corpus.py
venv\Scripts\python.exe -m bec_detector scan data/samples --case "Demo" --case-id CASE-001 --examiner "Your Name" --audit output/audit.jsonl --json output/case_report.json --html output/case_report.html
```

Verify the audit chain:

```bash
venv\Scripts\python.exe -m bec_detector verify-audit output/audit.jsonl
```

Launch the investigator dashboard at <http://127.0.0.1:8000>:

```bash
venv\Scripts\python.exe run_server.py
```

Run the full test suite:

```bash
venv\Scripts\python.exe -m pytest tests/ -q
```

---

## Architecture

```
bec_detector/
├── models.py              Canonical dataclasses (EmailArtifact, Indicator, Assessment, ...)
├── config.py              Weights, thresholds, trusted domains/relays — all tuning in one place
├── recommendations.py     Per-indicator investigator guidance
├── pipeline.py            Orchestrates all stages
│
├── acquisition/           STAGE 1
│   ├── custody.py         SHA-256 chain-of-custody records
│   └── loader.py          .eml / .mbox / directory -> EmailArtifact
│
├── analysis/              STAGE 2
│   ├── sender.py          Display-name spoofing, lookalike domains, SPF/DKIM/DMARC
│   ├── behavior.py        Corpus-baselined sending-pattern deviation
│   ├── text.py            NLP: urgency, authority, secrecy, payment intent (spaCy + NLTK)
│   ├── thread.py          Conversation reconstruction and hijack indicators
│   ├── stylometry.py      Per-sender writing-style comparison
│   ├── urls.py            Static URL analysis (never contacts a URL)
│   ├── attachments.py     Static attachment analysis (never executes a file)
│   └── lexicons.py        Social-engineering term lists
│
├── validation/            STAGE 3
│   ├── anomaly.py         Modified z-score outlier detection
│   └── fusion.py          Weighted fusion -> score, band, narrative
│
├── forensics/             DFIR SUPPORT LAYER
│   ├── audit.py           Hash-chained tamper-evident audit log
│   ├── ioc.py             IOC extraction and normalisation
│   ├── correlation.py     Local cross-case IOC correlation
│   ├── intel.py           ThreatIntelProvider adapter (local only)
│   ├── mitre.py           Potential ATT&CK technique mapping
│   ├── timeline.py        Investigation timeline
│   └── graph.py           Communication graph (NetworkX optional)
│
├── report/                STAGE 4
│   ├── builder.py         Case-level JSON report
│   └── html.py            Self-contained HTML investigator report
│
└── web/                   FastAPI dashboard + JSON API
    ├── app.py
    └── security.py        Upload validation and hardening
```

### Why a rule engine and not a classifier

The brief requires an **explainable** assessment. A weighted-additive model
with per-category caps yields a score that decomposes cleanly into named
findings, each quoting its own evidence. A trained classifier would produce a
number no examiner could defend in a report, and there is no labelled
real-world corpus available to train one honestly. Machine learning is deferred
to Phase 2 as an *additional* signal alongside the rules, not a replacement.

### How scoring works

1. **Deduplicate** — the same rule firing twice is still one finding.
2. **Accumulate per category** — each indicator contributes `weight × confidence`.
3. **Cap each category** — so one verbose body cannot outweigh hard header evidence.
4. **Corroboration bonuses** — a payment request is ordinary; a payment request
   *from* an unverified sender *under time pressure* is the BEC pattern itself.
5. **Verified-identity suppression** — an internal sender with passing SPF/DMARC
   and no divergence indicators earns *no* pressure bonus. This is what keeps a
   genuine "pay this today" message out of the BEC bands.
6. **Normalise to 0–100** and assign a band.

| Band | Score | Meaning |
|---|---|---|
| `BENIGN` | 0–24 | No meaningful BEC characteristics |
| `SUSPICIOUS` | 25–49 | Warrants analyst review |
| `LIKELY_BEC` | 50–74 | Do not action without out-of-band verification |
| `CONFIRMED_BEC` | 75–100 | Full BEC pattern present |

---

## Detection coverage

**Identity** — display-name impersonation of internal executives, homoglyph and
edit-distance lookalike domains, display names embedding a different address,
freemail asserting executive authority, Reply-To divergence, Reply-To on
consumer webmail, Return-Path mismatch.

**Authentication** — SPF, DKIM and DMARC verdicts from `Authentication-Results`;
missing-header and long-relay-chain cases.

**Behaviour** — known correspondent on an unfamiliar domain, one address using
multiple display names, first contact, off-hours sending, unusual recipient
sets. Baselined across the acquired corpus.

**Content (NLP)** — manufactured urgency, appeals to authority, enforced
secrecy, payment and wire instructions, **banking-detail change requests**,
gift-card solicitation, credential harvesting, fabricated thread continuity,
spaCy `MONEY`/`ORG`/`PERSON` entity confirmation, IBAN and account artefacts.

**Thread** — fabricated `Re:` with no threading headers, sender not party to the
conversation, Reply-To introduced mid-thread, new/dropped participants, and the
**payment pivot** (a non-financial conversation becoming a payment instruction
as the participating identity changes).

**Stylometry** — sentence length, type-token ratio, punctuation, capitalisation,
greeting and signature compared against the sender's *own* prior messages.

**URLs (static only)** — anchor-text/href mismatch, IP literals, punycode,
shorteners, credential-style paths, missing TLS, lookalike hosts.

**Attachments (static only)** — magic-byte type sniffing, extension/MIME
mismatch, double extensions, executable and macro-capable formats, SHA-256.

**Statistical** — modified z-score (median/MAD) outlier detection.

---

## Forensic capabilities

| Capability | Implementation |
|---|---|
| Evidence ID | `EV-<hash prefix>`, derived from content so identical bytes always yield the same id |
| Evidence hashing | SHA-256 over raw source bytes, taken **before** parsing |
| Chain of custody | Source, hash, size, acquisition time, examiner, tool version — in every report |
| Tamper-evident audit log | Hash-chained; each entry hashes its content plus its predecessor's hash |
| Integrity verification | `verify-audit` recomputes the chain and names the first broken entry |
| IOC extraction | Normalised addresses, domains, URLs, routable IPv4, attachment hashes |
| Cross-case correlation | Local JSON store; reports indicator reuse across cases |
| Threat intelligence | `ThreatIntelProvider` adapter; local list only, stated honestly |
| ATT&CK mapping | Indicator → technique, labelled potential, never attributive |
| Investigation timeline | Built only from real timestamps; undated messages recorded as gaps |
| Communication graph | Address/domain nodes, boundary-crossing relationships highlighted |

### Evidence discipline

The tool is deliberately conservative about what it will assert:

- **Thread hijacking** is only offered when sender or Reply-To divergence is
  observable *within a reconstructed thread*. A reply whose parent is simply
  absent from the corpus is reported as a **collection gap**, not a finding.
- **Stylometry** refuses to conclude without at least 3 prior messages from the
  same sender, reporting *"Insufficient historical data"* instead of inventing
  a baseline.
- **URLs are never contacted** and **attachments are never executed**. Contacting
  attacker infrastructure would disclose the investigation.
- **Correlation** reflects only this installation's local history. An absent IOC
  means "not seen here before", never "known good".
- The tool reports **technical indicators**. It does not determine that a
  criminal offence occurred.

---

## Validation results

**Development-corpus validation result** — measured by
`tests/test_validation.py` against `data/samples/labels.json`:

```
TP=9  FP=0  TN=11  FN=0
precision=1.000  recall=1.000  F1=1.000
```

Score separation: lowest malicious **100.0**, highest benign **29.6**.

> **These are development-corpus validation results, not real-world accuracy.**
> They are measured on a 22-message synthetic corpus written specifically for
> this project. Perfect scores on self-authored data demonstrate that the
> pipeline works end to end and that the rules fire as designed — they say
> nothing about generalisation. Validation against an independent corpus
> (e.g. Enron ham plus a public phishing set) is Phase 2 work and is required
> before any performance claim is made.

### Demonstration cases

| Case | File(s) | Demonstrates |
|---|---|---|
| 1 | `bec_01_ceo_wire_urgent.eml` | Executive impersonation + urgency + financial request |
| 2 | `bec_02_vendor_bank_change.eml` | Vendor bank-account change |
| 3 | `bec_08_link_and_attachment.eml` | Lookalike domain + deceptive link + double-extension executable |
| 4 | `thread_01/02/03_*.eml` | Genuine two-message thread, then a hijack of it |
| 5 | `susp_03_legit_urgent_payment.eml` | **Legitimate urgent payment request — not flagged** |

Case 5 is the critical control: urgency, a real sum and a real deadline, but a
verified internal sender. It scores **29.6 (BENIGN/SUSPICIOUS boundary)** rather
than a BEC band, demonstrating that **urgency alone ≠ BEC** and that the verdict
comes from indicator *combination*.

### Sample data

All 22 messages in `data/samples/` are fabricated. The organisation
(`northwind-logistics.com`), its staff, its vendors and all attacker
infrastructure are invented. No real mailbox, person or domain is represented.
`data/local_intel.json` contains fictional indicators only.

---

## Interfaces

| Interface | Command / endpoint |
|---|---|
| CLI scan | `python -m bec_detector scan <path> [-v] [--case-id ID] [--audit F] [--json F] [--html F]` |
| CLI audit verify | `python -m bec_detector verify-audit <log.jsonl>` |
| CLI status | `python -m bec_detector status` |
| Dashboard | `GET /` |
| HTML analysis | `POST /analyse` |
| JSON API | `POST /api/analyse` |
| Health | `GET /api/health` |

Analysis runs entirely locally. **There are no outbound network calls anywhere
in the analysis path** — verified by `tests/test_security.py`.

---

## Security

The tool ingests hostile input by design. See [`docs/security.md`](docs/security.md)
for the full threat model and review. Summary:

- Uploads are validated, extension/MIME-restricted, and size-limited **while
  streaming** (an oversized file is abandoned before it is fully read)
- Filenames are sanitised and **never used as filesystem paths**
- Attachments are never written to disk and never executed
- No `subprocess`, `eval`, `exec`, `shell=True` or `pickle` anywhere
- No hard-coded secrets
- Errors are generic; attacker-controlled content is HTML-escaped in reports
- Server binds `127.0.0.1` only

**No authentication is implemented** — this is a scoped decision for the
milestone. The intended design (Argon2id, server-side sessions, CSRF, role
separation) is documented in `docs/security.md`. Do not expose this build on a
shared network.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/research_mapping.md`](docs/research_mapping.md) | Every component mapped to a paper section; claims the paper may and may not make |
| [`docs/security.md`](docs/security.md) | Application threat model, security review, residual risks |

---

## Current status — 50% milestone

**Complete**

Acquisition with chain of custody · evidence IDs · display-name spoofing ·
lookalike domains · SPF/DKIM/DMARC · behavioural deviation · urgency /
authority / secrecy / financial-intent NLP · thread reconstruction and hijack
detection · stylometry with insufficient-data handling · static URL analysis ·
static attachment analysis · statistical anomaly detection · weighted
explainable fusion · IOC extraction · cross-case correlation · threat-intel
adapter · ATT&CK mapping · timeline · communication graph · hash-chained audit
log with verification · JSON + HTML reports · CLI · investigator dashboard ·
22-message labelled corpus · 92 tests

**Deferred to Phase 2**

- Validation against an independent public corpus (required before any
  real-world accuracy claim)
- ML classifier as a supplementary signal
- Authentication and multi-user case management
- Live behavioural baselining over real multi-month mailbox history
- Full IDN/punycode homoglyph normalisation in the domain comparer
- Archive extraction in an isolated sandbox
- Outlook `.msg` / PST support; live IMAP acquisition
- External threat-intelligence providers behind the existing adapter
- PDF report export

---

## Environment

Verified on Python **3.14.3** (Windows 11). spaCy 3.8.16 ships a `cp314` wheel,
so no version workaround is needed. Both NLP backends degrade gracefully: if a
model is unavailable the analyser falls back to regex matching and records that
fact in the report footer, so a missing model reduces precision but never
aborts a forensic run. NetworkX is optional — the communication graph falls
back to a builtin implementation if it is absent.
