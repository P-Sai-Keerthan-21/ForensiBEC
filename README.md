# Business Email Compromise (BEC) Detector

Cyber Forensics capstone project — an explainable detection tool for Business
Email Compromise, built around the standard forensic workflow:

```
Acquisition  ->  Analysis  ->  Validation  ->  Report
```

The detector ingests email evidence, extracts sender / behavioural / linguistic
features, identifies anomalies, fuses the indicators into a single risk score,
and produces an assessment in which **every point of the score is attributable
to a named rule and the exact header or sentence that triggered it**.

---

## Quick start

```bash
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m spacy download en_core_web_sm
venv\Scripts\python.exe -c "import nltk; nltk.download('wordnet'); nltk.download('punkt_tab')"
```

Generate the labelled sample corpus, then scan it:

```bash
venv\Scripts\python.exe data/build_corpus.py
venv\Scripts\python.exe -m bec_detector scan data/samples --case "Demo" --examiner "Your Name" --json output/case_report.json --html output/case_report.html
```

Run the web interface at <http://127.0.0.1:8000>:

```bash
venv\Scripts\python.exe run_server.py
```

Run the test and validation suite:

```bash
venv\Scripts\python.exe -m pytest tests/ -q
```

---

## Architecture

```
bec_detector/
├── models.py              Canonical dataclasses (EmailArtifact, Indicator, Assessment)
├── config.py              Weights, thresholds, trusted domains — all tuning in one place
├── pipeline.py            Orchestrates the four stages
│
├── acquisition/           STAGE 1
│   ├── custody.py         SHA-256 chain-of-custody records
│   └── loader.py          .eml / .mbox / directory -> EmailArtifact
│
├── analysis/              STAGE 2
│   ├── sender.py          Display-name spoofing, lookalike domains, SPF/DKIM/DMARC
│   ├── behavior.py        Corpus-baselined sending-pattern deviation
│   ├── text.py            NLP: urgency, authority, secrecy, payment intent (spaCy + NLTK)
│   └── lexicons.py        Social-engineering term lists
│
├── validation/            STAGE 3
│   ├── anomaly.py         Modified z-score outlier detection over the corpus
│   └── fusion.py          Weighted indicator fusion -> score, band, narrative
│
├── report/                STAGE 4
│   ├── builder.py         Case-level JSON report
│   └── html.py            Self-contained HTML report
│
└── web/                   FastAPI upload UI + JSON API
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
   *from* an unverified sender *under time pressure* is the BEC pattern itself,
   and the score reflects that interaction.
5. **Normalise to 0–100** and assign a band.

| Band | Score | Meaning |
|---|---|---|
| `BENIGN` | 0–24 | No meaningful BEC characteristics |
| `SUSPICIOUS` | 25–49 | Warrants analyst review |
| `LIKELY_BEC` | 50–74 | Do not action without out-of-band verification |
| `CONFIRMED_BEC` | 75–100 | Full BEC pattern present |

---

## Detection coverage

**Sender / identity** — display-name impersonation of internal executives,
homoglyph and edit-distance lookalike domains, display names embedding a
different address, freemail addresses asserting executive authority, Reply-To
divergence, Reply-To pointing at consumer webmail, Return-Path mismatch.

**Authentication** — SPF, DKIM and DMARC verdicts parsed from
`Authentication-Results`; missing-header and long-relay-chain cases.

**Behaviour** — known correspondent writing from an unfamiliar domain, one
address using multiple display names, first contact, off-hours sending,
unusual recipient sets. Baselined across the acquired corpus.

**Content (NLP)** — manufactured urgency, appeals to authority, enforced
secrecy, payment and wire instructions, **banking-detail change requests**
(the highest-signal BEC pattern), gift-card solicitation, credential
harvesting, fabricated thread continuity, spaCy `MONEY`/`ORG`/`PERSON` entity
confirmation, IBAN and account-number artefacts.

**Statistical** — modified z-score (median/MAD) outlier detection on body
length, recipient count, relay hops, punctuation and capitalisation.

---

## Validation results

Measured by `tests/test_validation.py` against `data/samples/labels.json`:

```
TP=7  FP=0  TN=8  FN=0
precision=1.000  recall=1.000  F1=1.000
```

Score separation: lowest malicious **83.4**, highest benign **23.9**.

> **Read this honestly.** These figures are measured on a 17-message synthetic
> corpus written specifically for this project. Perfect scores on self-authored
> data demonstrate that the pipeline works end to end and that the rules fire
> as designed — they are **not** evidence of real-world accuracy. Validation
> against an independent corpus (e.g. Enron ham + a public phishing set) is
> Phase 2 work and is required before any performance claim is made.

### Sample data

All 17 messages in `data/samples/` are fabricated. The organisation
(`northwind-logistics.com`), its staff, its vendors and all attacker
infrastructure are invented. No real mailbox, person or domain is represented.
Regenerate with `python data/build_corpus.py`.

---

## Chain of custody

Every acquired message carries a custody record computed over the **raw source
bytes before parsing**:

```json
{
  "source_path": "data/samples/bec_01_ceo_wire_urgent.eml",
  "sha256": "…64 hex chars…",
  "size_bytes": 1284,
  "acquired_utc": "2026-09-14T17:08:26+00:00",
  "examiner": "K. Guthala",
  "tool_version": "BEC-Detector 0.5.0"
}
```

This record is reproduced in both the JSON and HTML reports, so a finding can
always be traced back to the exact byte sequence that produced it.

---

## Interfaces

| Interface | Command / endpoint |
|---|---|
| CLI scan | `python -m bec_detector scan <path> [-v] [--json F] [--html F]` |
| CLI status | `python -m bec_detector status` |
| Web UI | `GET /` |
| HTML analysis | `POST /analyse` (multipart `.eml` upload) |
| JSON API | `POST /api/analyse` |
| Health | `GET /api/health` |

Analysis runs entirely locally. Nothing is transmitted to any external service.

---

## Current status — 50% milestone

**Complete**

- Acquisition of `.eml`, `.mbox` and directories, with chain of custody
- Display-name spoofing and lookalike-domain detection
- SPF / DKIM / DMARC header authentication analysis
- Urgency, authority, secrecy and payment-intent NLP (spaCy + NLTK)
- Corpus-baselined behavioural deviation
- Statistical anomaly detection
- Weighted indicator fusion with corroboration logic
- Explainable JSON + HTML reporting
- CLI, FastAPI web UI and JSON API
- 17-message labelled corpus, 24 passing tests including a validation harness

**Deferred to Phase 2**

- Validation against an independent public corpus (required before any
  real-world accuracy claim)
- ML classifier as a supplementary signal
- Live behavioural baselining over real multi-month mailbox history
- URL and attachment analysis; full IDN/punycode homoglyph handling
- Outlook `.msg` and PST support
- Live IMAP acquisition
- PDF report export

---

## Environment

Verified on Python **3.14.3** (Windows 11). spaCy 3.8.16 ships a `cp314` wheel,
so no version pinning workaround is needed. Both NLP backends degrade
gracefully: if a model is unavailable the analyser falls back to regex matching
and records that fact in the report footer, so a missing model reduces
precision but never aborts a forensic run.
