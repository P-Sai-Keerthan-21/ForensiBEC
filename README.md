# ForensiBEC — Business Email Compromise Investigation Tool

A cyber-forensics capstone: an explainable tool for investigating suspected
Business Email Compromise, built around the forensic workflow

```
Acquisition  ->  Analysis  ->  Validation  ->  Report
```

It preserves email evidence under chain of custody, analyses each message
across independent evidence families, and produces a risk assessment where
**every point of the score traces to a named finding and the exact header or
sentence that triggered it**. Each finding keeps **observed evidence**,
**system inference**, **risk** and **recommendation** separate, so an
investigator can accept an observation while disputing the conclusion drawn
from it.

The investigator makes the decisions. The tool reports technical indicators;
it does not decide whether a crime occurred, and it attributes nothing to
anyone.

> **All data in this repository is synthetic.** No figure here is a real-world
> accuracy, detection rate or false-positive rate. See
> [`docs/research.md`](docs/research.md).

---

## 1. The problem

Business Email Compromise is fraud by email that impersonates someone the
victim trusts, such as an executive, a supplier or a lawyer, to redirect a
payment or extract data. It rarely carries malware, so signature-based filters
miss it. The signals are spread across headers (look-alike domains, Reply-To
redirection, failed authentication), behaviour (a known contact writing from a
new domain, at an odd hour), language (urgency, secrecy, a changed bank
account) and conversation structure (a hijacked thread).

An investigator needs more than a label. They need to know which evidence
supports the suspicion, how strong it is, what is missing, and what to check
next, in a form that survives review. That is what this tool is built for.

## 2. Architecture

```
bec_detector/     the forensic application
  acquisition/    SHA-256 before parsing, custody records, parse guards
  analysis/       sender/auth, Unicode confusables, behaviour, NLP, thread,
                  stylometry, static URL and attachment analysis
  validation/     statistical anomaly, evidence fusion
  forensics/      audit chain, IOCs, local intel, correlation, ATT&CK,
                  timeline, evidence graph
  report/         report assembly, JSON, self-contained HTML
  cases.py        case store: preserved evidence, findings, integrity, search
  feedback.py     investigator determinations (no retraining)
  assistant.py    grounded explanations (no language model)
  web/            FastAPI dashboard and JSON API
research/         evaluation of the application; never imported by it
data/             synthetic samples, corpus generators, local intel list
```

`bec_detector` never imports `research`, so no experiment, model or piece of
feedback can change a verdict. Full detail: [`docs/architecture.md`](docs/architecture.md),
[`docs/pipeline.md`](docs/pipeline.md).

### How a score is built

Analysis runs in **two passes**. Pass 1 observes the whole evidence set to
build behavioural, thread and writing-style baselines. Pass 2 scores each
message against them. Deviation means nothing without a baseline.

Scoring is **rule-based evidence fusion**:

1. each finding contributes `weight × confidence`;
2. contributions are summed per category, and **each category is capped** so
   one verbose body cannot outweigh header evidence;
3. **corroboration bonuses** apply when independent families agree (a payment
   request *from an unverified sender under pressure*);
4. **verified-identity suppression**: an internal sender with passing
   SPF/DMARC and no divergence earns no pressure bonus. This keeps a genuine
   "please pay this today" out of the BEC bands;
5. the total is normalised to 0–100 and banded.

| Band | Score | Meaning |
|---|---|---|
| `BENIGN` | 0–24 | No meaningful BEC characteristics |
| `SUSPICIOUS` | 25–49 | Warrants review |
| `LIKELY_BEC` | 50–74 | Do not act without out-of-band verification |
| `CONFIRMED_BEC` | 75–100 | Full BEC pattern present in the evidence |

Scores are not probabilities. The full arithmetic is retained on every
assessment and printed in the report.

**Why rules and not a classifier:** a score an examiner can decompose, defend
and challenge. Machine learning is evaluated alongside the engine as a
research layer (§8) and never replaces it.

## 3. Investigation workflow

```
create case -> add evidence (hashed, preserved write-once)
            -> analyse (two-pass, audit-logged)
            -> review: findings, graph, timeline, IOCs, related cases, report
            -> ask the grounded assistant
            -> record investigator determination
            -> verify integrity (re-hash evidence, check audit chain)
```

## 4. Installation

Python 3.14.3 on Windows 11 has been verified.

```bash
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m spacy download en_core_web_sm
venv\Scripts\python.exe -c "import nltk; nltk.download('wordnet')"
venv\Scripts\python.exe -m bec_detector status
```

Both NLP back-ends are optional at run time. If one is missing, analysis falls
back to regex matching and the report says so.

| Environment variable | Purpose | Default |
|---|---|---|
| `FORENSIBEC_DATA_DIR` | Where cases, the IOC store and outputs live | `output/` |
| `FORENSIBEC_ALLOWED_HOSTS` | Accepted `Host` headers for the web app | `127.0.0.1,localhost` |

## 5. Command line

```bash
# One-shot analysis of a file, .mbox or directory
venv\Scripts\python.exe -m bec_detector scan data/samples --case "Demo" --examiner "Examiner A" --audit output/audit.jsonl --html output/case_report.html --json output/case_report.json
venv\Scripts\python.exe -m bec_detector verify-audit output/audit.jsonl

# Case management
venv\Scripts\python.exe -m bec_detector case create CASE-001 --examiner "Examiner A"
venv\Scripts\python.exe -m bec_detector case add CASE-001 data/samples
venv\Scripts\python.exe -m bec_detector case analyse CASE-001
venv\Scripts\python.exe -m bec_detector case show CASE-001
venv\Scripts\python.exe -m bec_detector case ask CASE-001 "Why was this email flagged?" --evidence EV-88F7BCE5D4FD
venv\Scripts\python.exe -m bec_detector case feedback CASE-001 EV-88F7BCE5D4FD confirmed_suspicious --examiner "Examiner A"
venv\Scripts\python.exe -m bec_detector case verify CASE-001
venv\Scripts\python.exe -m bec_detector case search northwind-l0gistics.com
venv\Scripts\python.exe -m bec_detector case list
```

`case export-feedback` writes investigator labels for a *future, deliberate*
retraining step. Nothing retrains automatically.

## 6. Web dashboard and API

```bash
venv\Scripts\python.exe run_server.py        # http://127.0.0.1:8000
```

| Page | Purpose |
|---|---|
| `/` | Upload evidence into a new or existing case |
| `/cases`, `/cases/{id}` | Case list; case page with findings, recommendations, IOCs, evidence graph, timeline, related cases, evidence register, audit trail, feedback |
| `/cases/{id}/report` | Full forensic report |
| `/cases/{id}/verify` | Re-hash evidence and verify the audit chain |
| `/cases/{id}/ask` | Grounded assistant |
| `/search`, `/about` | Cross-case search; method and limitations |

| API | Method |
|---|---|
| `/api/health` | GET |
| `/api/analyse` | POST (multipart: `case`, `files`) |
| `/api/cases`, `/api/cases/{id}`, `/api/cases/{id}/analysis`, `/api/cases/{id}/verify` | GET |
| `/api/search?q=` | GET |
| `/api/cases/{id}/feedback` | GET, POST |
| `/api/cases/{id}/assistant` | POST `{"question": ..., "evidence_id": ...}` |

A step-by-step walkthrough is in [`docs/demo.md`](docs/demo.md).

## 7. Features

**Identity and authentication:** display-name impersonation of internal
executives; look-alike domains via IDNA decoding, NFKC, a TR39-derived
confusable skeleton and edit distance; mixed-script domains; freemail claiming
executive authority; Reply-To and Return-Path divergence; SPF, DKIM and DMARC
verdicts.

**Behaviour:** a known correspondent on a new domain, display-name rotation,
first contact, off-hours sending, unusual recipient sets.

**Content (NLP):** urgency, authority, secrecy, payment instructions,
banking-detail changes, gift cards, credential requests; spaCy `MONEY`, `ORG`
and `PERSON` entities; NLTK lemmatisation.

**Conversation:** threads reconstructed **from `References`, `In-Reply-To` and
`Message-ID` only**. Detects a fabricated `Re:`, a sender foreign to the
thread, a Reply-To introduced mid-thread, and a payment pivot. A reply whose
parent was never collected is reported as a *collection gap*, not a finding.

**Stylometry:** writing style, greeting and signature compared with the
sender's *own* earlier messages. It refuses to conclude with fewer than three.

**Static artefacts:** URLs are never contacted and attachments are never
executed. Checks cover anchor/href mismatch, IP literals, punycode and
homograph hosts, shorteners, credential paths, magic-byte type sniffing,
extension/MIME mismatch, double extensions and macro formats.

**Forensics:** SHA-256 before parsing; content-derived evidence IDs; chain of
custody; hash-chained audit logs with verification; IOC extraction; a local
threat-intelligence list (fictional; stated in every report); local cross-case
correlation (flagged mail only, partner allowlist); potential ATT&CK mapping,
never attributive; a timeline from real timestamps only; an evidence graph
where every edge records the header or finding that established it.

**Case management:** evidence preserved write-once under its hash and
re-verified on every read; findings retained; search; related cases via
shared indicators.

**Report:** 16 case-level sections plus 28 per-message subsections, covering
an executive summary, findings as
evidence/inference/risk/recommendation, explicit statements of what was *not*
found, the fusion arithmetic, graph, timeline, IOCs, custody, the audit chain,
investigator determinations, limitations and a reproducibility fingerprint.

**Investigator feedback:** confirmed suspicious / confirmed benign / needs
review, recorded in a hash-chained log with the system's assessment at the
time. See [`docs/feedback.md`](docs/feedback.md).

**Grounded assistant:** explains a case from its structured findings only.
Every claim cites evidence, certainty and attribution language is rejected,
and it contains no language model. See [`docs/ai_assistant.md`](docs/ai_assistant.md).

## 8. Research methodology and evaluation

Two result families are kept apart:

| | Development results | Research results |
|---|---|---|
| Data | 26 hand-written messages the engine was built against | 900-message generated corpus (plus a 400-message drift generation) |
| Result | TP 10, FP 0, TN 14, FN 0; lowest malicious 78.4, highest benign 29.6 | Below |

The development result shows that the rules fire as designed. It is optimistic
by construction and says nothing about generalisation.

**Research results (synthetic, not real-world):**

| Experiment | Finding |
|---|---|
| ML baselines, held-out test | F1: Logistic Regression 0.987, Random Forest 0.993, Linear SVM 1.000 |
| Original ablation (6485 text vs 82 structured features) | Inconclusive: every delta within CV noise |
| Feature-balanced ablation (82 vs 82) | Structured evidence adds signal: ΔF1 **+0.0257**, 95% CI [+0.0181, +0.0332], p < 0.0001, 15 paired folds; holds at every component count tested |
| **Rule engine** on the research test split | Precision 0.631, recall 0.921, **false-positive rate 0.387**, ROC-AUC 0.903 |
| Adversarial robustness (11 transformations) | At most 1 of 70 detected attacks evaded per transformation, all compromised-account messages; cosmetic reformatting newly flags 8–14 of 106 benign messages |
| Concept drift (documented generation-2 shift) | Shift detected, control clean; rule-engine recall on the novel lure 0.069 |
| Performance (one machine) | 42–54 ms per message end-to-end for 1–100 messages |

Method: stratified splits; vectorisers and reductions fitted inside folds;
paired repeated cross-validation; significance requires both p < 0.05 and a CI
excluding zero; the balanced ablation's parameter was fixed before results were
seen. Two rounds of results were regenerated after genuine bugs were found, and
both are disclosed with before/after figures.

Documents: [`research.md`](docs/research.md) (index and methodology) ·
[`evaluation.md`](docs/evaluation.md) · [`adversarial_testing.md`](docs/adversarial_testing.md) ·
[`concept_drift.md`](docs/concept_drift.md) · [`performance.md`](docs/performance.md) ·
[`research_mapping.md`](docs/research_mapping.md).

## 9. Testing

```bash
venv\Scripts\python.exe -m pytest -q
```

492 tests, covering evidence integrity, every analyser, fusion, the report
contract (no invented evidence), case management, the dashboard, security
regressions, the assistant's grounding and prompt-injection behaviour,
feedback, and the research harnesses (leakage, significance rules,
determinism). Tests use a temporary data directory and never touch real case
data.

## 10. Security

The tool ingests hostile input by design. Summary of
[`docs/security.md`](docs/security.md):

- Uploads are validated, type-restricted and size-limited **while streaming**.
- Filenames are never used as paths; evidence is stored under its hash.
- MIME nesting bombs and unparseable input are rejected with a reason and
  logged, never silently dropped.
- CSRF protection via `Sec-Fetch-Site`/`Origin`; a `Host` allowlist blocks DNS
  rebinding.
- Jinja2 autoescaping; report content is escaped.
- No `subprocess`, `eval`, `exec`, `shell=True` or `pickle`; no hard-coded
  secrets; no outbound network calls in the analysis path.
- The server binds `127.0.0.1`. **There is no authentication**: do not expose
  it on a shared network.

## 11. Limitations

The most important, in full in [`docs/limitations.md`](docs/limitations.md):

1. **No real-world validation.** Every figure comes from synthetic data.
2. **High false-positive rate on the research corpus:** the engine flags about
   39% of benign test mail, driven by finance/urgency wording from senders it
   cannot verify, a weak signature heuristic, and display-name rotation.
3. **Poor generalisation to new lures:** hand-written lexicons missed 93% of
   the drift corpus's novel lure.
4. **Compromised accounts are the weak spot:** with genuine authentication the
   verdict rests on wording and style.
5. Known gaps include combosquat domains, a whitespace-sensitive currency
   pattern, and stylometry reacting to formatting. Archives, `.msg` and PST
   are not supported.
6. There is no authentication or TLS, and no locking for concurrent writes to
   one case.

## 12. Future work

- Validation on an independent corpus (public phishing plus a benign corpus
  such as Enron). This is the most important gap.
- Fix the documented weaknesses and re-evaluate on fresh data: signature-block
  detection, per-message display-name change, whitespace normalisation,
  combosquat detection, format-insensitive stylometry.
- Calibrated risk estimates, separate from the rule score.
- Behavioural weighting for compromised-account detection.
- Authentication, roles and TLS (design in `docs/security.md` §3).
- Sandboxed archive extraction; `.msg`/PST; IMAP acquisition.
- External threat-intelligence providers behind the existing adapter.
- A model-backed assistant provider under the constraints in
  `docs/ai_assistant.md`.
