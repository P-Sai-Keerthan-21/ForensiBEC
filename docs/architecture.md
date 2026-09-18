# Architecture

ForensiBEC is two packages with a one-way dependency.

```
bec_detector/   the forensic application - what investigators use
research/       evaluation of that application - never imported by it
```

`bec_detector` never imports `research` (`test_no_code_path_trains_on_feedback`
asserts this), so no experiment, model or feedback can alter a verdict.

---

## 1. Processing flow

```
        evidence (.eml / .mbox / upload)
                    |
   ACQUISITION      |  SHA-256 over raw bytes BEFORE parsing -> custody record
   acquisition/     |  multipart-depth guard; unparseable input rejected, logged
                    v
             EmailArtifact  (models.py)
                    |
   PASS 1           |  observe the whole evidence set:
   pipeline.fit     |  behaviour baseline, header-based threads, per-sender style,
                    |  statistical profile
                    v
   PASS 2 (per message)
   ANALYSIS   sender/auth . confusable domains . behaviour . NLP . financial
   analysis/  thread (headers only) . stylometry . URLs (static) . attachments (static)
                    |
              IOCs -> local intelligence -> local cross-case correlation
                    |
   VALIDATION  statistical anomaly -> FUSION (weight x confidence, category caps,
   validation/ corroboration bonus, verified-identity suppression) -> score + band
                    |
   REPORT     ATT&CK mapping . timeline . evidence graph . assembly (report/assemble.py)
   report/    -> JSON + self-contained HTML
                    |
   CASE       evidence preserved by hash . findings retained . audit chain
   cases.py   feedback (feedback.py) . assistant (assistant.py)
```

The two-pass structure is load-bearing: behavioural, thread and stylometric
findings describe deviation, which is undefined without a baseline drawn from
the evidence set.

## 2. Package map

| Module | Responsibility |
|---|---|
| `models.py` | `EmailArtifact`, `Indicator`, `Assessment`, `CustodyRecord`, … |
| `config.py` | Every scoring parameter and trusted-domain list. The report fingerprints it. |
| `acquisition/loader.py` | Parse `.eml`/`.mbox`/directories; parse guard; skipped-file reporting |
| `acquisition/custody.py` | SHA-256 and chain-of-custody record |
| `analysis/sender.py` | Display-name impersonation, look-alike domains, Reply-To/Return-Path, SPF/DKIM/DMARC |
| `analysis/confusables.py` | IDNA decoding, NFKC, TR39-derived confusable skeleton, mixed-script detection |
| `analysis/behavior.py` | Corpus-baselined sender behaviour |
| `analysis/text.py` + `lexicons.py` | Urgency, authority, secrecy, financial intent; spaCy NER, NLTK lemmatisation |
| `analysis/thread.py` | Conversation reconstruction from `References`/`In-Reply-To`/`Message-ID` |
| `analysis/stylometry.py` | Per-sender writing-style comparison; refuses without 3 prior messages |
| `analysis/urls.py`, `attachments.py` | Static analysis only: no URL is contacted, no file executed |
| `validation/anomaly.py` | Modified z-score outliers |
| `validation/fusion.py` | Score arithmetic, retained in full on the assessment |
| `forensics/audit.py` | Hash-chained append-only log and verification |
| `forensics/ioc.py`, `correlation.py` | IOC extraction; local cross-case store (flagged messages only) |
| `forensics/intel.py` | `ThreatIntelProvider` interface; local list only |
| `forensics/mitre.py` | Potential ATT&CK mapping, never attributive |
| `forensics/timeline.py` | Events from real timestamps only |
| `forensics/evidence_graph.py` | Typed entity graph; every edge carries provenance |
| `forensics/graph.py` | Address-level communication graph |
| `report/assemble.py` | Single assembly point for every report field |
| `report/html.py` | Self-contained HTML; evidence / inference / risk / recommendation |
| `cases.py` | Case store: preserved evidence, findings, integrity, search, related cases |
| `feedback.py` | Investigator determinations; controlled export |
| `assistant.py` | Grounded explanations; provider interface |
| `recommendations.py` | Per-finding investigator guidance |
| `web/app.py`, `security.py` | FastAPI dashboard and API; upload validation, CSRF, trusted hosts |
| `__main__.py` | CLI: `scan`, `verify-audit`, `status`, `case …` |

| Research module | Purpose |
|---|---|
| `features.py` | ML features built from the engine's own analysers |
| `baselines.py`, `evaluate.py` | Three classical baselines and their metrics |
| `ablation.py`, `balanced_ablation.py` | Which evidence families carry signal |
| `engine_eval.py` | The rule engine itself on the research corpus |
| `robustness.py` | Adversarial transformations |
| `drift.py` | Distribution shift and cross-generation performance |
| `performance.py` | Local timing and memory |

## 3. Data at rest

```
<FORENSIBEC_DATA_DIR, default output/>
├── cases/<CASE-ID>/
│   ├── case.json          metadata, evidence register, latest summary
│   ├── evidence/<sha256>.eml   original bytes, write-once, read-only
│   ├── audit.jsonl        hash-chained audit trail
│   ├── feedback.jsonl     hash-chained investigator determinations
│   ├── analysis.json      full structured result
│   └── report.html        rendered report
├── ioc_store.json         local cross-case correlation (flagged messages only)
└── research/              experiment outputs
```

Tests set `FORENSIBEC_DATA_DIR` to a temporary directory for every session
(`tests/conftest.py`), so they never touch real case data.

## 4. Design decisions

| Decision | Reason |
|---|---|
| Rule-based fusion as the decision path | Every point of a score traces to a named finding and quoted evidence. ML is evaluated alongside, never substituted. |
| Hash before parse | The custody hash identifies exactly the bytes received, independent of parser behaviour |
| Evidence stored under its hash | No user-controlled path; identical bytes deduplicate |
| Threads from headers, not subjects | Subject similarity is not evidence that two messages belong together |
| IOCs recorded only from flagged mail | Otherwise legitimate correspondents become "indicators" |
| Static-only URL and attachment analysis | Contacting attacker infrastructure would disclose the investigation |
| Deterministic assistant | Grounded by construction; nothing leaves the machine |
| No authentication | Scoped out; localhost-only, CSRF and Host checks compensate (see `security.md`) |
