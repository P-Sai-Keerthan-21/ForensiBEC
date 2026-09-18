# FORENSIBEC — Processing Pipeline

The authoritative flow, matching `bec_detector/pipeline.py`.

---

## Two-pass structure

The single most important structural point: **the whole corpus is acquired and
observed before any message is scored.**

Four analysis stages — behaviour, thread, stylometry and statistical anomaly —
describe how a message deviates from what is *normal*. "Normal" does not exist
until the corpus has been observed, so a single-pass design would make those
stages meaningless.

```
PASS 1  acquire all  ->  fit() baselines
PASS 2  for each message: assess() against those baselines
```

---

## Full pipeline

```
                          FORENSIBEC
                              │
                              ▼
                   ┌──────────────────────┐
                   │   Evidence Upload    │   CLI / dashboard / API
                   └──────────┬───────────┘
                              ▼
        ═══════════════ STAGE 1: ACQUISITION ═══════════════
                              │
                    SHA-256 over raw bytes
                    (taken BEFORE parsing)
                              ▼
                  Evidence ID  +  Chain of Custody
                              ▼
                  RFC 5322 / MIME header parsing
                              │
                              ▼
        ┌─────────────── PASS 1: BASELINE ───────────────┐
        │  observe whole corpus before scoring anything  │
        │  behaviour · threads · style · anomaly model   │
        └────────────────────────┬───────────────────────┘
                                 ▼
        ═══════════════ STAGE 2: ANALYSIS ═══════════════
                    (PASS 2 — per message)
                                 │
     ┌──────────┬──────────┬─────┴─────┬──────────┬──────────┐
     ▼          ▼          ▼           ▼          ▼          ▼
 Identity    Auth      Behaviour      NLP       Thread    Stylometry
 SENDER   SPF/DKIM/   deviation   ┌─────────┐  conversa-  vs sender's
 spoofing   DMARC     vs corpus   │ urgency │  tion re-   OWN prior
 lookalike            first-seen  │authority│  construc-  messages
 domains              off-hours   │ secrecy │  tion       (refuses
 Reply-To             new domain  │─────────│             without a
 divergence           for known   │FINANCIAL│             baseline)
                      name        │ intent  │
                                  └─────────┘
                                  payment ·
                                  bank change ·
                                  gift card ·
                                  spaCy MONEY
     │          │          │           │          │          │
     └──────────┴────┬─────┴───────────┴────┬─────┴──────────┘
                     ▼                      ▼
              URL (static)           Attachment (static)
              never contacted        never executed
              IP literal ·           magic-byte sniff ·
              punycode ·             ext/MIME mismatch ·
              anchor mismatch        double extension ·
                                     SHA-256
                     │                      │
                     └───────────┬──────────┘
                                 ▼
                        IOC EXTRACTION
                 addresses · domains · URLs ·
                 routable IPv4 · attachment hashes
                                 │
                     ┌───────────┴───────────┐
                     ▼                       ▼
            Local Threat Intel      Cross-Case Correlation
            (adapter; local          (local store only —
             list only, external      "IOC reuse across cases")
             stated as NOT
             configured)
                     │                       │
                     └───────────┬───────────┘
                                 ▼
                      Statistical Anomaly
                    modified z-score (median/MAD)
                                 │
                                 ▼
        ═══════════════ STAGE 3: VALIDATION ═══════════════
                                 │
                        EVIDENCE FUSION
                    1. deduplicate rule codes
                    2. sum weight x confidence
                    3. cap per category
                    4. corroboration bonuses
                    5. verified-identity suppression
                    6. normalise 0-100
                                 ▼
                    ┌────────────────────────┐
                    │     BEC RISK SCORE     │
                    │  BENIGN / SUSPICIOUS / │
                    │ LIKELY_BEC / CONFIRMED │
                    └───────────┬────────────┘
                                ▼
                   EXPLAINABLE INVESTIGATION
              every finding carries, separately:
                OBSERVED EVIDENCE  (what was seen)
                INFERENCE          (what it means)
                RECOMMENDATION     (what to do)
                BASIS + CONFIDENCE (how firm)
                                ▼
        ═══════════════ STAGE 4: REPORT ═══════════════
                                │
      ┌──────────┬──────────────┼──────────────┬──────────┐
      ▼          ▼              ▼              ▼          ▼
  Timeline   Comms Graph      IOCs      Potential      Evidence
  real       addresses/     normalised  ATT&CK map     Integrity
  timestamps domains,       + cross-    (labelled      SHA-256 +
  only;      boundary-      case links  potential,     hash-chained
  undated =  crossing                   never          audit log +
  collection edges                      attribution)   verification
  gap
      └──────────┴──────────────┬──────────────┴──────────┘
                                ▼
                        FORENSIC REPORT
                    self-contained HTML + JSON
```

---

## Stage → module map

| Stage | Module | Category emitted |
|---|---|---|
| Acquisition, custody | `acquisition/custody.py`, `acquisition/loader.py` | — |
| Identity (incl. Unicode confusables, mixed script) | `analysis/sender.py`, `analysis/confusables.py` | `SENDER` |
| Authentication | `analysis/sender.py` | `AUTHENTICATION` |
| Behaviour | `analysis/behavior.py` | `BEHAVIOR` |
| NLP **incl. financial intent** | `analysis/text.py`, `analysis/lexicons.py` | `CONTENT` |
| Thread (from `References` / `In-Reply-To` / `Message-ID` only) | `analysis/thread.py` | `THREAD` |
| Stylometry | `analysis/stylometry.py` | `STYLOMETRY` |
| URL (static) | `analysis/urls.py` | `URL` |
| Attachment (static) | `analysis/attachments.py` | `ATTACHMENT` |
| Statistical anomaly | `validation/anomaly.py` | `ANOMALY` |
| Threat intel / correlation | `forensics/intel.py`, `forensics/correlation.py` | `INTELLIGENCE` |
| Fusion, scoring | `validation/fusion.py` | — |
| IOC, timeline, graph, ATT&CK | `forensics/` | — |
| Evidence graph (typed entities, provenance on every edge) | `forensics/evidence_graph.py` | — |
| Report assembly and rendering | `report/assemble.py`, `report/builder.py`, `report/html.py` | — |
| Case store, feedback, assistant (after the pipeline) | `cases.py`, `feedback.py`, `assistant.py` | — |

**Note:** financial intent is *not* a separate stage. It is detected inside the
NLP module, because the signal is linguistic — the lexicons for payment
instructions, banking changes and gift cards sit alongside urgency and secrecy,
and spaCy `MONEY` entities corroborate them.

---

## Rule-code distribution

| Module | Rule codes |
|---|---|
| `sender.py` | 14 |
| `text.py` | 9 |
| `urls.py` | 9 |
| `thread.py` | 6 |
| `attachments.py` | 6 |
| `behavior.py` | 5 |
| `stylometry.py` | 3 |
| `intel.py` | 2 |
| `anomaly.py` | 1 |
| `correlation.py` | 1 |
| **Total** | **56** (every code has a weight in `config.WEIGHTS`) |

Ten indicator categories, each independently capped during fusion so no single
evidence family can dominate a verdict. The full fusion arithmetic (raw and
capped totals per category, corroboration bonuses, identity suppression,
thresholds) is retained on every assessment and printed in the report.

---

## Cross-cutting: the audit chain

Not a stage — it runs *alongside* every stage. Each action appends an entry
whose hash covers both its own content and the previous entry's hash:

```
case_opened -> evidence_acquired (xN) [-> evidence_skipped] -> baseline_established
            -> message_assessed (xN) -> iocs_recorded
```

Case-backed analysis adds `case_created`, `evidence_added`,
`case_report_generated`, `integrity_verified` and `investigator_assessment` to
the case's own log (`<data dir>/cases/<CASE-ID>/audit.jsonl`). Unparseable
input is logged as `evidence_skipped` with the reason, never dropped silently.
IOCs are recorded to the cross-case store only for messages in the
`LIKELY_BEC` or `CONFIRMED_BEC` bands.

Altering, reordering or deleting any entry breaks the chain from that point
onward. `python -m bec_detector verify-audit <log>` names the first broken
entry and exits non-zero.
