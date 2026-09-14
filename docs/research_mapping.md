# Research Paper Mapping

Maps every implemented component to the paper section it supports, and back to
the clause of the original problem statement it satisfies.

Read alongside [`docs/security.md`](security.md) (application threat model) and
the validation caveat in the README.

---

## 1. Original problem statement → implementation → paper section

| Problem requirement | Implementation | Module | Paper section |
|---|---|---|---|
| Display-name spoofing | Impersonation rule: external sender asserting an internal executive identity; display name embedding a different address | `analysis/sender.py` | Feature Engineering → Identity Features |
| Look-alike domains (implied by spoofing) | Confusable normalisation + Levenshtein distance against trusted domains | `analysis/sender.py` | Feature Engineering → Identity Features |
| Unusual sending behaviour | Corpus-baselined deviation: known correspondent on a new domain, display-name rotation, first contact, off-hours send, unusual recipient set | `analysis/behavior.py` | Feature Engineering → Behavioural Analysis |
| Urgency language | Lexicon matching over NLTK-lemmatised text, with multi-cue confidence weighting | `analysis/text.py`, `analysis/lexicons.py` | NLP Analysis |
| Extract sender features | Header parsing into `EmailArtifact`; From / Reply-To / Return-Path comparison; SPF, DKIM, DMARC verdict extraction | `acquisition/loader.py`, `analysis/sender.py` | Feature Engineering |
| Extract behaviour features | `BehaviorBaseline` two-pass observe-then-score design | `analysis/behavior.py` | Feature Engineering → Behavioural Analysis |
| Extract text features | Urgency, authority, secrecy, payment intent, banking change, gift card, credential solicitation; spaCy NER for `MONEY`/`ORG`/`PERSON` | `analysis/text.py` | NLP Analysis |
| Identify anomalies | Modified z-score (median/MAD) outlier detection over corpus-relative features | `validation/anomaly.py` | Anomaly Detection |
| Combine indicators into an assessment | Weighted-additive fusion with deduplication, per-category caps, corroboration bonuses and a verified-identity suppression rule | `validation/fusion.py` | Proposed Methodology → Evidence Fusion |
| Explainable risk assessment | Every indicator carries observed evidence, inference, recommendation, basis and confidence | `models.py`, `report/html.py` | Explainability / Results |
| Python + spaCy/NLTK | spaCy `en_core_web_sm` NER, NLTK WordNet lemmatisation, both degrading gracefully to regex | `analysis/text.py` | Implementation |
| Acquisition → Analysis → Validation → Report | Four-stage package structure mirrored by the pipeline orchestrator | `pipeline.py` | Proposed Methodology |

---

## 2. Forensic contributions → paper section

| Contribution | Implementation | Module | Paper section |
|---|---|---|---|
| Digital evidence integrity | SHA-256 over raw source bytes taken **before** parsing | `acquisition/custody.py` | Digital Evidence Integrity |
| Evidence identity | `EV-<hash prefix>` derived from the content hash, so identical bytes always yield the same id | `models.py` | Digital Evidence Integrity |
| Chain of custody | Source path, hash, size, acquisition time, examiner, tool version — reproduced in every report | `acquisition/custody.py`, `report/` | Digital Evidence Integrity |
| Tamper-evident audit logging | Hash-chained append-only log; each entry hashes its content plus its predecessor's hash | `forensics/audit.py` | Digital Evidence Integrity → Audit Trail |
| Integrity verification | `verify()` recomputes the chain and reports the first broken entry; exposed as `verify-audit` | `forensics/audit.py`, `__main__.py` | Digital Evidence Integrity → Audit Trail |
| Conversation reconstruction | Message-ID / In-Reply-To / References threading; fabricated-reply, Reply-To-introduction and payment-pivot detection | `analysis/thread.py` | Thread & Conversation Analysis |
| Authorship consistency | Per-sender stylometry with an explicit insufficient-data refusal | `analysis/stylometry.py` | Stylometric Analysis |
| Static URL analysis | IP literal, punycode, shortener, anchor/href mismatch, suspicious path, TLS — never contacting the URL | `analysis/urls.py` | Static Artefact Analysis |
| Static attachment analysis | Magic-byte type sniffing, extension/MIME mismatch, double extension, executable and macro detection, SHA-256 — never executing the file | `analysis/attachments.py` | Static Artefact Analysis |
| IOC extraction | Normalised addresses, domains, URLs, routable IPv4, attachment hashes | `forensics/ioc.py` | Threat-Aware Investigation |
| Cross-case IOC correlation | Local JSON-backed store; reports indicator reuse across cases, filtering non-discriminating indicators | `forensics/correlation.py` | Threat-Aware Investigation → Case Linkage |
| Threat-intelligence architecture | Abstract `ThreatIntelProvider` with a local-only implementation; external status stated honestly | `forensics/intel.py` | System Architecture → Extensibility |
| ATT&CK evidence mapping | Indicator → technique mapping, labelled as potential and never attributive | `forensics/mitre.py` | Threat Modelling |
| Investigation timeline | Events built only from real timestamps; undated messages recorded as collection gaps | `forensics/timeline.py` | Investigative Workflow |
| Communication graph | Address/domain nodes, communication edges, boundary-crossing relationship highlighting (NetworkX optional) | `forensics/graph.py` | Relationship Analysis |
| Application security | Upload validation, streaming size limits, filename sanitisation, no execution, no disk writes, generic errors | `web/security.py` | Secure System Design |

---

## 3. Suggested paper structure

1. **Introduction** — BEC as a financially-motivated social-engineering threat; why signature-based mail filtering misses it.
2. **Related Work** — rule-based vs ML phishing detection; the explainability gap in forensic contexts.
3. **Proposed Methodology** — the four-stage Acquisition → Analysis → Validation → Report pipeline (`pipeline.py`).
4. **Feature Engineering** — identity, authentication and behavioural features (§1, §2).
5. **NLP Analysis** — lexicon design, lemmatisation, NER-corroborated financial intent.
6. **Thread & Conversation Analysis** — reconstruction method and the evidence discipline that governs hijack claims.
7. **Stylometric Analysis** — feature set, baseline requirement, and the refusal-to-conclude rule.
8. **Static Artefact Analysis** — URL and attachment handling under a no-contact, no-execution constraint.
9. **Anomaly Detection** — modified z-score and why MAD suits small forensic corpora.
10. **Evidence Fusion** — weighting, category caps, corroboration, verified-identity suppression; the case for rules over a classifier.
11. **Digital Evidence Integrity** — hashing, custody, hash-chained audit log, verification.
12. **Threat-Aware Investigation** — IOC extraction, local correlation, intelligence adapter, ATT&CK mapping.
13. **Secure System Design** — the application's own threat model (`docs/security.md`).
14. **Results** — development-corpus validation, per-indicator contribution analysis.
15. **Limitations and Future Work** — see §4.
16. **Conclusion**

---

## 4. Claims the paper may and may not make

**Supported by the current implementation**

- A fully explainable BEC risk assessment in which every score point traces to a named rule and quoted evidence.
- End-to-end forensic workflow with verifiable evidence integrity.
- Detection across seven independent evidence families (identity, authentication, behaviour, content, thread, URL, attachment) plus statistical anomaly.
- Correct rejection of the urgency-alone control case, demonstrating that indicator combination — not any single signal — drives the verdict.

**NOT supported — do not claim**

- Real-world accuracy, generalisation, or comparison against published detectors. The reported precision/recall/F1 are **development-corpus validation results** on a self-authored 22-message corpus. See the README caveat.
- Threat attribution. The ATT&CK layer maps observed indicators to techniques commonly associated with such behaviour; it identifies no actor.
- External threat-intelligence coverage. Only a local operator-maintained list is consulted.
- That a criminal offence occurred. The tool reports technical indicators; that determination is not a technical one.

**Required before an accuracy claim**

Validation against an independent corpus — e.g. Enron for benign traffic plus a public phishing set — with a held-out split and confusion matrix. This is Phase 2 work and is not yet done.
