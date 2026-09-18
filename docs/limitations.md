# Limitations

A consolidated list, most consequential first. Each links to the document with
the evidence.

## 1. No real-world validation

**Every performance figure in this project comes from synthetic data.** The
26 development messages were written by hand; the 900-message research corpus
and the 400-message drift generation were produced by seeded generators. No
real mailbox, real BEC case or independent public corpus has been used. None
of the reported numbers is a real-world accuracy estimate, and none should be
quoted as one. Validation against independent data (for example a public
phishing corpus with a benign corpus such as Enron) is the most important
missing piece of work.

## 2. The rule engine's false-positive rate on the research corpus is high

The engine investigators rely on flags a large share of benign research mail —
around 39% on the test split after the bug fixes described in
[`evaluation.md` §8](evaluation.md), where the drivers are broken down. Part of
this is a deliberately harsh benign corpus: it shares pressure, secrecy and
payment wording with the attack class, by design. Part is the engine: the
signature-block stylometry heuristic, `DISPLAY_NAME_CHANGED` firing on every
message from an address that has used several display names, and
content-heavy scoring for senders whose identity can't be verified. On the
26-message development corpus the engine produces no false positives, and the
difference between the two results is itself a warning about small,
hand-written test sets.

## 3. The rule engine does not generalise to new lures

Under the documented generation-2 shift (compromised mailboxes plus a lure
worded to avoid its lexicons), the rule engine caught about 7% of novel-lure
attacks and ranked messages worse than chance (ROC-AUC 0.459). The ML baseline
degraded far less. See [`concept_drift.md`](concept_drift.md). Hand-written
lexicons need maintenance, and the drift detector exists to say when they are
out of date.

## 4. Compromised-account BEC is the weak spot

When the mailbox is genuine, identity and authentication evidence is clean and
the verdict rests on wording and style. Every evasion in the robustness
experiment was a compromised-account message
([`adversarial_testing.md`](adversarial_testing.md)).

## 5. Known detection gaps

| Gap | Where documented |
|---|---|
| Combosquat domains (`brand-payments.com`) are not treated as look-alikes | `adversarial_testing.md` §4 |
| Doubled spaces defeat the currency pattern | `adversarial_testing.md` §4 |
| Stylometry reacts to cosmetic formatting (capitals, punctuation, padding) | `adversarial_testing.md` §4 |
| Signature-block heuristic uses the last three lines, which may be body text | `evaluation.md` §8 |
| Confusable table is a curated subset of Unicode TR39 | `analysis/confusables.py` |
| Archives are not extracted; attachment contents are not analysed | `security.md` §2.4 |
| Outlook `.msg` and PST are not supported | — |

## 6. Methodological limits of the research

- The ML ablation's aggregate result is ceiling-limited; the feature-balanced
  re-test is the informative one ([`evaluation.md`](evaluation.md) §5–6).
- Confidence intervals describe variation across folds of one synthetic corpus,
  not across corpora.
- Robustness uses fixed transformation tables, not an adaptive attacker.
- Drift is one hand-chosen step change, not a trajectory; corpus-relative
  indicators are excluded from drift measurement.
- Performance was measured on one machine at 1, 10 and 100 messages only
  ([`performance.md`](performance.md)).

## 7. Risk score is not a probability

Scores are the capped, corroboration-adjusted sum of rule contributions. They
are not calibrated probabilities, and band thresholds were set by design, not
fitted. The threshold table in `evaluation.md` §8 is analysis, not selection.

## 8. Operational limits

| Limit | Mitigation in place |
|---|---|
| No authentication or user accounts | Binds to `127.0.0.1`; CSRF and trusted-host checks (`security.md`) |
| No TLS | Localhost only |
| Case data stored unencrypted | Protect the data directory with filesystem permissions |
| Concurrent analysis of one case is not locked | Single-analyst use |
| Threat intelligence is a local list only | Stated in every report; the adapter supports future providers |
| Assistant uses keyword intents and templates | Grounding validator; unsupported questions get a list, not a guess |

## 9. What the tool does not do

It does not determine whether a crime occurred, identify or attribute an
attacker, contact any URL or host found in evidence, execute attachments,
retrain itself from investigator feedback, or send evidence off the machine.
