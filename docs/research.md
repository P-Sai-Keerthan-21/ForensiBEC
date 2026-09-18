# Research Package

This is the index for every experiment in the project: what data each one
used, how to reproduce it, what it found, and how far that finding reaches.
The detail lives in the linked documents. This page keeps the data sources
apart.

> **No real-world data has been used anywhere in this project.** Every figure
> below describes synthetic data. None of them is a real-world accuracy,
> detection rate or false-positive rate.

---

## 1. Data: three sources, never merged

| | Development samples | Synthetic research corpus | Synthetic drift corpus |
|---|---|---|---|
| Location | `data/samples/` | `data/research/{train,validation,test}/` | `data/research_drift/gen2/` |
| Size | 26 messages + `labels.json` | 900 messages (539 / 179 / 182) | 400 messages |
| Produced by | `data/build_corpus.py` (hand-written messages) | `data/build_research_corpus.py`, seed `20260918` | `data/build_drift_corpus.py`, seed `20270301` |
| Purpose | Unit/integration tests, demo, rule development | ML baselines, ablations, rule-engine evaluation, robustness | Distribution-shift experiment only |
| Used to set engine weights? | **Yes** (so results on it are optimistic by construction) | **No**; the engine was never tuned on it | **No** |
| Result family | "Development results" | "Research results" | "Drift results" |
| **Real data** | — | — | — |

The organisation (`northwind-logistics.com`), its staff, vendors and attacker
infrastructure are invented. IP addresses are from documentation ranges
(TEST-NET). `data/local_intel.json` lists only fictional indicators and says so
in its own header.

Every research output file carries `"not_real_world_accuracy": true` and a
`provenance` statement in its own JSON payload, so a number copied out of
context still carries its caveat.

---

## 2. Experiments

Run from the project root, in this order. The corpus builders are
byte-reproducible; everything downstream is seeded.

```bash
venv\Scripts\python.exe data/build_research_corpus.py
venv\Scripts\python.exe data/build_drift_corpus.py
venv\Scripts\python.exe -m research.evaluate
venv\Scripts\python.exe -m research.ablation
venv\Scripts\python.exe -m research.balanced_ablation
venv\Scripts\python.exe -m research.engine_eval
venv\Scripts\python.exe -m research.robustness
venv\Scripts\python.exe -m research.drift
venv\Scripts\python.exe -m research.performance
```

Outputs go to `output/research/*.json`.

| # | Experiment | Question | Headline (synthetic) | Document |
|---|---|---|---|---|
| 1 | ML baselines | Can classical models separate the classes using the engine's features plus text? | Held-out test F1: LR 0.987, RF 0.993, Linear SVM 1.000 | [`evaluation.md` §4](evaluation.md) |
| 2 | Original ablation (unbalanced) | Does adding each forensic evidence family to text improve F1? | **Inconclusive.** Every delta within CV noise; text alone already 0.985 with 6485 vs 82 features | [`evaluation.md` §5](evaluation.md) |
| 3 | Feature-balanced ablation | Same question with text reduced to 82 SVD components | **Structured evidence helps.** B − A = +0.0257, 95% CI [+0.0181, +0.0332], p < 0.0001; significant at every component count tested | [`evaluation.md` §6](evaluation.md) |
| 4 | Rule engine on the research corpus | How does the system investigators use perform? | Test: precision 0.631, recall 0.921, **FPR 0.387**, ROC-AUC 0.903 | [`evaluation.md` §8](evaluation.md) |
| 5 | Adversarial robustness | Do rewording and re-dressing evade the engine or cause false alarms? | 1 evasion in 70 for 3 of 11 transformations, all compromised-account messages; cosmetic reformatting newly flags 8–14 of 106 benign messages | [`adversarial_testing.md`](adversarial_testing.md) |
| 6 | Concept drift | Does the system notice, and survive, a documented shift? | Shift detected (control clean). Rule engine novel-lure recall 0.069, ROC-AUC 0.459; RF recall 0.751 | [`concept_drift.md`](concept_drift.md) |
| 7 | Performance | How long does analysis take here? | 42–54 ms per message end-to-end for 1–100 messages, one machine | [`performance.md`](performance.md) |

The development-sample result (TP 10, FP 0, TN 14, FN 0, from
`tests/test_validation.py`) is a regression check, not an experiment. The
engine was developed against those messages.

---

## 3. Statistical methodology

### 3.1 Splits and leakage control

- Stratified 60/20/20 train / validation / test. Disjointness and class
  balance are asserted by `tests/test_research.py`.
- TF-IDF vectorisers, SVD and scalers are fitted **inside each fold, on
  training data only** (`test_vectoriser_is_not_fitted_on_test_data`,
  `test_reduction_is_unsupervised`).
- ML features are computed by the engine's own analysers from message
  content and headers; the label is never an input.
- The rule engine was not tuned on the research corpus. No weight or
  threshold was changed in response to a research result; bug fixes changed
  engine behaviour and are disclosed in §4.

### 3.2 Cross-validation

| Experiment | Scheme | Folds |
|---|---|---|
| Original ablation | `StratifiedKFold`, 5 splits, over the pooled corpus, plus the held-out test split | 5 |
| Balanced ablation | `RepeatedStratifiedKFold`, 5 splits × 3 repeats | 15 |

All configurations in one experiment use **identical folds**, so per-fold
scores are paired.

### 3.3 Significance

- **Test:** paired t-test on per-fold F1 differences (`scipy.stats.ttest_rel`).
- **Interval:** 95% CI of the mean difference, `mean ± t(0.975, n−1) × sd / √n`.
- **Decision rule:** "significant" requires **both** p < 0.05 **and** a CI
  that excludes zero (`test_significance_requires_both_p_and_ci`).
- **Pre-registration:** the balanced ablation's one free parameter (82 SVD
  components, the number of structured features) was fixed by a matching rule
  before any result was seen. Other component counts (25, 50, 150, 300) are
  reported as a sensitivity check and did not select the primary result.
- **Scope of the intervals:** they describe variation across folds of **one**
  synthetic corpus. They say nothing about variation across corpora or
  populations. Repeated CV folds overlap, so the paired t-test is somewhat
  optimistic; the sensitivity check is a partial safeguard.
- **One primary comparison** (B − A). Four secondary comparisons are reported
  without multiple-comparison correction and should be read as descriptive.

### 3.4 Other measures

| Measure | Where | Definition |
|---|---|---|
| ROC-AUC, PR-AUC | All classifiers; rule engine using its 0–100 score | scikit-learn `roc_auc_score`, `average_precision_score` |
| FPR / FNR | All | From the confusion matrix at the configured threshold |
| Population Stability Index | Drift | 10 quantile bins from the reference; < 0.10 stable, 0.10–0.25 moderate, > 0.25 significant |
| Jensen-Shannon divergence | Drift | Between word-frequency distributions (lower-case tokens of three or more letters) |
| Evasion / induced false positive | Robustness | A detected message dropping below LIKELY_BEC / a benign message rising to it |

### 3.5 Determinism

Seeds are fixed throughout (`20260918` for the research corpus and models,
`20270301` for generation 2). A hash-seed dependency in URL analysis once made
results vary between processes. It was fixed, and the balanced ablation was
re-run under two different `PYTHONHASHSEED` values with identical output
(`test_url_lookalike_is_independent_of_hash_seed`).

---

## 4. Result integrity

Two rounds of results were **regenerated** after genuine implementation bugs
were found. Both are disclosed in `evaluation.md`, with before/after tables,
and the pre-fix outputs are committed:

| Correction | Bugs | Snapshot |
|---|---|---|
| #1 | Hash-seed-dependent URL look-alike check; own-estate URL flagged as a credential page | `output/research/pre_fix_68b0e0a/` |
| #2 | Stylometry greeting/signature tautology; subject-based thread grouping | `output/research/pre_fix_thread_style/` |

Neither correction changed an ML conclusion. Correction #2 materially improved
the rule engine's false-positive rate (0.613 → 0.387 on test) because the bugs
had been adding findings to benign mail.

Two methodological changes were made **after** seeing results, and are labelled
as such where they appear:

- **Robustness:** text transformations were changed to leave URLs
  byte-identical, because stripping punctuation from a URL destroys the link
  rather than disguising it.
- **Drift:** corpus-relative indicators (first-time sender, style change,
  thread findings and similar) are excluded from drift measurement, because
  they describe position within an evidence set rather than the input
  distribution, and they false-alarmed on the gen-1 control.

Neither change was made to improve the engine's own scores, and the engine was
not tuned in response to either experiment.

---

## 5. What the research does and does not support

**Supported, on synthetic data:**

- Structured forensic evidence carries classification signal beyond text at
  equal capacity (balanced ablation).
- Identity and header evidence makes the engine resistant to text-only
  rewording; compromised-account messages are its weak point.
- The drift detector distinguishes a documented shift from a same-distribution
  control.

**Not supported:**

- Any real-world accuracy or false-positive rate.
- That fusion beats the full-capacity text model (the unbalanced ablation was
  inconclusive, and the unbalanced full-fusion model C significantly beats the
  balanced one).
- That generation 2 resembles how real attackers change.
- Performance beyond 100 messages or on other hardware.

The consolidated list of limitations is in [`limitations.md`](limitations.md).
