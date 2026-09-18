# Research Evaluation and Ablation

**Result type: RESEARCH RESULTS on a SYNTHETIC corpus.**
These are not, and must not be reported as, real-world accuracy.

Reproduce with:

```bash
venv\Scripts\python.exe data/build_research_corpus.py
venv\Scripts\python.exe -m research.evaluate
venv\Scripts\python.exe -m research.ablation            # unbalanced baseline
venv\Scripts\python.exe -m research.balanced_ablation   # feature-balanced
venv\Scripts\python.exe -m research.engine_eval         # the rule engine itself (§8)
```

Machine-readable output: `output/research/evaluation.json`, `output/research/ablation.json`, `output/research/balanced_ablation.json`, `output/research/engine_evaluation.json`.
Every file carries `"not_real_world_accuracy": true` in its own payload, so a
number cannot be separated from its caveat by being copied out of context.

> ### Correction notice — results regenerated after an implementation bug
>
> The figures in this document were **regenerated** after two bugs in URL
> analysis (`bec_detector/analysis/urls.py`) were found during the Unicode
> confusables work. Both affected the `artifact` feature group.
>
> 1. **Non-determinism.** With two trusted domains configured, the URL
>    look-alike check broke on whichever came first in `set` iteration order,
>    which varies with Python's per-process hash seed. A legitimate
>    `intranet.northwind-logistics.com` link was flagged as a look-alike in
>    roughly half of all process runs (verified: hash seeds 3 and 5 flagged it,
>    0/1/2/4 did not). This is why configuration B moved from 0.9824 to 0.9828
>    between two runs of the balanced ablation — a discrepancy that was not
>    investigated at the time.
> 2. **Own-estate false positive.** `URL_SUSPICIOUS_PATH` compared hosts by
>    exact membership, so the organisation's own
>    `portal.northwind-logistics.com/invoices/view` was scored as a credential
>    page.
>
> 114 benign research messages carry own-estate links and were exposed to one
> or both bugs. After the fix, the balanced ablation was re-run under hash
> seeds 0 **and** 3 and produced **identical** results, so the reported figures
> are now reproducible across processes. `test_url_lookalike_is_independent_of_hash_seed`
> guards this.
>
> The pre-fix outputs are preserved in `output/research/pre_fix_68b0e0a/`.
> **No conclusion changed.** Every comparison that was significant remains
> significant, in the same direction.
>
> | Figure | Pre-fix (`68b0e0a`) | Post-fix |
> |---|---|---|
> | Linear SVM held-out test F1 | 0.993 | 1.000 |
> | Random Forest held-out ROC-AUC | 0.999 | 1.000 |
> | Ablation 1, structured-only test F1 | 0.960 | 0.953 |
> | Ablation 1, structured-only CV-F1 | 0.9732 ± 0.0109 | 0.9745 ± 0.0076 |
> | Ablation 1, configurations A–I | — | unchanged |
> | Ablation 2, B − A (primary) | +0.02339 | **+0.02254** |
> | Ablation 2, D − A | +0.01365 (p=0.0022) | **+0.01132** (p=0.0042) |
> | Ablation 2, B F1 | 0.9828 | 0.9820 |
> | Ablation 2, D F1 | 0.9731 | 0.9708 |
>
> The "post-fix" column is the state after this first correction. Correction #2
> (below) changed several figures again.

> ### Correction notice #2 — stylometry and threading bugs
>
> While examining the rule engine's false positives on the research corpus
> (§8), two further implementation bugs were found. Both are in analysers that
> feed the `thread` and `stylometry` feature groups, so the research outputs
> were regenerated again.
>
> 1. **Stylometry tautology** (`analysis/stylometry.py`). The "has this sender
>    used this greeting / signature before?" check built its comparison set by
>    removing *every* occurrence of the current greeting, then asked whether
>    the current greeting was absent from that set - which is always true. Any
>    sender who had ever varied their greeting or sign-off therefore received
>    `STYLE_GREETING_CHANGE` / `STYLE_SIGNATURE_CHANGE` on every message. Now
>    only the current message's own entry is removed before the check.
> 2. **Subject-based thread grouping** (`analysis/thread.py`). Threads were
>    grouped partly by normalised subject line. That contradicts the
>    documented design (threads from `References` / `In-Reply-To` /
>    `Message-ID` only): two unrelated "Invoice" emails were treated as one
>    conversation, and thread-hijack findings fired across them. Threads are
>    now rooted by headers only, with a cycle guard.
>
> Regression tests for both are in `tests/test_forensics.py`. The outputs from
> before this fix are preserved in `output/research/pre_fix_thread_style/`.
> **No ML conclusion changed.** Every comparison keeps its direction and its
> significance. The rule engine's false-positive rate on the research corpus
> fell substantially (§8).
>
> | Figure | Before (#1 state) | After |
> |---|---|---|
> | Logistic Regression test F1 | 0.980 | 0.987 |
> | Ablation 1, H (+ Stylometry) CV-F1 | 0.9905 | 0.9919 |
> | Ablation 1, I (full fusion) CV-F1 | 0.9877 | 0.9891 |
> | Ablation 1, structured-only test F1 | 0.953 | 0.960 |
> | Ablation 2, B − A (primary) | +0.02254 | **+0.02565** |
> | Ablation 2, D − A | +0.01132 (p=0.0042) | +0.01209 (p=0.0058) |
> | Ablation 2, B − C | −0.00941 (p=0.0008) | −0.00723 (p=0.0067) |
> | Ablation 2, B F1 / false positives | 0.9820 / 9 | 0.9851 / 3 |
> | Rule engine, test precision / recall / FPR | 0.525 / 0.947 / 0.613 | 0.631 / 0.921 / 0.387 |
> | Rule engine, test ROC-AUC | 0.869 | 0.903 |

---

## 1. Two result families — never merge them

| | Development results | Research results |
|---|---|---|
| **What** | The forensic rule engine | ML baselines |
| **Data** | `data/samples` — 26 hand-written messages | `data/research` — 900 generated messages |
| **Reported by** | `tests/test_validation.py` | `research/evaluate.py` |
| **Current** | TP=10 FP=0 TN=14 FN=0 | see §4 |

Both are synthetic. Neither estimates real-world performance.

---

## 2. Corpus

Generated by `data/build_research_corpus.py`, seed `20260918`, byte-reproducible.

| Split | Messages | Benign | Malicious |
|---|---|---|---|
| train | 539 | 315 | 224 |
| validation | 179 | 105 | 74 |
| test | 182 | 106 | 76 |

> Corrected: an earlier version of this table showed 307/232, 102/77 and
> 103/79 - counts printed by a previous corpus generation that was later
> discarded. Every reported metric was computed from the actual split files,
> so no figure was affected; only this table was stale.

Stratified 60/20/20. Splits verified disjoint and balance-matched by
`tests/test_research.py`.

### Difficulty controls, and why they exist

The first three generations of this corpus were **discarded** because every
model and every ablation configuration scored 1.000, making the experiment
incapable of answering its own question. Each discard identified a specific
artifact:

| Generation | Failure | Cause | Fix |
|---|---|---|---|
| 1 | All models 1.000 | Malicious always failed SPF/DKIM/DMARC; benign always passed | Added compromised-account BEC (passing auth) and relayed benign mail (softfail) |
| 2 | Still ~1.000 | Classes drew from **disjoint sentence pools**; TF-IDF learned which pool | Shared the urgency/payment/secrecy/authority pools between classes |
| 3 | Still ~0.99 | 21 structured features fired on **one class only** — benign mail never carried an IBAN, a URL, a Return-Path, or an executive title | Gave benign mail the legitimate form of each property |

Feature-importance diagnosis after generation 3 left 11 single-class features.
Those were retained deliberately, because they are genuinely discriminative in
the real phenomenon rather than artifacts of the generator:

`BANKING_CHANGE_REQUEST`, `GIFT_CARD_REQUEST`, `CREDENTIAL_SOLICITATION`,
`LOOKALIKE_DOMAIN`, `DISPLAY_NAME_IMPERSONATION`, `FREEMAIL_EXEC_CLAIM`,
`REPLY_TO_FREEMAIL`, `RETURN_PATH_MISMATCH`, `URL_IP_LITERAL`, `URL_NO_TLS`.

---

## 3. Models

Three classical, interpretable baselines. Each declares a rationale in
`research/baselines.py`; `tests/test_research.py` asserts none is undocumented.

| Model | Why it is here |
|---|---|
| Logistic Regression | Linear and decomposable, like the rule engine's score |
| Random Forest | Represents the conjunctive BEC pattern (identity **and** financial **and** pressure) |
| Linear SVM | Strong sparse-text baseline; checks the TF-IDF arm is not under-served |

Seed `20260918` throughout. Vectorisers are fitted on training folds only —
`test_vectoriser_is_not_fitted_on_test_data` enforces this.

---

## 4. Model comparison — held-out test split

| Model | Precision | Recall | F1 | Accuracy | ROC-AUC | PR-AUC | FPR | FNR |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.987 | 0.987 | 0.987 | 0.989 | 0.9995 | 0.9993 | 0.009 | 0.013 |
| Random Forest | 1.000 | 0.987 | 0.993 | 0.995 | 1.000 | 1.000 | 0.000 | 0.013 |
| Linear SVM | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

---

## 5. Ablation study 1 - unbalanced (baseline)

Cumulative feature groups, Random Forest, 5-fold stratified CV over the pooled
corpus alongside the held-out test split.

| Cfg | Configuration | Features | Test F1 | CV F1 | ±sd | Δ vs previous |
|---|---|---|---|---|---|---|
| A | Text only | 6485 | 0.993 | 0.9850 | 0.0111 | — |
| B | + Header | 6499 | 0.993 | 0.9877 | 0.0119 | +0.0027 |
| C | + Identity | 6510 | 0.993 | 0.9905 | 0.0070 | +0.0028 |
| D | + Behaviour | 6519 | 0.993 | 0.9891 | 0.0069 | −0.0014 |
| E | + NLP | 6527 | 0.993 | 0.9932 | 0.0043 | +0.0041 |
| F | + Financial | 6533 | 0.993 | 0.9878 | 0.0081 | −0.0054 |
| G | + Thread | 6542 | 0.993 | 0.9905 | 0.0070 | +0.0027 |
| H | + Stylometry | 6549 | 0.993 | 0.9919 | 0.0051 | +0.0014 |
| I | **Full fusion** | 6567 | 0.993 | 0.9891 | 0.0093 | −0.0028 |
| S | Structured only (no text) | 82 | 0.960 | 0.9745 | 0.0095 | — |

### 5.1 The result is negative *in this configuration*

> **Superseded in part by §6.** This experiment is preserved unchanged as the
> unbalanced baseline. Its conclusion was revisited after the confound
> identified in §5.2 item 2 was controlled for; see §6.4 for what changed.


**On this corpus, adding forensic evidence families to a text-only classifier
does not measurably improve classification accuracy.**

Every marginal change (largest: +0.0041) is smaller than the cross-validation
standard deviation of the configuration that produced it (0.0043–0.0119). The
deltas are within noise. They are also non-monotonic — configurations F and I
score *lower* than their predecessors — which is the signature of random
fluctuation rather than signal.

The per-family breakdown gives the same answer: recall on the hard
compromised-account subset is 1.000 for text-only and 0.981 for every fused
configuration. Fusion did not rescue the hard cases here.

**No claim that "evidence fusion beats text-only classification" is supported
by this experiment as configured.** The hypothesis was tested and not confirmed
under a 79:1 feature imbalance. §6 tests it again with that imbalance removed.

### 5.2 Why — and what it does and does not imply

The honest diagnosis is a ceiling effect plus a feature-count imbalance:

1. **Text-only already scores 0.985.** There is 1.5 points of headroom. No
   feature family can demonstrate value inside that margin.
2. **6485 TF-IDF features versus 82 structured features.** Even where the
   structured evidence is decisive for an individual message, it is
   numerically swamped in the design matrix.
3. **Synthetic text is more separable than real BEC text.** Real fraudulent
   mail is written by humans imitating genuine correspondence. A template
   generator cannot reproduce that difficulty, however much the pools overlap.

What this does **not** imply:

- It does not show that forensic evidence is useless. It shows that on
  *this synthetic corpus*, under *this metric*, it does not move accuracy.
- It does not validate text-only classification for deployment. A TF-IDF model
  scoring 0.985 here would be far weaker on real mail, and — critically —
  cannot explain a single one of its decisions.

### 5.3 What the project's contribution actually rests on

This negative result sharpens rather than undermines the research position.
ForensiBEC's claim is **not** that fusion classifies more accurately. It is
that fusion produces an *investigable* result:

| | Text-only classifier | Forensic evidence fusion |
|---|---|---|
| Output | A probability | Named findings, each quoting the header or sentence that triggered it |
| Defensible in a report | No | Yes |
| Traceable to evidence | No | Yes, with SHA-256 custody |
| Says what to do next | No | Yes, per finding |
| Catches account takeover | Only if wording differs | Yes, via stylometry against the sender's own baseline |

Accuracy is the wrong yardstick for that claim, and the ablation is the
evidence that accuracy alone cannot separate the two approaches. The
distinguishing property is explainability, which `tests/test_forensics.py`
verifies structurally (every indicator carries observed evidence, inference,
basis and recommendation) rather than statistically.

### 5.4 What would make the ablation conclusive

Required before any fusion-improves-detection claim:

1. An independent corpus not generated by this project — public phishing sets
   plus a benign corpus such as Enron.
2. Feature-count balancing (dimensionality reduction on the text channel) so
   82 structured features are not competing against 6485 lexical ones.
3. Evaluation restricted to the hard subset, with enough compromised-account
   cases for the per-family recall to have usable statistical support.

Item 2 was carried out in §6. Items 1 and 3 have **not** been done.

---

---

## 6. Ablation study 2 — feature-balanced

`research/balanced_ablation.py` · `output/research/balanced_ablation.json`

The baseline experiment (§5) compared ~6485 text features against 82 structured
ones. A channel outnumbered 79:1 can be decisive for individual messages and
still fail to move an aggregate metric, because the learner's capacity is
dominated by the larger block. §5.2 named this as a confound; this section
removes it and re-tests the hypothesis.

### 6.1 Method

**Reduction.** Truncated SVD (latent semantic analysis) on the combined
word + character TF-IDF matrix. SVD was chosen over supervised feature
selection specifically because selection ranks features by their association
with the label, which would leak target information into the representation.
SVD is unsupervised and never sees a label — `test_reduction_is_unsupervised`
enforces this.

**Pre-registered parameter.** The component count is fixed at **82**, the
number of structured features, by a matching rule stated before any result was
observed. It was not searched for, and no configuration was selected because
it favoured fusion. `test_matching_rule_still_holds` fails if the structured
feature count ever drifts away from 82, so the balance cannot silently break.

**Cross-validation.** `RepeatedStratifiedKFold`, 5 splits × 3 repeats = 15
folds, seed `20260918`. Every configuration is evaluated on **identical folds**,
so per-fold scores are paired.

**Significance.** Paired t-test on per-fold F1 differences. A difference is
called significant only when `p < 0.05` **and** the 95% confidence interval
excludes zero — `test_significance_requires_both_p_and_ci` asserts both
conditions are enforced in code.

**Leakage control.** Vectoriser, SVD and scaler are all fitted inside each fold
on training data only.

### 6.2 Configurations and results

| Cfg | Configuration | Text | Struct | Precision | Recall | F1 | ±sd | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|
| A | Balanced text only | 82 | 0 | 0.9684 | 0.9509 | **0.9594** | 0.0161 | 0.9957 | 0.9942 |
| B | Balanced text + structured | 82 | 82 | 0.9973 | 0.9733 | **0.9851** | 0.0069 | 0.9993 | 0.9992 |
| C | Full fusion (unbalanced text) | 6825 | 82 | 1.0000 | 0.9848 | **0.9923** | 0.0073 | 0.9999 | 0.9999 |
| D | Structured only | 0 | 82 | 0.9838 | 0.9599 | **0.9715** | 0.0156 | 0.9976 | 0.9971 |

Means over 15 folds; ±sd is the sample standard deviation of per-fold F1.

**Pooled confusion matrices** (summed across all 15 folds):

| Cfg | Configuration | TN | FP | FN | TP |
|---|---|---|---|---|---|
| A | Balanced text only | 1543 | 35 | 55 | 1067 |
| B | Balanced text + structured | 1575 | 3 | 30 | 1092 |
| C | Full fusion (unbalanced text) | 1578 | 0 | 17 | 1105 |
| D | Structured only | 1560 | 18 | 45 | 1077 |

### 6.3 Statistical comparisons

**Primary — the experiment:**

| Comparison | Mean ΔF1 | 95% CI | p | Verdict |
|---|---|---|---|---|
| **B − A** (structured added at equal text capacity) | **+0.02565** | [+0.01813, +0.03317] | <0.0001 | **Significant improvement** |

**Secondary:**

| Comparison | Mean ΔF1 | p | Verdict |
|---|---|---|---|
| D − A (82 forensic vs 82 text features) | +0.01209 | 0.0058 | Significant improvement |
| C − A (unbalanced fusion vs balanced text) | +0.03287 | <0.0001 | Significant improvement |
| B − C (balanced fusion vs unbalanced fusion) | −0.00723 | 0.0067 | Significant degradation |
| B − D (fusion vs structured alone) | +0.01355 | 0.0014 | Significant improvement |

**Sensitivity (robustness only — did not select the primary parameter):**

| SVD components | Text-only F1 | Fusion F1 | ΔF1 | p | Significant |
|---|---|---|---|---|---|
| 25 | 0.9520 | 0.9828 | +0.03077 | <0.0001 | yes |
| 50 | 0.9520 | 0.9828 | +0.03081 | <0.0001 | yes |
| **82** (pre-registered) | 0.9594 | 0.9851 | +0.02565 | <0.0001 | yes |
| 150 | 0.9667 | 0.9828 | +0.01612 | 0.0008 | yes |
| 300 | 0.9584 | 0.9787 | +0.02022 | 0.0005 | yes |

The direction and significance hold at every component count tested, so the
finding is not an artifact of the pre-registered choice.

### 6.4 What changed, and what did not

**The conclusion of §5.1 does not survive contact with a fair comparison.**

Adding structured forensic evidence to a text channel of equal capacity
improves F1 by **+0.0257** (95% CI [+0.0181, +0.0332], p < 0.0001). That is
more than **three times the CV standard deviation**, where the unbalanced
experiment's largest delta (+0.0041) sat *inside* it. The earlier negative
result was substantially an artifact of the 79:1 feature imbalance, not
evidence that forensic features lack signal.

The error mechanism is visible in the confusion matrices. Against balanced
text alone, adding structured evidence cuts **false positives from 35 to 3**
(−91%) and **false negatives from 55 to 30** (−45%). For an investigator those
are the two numbers that matter: fewer benign messages dragged into review, and
fewer attacks missed.

Two further findings are worth stating plainly because neither was predicted:

1. **At equal capacity, forensic evidence outperforms text.** Configuration D
   (82 structured features, no text at all) beats configuration A (82 text
   components) by +0.0121 (p = 0.0058). Eighty-two engineered forensic
   features carry more separable signal than eighty-two dimensions of latent
   semantic structure.

2. **The unbalanced full-fusion arm is still the strongest overall.**
   Configuration C reaches 0.9923 and significantly beats balanced fusion
   (p = 0.0067). Reducing the text channel *does* discard useful information.
   The balancing is a diagnostic instrument for attributing credit between
   channels — it is not a recommendation to deploy a reduced text channel.

**What has not changed.** Everything in §5.3 still stands. This experiment
shows that forensic features contribute measurable classification signal; it
does not show that classification accuracy is the right way to judge the
system. The project's contribution remains investigability — named findings
quoting their own evidence, chain of custody, and per-finding recommendations —
none of which any F1 score measures.

### 6.5 Limitations specific to this experiment

- Everything remains synthetic. Absolute values are an optimistic upper bound;
  only the **relative** comparison between configurations is meaningful.
- SVD is a linear reduction. A non-linear text encoder might preserve more of
  the discarded signal, which would narrow the A-versus-B gap. This has not
  been tested.
- Results are for Random Forest. The direction was not re-verified across all
  three baseline models.
- Fifteen paired folds drawn from one 900-message corpus. The confidence
  intervals describe variation across folds of *this* corpus, not variation
  across corpora.
- The improvement is measured against a *reduced* text baseline. Against the
  full text channel (§5) the marginal gain remains small, because text-only
  already saturates at 0.985 on synthetic data.

---

## 7. Limitations

- Everything here is synthetic; no real mailbox contributed.
- Absolute scores are an optimistic upper bound.
- The unbalanced ablation's aggregate result is inconclusive (§5.1); the
  feature-balanced re-test (§6) finds a significant fusion benefit once the
  79:1 channel imbalance is removed.
- Per-family recall rests on ~50 compromised-account messages across
  validation and test — enough to notice a large effect, not a small one.
- No calibration analysis yet: the risk score and statistical confidence are
  still the same number, which §5.3 argues they should not be.
- The balanced experiment covers one model (Random Forest) and one linear
  reduction (SVD); see §6.5.
- The rule engine investigators actually use performs far worse on this corpus
  than the ML baselines (§8). The ML figures describe what the *features* can
  support, not what the deployed engine achieves.

Related experiments, reported separately:

| Experiment | Document |
|---|---|
| Adversarial robustness (fixed transformations) | [`adversarial_testing.md`](adversarial_testing.md) |
| Concept drift (generation-2 corpus) | [`concept_drift.md`](concept_drift.md) |
| Local performance | [`performance.md`](performance.md) |

---

## 8. The rule engine on the research corpus

`research/engine_eval.py` · `output/research/engine_evaluation.json`

§4–§6 evaluate ML models built from the engine's features. This section
evaluates the **engine itself** — the fusion score and band investigators see —
on the same splits. The engine was **not tuned on this corpus**: its weights
and thresholds were set on the development samples before the corpus existed,
and nothing below was used to change them. Intelligence and cross-case
correlation are disabled; each split is analysed as one evidence set (two-pass).

A message counts as flagged when its score reaches the `LIKELY_BEC` band (50).

### 8.1 Results at the configured threshold

| Split | n | TP | FP | FN | TN | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|---|
| train | 539 | 213 | 135 | 11 | 180 | 0.612 | 0.951 | 0.745 | 0.429 | 0.936 | 0.933 |
| validation | 179 | 71 | 48 | 3 | 57 | 0.597 | 0.959 | 0.736 | 0.457 | 0.952 | 0.946 |
| **test** | 182 | 70 | 41 | 6 | 65 | **0.631** | **0.921** | **0.749** | **0.387** | 0.903 | 0.896 |

Before correction #2 the test split read precision 0.525, recall 0.947,
FPR 0.613, ROC-AUC 0.869 (`output/research/pre_fix_thread_style/`). Recall
fell slightly because the stylometry bug had also, by accident, been adding
findings to some compromised-account messages; that recall was not earned.

**The engine flags about 39% of benign test mail.** That is the honest
headline, and it is far worse than the ML baselines (FPR ≤ 0.009) on the same
data. The development corpus result (FP = 0 of 14) did not predict it.

### 8.2 Where the false positives come from (test split)

| Benign group | Flagged |
|---|---|
| Internal, finance/urgency wording | 28 / 31 |
| External, relayed (SPF softfail) | 7 / 11 |
| External, finance/urgency wording | 6 / 15 |
| External, routine | 0 / 10 |
| Internal, routine | 0 / 39 |

Routine mail is never flagged. The corpus deliberately gives benign mail the
same payment, urgency and secrecy wording as attacks, and the engine scores
that wording heavily when it cannot verify the sender's identity.

Indicators present on the 41 false positives: `PAYMENT_REQUEST` 41,
`MONEY_ENTITY_PRESENT` 41, `STYLE_SIGNATURE_CHANGE` 39, `URGENCY_LANGUAGE` 33,
`DISPLAY_NAME_CHANGED` 32.

Two are engine weaknesses, not corpus design:

- **`STYLE_SIGNATURE_CHANGE`** takes the last three non-empty lines as the
  signature block. When a message has no sign-off those lines are body text,
  so a "new signature" is reported. The generator varies closing lines, which
  exposes this.
- **`DISPLAY_NAME_CHANGED`** fires on every message from an address that has
  used more than one display name in the evidence set, not only on the
  message where the name changed.

Neither was changed. Fixing them on the basis of this corpus would be tuning
to the test data; both are recorded in [`limitations.md`](limitations.md).

### 8.3 Missed attacks (test split)

| Attack group | Missed |
|---|---|
| Compromised account (genuine mailbox, passing authentication) | 6 / 33 |
| Spoofed identity (look-alike, freemail, auth failure) | 0 / 43 |

Every miss is a compromised-account message, where the only evidence is
wording and style.

### 8.4 Threshold table (analysis only — not used to select anything)

| Threshold | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| 25 | 0.466 | 0.987 | 0.633 | 0.811 |
| 40 | 0.543 | 0.921 | 0.683 | 0.557 |
| **50 (configured)** | 0.631 | 0.921 | 0.749 | 0.387 |
| 60 | 0.698 | 0.882 | 0.779 | 0.274 |
| 75 | 0.857 | 0.789 | 0.822 | 0.094 |
| 90 | 0.920 | 0.605 | 0.730 | 0.038 |

A higher threshold would trade recall for precision. The configured threshold
was not moved: choosing it from the test split would make the figures above
optimistic, and the engine is designed to over-refer to a human rather than
under-refer.
