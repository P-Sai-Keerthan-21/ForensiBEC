# Concept Drift

**Result type: controlled experiment on SYNTHETIC data.** Generation 2 is a
documented, hand-chosen shift of the corpus generator. It does **not**
reproduce real attacker evolution, which is gradual, multi-dimensional and
adversarial.

Reproduce:

```bash
venv\Scripts\python.exe data/build_drift_corpus.py
venv\Scripts\python.exe -m research.drift
```

Output: `output/research/drift.json`.

---

## 1. Questions

1. **Detection:** does the system notice when incoming mail no longer resembles
   the data it was built and trained on?
2. **Impact:** when the attack pattern changes, how much do the rule engine and
   an ML baseline degrade?

## 2. The shift

`data/build_drift_corpus.py` imports the original generator unchanged, so
generation 1 stays byte-identical; this is tested.

| | Generation 1 | Generation 2 |
|---|---|---|
| Attacks from compromised genuine mailboxes | 35% | **80%** |
| Lure | bank change, wire, gift card, credential | **salary-deposit switch; "route settlements to our new institution"**, worded to avoid the engine's lexicons |
| Pressure language on attacks | ~80% | ~25% |
| Dates | Jan–Aug 2026 | Mar–Oct 2027 |
| Benign generator | — | unchanged |
| Size | 900 (3 splits) | 400 (223 benign, 177 malicious) |

The remaining 20% of generation-2 attacks come from the original generator
unchanged.

## 3. Detection method

| Measure | Applied to | Reading |
|---|---|---|
| Population Stability Index | each intrinsic numeric feature | < 0.10 stable, 0.10–0.25 moderate, **> 0.25 significant** |
| Firing-rate change | each intrinsic engine indicator | notable at an absolute change ≥ 0.15 |
| Jensen–Shannon divergence | unigram vocabulary | reported against the control |

The verdict is **"Distribution shift detected"** or **"No significant
distribution shift detected"**. It never says "new attack detected": a shift
means the reference data no longer describes the input, and that is not
evidence of malice. `test_verdicts_never_claim_an_attack` checks this.

### Control, and a correction made because of it

Every run also compares generation-1 train against generation-1 test. They come
from the same generator, so the detector must stay quiet.

**The first run did not.** It alarmed on the control because
`DISPLAY_NAME_CHANGED` fired on 86% of the 539-message train split but only 64%
of the 182-message test split. The cause: that indicator is **corpus-relative**.
It depends on how many other messages from the same sender were analysed
alongside, and a larger set contains more repeat senders. Behavioural-baseline,
stylometric and thread-divergence indicators all share that property, so they
describe the corpus rather than the message.

They were therefore excluded from drift measurement (`CORPUS_RELATIVE_CODES`).
**The exclusion was made after seeing the control fail, and is reported here
for that reason.** The justification is methodological, not tuning: a
distribution comparison needs features that are properties of individual
messages. The control then passes.

## 4. Results

### 4.1 Detection

| Comparison | Verdict | Significant PSI features | Notable indicator shifts | Vocabulary JSD | New vocabulary |
|---|---|---|---|---|---|
| gen-1 train vs gen-1 test (control) | **No significant shift** | 0 | 0 | 0.012 | 0.0% |
| gen-1 train vs gen-2 | **Distribution shift detected** | 1 | 4 | 0.092 | 11.3% |

What moved in generation 2:

| Evidence | Reference | Generation 2 |
|---|---|---|
| `subject_length` | — | PSI 0.66 |
| `SPF_FAIL` firing rate | 0.33 | 0.09 |
| `DMARC_FAIL` firing rate | 0.33 | 0.09 |
| `MONEY_ENTITY_PRESENT` firing rate | 0.51 | 0.30 |
| `AUTHORITY_PRESSURE` firing rate | 0.25 | 0.09 |

Vocabulary divergence is 7.6× the control. These shifts are exactly the
fingerprint of the change: compromised mailboxes authenticate cleanly, and the
new lure uses less pressure and different wording.

### 4.2 Impact

| System | Data | Precision | Recall | F1 | FPR | ROC-AUC | Novel-lure recall |
|---|---|---|---|---|---|---|---|
| Rule engine | gen-1 test | 0.631 | 0.921 | 0.749 | 0.387 | 0.903 | — |
| Rule engine | **gen-2** | 0.309 | **0.237** | 0.268 | 0.421 | **0.459** | **0.069** (10/145) |
| Random Forest trained on gen-1 | gen-1 test | 1.000 | 0.987 | 0.993 | 0.000 | 1.000 | — |
| Random Forest trained on gen-1 | **gen-2** | 1.000 | 0.751 | 0.858 | 0.000 | 0.999 | **0.697** (101/145) |

Confusion matrices on generation 2: rule engine TP 42, FP 94, FN 135, TN 129;
Random Forest TP 133, FP 0, FN 44, TN 223.

## 5. Interpretation

**The rule engine collapses under this shift.** It catches 10 of 145 novel-lure
attacks. Its ROC-AUC of 0.459 means it ranks generation-2 mail *worse than
chance*: novel-lure attacks from genuine mailboxes now score lower than typical
benign finance mail. Both of its main evidence sources are gone. Identity and
authentication are clean because the mailbox is genuine, and the lexicons don't
cover the new wording. This is the known weakness of hand-written rules.

**The learned baseline degrades much less.** Recall falls from 0.987 to 0.751
and ranking stays nearly perfect (ROC-AUC 0.999), so most of its loss comes
from the threshold, not the representation. This cuts against a simple "rules
are better" story, and it is reported as found.

Two cautions before reading much into the Random Forest's advantage:

- The novel lure still carries an account-number or IBAN line, and the model
  learned from generation 1 that such lines accompany fraud. Its resilience
  here may rest heavily on that one generator artifact, which a real attacker
  would not reliably reproduce.
- Its precision of 1.000 holds only because the benign generator is unchanged.
  Real benign mail drifts too.

**What the drift detector is for.** It did its job: it flagged the shift using
evidence an operator can read, before anyone had labels for the new mail. In
practice that is the trigger to re-examine the rules and re-validate any
model — not a verdict on individual messages.

## 6. Limitations

- One hand-chosen shift, not a trajectory. A gradual drift would need
  sequential monitoring (windowed PSI or CUSUM), which is not implemented.
- The detector's thresholds are the conventional PSI bands, not calibrated on
  labelled drift events.
- Excluding corpus-relative indicators also means drift in *behaviour* (for
  example, senders changing domain more often) is not measured. A
  size-normalised behavioural comparison would be needed.
- Everything is synthetic; see the provenance note above.
