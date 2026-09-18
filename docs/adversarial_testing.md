# Adversarial Robustness

**Result type: controlled local experiment on SYNTHETIC data.** These results
describe how this rule engine responds to eleven specific transformations. They
are not a measure of resistance to a real, adaptive adversary.

Reproduce:

```bash
venv\Scripts\python.exe -m research.robustness
```

Output: `output/research/robustness.json` (includes every per-message result).

---

## 1. Question

If an attacker rewords, reformats or re-dresses a BEC message, does the
forensic engine still flag it? And does harmless reformatting of benign mail
cause false alarms?

## 2. Method

| Setting | Value |
|---|---|
| Target | Forensic rule engine (`BECPipeline`), the system's decision path, not the ML baselines |
| Data | Research corpus **test split**: 76 malicious, 106 benign |
| Baseline | Behavioural, thread and stylometric baselines fitted on the *original* messages |
| Threat intelligence | Disabled, so the static local indicator list cannot mask or inflate an effect |
| Correlation | Disabled |
| "Detected" | Scored LIKELY_BEC or CONFIRMED_BEC |
| Seed | 20260918; all transformations deterministic |

Safety: transformations edit the headers and body text of already-synthetic
messages. None adds an attachment, a link or a payload
(`test_transformations_never_add_payloads`). Nothing is fetched or sent.

**The engine was not tuned in response to these results.**

### Two corrections to the experiment itself

The first run produced one artificial evasion, and the cause was the
experiment, not the engine:

- "Punctuation stripped" also removed the dots and colons *inside URLs*, turning
  `http://203.0.113.45/secure/login.php` into a non-link. A broken link isn't an
  attack. Text transformations now edit prose only and leave every URL
  byte-identical.
- The upper-case transformation had the same flaw (URL paths are
  case-sensitive), although it caused no evasion.

## 3. Results

Figures are from the run after correction #2 in
[`evaluation.md`](evaluation.md) (stylometry and threading fixes). The earlier
run is preserved in `output/research/pre_fix_thread_style/robustness.json`.
It also had three evasions (paraphrase, combosquat, combined) rather than
(soften, paraphrase, combined), and its benign false-positive baseline was 65 of 106.

### 3.1 Evasion (malicious messages, n = 76)

| Transformation | Detected before | Detected after | Evaded | Mean Δscore | Worst Δscore |
|---|---|---|---|---|---|
| Body in capitals | 70 | 70 | 0 | +1.8 | −6.7 |
| Lower case | 70 | 70 | 0 | −0.8 | −9.0 |
| Punctuation stripped (URLs kept) | 70 | 70 | 0 | +2.3 | 0.0 |
| Whitespace inflated | 70 | 70 | 0 | −0.6 | −7.5 |
| Benign padding (dilution) | 70 | 70 | 0 | +3.8 | 0.0 |
| Urgency wording softened | 70 | 69 | **1** | −1.9 | −19.0 |
| Financial wording paraphrased | 70 | 69 | **1** | −2.3 | −29.3 |
| Executive title removed | 70 | 70 | 0 | −0.2 | −16.8 |
| Brand domain → Unicode homoglyph | 70 | **75** | 0 | +7.5 | 0.0 |
| Brand domain → combosquat | 70 | 70 | 0 | +2.4 | −12.0 |
| Combined (soften + paraphrase + pad + strip title) | 70 | 69 | **1** | −0.5 | −24.2 |

### 3.2 False-positive induction (benign messages, n = 106)

| Transformation | Flagged before | Flagged after | Newly flagged | Mean Δscore |
|---|---|---|---|---|
| Body in capitals | 41 | 49 | **8** | +4.4 |
| Lower case | 41 | 40 | 0 | −0.7 |
| Punctuation stripped | 41 | 53 | **12** | +5.8 |
| Whitespace inflated | 41 | 32 | 0 | −3.4 |
| Benign padding | 41 | 55 | **14** | +8.5 |

> **Read the "flagged before" column.** Before any transformation the engine
> already flags **41 of 106 benign test messages**. That baseline false-positive
> rate is a separate, more important finding, reported and analysed in
> [`docs/evaluation.md` §8](evaluation.md).

## 4. Interpretation

### What holds up

- **Rewording rarely evades detection.** No single transformation removed
  detection from more than 1 of 70 detected attacks. Softening urgency removed
  the urgency finding from 47 messages and paraphrasing removed the
  banking-change finding from 9, but in almost every case identity and header
  evidence (look-alike domain, Reply-To divergence, failed authentication) kept
  the message above the threshold. This is the practical benefit of fusing
  evidence families: a text-only rewrite leaves the header evidence untouched.
- **Homoglyph domains increase detection**, from 70 to 75. The Unicode
  confusable analysis maps the Cyrillic characters back to the trusted brand,
  and the unfamiliar domain adds behavioural findings.

### What degrades

1. **Every evasion was a compromised-account case.** The three evasions
   (`ceo_fraud_compromised` once, `vendor_invoice_compromised_subtle` twice)
   came from genuine mailboxes with passing authentication and no look-alike.
   With no header evidence to fall back on, the verdict rests on content and
   style, and these messages sat just above the threshold (53.1 and 54.7).
   Paraphrasing `"banking details have changed"` removed
   `BANKING_CHANGE_REQUEST` and the score fell from 54.7 to 33.3; softening one
   urgency phrase took the other from 53.1 to 39.0.
2. **Combosquatting is not detected as a look-alike.**
   `northwind-logistics-payments.com` contains the brand but its skeleton is 8
   edits from the trusted domain, beyond the threshold of 2. The
   `LOOKALIKE_DOMAIN` finding was lost from 26 messages. None evaded in this
   run, because other evidence carried them, but the finding silently
   disappears. (In the earlier run one combosquat message did evade.)
3. **Stylometry reacts to cosmetic formatting.** Capitals, stripped punctuation
   and padding add `STYLE_DEVIATION` to benign messages; padding also trips
   `STATISTICAL_OUTLIER`. Messages already sitting just under the threshold
   are pushed over it, which accounts for 8 to 14 newly flagged benign
   messages. The feature meant to catch account takeover can't tell a
   different author from a different format.
4. **The currency pattern breaks on doubled spaces.** `GBP 12,345` matches but
   `GBP  12,345` does not, so `MONEY_ENTITY_PRESENT` was lost from 37
   messages. Detection was unaffected because other evidence carried those
   messages, but the finding silently disappears. (It is also why whitespace
   inflation *lowers* benign false positives, 41 → 32.)

## 5. Limitations

- Transformations are fixed tables, not an adaptive attacker who observes the
  engine's output and iterates.
- The synthetic corpus draws from fixed sentence pools, so a paraphrase table
  can cover its vocabulary far more completely than it could real prose.
- Seventy-six malicious messages: an evasion rate of 1/70 has wide
  uncertainty. With 0–1 events, the experiment can only show that evasion is
  *uncommon* under these transformations, not estimate its rate.
- Only the rule engine was tested, not the ML baselines.

## 6. What would address the degradations (not implemented)

Recorded as future work. None of these was applied, because tuning the engine
against its own test set would invalidate the experiment:

- Whitespace-normalise text before matching currency and phrase patterns.
- Treat brand-substring domains (combosquats) as a separate, lower-confidence
  look-alike class.
- Normalise case and punctuation before computing stylometric features, and
  require deviation on more than one independent feature.
- For compromised-account detection, weight behavioural signals (new recipient
  set, unusual timing, first request of its kind) more heavily than wording.
