# Evaluator Demonstration

A 15-minute walkthrough of the working system. Every command below was run
against this repository. Commands are for Windows (PowerShell or `cmd`) from
the project root; on Linux/macOS use `venv/bin/python`.

All data is synthetic. Evidence IDs (`EV-…`) are derived from each file's
SHA-256, so they are the same on every machine that has a byte-exact checkout
(`.gitattributes` stops Git from converting `.eml` line endings).

---

## 0. Setup (once)

```bash
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m spacy download en_core_web_sm
venv\Scripts\python.exe -c "import nltk; nltk.download('wordnet')"
venv\Scripts\python.exe -m bec_detector status
```

`status` reports which NLP back-ends loaded. If one is missing, analysis still
runs on regex matching and the report says so.

## 1. Test suite

```bash
venv\Scripts\python.exe -m pytest -q
```

Expected: all tests pass, none skipped (about 2–3 minutes).

## 2. One-shot scan of the development samples

```bash
venv\Scripts\python.exe -m bec_detector scan data/samples --case "Demo" --case-id CASE-SCAN --examiner "Examiner A" --audit output/audit.jsonl --html output/case_report.html --json output/case_report.json
venv\Scripts\python.exe -m bec_detector verify-audit output/audit.jsonl
```

Open `output/case_report.html`. Points to show:

- **Summary:** 10 CONFIRMED_BEC, 1 SUSPICIOUS, 15 BENIGN.
- **`susp_03_legit_urgent_payment.eml`:** urgent, a real amount and a deadline,
  but a verified internal sender. It scores 29.6 (SUSPICIOUS), not a BEC band:
  urgency alone is not BEC.
- **`ato_04_takeover.eml`:** passing SPF, DKIM and DMARC from a genuine
  mailbox, caught at 78.4 by stylometry against the sender's three earlier
  messages.
- **Each finding** is laid out as observed evidence → system inference → risk
  → recommendation, and the fusion arithmetic shows how the score was built.
- **Evidence integrity:** SHA-256 per message, and the audit chain status.

## 3. Case workflow (CLI)

```bash
venv\Scripts\python.exe -m bec_detector case create CASE-DEMO --examiner "Examiner A" --title "Vendor bank change"
venv\Scripts\python.exe -m bec_detector case add CASE-DEMO data/samples --examiner "Examiner A"
venv\Scripts\python.exe -m bec_detector case analyse CASE-DEMO
venv\Scripts\python.exe -m bec_detector case show CASE-DEMO
```

Evidence is preserved at `output/cases/CASE-DEMO/evidence/<sha256>.eml`,
write-once and read-only. The report is `output/cases/CASE-DEMO/report.html`.

Ask the grounded assistant about the vendor bank-change email
(`bec_02_vendor_bank_change.eml` is `EV-88F7BCE5D4FD`):

```bash
venv\Scripts\python.exe -m bec_detector case ask CASE-DEMO "Why was this email flagged?" --evidence EV-88F7BCE5D4FD
```

The answer is structured as Evidence → Inference → Risk → Recommendation. Every
line ends with the citations that support it, and it closes with the fixed
caveats: scores are not probabilities, no offence is determined, and no actor
is attributed.

Record an investigator determination, then verify the case:

```bash
venv\Scripts\python.exe -m bec_detector case feedback CASE-DEMO EV-88F7BCE5D4FD confirmed_suspicious --examiner "Examiner A" --notes "Vendor called on known number; no change requested"
venv\Scripts\python.exe -m bec_detector case verify CASE-DEMO
venv\Scripts\python.exe -m bec_detector case search northwind-l0gistics.com
```

`verify` re-hashes all 26 preserved files and checks the audit chain. The
feedback appears in the report's investigator section with "agrees" derived
against the system's assessment at the time. The system's own findings are
not changed by it.

> A case ID can only be created once. To re-run this section, use a new ID or
> delete `output/cases/CASE-DEMO`.

## 4. Dashboard

```bash
venv\Scripts\python.exe run_server.py
```

Open <http://127.0.0.1:8000>.

1. **Upload:** enter a case ID (for example `CASE-WEB`), choose
   `data/samples/bec_08_link_and_attachment.eml` and
   `data/samples/ben_03_vendor_normal.eml`, and click Analyse. The browser is
   redirected to the case page.
2. **Case page:** the assessment table, recommendations, IOCs, the evidence
   graph, the timeline, the evidence register with hashes, and the audit trail.
3. **Verify integrity:** re-hashes the evidence and records the check in the
   audit log.
4. **Ask about this case:** try *"Explain the evidence graph"* or *"What should
   I review next?"*.
5. **Investigator feedback:** record a determination and watch it appear in
   the report and audit trail.
6. **Cases** and **Search:** try searching `203.0.113.45`.

API equivalents:

```bash
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8000/api/cases
curl -F "case=CASE-API" -F "files=@data/samples/bec_02_vendor_bank_change.eml" http://127.0.0.1:8000/api/analyse
```

## 5. Security behaviour (optional)

- `curl -H "Host: evil.example" http://127.0.0.1:8000/api/health` returns 400
  (DNS-rebinding guard).
- A POST carrying `Origin: https://evil.example` returns 403 (CSRF guard).
- `tests/test_security_audit.py` covers MIME nesting bombs, malformed input and
  path traversal.

## 6. Research reproduction (optional, about 10–20 minutes)

```bash
venv\Scripts\python.exe -m research.evaluate
venv\Scripts\python.exe -m research.balanced_ablation
venv\Scripts\python.exe -m research.engine_eval
venv\Scripts\python.exe -m research.robustness
venv\Scripts\python.exe -m research.drift
```

Each prints a banner stating that it reports synthetic research results. See
[`research.md`](research.md) for what each one shows and does not show.
