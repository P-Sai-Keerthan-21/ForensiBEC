# Investigator Feedback

The system produces **risk assessments**. Investigators make
**determinations**. This module records the second without ever altering the
first.

## Recording a determination

| Where | How |
|---|---|
| Dashboard | Case page, *Investigator assessment* panel, one form per message |
| API | `POST /api/cases/{case_id}/feedback` with `{"evidence_id", "assessment", "examiner", "notes"}` |
| CLI | `python -m bec_detector case feedback CASE-ID EV-... confirmed_suspicious --examiner "Name" --notes "..."` |

Assessments: `confirmed_suspicious`, `confirmed_benign`, `needs_review`.
The examiner is required; notes are optional (maximum 2,000 characters).

## What a record contains

| Field | Purpose |
|---|---|
| `case_id`, `evidence_id`, `evidence_sha256` | Binds the determination to the exact bytes reviewed |
| `examiner`, `timestamp_utc` | Attribution |
| `system_score`, `system_band` | What the system said **at that moment** |
| `system_config_sha256` | The scoring configuration in force, so a later rule change can't blur what the system said |
| `assessment`, `notes` | The human determination |
| `agreement` | **Derived**, never entered: `agrees`, `system false positive`, `system false negative`, or `undetermined` |

## Integrity

- **Append-only.** A correction is a new record; the latest record per evidence
  item is the current determination. The full history stays visible in the
  report.
- **Hash-chained.** Records are written to `cases/<ID>/feedback.jsonl` with the
  same chaining as the audit trail. Editing any record breaks verification
  (`GET /api/cases/{id}/feedback` reports integrity).
- **Mirrored.** Each record also appends an `investigator_assessment` entry to
  the case audit chain.
- **Separate.** System findings, scores and bands are never changed by
  feedback (`test_system_findings_unchanged_by_feedback`). The report shows
  human determinations in their own section, labelled as such.

## No automatic retraining

Nothing in this application trains on feedback. The `bec_detector` package
does not import the research package at all, and a test asserts it.

`python -m bec_detector case export-feedback labels.json [CASE-ID ...]`
produces candidate labels for a **future, deliberate** retraining step. That
step is not implemented.

### Poisoning resistance in the export

Anyone who can record feedback could try to poison a future model with false
labels. The export applies these safeguards:

| Rule | Why |
|---|---|
| Only cases whose evidence and both hash chains verify intact | A tampered case contributes nothing |
| `needs_review` is never exported as a label | Uncertainty is not a label |
| Evidence on which examiners disagree is **withheld, not resolved** | No majority vote or "latest wins" for training data |
| Every label is bound to the evidence SHA-256 | A label can't be moved onto different content |
| Examiner, timestamp and system configuration are retained | Every label is attributable and auditable |

**What the export does not defend against:** a single examiner, or colluding
examiners, deliberately and consistently mislabelling evidence. Guarding
against that needs access control and review workflows (see
`docs/security.md` §3), and a retraining step that compares any model trained
on feedback against a held-out, independently labelled set before it is used.
