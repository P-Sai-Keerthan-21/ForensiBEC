# Application Security Review

The tool ingests hostile input by design: every uploaded file is, by
assumption, attacker-authored. This document records the review of the
application itself, not of the mail it analyses.

---

## 1. Threat model

| Asset | Threat | Control |
|---|---|---|
| Analyst workstation | Malicious attachment executes | Attachments are never extracted to a separate file and never executed; only hashed and type-sniffed in memory |
| Analyst workstation | Malicious URL contacted, alerting the attacker | Static analysis only; the tool never resolves or requests a URL found in evidence |
| Filesystem | Path traversal via upload filename | Filenames are sanitised to a label and never joined to a path |
| Availability | Memory exhaustion via large upload | Size enforced while streaming; upload abandoned before full read |
| Evidence | Silent modification of findings | SHA-256 over source bytes + hash-chained audit log |
| Confidentiality | Evidence leaving the machine | No outbound network calls anywhere in the analysis path |

---

## 2. Review findings

### 2.1 Path traversal — **not exploitable**

Upload filenames are untrusted input. `sanitise_filename()` strips every
directory component, NFKC-normalises, removes non-printable characters, and
replaces anything outside `[A-Za-z0-9._-]`.

The stronger guarantee is architectural: **the sanitised name is never used to
open, create or locate a file.** It is a label in the report and the custody
record only. Even an unsanitised name could not traverse anything, because no
filesystem operation consumes it.

Verified: uploading `../../../etc/passwd.eml` records the source as `passwd.eml`.

### 2.2 Unrestricted file upload — **mitigated**

- Extension allowlist: `.eml`, `.mbox`, `.txt`, `.msg-text`
- Content-type allowlist
- Non-message types rejected with HTTP 400

Verified: `x.exe` → 400.

### 2.3 Excessive file size — **mitigated**

`read_limited()` reads in 64 KB chunks and aborts as soon as the limit is
exceeded. The earlier implementation called `await upload.read()` and checked
the length afterwards, which admitted the whole body to memory before
rejecting it. That was found and corrected during this review.

Limits: 10 MB per file, 50 MB per submission, 100 files per request.

Verified: 11 MB upload → 400; empty upload → 400.

### 2.4 Unsafe attachment handling — **mitigated**

Attachments are decoded in memory only long enough to compute SHA-256 and read
leading magic bytes. They are never extracted to a separate file, never passed to a shell,
never opened by an external handler, and archives are **not** extracted
(recorded explicitly as unexamined in the report).

### 2.5 Arbitrary command execution — **none present**

`subprocess`, `os.system`, `eval`, `exec`, `shell=True` and `pickle` do not
appear anywhere in the codebase. Re-check with:

```bash
grep -rnE "subprocess|os\.system|eval\(|exec\(|shell=True|pickle" bec_detector/
```

### 2.6 Hard-coded secrets — **none present**

The application has no credentials, API keys or tokens. `data/local_intel.json`
holds only operator-maintained indicators and contains no secret material.

### 2.7 Sensitive information in logs — **reviewed**

The audit log records actions, evidence identifiers and hashes — not message
bodies. Evidence content appears only in the report, which is the intended
work product and stays on the analyst's machine.

Note for deployment: reports contain the full evidence content by design.
Treat generated reports as case material and store them accordingly.

### 2.8 Unsafe error messages — **mitigated**

Errors returned to the client are generic and state only what the user must
fix. No stack traces, filesystem paths or internal state are disclosed.
`_error_page()` HTML-escapes its message.

### 2.9 Server-side request forgery — **not applicable**

There is no code path that makes an outbound request. URL analysis is purely
lexical, which is a deliberate forensic requirement as well as a security one:
contacting attacker infrastructure would disclose the investigation.

### 2.10 Evidence retention — **changed by case management**

Earlier builds analysed uploads in memory and wrote nothing to disk. Case
management requires preserving original evidence, so accepted messages are
now written to the case store. The controls on that write:

| Control | Implementation |
|---|---|
| No user-controlled path | Stored as `cases/<CASE-ID>/evidence/<sha256>.eml`. The uploaded filename is metadata only. |
| Case ID cannot traverse | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, then the resolved path is checked to lie inside the store |
| Write-once | Exclusive create (`open(..., "xb")`); identical bytes are a no-op; a colliding file with different content is refused, never overwritten |
| Tamper evidence | Every read re-hashes the file and refuses mismatches; `case verify` / `GET /api/cases/{id}/verify` re-hash the whole register |
| Not served back | The web interface never returns stored evidence bytes |
| Not executed | Stored evidence is only ever read and parsed as a message |
| Read-only | Files are chmod read-only after writing (best effort on Windows) |

Tests: `tests/test_cases.py` (`test_evidence_stored_under_its_hash_not_its_filename`,
`test_tampered_evidence_is_detected`, `test_analysis_refuses_tampered_evidence`,
`test_evidence_file_is_never_overwritten`, `test_traversal_case_id_cannot_create_directories`).

Residual risk: the case store holds real message content. Treat the data
directory (`output/` by default, or `FORENSIBEC_DATA_DIR`) as case material.

### 2.11 MIME nesting bomb — **found and fixed in the final audit**

A ~40 KB message containing 2,000 nested `multipart/mixed` containers exhausted
the Python standard-library parser's recursion limit (around 1,000 levels) and
crashed analysis with HTTP 500. No internals leaked, but the request failed and
earlier builds could leave evidence stored without an analysis.

Fix: messages declaring more than 100 multipart containers are refused before
parsing (`MAX_MULTIPART_CONTAINERS`), and any `RecursionError` during parsing is
converted to `EvidenceParseError`. The web intake now parses each upload before
accepting it, so unparseable evidence is rejected with a reason and never stored.
A folded `Content-Type` header that evades the count still hits the recursion
guard.

### 2.12 Silent evidence loss — **found and fixed**

Directory acquisition skipped any file that failed to parse, with no record.
For a forensic tool, evidence disappearing without trace is itself a defect.
Skipped files are now returned to the caller, written to the audit log as
`evidence_skipped` with the reason, and printed as a warning by the CLI.

### 2.13 Cross-site request forgery — **found and fixed**

With no login, any web page the investigator visited could submit a form to
`http://127.0.0.1:8000/analyse` and **plant fabricated evidence into an existing
case** — a direct attack on evidence integrity.

Fix: state-changing requests are refused (403) when the browser marks them
`Sec-Fetch-Site: cross-site`, or when an `Origin` header names a different
origin or is `null`. Non-browser clients (CLI, scripts) send neither header and
are unaffected.

### 2.14 DNS rebinding — **found and fixed**

A hostile site that re-points its own hostname at 127.0.0.1 becomes same-origin
with the app and could read case data. The app now serves only requests whose
`Host` is on an allowlist (`FORENSIBEC_ALLOWED_HOSTS`, default
`127.0.0.1,localhost`); anything else receives 400.

### 2.15 Malformed input — **verified**

Binary garbage, missing or broken MIME boundaries, invalid base64, invalid
UTF-8, NUL bytes, 1 MB header lines, encoded-word floods, impossible dates,
malformed URLs and right-to-left override characters all produce a normal
response. Malformed API requests (missing fields, wrong content type, oversized
fields, wrong methods) return 4xx without internal detail.

Tests: `tests/test_security_audit.py` (38 tests), including a repository-wide
static scan of `bec_detector/`, `research/`, `data/` and `run_server.py` for
code execution, unsafe deserialisation, outbound network calls and debug-mode
servers. The earlier scan covered `bec_detector/` only.

---

## 3. Authentication — architecture only

No authentication is implemented. This is a deliberate scoping decision for the
50% milestone, and the tool is intended to run on `127.0.0.1` for a single
local analyst.

**If authentication is added, the design is:**

- Argon2id password hashing (never plaintext, never unsalted SHA-family)
- Server-side sessions, `HttpOnly` + `Secure` + `SameSite=Strict` cookies
- CSRF tokens on every state-changing form
- Role separation: `analyst` (submit, read own cases) vs `lead` (all cases, edit intelligence)
- Every authentication event appended to the existing hash-chained audit log
- Rate limiting on the login route

**Do not deploy the current build on a network interface reachable by others.**
`run_server.py` binds `127.0.0.1` for this reason.

---

## 4. Residual risks

| Risk | Status |
|---|---|
| No authentication | Accepted for this milestone; localhost-only |
| No TLS | Accepted; localhost-only |
| Archive contents unexamined | By design; reported explicitly rather than silently |
| spaCy/NLTK model files trusted | Installed from PyPI at setup; standard supply-chain assumption |
| Reports contain full evidence | By design; handle as case material |
| IOC store is plain JSON | Readable and editable by anyone with filesystem access; integrity of *findings* is protected by the audit chain, not the store |
| Concurrent writes to one case | Two simultaneous analyses of the same case can race on `case.json`. Single-analyst localhost use makes this unlikely; there is no file locking |
| CSRF defence relies on browser headers | Modern browsers send `Origin`/`Sec-Fetch-Site` on cross-site POSTs; very old browsers may not. There is no CSRF token |
| Case data readable by local users | The data directory is not encrypted; protect it with filesystem permissions |

---

## 5. Re-running the review

```bash
grep -rnE "subprocess|os\.system|eval\(|exec\(|shell=True|pickle" bec_detector/
python -m pytest tests/test_security.py tests/test_security_audit.py -v
```
