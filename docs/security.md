# Application Security Review

The tool ingests hostile input by design: every uploaded file is, by
assumption, attacker-authored. This document records the review of the
application itself, not of the mail it analyses.

---

## 1. Threat model

| Asset | Threat | Control |
|---|---|---|
| Analyst workstation | Malicious attachment executes | Attachments are never written to disk and never executed; only hashed and type-sniffed in memory |
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
leading magic bytes. They are never written to disk, never passed to a shell,
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

---

## 5. Re-running the review

```bash
grep -rnE "subprocess|os\.system|eval\(|exec\(|shell=True|pickle" bec_detector/
python -m pytest tests/test_security.py -v
```
