# Standards mapping

Every control in DOOM mapped to **OWASP ASVS 4.0** and tagged with its **CWE**
identifier, so the security posture can be discussed in a shared vocabulary
rather than in adjectives.

Two honest claims, and one non-claim:

- **ASVS Level 1: met in full.**
- **ASVS Level 2: met**, with two requirements answered by compensating
  controls rather than literally, both argued in §4.
- **ASVS Level 3 is not claimed.** L3 expects things this deployment does not
  have — segregation of duties, phishing-resistant multi-factor
  authentication, HSM-backed key management, and independent verification.

> **Correction.** An earlier revision of this document called missing MFA "the
> largest gap against L2". That was wrong, and it is worth saying so rather
> than quietly editing: ASVS 4.0 has **no blanket Level 2 requirement for
> multi-factor authentication.** V2.2.4 (phishing resistance via MFA) is
> **Level 3**, and V2.7/V2.8 are conditional — they apply *if* OTP or
> out-of-band authenticators are used. DOOM is single-factor by deliberate
> choice, which is an L3 gap, not an L2 one. See §4.

Where a requirement does not apply, it says so and why. A mapping that claims
everything applies is not a mapping.

---

## 1. Control matrix

### V2 — Authentication

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 2.1.1 | 12-character minimum | `PASSWORD_MIN = 12` (D-03) | 521 |
| 2.1.2 | 64+ characters permitted | `PASSWORD_MAX = 128` | 521 |
| 2.1.3 | No truncation | Argon2id hashes the full value | 521 |
| 2.1.7 | Breach-corpus screening | `COMMON_PASSWORDS` in `security/passwords.py` | 521 |
| 2.1.9 | **No composition rules** | Deliberately absent, per NIST SP 800-63B | 521 |
| 2.2.1 | Anti-automation on login | Per-IP limit + per-account lockout (D-04) | 307 |
| 2.2.3 | Notify on credential change | Password change invalidates other sessions (T-06) | 640 |
| 2.4.1 | Approved KDF | Argon2id `t=3, m=64 MiB, p=4` (D-02) | 916 |
| 2.4.4 | Per-credential salt | `argon2-cffi`, 16-byte salt | 759 |
| 2.5.4 | No shared/default accounts | Seed account is opt-in and documented | 798 |

*Not applicable:* 2.6–2.9 (OTP, cryptographic and hardware authenticators) —
single-factor by design; 2.5.1–2.5.3 (reset flows) — no reset flow exists, and
the reasoning is D-12.

### V3 — Session management

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 3.2.1 | New token on authentication | `session.clear()` then re-issue (T-04) | 384 |
| 3.2.3 | Tokens in secure cookies only | `HttpOnly`, `Secure`, `SameSite=Lax` | 522 |
| 3.3.1 | Logout invalidates | `session.clear()` + `session_version` | 613 |
| 3.3.2 | Re-authentication period | 12-hour lifetime | 613 |
| 3.4.1–3.4.3 | Cookie attributes | `config.py` | 614, 1275 |
| 3.3.4 | **View and terminate active sessions** | `user_sessions` table listed on the account page; revocation requires the password and takes effect on the session's next request | 613 |
| 3.5.2 | No static API tokens | Share tokens are 256-bit and revocable | 798 |

### V4 — Access control

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 4.1.1 | Enforced server-side | `get_owned_or_404()` on every route | 602 |
| 4.1.2 | Attributes not user-manipulable | Field-by-field binding; never `**request.form` (D-07) | 639 |
| 4.1.3 | Least privilege | App DB role holds DML only (D-08) | 272 |
| 4.1.5 | **Fail securely** | Ownership is a `WHERE` clause; a miss is 404 not 403 (D-06) | 639 |
| 4.2.1 | No IDOR | Ownership filtered inside the query | 639 |
| 4.2.2 | CSRF on state change | `CSRFProtect` global; no state change on GET | 352 |
| 4.3.2 | No directory browsing | Uploads served only through an authorised handler | 548 |

### V5 — Validation, sanitisation, encoding

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 5.1.1 | Mass-assignment defence | Explicit form fields only (T-10) | 915 |
| 5.1.3 | Positive validation | Allowlists throughout `validation.py` | 20 |
| 5.1.4 | Typed and bounded | Every limit a named constant (D-01) | 20 |
| 5.2.1 | Untrusted HTML sanitised | `nh3` allowlist for Markdown | 79 |
| 5.2.5 | Template injection | Jinja2 autoescaping; zero `safe` filter, build-enforced | 1336 |
| 5.2.6 | **SSRF defence** | User URLs never fetched (D-13); lookup pinned in code (D-32) | 918 |
| 5.3.3 | Contextual output encoding | Jinja2 autoescaping | 79 |
| 5.3.4 | Parameterised queries | SQLAlchemy; `websearch_to_tsquery` bound | 89 |
| 5.3.8 | OS command injection | No shell invocation anywhere | 78 |
| 5.3.9 | Path traversal | Stored names are generated UUIDs (D-10) | 22 |
| 5.3.10 | XXE | No XML parsing; SVG rejected | 611 |

### V1 / V6 — Architecture and secrets

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 1.1.2 | Threat modelling | `THREAT-MODEL.md`, written before the code | 1053 |
| 1.1.4 | Trust boundaries documented | `THREAT-MODEL.md` §4 | 1059 |
| 1.2.1 | Unique low-privilege runtime account | uid 10001, no shell | 250 |
| 1.4.4 | Single vetted access control mechanism | `get_owned_or_404()` | 284 |
| 1.7.1 | Common logging format | Structured JSON to stdout | 778 |
| 1.10.1 | **Source code control** | Git repository with a documented history | 1105 |
| 1.11.2 | No race conditions in high-value logic | See V11.1.6 | 367 |
| 6.3.1 | CSPRNG for secrets | `secrets.token_urlsafe`, `secrets.choice` | 338 |
| 6.4.1 | **Secrets management** | Read from mounted files, never the environment: absent from `docker inspect`, from child processes and from `/proc/<pid>/environ` | 522 |

### V7 — Errors and logging

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 7.1.1 | No sensitive data in logs | Redaction filter in `security/logging.py` | 532 |
| 7.1.3 | Security events logged | `audit_log`, including denied access | 778 |
| 7.2.1 | Authentication decisions logged | Success and failure both recorded | 778 |
| 7.3.1 | **Log injection prevented** | Structured JSON; encoder escapes newlines | 117 |
| 7.3.3 | **Logs protected from alteration** | Hash chain + `UPDATE`/`DELETE` revoked (D-33) | 117 |
| 7.4.1 | Generic error messages | Correlation ID only (D-17) | 209 |

### V8 — Data protection

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 8.1.1 | Sensitive data not cached in server components | `Cache-Control: no-store` + `Vary: Cookie` on every authenticated response | 524 |
| 8.2.1 | Anti-caching headers in the browser | Same, plus `Pragma: no-cache` for HTTP/1.0 caches | 525 |
| 8.2.2 | No sensitive data in browser storage | No `localStorage` or `sessionStorage` use at all | 922 |
| 8.3.4 | Inventory of sensitive data | Asset table in `THREAT-MODEL.md` §2 | 200 |

### V11 — Business logic

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 11.1.2 | Steps in order, no skipping | Checkout, return and move each validate current state | 841 |
| 11.1.3 | Realistic human-time limits | Rate limits on login, register, share, lookup | 799 |
| 11.1.4 | **Anti-automation on high-value flows** | Write and upload limits on capture, create, adjust, checkout, upload and search — not authentication alone | 799 |
| 11.1.5 | Business logic limits | Quantity bounds, storage quota, tree depth | 841 |
| 11.1.6 | No TOCTOU / race conditions | Atomic quantity arithmetic; `SELECT … FOR UPDATE` for checkout | 367 |

### V12 — Files and resources

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 12.1.1 | Upload size limits | Caddy 12 MB → Flask 10 MB → per-file check | 400 |
| 12.1.3 | **Resource quotas** | Per-account storage ceiling, checked before write (T-46) | 770 |
| 12.2.1 | Type validated by content | libmagic, not filename or Content-Type | 434 |
| 12.3.1 | Filename not user-controlled | Generated UUIDs | 22 |
| 12.3.3 | No path traversal | Prevented by construction | 22 |
| 12.4.2 | Content scanned or neutralised | Full decode and re-encode destroys payloads | 509 |
| 12.5.2 | Dangerous types rejected | SVG and archives excluded by allowlist | 434 |
| 12.6.1 | SSRF protections on upload | No remote fetch on any upload path | 918 |

### V13 / V14 — API and configuration

| ASVS | Requirement | Implementation | CWE |
|---|---|---|---|
| 13.2.1 | Correct HTTP verbs | State changes are POST with a token | 650 |
| 14.1.1 | Reproducible build | Pinned dependencies and base images | 1104 |
| 14.2.1 | No known-vulnerable components | Pinned; scanning on the roadmap | 1104 |
| 14.4.1 | Content-Type on responses | Explicit; `nosniff` everywhere | 173 |
| 14.4.3 | **Content Security Policy** | No `unsafe-inline`; `script-src 'self'` | 1021 |
| 14.4.4 | `X-Content-Type-Options` | Global and per-file | 430 |
| 14.4.5 | HSTS | Caddy and application both | 319 |
| 14.4.7 | Clickjacking defence | `frame-ancestors 'none'` + `X-Frame-Options` | 1021 |
| 14.5.3 | CSRF origin verification | `WTF_CSRF_SSL_STRICT` (D-22) | 352 |

---

## 2. Other standards cited

| Standard | Where it applies |
|---|---|
| **NIST SP 800-63B** | Password policy: length over composition, breach screening, no forced rotation (D-03) |
| **NIST SP 800-53 AU-9** — *Protection of Audit Information* | Hash-chained, append-only audit log (D-33) |
| **NIST SP 800-53 AC-3, AC-6** | Ownership filtering; least-privilege database role |
| **NIST SP 800-53 SC-8** | TLS in transit, HSTS |
| **NIST CSF 2.0** | PR.AA (access control), PR.DS (data security), DE.AE (event analysis) |
| **GS1 General Specifications** | GTIN-8/12/13/14 barcode format — and the reason a barcode can be validated to digits at all (T-43) |
| **OWASP Top 10 2021** | A01 broken access control, A03 injection, A05 misconfiguration, A07 auth failures, A10 SSRF |
| **CIS Docker Benchmark** | Non-root user, dropped capabilities, read-only rootfs, no new privileges |

**Deliberately not claimed:** PCI DSS (no cardholder data — stating this is
itself the correct answer), HIPAA (no health data), SOC 2 (an organisational
audit, not a property of software).

---

## 3. Privacy posture

Not a certification, but the design decisions line up with GDPR principles and
are worth stating plainly:

| Principle | How |
|---|---|
| **Data minimisation** (Art. 5(1)(c)) | Every profile field optional; email collected but never used for delivery (D-25) |
| **Storage limitation** | Self-hosted; the operator controls retention entirely |
| **Right of access** (Art. 15) | `/account/activity.csv` exports the full audit trail |
| **Right to erasure** (Art. 17) | Account deletion cascades — with the audit trail deliberately surviving as a legitimate-interest record (D-33) |
| **Data protection by design** (Art. 25) | Threat model written before the code |

---

## 4. Gaps — stated, not hidden

The value of a mapping is in what it admits.

| Gap | ASVS | Level | Status |
|---|---|---|---|
| **No multi-factor authentication** | 2.2.4 | **L3** | Single-factor by design. Not an L2 requirement — see the correction at the top. It remains the strongest available improvement for a system holding a map to physical property |
| **Internal traffic is unencrypted** | 1.9.1, 9.2.2 | L2 | **Compensating control.** `db` and `cache` sit on a Docker network declared `internal: true`, with no route off the host and no published ports, and both require passwords. TLS between them would protect against an attacker already executing inside that network — at which point the application's own credentials are readable anyway. Argued rather than implemented, deliberately |
| **Logs are not shipped off-host** | 1.7.2 | L2 | **Compensating control.** Logs go to stdout in structured JSON, which is what a collector consumes; the *audit* trail — the security-relevant half — is in Postgres, hash-chained and append-only, which is a stronger property than remote shipping alone provides |
| **No dependency vulnerability scanning** | 14.2.1 | L2 | Dependencies pinned but unscanned. Deliberately out of scope for this build; `PIPELINE-NOTES.md` has the roadmap and it is the first thing to add |
| **No SBOM** | 14.2.5 | L2 | Same; one `syft` command |
| **No malware scanning of uploads** | 12.4.1 | L2 | Files are never executed, always served as attachments with `nosniff`, and images are fully re-encoded — which destroys embedded payloads more reliably than signature scanning finds them. ClamAV is the production addition |
| **No segregation of duties** | V4 | L3 | Meaningless while single-account; essential the moment it is not. What a warehouse operation would ask about first |
| **DNS rebinding window in barcode lookup** | 5.2.6 | L2 | Resolve-then-connect leaves a gap. Bounded by the lookup being off by default, pinned to a code-level provider list, and refusing redirects (D-32) |
| **Audit chain is evident, not proof** | 7.3.3 | L2 | Someone with database access *and* the source can recompute it. An externally recorded head hash is the mitigation, and the account page shows one (D-33) |
| **Username disclosure on registration** | V2.2 | L2 | Unavoidable — the form must say a name is taken. Rate limited (D-05) |

**On the two compensating-control arguments.** Both are places where the
literal requirement is not met and the risk it addresses is. That distinction
is the honest way to claim a level: neither is marked "met" above, and a
verifier is free to disagree with the argument. Pretending they were
implemented would be worse than either.

---

## 5. Verifying the claims

Most of this matrix is executable rather than asserted:

```bash
make test           # 228 tests pinning the controls above
make lint           # fails if any template could bypass autoescaping
make audit-verify   # walks the audit hash chain
make db-shell-app   # connect as the app role and try to exceed its privileges
```

Secrets never reach the process environment (6.4.1):

```bash
docker inspect doom-web-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -i password
# only *_FILE paths appear, never a value

docker compose exec web sh -c 'tr "\0" "\n" < /proc/1/environ | grep -cE "^(SECRET_KEY|APP_DB_PASSWORD|REDIS_PASSWORD)="'
# 0
```

As the application's own database role, all of these must fail:

```sql
DROP TABLE items;                     -- must be owner of table items
SELECT * FROM pg_shadow;              -- permission denied
UPDATE audit_log SET detail = 'x';    -- permission denied
DELETE FROM audit_log;                -- permission denied
```
