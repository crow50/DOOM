# Documented security policies

Several ASVS requirements ask not for a control but for a *documented* one:
that the application define its validation rules, its anti-automation
response, its authorization model, its session limits, its key lifecycle and
its patching deadlines, so that the implementation can be checked against a
stated intention rather than against a reader's assumption. This file is that
statement. Where a policy is enforced in code, the constant and the test that
pins it are named, because a policy nothing enforces is a wish.

Scope: current execution is isolated local self-hosting. Rows that depend on a
public deployment are marked **operator** and are readiness targets, not claims
about a running system. See [HOSTED-READINESS.md](HOSTED-READINESS.md).

---

## 1. Input validation rules — v5.0.0-2.1.1, v5.0.0-2.2.1, v5.0.0-2.2.2

Every bound the application enforces is a named constant in
[`app/doom/validation.py`](../../app/doom/validation.py), and nothing invents a
limit locally. The rules:

- **Positive validation, never denial.** Every list in that module is an
  allowlist: accepted upload types, accepted filename extensions per type,
  accepted location kinds, the username character class, the barcode
  alphabet. A denylist fails open on the case nobody thought of.
- **Structure before value.** A path parameter is parsed to a UUID before it
  reaches any comparison; a share code is matched against its exact shape
  before it reaches a lookup. A value that could not have been issued by this
  application is refused without a database round trip.
- **The same constant at every layer that can enforce it.** A text field is
  bounded by a WTForms validator, a column length and a Postgres `CHECK`. An
  upload is bounded by the Caddy body cap, `MAX_CONTENT_LENGTH`, a magic-byte
  sniff and a full decode/re-encode. HTML `maxlength` is a usability hint and
  is never counted as a control.
- **Validation is server-side.** Client-side checks exist only to give faster
  feedback. No server decision depends on one, which is what
  `v5.0.0-2.2.2` asks for; the test suite drives the server directly rather
  than through a browser for exactly this reason.
- **Canonicalise once, early.** Usernames are case-folded and normalised at
  the boundary (`normalize_username`); the redirect validator inspects the
  exact string it will emit rather than a normalised copy of it, because the
  browser will act on the exact string.

Business-flow ordering (`v5.0.0-2.3.1`) is enforced by the same principle:
a PIN-protected share renders its content only after the PIN has been
accepted in this session, quantity changes are computed by the database rather
than submitted by the client, and a checkout cannot be returned before it has
been taken out.

## 2. Anti-automation and adaptive response — v5.0.0-6.1.1, v5.0.0-6.3.1

Defence against credential stuffing, brute force and scraping is layered, and
each layer is a constant in `validation.py`:

| Surface | Limit | Constant |
|---|---|---|
| Sign-in | 10 per 15 minutes per IP | `LOGIN_RATE_LIMIT` |
| Registration | 5 per hour per IP | `REGISTER_RATE_LIMIT` |
| Share pages | 30/minute, 300/hour per IP | `SHARE_RATE_LIMIT` |
| Writes | 120/minute, 2000/hour per IP | `WRITE_RATE_LIMIT` |
| Uploads | 30/minute, 300/hour per IP | `UPLOAD_RATE_LIMIT` |
| Barcode lookup | 20 per hour | `LOOKUP_RATE_LIMIT` |

The **adaptive response** is account lockout: `LOCKOUT_THRESHOLD` consecutive
failures lock an account, and the lock lengthens over successive rounds
(`LOCKOUT_BACKOFF_SECONDS`) to a ceiling of `LOCKOUT_MAX_SECONDS`. The cap is
deliberate and is argued in D-04: an unbounded lockout converts a guessing
attack into a denial-of-service one against the account's real owner.

A locked account reports the same message as a wrong password, and an unknown
username costs the same time as a known one, so neither the lockout nor the
user table is observable from outside.

**Rate limiting fails closed** (D-14): if the limiter's backing store is
unreachable, requests are refused rather than allowed through unlimited.

## 3. Context-specific password words — v5.0.0-6.1.2, v5.0.0-6.2.11

Two lists screen a candidate password, and they do different jobs:

- `security/data/common_passwords.txt` — the top 10,000 breached passwords
  that are at least `PASSWORD_MIN` characters long, so the screen is reachable
  rather than pre-empted by the length check. Provenance is in the file header.
- `validation.CONTEXT_WORDS` — words this system itself suggests: `doom`,
  `inventory`, `warehouse`, `organizer`, `organiser`, `storage`. Matched as a
  case-folded substring, so `MyDoomPassphrase` is refused along with `doom`.
  A breach list cannot catch `doominventory2026`; an attacker who knows what
  they are looking at will try it first.

The username is screened against the password separately.

**Operators should extend `CONTEXT_WORDS`** with their organisation name, site
names and any project codename that is visible on the labels people will be
looking at while they choose a password. The list is deliberately code rather
than configuration so that a change to it is reviewed and tested.

Composition rules are deliberately absent (D-03), following NIST SP 800-63B:
length and screening resist guessing, character-class rules produce
`Password1!`.

## 4. Authorization model — v5.0.0-8.1.1, v5.0.0-8.2.1, v5.0.0-8.2.2, v5.0.0-8.3.1

**Function level.** Every route is one of: public (the landing page, robots),
capability-scoped (the three share endpoints), or `@login_required`. There are
no roles and no administrative surface inside the application — operator
actions are CLI commands run against the container, so there is no privileged
HTTP endpoint to reach by guessing a URL. `tests/test_authz_coverage.py` holds
a map of every endpoint to how it is scoped and fails if a new route is added
without an entry, so the model cannot drift silently.

**Data level.** Ownership is a `WHERE` clause, never an `if` statement (D-07).
A fetch goes through `get_owned_or_404`, whose predicate `owner_id ==
current_user.id` is part of the `SELECT`; there is no window between loading a
row and deciding whether the caller may have it. A row that exists but belongs
to someone else and a row that does not exist are the same event — zero
results — and both answer 404, never 403 (D-06).

**Trusted layer.** All of it runs server-side. Nothing in a form, a cookie, a
header or a URL parameter selects the account whose data is returned; the
identity comes from the signed session and nowhere else.

**Changes apply immediately.** Revoking a share, rotating a token, changing a
password or ending a device session takes effect on the next request rather
than at the next sign-in, because the session row and the share row are both
consulted per request.

## 5. Session policy — v5.0.0-7.1.2, v5.0.0-7.3.1

| Policy | Value | Constant |
|---|---|---|
| Absolute lifetime | 12 hours | `SESSION_LIFETIME_HOURS` |
| Idle timeout | 60 minutes | `SESSION_IDLE_MINUTES` |
| Concurrent sessions per account | 10 | `MAX_CONCURRENT_SESSIONS` |
| Behaviour at the limit | the least recently used session is ended | `_enforce_session_cap` |
| Re-authentication | required before ending another session | `RevokeSessionForm` |

**Why 60 minutes and not 15.** The realistic exposure is an unattended phone
or a shared terminal, and the data is a map to physical property rather than
money or health records. A warehouse user genuinely does pocket the phone and
walk for twenty minutes between scans; a timeout they trip over repeatedly is
one they work around, by never signing out on a device that never locks. The
absolute 12-hour cap bounds the damage either way.

**Why eviction rather than refusal.** Refusing the eleventh sign-in locks
someone out of the device in their hand because of a session they forgot on a
machine they no longer own, with an operator as the only way back. Every
session is listed on the account page with its address, device and last-seen
time, and any one can be ended individually after re-entering the password.

Ending a session revokes the row rather than only dropping the cookie, so a
copied cookie cannot be retried, and sign-out sends `Clear-Site-Data` for
cache, cookies and storage.

## 6. Cryptographic policy and key lifecycle — v5.0.0-11.1.1, v5.0.0-11.4.1

**Algorithms in use.** Argon2id (t=3, 64 MiB, p=4) for passwords and share
PINs; HMAC-SHA256 for the session cookie, the CSRF serializer and the share
PIN approval; SHA-256 for content addressing and the audit hash chain;
`secrets` (the OS CSPRNG) for every token, code and salt. No SHA-1, MD5 or
SHA-224 is reachable from the application package, and a test walks the AST to
keep it that way rather than trusting a grep over prose.

Flask and Flask-WTF both default to HMAC-SHA1; `security/sessions.py` raises
both to SHA-256 and explains why there is no accept-either fallback.

**Keys and their lifecycle.**

| Key | Created | Stored | Rotated | Effect of rotation |
|---|---|---|---|---|
| `SECRET_KEY` | `make init`, 32 bytes from `openssl rand` | file, mode 0400, mounted read-only | operator, on suspicion of exposure | every session cookie and CSRF token is invalidated; everyone signs in again |
| `APP_DB_PASSWORD` | `make init` | file, as above | operator | the application reconnects; no data effect |
| `REDIS_PASSWORD` | `make init` | file, as above | operator | rate-limit counters reset |
| Share tokens | per label, `secrets.token_urlsafe(32)` | database column | owner, from the label screen | the printed label stops working immediately |
| Password hashes | per user | database column | on password change, and transparently when cost parameters rise | prior sessions are invalidated |

No key is shared between more than the two parties that need it (the
application and the store it authenticates to). Secrets are read from files
rather than the environment (D-36, "Secrets as files, not environment
variables") so they do not appear
in `docker inspect` or in any child process's `/proc/<pid>/environ`;
`make verify-secrets` checks that property rather than assuming it.

**Operator** — custody of the host directory holding those files, the schedule
on which they are rotated, and destruction of superseded copies are deployment
obligations. A managed vault would satisfy `v5.0.0-13.3.1` more completely
than a mounted directory; the mount point is the seam where one would attach.

## 7. Third-party components: remediation deadlines — v5.0.0-15.1.1, v5.0.0-15.2.1

Deadlines run from the moment a fix becomes available to this project — a
released upstream version, a distribution package, or a viable upstream patch
— not from disclosure, because a deadline that starts before a remedy exists
cannot be met and so is not a deadline.

| Severity of the finding, as it applies here | Deadline | Gate |
|---|---|---|
| Critical, reachable from the application | 72 hours | image scan fails the build |
| High | 7 days | image scan fails the build at `--severity HIGH` |
| Medium | 30 days | recorded in the alert register; release gate refuses an unaccepted medium |
| Low | 90 days, or the next routine dependency refresh | alert register |
| No fix available | reassessed weekly; mitigations recorded per alert | alert register |

"As it applies here" is doing real work: a scanner's severity is assigned to
the component, not to this deployment. Reachability, configuration and
container hardening are recorded per alert in
[alerts.json](alerts.json), and a finding whose residual risk is reduced still
carries its original severity in the record.

**Mechanism.** Renovate proposes dependency and base-image updates
continuously. Trivy and Grype gate every build and also run on a schedule, so
a component that was clean when it merged is re-examined without waiting for
the next commit. Both run without `--ignore-unfixed`: an unavailable patch is
still a risk and stays visible. A CycloneDX SBOM is generated per build and
retained, so "which versions were in the image we shipped" is answerable
after the fact.

Passing a gate is not the same as meeting a deadline: the gate blocks a build,
while the deadline governs the register. A finding past its deadline without
an approved, time-limited exception in [exceptions.json](exceptions.json) is a
release blocker.

## 8. Logging policy — v5.0.0-16.2.5, v5.0.0-16.4.2

**What is recorded.** Authentication outcomes, lockouts, access denials,
share resolution misses, upload accept/reject, and every mutation, as an
append-only hash-chained `audit_log` table plus structured JSON to stdout.

**What is never recorded.** Passwords, PINs, session cookies, CSRF tokens,
share tokens, and secret values of any kind. Three mechanisms, because one is
not enough:

- structured fields are redacted by key name (`SENSITIVE_KEY_FRAGMENTS`);
- request paths and `Referer` URLs are scrubbed, after percent-decoding, so
  `/t/<code>` and `/%74/<code>` are both reduced;
- free-text messages and exception tracebacks are scrubbed for
  share-code-shaped values and for `key=value` pairs whose key is sensitive,
  because a message has no keys and a library's exception text is not ours to
  choose.

**Retention and access.** The `audit_log` table is append-only for the
application's database role — `UPDATE` and `DELETE` are revoked, so the
application cannot rewrite its own history even if compromised. Container
stdout is collected by the Docker daemon under the host's log driver.

**Operator** — retention period, access control on the host's log store, time
synchronisation of the host clock, and shipping to a separate system for
alerting (`v5.0.0-16.4.3`) are deployment obligations that no code in this
repository can discharge. They are recorded as unmet rather than as not
applicable.
