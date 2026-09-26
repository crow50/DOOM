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

**Against NIST SP 800-63B.** AAL1 asks for a 30-day absolute limit and a
12-hour inactivity limit; AAL2 asks for 12 hours absolute and 30 minutes idle.
The absolute lifetime here is 12 hours, which meets AAL2. The idle timeout is
60 minutes, which does not, and the deviation is deliberate for the reason
above: this is a physical-inventory tool used while walking around a building,
the data is a map to property rather than to money or health records, and the
alternative to a workable timeout is a user who never signs out. The controls
that carry the difference are the 12-hour absolute cap, per-device revocation
that takes effect on the next request, a concurrent-session limit, and - for
accounts that enable it - a second factor on every new sign-in.

**Why eviction rather than refusal.** Refusing the eleventh sign-in locks
someone out of the device in their hand because of a session they forgot on a
machine they no longer own, with an operator as the only way back. Every
session is listed on the account page with its address, device and last-seen
time, and any one can be ended individually after re-entering the password.

Ending a session revokes the row rather than only dropping the cookie, so a
copied cookie cannot be retried, and sign-out sends `Clear-Site-Data` for
cache, cookies and storage.

## 6. Cryptographic policy and key lifecycle — v5.0.0-11.1.1, v5.0.0-11.4.1

**Algorithms in use.** Argon2id (t=3, 64 MiB, p=4) for passwords, share PINs
and recovery codes; HMAC-SHA256 for the session cookie, the CSRF serializer and
the share PIN approval; SHA-256 for content addressing and the audit hash
chain; `secrets` (the OS CSPRNG) for every token, code and salt. Every
primitive provides at least 128 bits of security.

**The one exception, and why it is one.** `security/totp.py` uses HMAC-SHA1,
because RFC 6238 fixes it as the default TOTP construction and authenticator
applications implement that and only that — a SHA-256 variant would be a second
factor nobody could enrol. NIST SP 800-131A Rev. 2 still permits HMAC-SHA1; it
is SHA-1 *signatures* that are withdrawn, and this is a MAC over a 160-bit
secret with a 30-second validity. The exception is confined to that one module
and a test asserts "SHA-1 appears there and nowhere else" rather than exempting
the file, so a second use anywhere in the package fails the suite.

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

A mounted certificate is the one key in this table that nothing here renews.
Caddy reads a `tls <file>` certificate once, at config load, and does not watch
the file, so a renewal in place keeps serving the old certificate until the
container restarts — and then keeps serving it past expiry. `make verify-cert`
compares the file on disk against what is actually on the wire and fails when
they differ, which turns that from something an operator has to remember into
something they can check.

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
[findings.json](findings.json), and a finding whose residual risk is reduced still
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

## 9. Communication needs and the outbound allowlist — v5.0.0-13.1.1, v5.0.0-13.2.4, v5.0.0-13.2.5

**Every connection this application makes, in full.**

| From | To | Protocol | Authenticated by | When |
|---|---|---|---|---|
| Browser | Caddy | HTTPS | — | every request |
| An operator's own reverse proxy | Caddy | HTTPS | — | only in the topology where something else terminates public TLS |
| Caddy | `web:8000` | HTTPS, verify-full against the internal CA, over an internal-only Docker network | TLS certificate (CN=web) | every request |
| `web` | `db:5432` | PostgreSQL, TLS required (`hostssl`), verify-full | restricted role + file-mounted password + TLS certificate (CN=db) | every request |
| `web` | `cache:6379` | Redis, TLS-only (`port 0`), verify-full | file-mounted password + TLS certificate (CN=cache) | rate-limit checks |
| `web` | a barcode provider | HTTPS | none (public API) | **only** when `BARCODE_LOOKUP_PROVIDER` is set |
| Caddy | an ACME directory | HTTPS | ACME account key | **only** when `DOOM_DOMAIN` is a public name |
| `clamav` | database.clamav.net | HTTPS | ClamAV's own CVD signature verification | signature updates, periodic |
| `web` | `clamav:3310` | clamd `INSTREAM` protocol over an internal-only Docker network | — | every upload |

The second row is optional and operator-chosen: a homelab that already runs
Traefik or its own Caddy as the thing holding certificates can put it in front
of this stack. That topology needs the upstream declared in `trusted_proxies`,
or every visitor collapses into one per-IP rate-limit bucket and every audit
row records the proxy's address — a failure that is invisible until it
matters. `caddy/conf.d/README.md` covers it, along with the two other routes
to a publicly trusted certificate, and `evidence/proxy-client-ip.txt` records
that declaring a proxy is what changes the behaviour and that the default
ignores a forged chain.

There is no telemetry, no analytics, no error-reporting service, no CDN, no
webfont and no third-party script. A page this application serves makes
requests to its own origin and nowhere else, which is what `connect-src 'self'`
in the CSP states and what the absence of any external `<script>` or `<link>`
in the templates enforces.

**The user-supplied-destination case**, which the requirement asks about
specifically: there is exactly one, the barcode lookup, and the user does not
supply a destination. They supply a *barcode*. The provider is named by an
operator-set configuration value that selects an entry in a dict in code
(`validation.BARCODE_PROVIDERS`), the scheme and host come from that entry, and
redirects are refused. A request cannot be steered by anything a user types.

**The server-level allowlist is a deny-all.** The application container is on
two Docker networks, both `internal: true` — `proxy`, which Caddy bridges to
reach it, and `internal`, which carries the database and the cache. It has no
route off the host. An SSRF in the application therefore has nowhere to go,
which is worth more than the validation in `security/lookup.py` because it
holds even when that validation is wrong.

Enabling `BARCODE_LOOKUP_PROVIDER` requires adding the `edge` network back to
the `web` service in `docker-compose.yml`. That is deliberately a change an
operator has to make and a reviewer can see, rather than a capability that is
always present and merely unused. Until DNS rebinding is closed in the lookup
path — address validation and connection perform separate resolutions — the
recommendation in the release assessment stands: leave it unset.

**`clamav` is the one exception that is not operator-opt-in.** It sits on its
own `clamav_updates` network — a real route off the host, unlike every other
network in this stack — because a scanner that never updates its signatures
is not meaningfully scanning. That network carries only `clamav`, reaches only
`database.clamav.net`, and publishes no port, so it grants egress without
granting LAN reachability. `web` still cannot reach the internet: it talks to
`clamav` over `internal`, the same no-route-off-host network it already shares
with `db` and `cache`.

## 10. Upload rules — v5.0.0-5.1.1

| | |
|---|---|
| Permitted content types | `image/jpeg`, `image/png`, `image/webp`, `application/pdf`, `text/plain`, `text/markdown` |
| Expected extensions | per type, in `validation.UPLOAD_EXTENSIONS_FOR_TYPE` |
| Maximum size, per file | 10 MB (`UPLOAD_MAX_BYTES`), rejected by Caddy at 12 MB before Python sees it |
| Maximum decoded size | 50,000,000 pixels (`MAX_IMAGE_PIXELS`), checked before decoding |
| Files per request | 10 |
| Per-account ceiling | 2 GB and 5,000 files |
| Archives | not accepted, so there is no unpacked size to bound |

**How a file is made safe.** Type is decided by libmagic from the bytes, never
from the filename or the browser's `Content-Type`. The submitted extension must
then agree with the sniffed type. Images are fully decoded and re-encoded into
a new container, which destroys polyglots and strips EXIF — including the GPS
coordinates that would otherwise publish the address of the building a photo of
a shelf was taken in. Stored names are generated UUIDs; the submitted name is
kept for display only and never joined to a path.

**What happens when a malicious file is detected.** clamd scans the raw bytes
of every upload - image or document - before anything is decoded
(`v5.0.0-5.4.3`, `app/doom/security/av.py`). A match is refused with a generic
message and audited with the scanner's signature name; so is a scanner that
does not answer, times out, or replies with something this client does not
recognise - the scan fails closed rather than degrading to "allow" when clamd
is unreachable. This sits alongside, not instead of, the controls that
predate it: SVG and archives are refused outright as types; anything that is
not an image is served with `Content-Disposition: attachment`,
`Content-Security-Policy: default-src 'none'; sandbox` and `nosniff`, so a
document cannot execute in this origin; and downloads are owner-authorised
only, so a malicious file one account uploads is not reachable by another.
`app/tests/test_uploads.py::TestAntivirusScanning` exercises the clean, the
EICAR-positive and the scanner-unavailable cases.

## 11. Data classification — v5.0.0-14.1.1, v5.0.0-14.1.2, v5.0.0-14.2.4

| Level | Data | Handling requirements |
|---|---|---|
| **Secret** | passwords, share PINs, recovery codes, TOTP secrets, `SECRET_KEY`, database and Redis passwords | never stored in the clear (Argon2id for the first three); never logged, in any form, hashed or otherwise; never in a URL; never in a response body; secrets read from mode-0400 files, not the environment |
| **Credential** | session cookies, CSRF tokens, share tokens, share handles | transmitted only in `Set-Cookie` or a request body; redacted from every log by key, by path and by shape; never in a URL or query string; `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefix |
| **Personal** | username, display name, email, timezone, source IP, user agent, activity history | `Cache-Control: no-store` on every authenticated response; visible only to the account itself; exportable by the owner; email never used for delivery; user agent truncated to 200 characters so it is a device label and not a fingerprint |
| **Inventory** | item and location names, descriptions, notes, quantities, photos, documents, physical addresses | owner-scoped by a `WHERE` clause; the ancestor chain — which *is* the physical address — is omitted from every shared view; image metadata stripped on upload |
| **Shared-by-choice** | the reduced view behind a share link | exactly the fields in `security/serializers.py` and no others; `noindex` on every response and in `robots.txt`; rate limited; revocable and rotatable by the owner |
| **Public** | the landing page, static assets, `robots.txt` | no requirements |

Two notes on things that look encoded and are not encrypted. A share token is
random rather than derived, so there is nothing in it to decode. The audit
chain's row hashes are SHA-256 over the row's content and are integrity values,
not confidentiality ones — they are published on the account page on purpose,
so a user can check their own history has not been rewritten.

**Retention.** Inventory and personal data live until the owner deletes them or
the account is deleted, which cascades. Audit rows are append-only and are never
deleted by the application — including by the account they describe, because a
history a user can edit is not a history. There is no automatic expiry; an
operator who needs one owns that decision and the compliance regime that
motivates it.

**Regulatory scope.** A self-hosted single-tenant inventory holding the
operator's own property records. No payment data, no health data, no data about
third parties beyond an optional email address the account holder supplies
about themselves. Where GDPR applies, the operator is the controller; access,
export and erasure are served by the account page, the CSV export and account
deletion respectively.

## 12. Logging inventory — v5.0.0-16.1.1, v5.0.0-16.2.3

| Layer | Events | Format | Destination | Retention | Access |
|---|---|---|---|---|---|
| Application | auth outcomes, lockouts, access denials, share misses, uploads, config and factor changes, unexpected errors | JSON, one object per line, UTC timestamps | stdout → Docker log driver | host log driver's policy | host operator |
| Application | every mutation and every security-relevant event | `audit_log` table, hash-chained | PostgreSQL | unbounded; never deleted | the acting account (own rows), operator (all) |
| gunicorn | access log, with share paths scrubbed | JSON via `security/gunicorn_logging.py` | stdout | as above | host operator |
| Caddy | access log, TLS errors | JSON | stdout | as above | host operator |
| PostgreSQL / Redis | engine logs | text | stdout | as above | host operator |

Nothing is written to a file inside any container: the application's filesystem
is read-only apart from the uploads volume and a 64 MB tmpfs. Nothing is
broadcast anywhere else — there is no log shipper configured, which is the open
gap at `v5.0.0-16.4.3`.

**Correlation.** Every request carries a correlation id, which appears in each
log line for that request and on the error page the user sees, so a report of
"I got an error at 14:20" resolves to exact lines without the user having to be
shown a stack trace.

## 13. Business logic limits and consistency — v5.0.0-2.1.2, v5.0.0-2.1.3, v5.0.0-2.3.2

**Per-user limits:** 2 GB and 5,000 attachments; 10 concurrent sessions; 10
files per upload request; location nesting to 12 levels; quantity between 0 and
1,000,000; the rate limits in section 2.

**Global limits:** a shared location listing is capped at 500 contents; search
terms at 100 characters; the request body at 10 MB.

**Combined-item consistency**, which is what `2.1.2` and `2.2.3` ask to see
documented. The rules that relate one field to another:

- an attachment belongs to exactly one parent — an item or a location, never
  both and never neither. Enforced by a `num_nonnulls` CHECK in the database,
  not only in code, because a bug in the application should not be able to
  produce a row that violates it;
- a location's `depth` must equal its parent's depth plus one, and a location
  cannot be its own ancestor;
- an item's location, if set, must belong to the same owner as the item;
- a checkout must be open before it can be returned, and a returned checkout
  cannot be returned twice;
- a quantity adjustment is computed by the database from the current value
  rather than submitted by the client, so two concurrent adjustments cannot
  both write the same result (D-18);
- a share PIN may exist only on a node that is shared.

There is no address or postcode validation of the kind the requirement's
example describes, because the one address field is free text describing a
building the owner already knows how to find; validating it against a postal
database would reject correct rural addresses and buy nothing.

## 14. Resource-demanding functionality — v5.0.0-15.1.3, v5.0.0-15.2.2

Three things here cost materially more than a page view, and each is bounded:

| Operation | Cost | Bound |
|---|---|---|
| Password and recovery-code verification | 64 MiB and ~50 ms of Argon2id, per attempt | rate limits and lockout; `PASSWORD_MAX` caps input; gunicorn concurrency is pinned in compose so workers × threads × 64 MiB fits the container's memory limit |
| Image decode and re-encode | proportional to pixel count | `MAX_IMAGE_PIXELS` checked before decoding; 10 MB body cap; upload rate limit |
| Activity CSV export | proportional to history length | owner-scoped, streamed, and bounded by the same per-user rate limit as other reads |

Nothing here is asynchronous and nothing is queued, because nothing takes long
enough to need it — the longest operation is a single image re-encode. The
defence against a slow response is therefore a bound on the input rather than a
job queue, which is the right shape while that stays true. Recovery-code
verification is the one place the cost is deliberately *not* minimised: it
checks every unspent code even after a match, so a rejection's duration does
not reveal where in the list a near-miss sat.

## 15. Authentication pathways — v5.0.0-6.1.3, v5.0.0-6.3.4

There is exactly one way to obtain an authenticated session:

1. `POST /login` with a username and password, verified with Argon2id;
2. if the account has a confirmed second factor, `POST /login/verify` with a
   TOTP code or a single-use recovery code.

No other pathway exists. There is no SSO, no OAuth, no API key, no bearer
token, no "remember me" cookie, no magic link, no email-based reset (D-12), and
no administrative bypass — operator recovery is `flask set-password`, run
against the container by somebody who already has the host, and it is subject
to the same password policy as any other change.

Share links are not an authentication pathway and do not produce a session:
they carry a capability to one read-only view of one node, and every route
behind them is unauthenticated by design.

Strength is therefore consistent by construction rather than by enforcement:
there is only one path, so there is no weaker one to fall back to. The
second-factor step cannot be skipped by starting anywhere else, because there
is nowhere else to start — which is the property `6.3.4` is really asking about
and the reason this section is short.

## 16. Cryptographic inventory — v5.0.0-11.1.2

| Item | Algorithm / size | Where it may be used | Where it must not |
|---|---|---|---|
| `SECRET_KEY` | 256-bit random | signing the session cookie and the CSRF token; keying the share-PIN approval MAC | never as an encryption key, never shared between deployments |
| Password hashes | Argon2id, 64 MiB / t=3 / p=4, 32-byte output, 16-byte salt | verifying passwords, share PINs, recovery codes | not a KDF for any other key |
| Session / CSRF MAC | HMAC-SHA256 | integrity of self-contained tokens | not for storing anything |
| TOTP secrets | 160-bit random, HMAC-SHA1 per RFC 6238 | second-factor verification only | nothing else; see section 6 |
| Share tokens | 256-bit random (`token_urlsafe(32)`) | addressing a shared node | not an account credential |
| Share handles | 128-bit random (`token_urlsafe(16)`) | naming an entry in one visitor's signed session | confers nothing on its own |
| Attachment digests | SHA-256 | content addressing, per-owner deduplication | not an integrity guarantee against an attacker with database write access |
| Audit row hashes | SHA-256 chain | tamper *evidence* | not proof — the application's own role cannot rewrite history, which is evidence of tampering rather than prevention of it |
| TLS certificates | Caddy-managed by default — internal CA locally, ACME for a public name — or a certificate the operator mounts and names with `tls` | transport to the browser | a second, separate internal CA (`make init`) signs db/cache/web's certificates for caddy->web, web->db and web->cache — see `v5.0.0-12.3.1`, `12.3.3` |

All of it comes from `hashlib`, `hmac`, `secrets` and `argon2-cffi`, which is
to say from OpenSSL and from the Argon2 reference implementation. Nothing
cryptographic in this repository is hand-rolled except the TOTP arithmetic in
section 6, which is thirty lines of standard-library primitives pinned to the
RFC's published vectors.

**Agility.** Every algorithm choice is a named constant or a single class
attribute in one module: password parameters in `security/passwords.py`, the
signing digest in `security/sessions.py`, the TOTP construction in
`security/totp.py`. Password hashes carry their own parameters, so raising the
cost re-hashes each account silently at its owner's next sign-in. Raising the
signing digest invalidates every issued cookie, which is why it changes the
salt too. There is no encrypted data at rest to re-encrypt.
