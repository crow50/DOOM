# D.O.O.M. - Security Controls

Every control below answers a threat named in [THREAT-MODEL.md](THREAT-MODEL.md)
and names the file that implements it. Reasoning behind the specific numbers
and algorithms is in [DECISIONS.md](DECISIONS.md).

The organising idea: **`app/doom/validation.py` is the single source of truth
for every limit in the system.** No form, column, template or constraint
invents a number. A limit is defined once and enforced at every layer capable
of enforcing it, so it cannot be tightened in one place and left loose in
another.

---

## 1. Control matrix

### Input validation

| Threat | Control | Where |
|---|---|---|
| Unbounded / malformed input | Every limit a named constant, enforced at each layer that can | `validation.py` |
| Oversized text | HTML `maxlength` → WTForms `Length` → column length → Postgres `CHECK` | `forms.py`, `models.py` |
| Out-of-range integers | `NumberRange` → column type → `CHECK` | `forms.py`, `models.py` |
| Arbitrary enum values | `SelectField` validates against its own choices | `forms.py` |
| T-32 ReDoS | Anchored regexes, single character class, no nested quantifiers | `validation.py` |
| Homograph usernames | NFKC normalisation + casefold before uniqueness; CITEXT unique index | `validation.py`, `models.py` |
| T-10 Mass assignment | Objects built field-by-field from validated forms; never `**request.form` | all blueprints |

A text field is bounded four times; an upload is bounded by Caddy, Flask,
a magic-byte sniff and a re-encode; an integer three times. The count varies
by data type - what does not vary is that the browser is never the last word.

**Worked example - one constant, four enforcement points:**

```
validation.py   ITEM_NAME_MAX = 120
       ├── forms.py       Length(max=v.ITEM_NAME_MAX)
       ├── models.py      String(v.ITEM_NAME_MAX)
       ├── models.py      CHECK (char_length(name) BETWEEN 1 AND 120)
       └── template       maxlength rendered from the same constant
```

### Authentication

| Threat | Control | Where |
|---|---|---|
| T-01 Brute force | Argon2id `t=3, m=64MiB, p=4`; 12-char minimum; breach-list screen | `security/passwords.py` |
| T-01 | Per-IP limit (10 / 15 min) + per-account lockout (5 failures) | `blueprints/auth.py` |
| T-02 Username enumeration | Identical error text; dummy Argon2 verify when the user does not exist | `security/passwords.py` |
| T-02 | Login form deliberately skips shape validation so all attempts take one path | `forms.py` |
| T-03 Cookie theft | `HttpOnly`, `Secure`, `SameSite=Lax`, 12-hour lifetime | `config.py` |
| T-04 Session fixation | `session.clear()` then re-issue on login | `blueprints/auth.py` |
| T-05 Forged cookie | Startup **fails closed** if `SECRET_KEY` is missing or a placeholder | `config.py` |
| T-06 Stale session after password change | `session_version` compared in the user loader | `blueprints/auth.py` |
| T-31 Lockout as DoS | Backoff **capped at 15 min**, self-expiring, no operator needed | `models.py`, `validation.py` |

### SQL injection

| Threat | Control | Where |
|---|---|---|
| T-08 | SQLAlchemy ORM throughout; zero string interpolation into SQL | all blueprints |
| T-08 | The one raw query uses `text()` with bound parameters | `blueprints/items.py` |
| T-35 Post-injection escalation | App connects as `doom_app`: DML only, not superuser, not owner | `db/init/01-roles.sh` |
| T-35 | Migrations use a **separate** admin DSN the app never holds | `Makefile` |

**The worked example, `blueprints/items.py`:**

```python
term = form.q.data.strip()[: v.SEARCH_QUERY_MAX]
escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
query = query.where(
    text("(items.name ILIKE :term ESCAPE '\\' "
         "OR coalesce(items.description, '') ILIKE :term ESCAPE '\\')")
    .bindparams(term=f"%{escaped}%")
)
```

The statement and the value travel separately, so the database never parses
user input as SQL. Writing `text(f"... ILIKE '%{term}%'")` instead is the
entirety of CWE-89. Wildcards are escaped so searching `100%` is a literal
search, not a match-everything scan.

**Verified** - as `doom_app`:

```
DROP TABLE items;          ERROR: must be owner of table items
SELECT * FROM pg_shadow;   ERROR: permission denied for view pg_shadow
CREATE TABLE pwned(x int); ERROR: permission denied for schema public
SELECT rolsuper ...        f
```

### Cross-site scripting

| Threat | Control | Where |
|---|---|---|
| T-19 | Jinja2 autoescaping on; **zero `\|safe` on user data**, enforced by `make lint` | templates, `Makefile` |
| T-19 | CSP with **no `unsafe-inline`** - all JS and CSS external | `security/headers.py` |
| T-12 Sniffed content | `X-Content-Type-Options: nosniff` globally and per file response | `security/headers.py`, `blueprints/files.py` |
| Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | `security/headers.py` |
| Token leak via referrer | `Referrer-Policy: same-origin` (see D-22); outbound links `rel="noopener noreferrer nofollow"` | `security/headers.py`, templates |

The CSP holds at `script-src 'self'` with no nonces **because** no template
contains an inline script or style. That is a design constraint the codebase
maintains, not a header copied in.

### Access control

| Threat | Control | Where |
|---|---|---|
| T-18 IDOR | Ownership is a `WHERE` clause; `get_owned_or_404` | `security/authz.py` |
| T-18 | Misses return **404, never 403** - 403 confirms existence | `security/authz.py` |
| T-18 | Cross-account writes: both ends of a move are checked | `blueprints/items.py` |
| Enumeration | UUID primary keys; no sequential ids to walk | `models.py` |
| T-26 Open redirect | `?next=` must be a single-slash relative path | `security/redirects.py` |
| T-09 CSRF | `CSRFProtect` globally; no state change on GET; POST + token for every mutation | `extensions.py` |

```python
def get_owned_or_404(model, obj_id):
    return db.session.execute(
        select(model).where(model.id == parsed, model.owner_id == current_user.id)
    ).scalar_one_or_none()
```

Fetch-then-check leaves a window between loading and deciding and leaks
existence through behaviour. Filtering inside the query makes an unauthorised
id and a nonexistent one the same event: zero rows.

### Public sharing

| Threat | Control | Where |
|---|---|---|
| T-20 Leaked URL → catalogue | Reduced serializers: owner, ancestors and history are **absent, not hidden** | `security/serializers.py` |
| T-20 | Share pages never link upward or sideways; no public index or search exists | `blueprints/share.py` |
| T-20 | Per-IP limits (30/min, 300/hr) make scraping impractical | `blueprints/share.py` |
| T-20 | `Referrer-Policy: same-origin` - token never travels to an outbound link | `blueprints/share.py` |
| T-37 | Site address absent from public serializers; only a site may hold one | `security/serializers.py`, `forms.py` |
| T-21 Search indexing | `X-Robots-Tag: noindex` + `robots.txt` + `<meta robots>` | `blueprints/share.py`, `main.py` |
| T-36 Token treated as authorisation | Token resolves to a read-only view; no mutating route exists under `/t/` | `blueprints/share.py` |
| Leaked link | Optional Argon2-hashed share PIN; rotation revokes instantly | `models.py`, `blueprints/labels.py` |

The threat is not the person holding the tag - they are already at the bin. It
is a **leaked URL**: a photo of a label posted online, a link forwarded once
too often. Hence: private by default, no upward links, nothing to enumerate.

### File security

| Threat | Control | Where |
|---|---|---|
| T-12 Disguised file | Type from magic bytes; filename and `Content-Type` ignored | `security/uploads.py` |
| T-12 Polyglot / embedded payload | Full decode and re-encode through Pillow | `security/uploads.py` |
| T-12 SVG, archives | Rejected by allowlist | `validation.py` |
| T-22 GPS in photos | EXIF destroyed by re-encoding | `security/uploads.py` |
| T-29 Decompression bomb | `Image.MAX_IMAGE_PIXELS` bounded | `security/uploads.py` |
| T-11 Path traversal | Stored names are generated UUIDs; no user string reaches a path | `security/uploads.py` |
| T-28 Oversized upload | Caddy 12 MB → Flask 10 MB → per-file check | `Caddyfile`, `config.py` |
| T-24 Direct file access | Caddy serves **no** route for the uploads volume | `Caddyfile` |
| Inline document execution | PDFs always `Content-Disposition: attachment` + sandbox CSP | `blueprints/files.py` |

**Verified** - a JPEG with `<script>alert('xss')</script>` appended stored at
4048 bytes, byte-for-byte the size of the clean re-encode, with zero matches
for `script`. Stored filenames are UUIDs at mode `0600`; the original name
lives only in the database.

### Account, activity, and export

| Threat | Control | Where |
|---|---|---|
| Cross-account activity disclosure | `actor_user_id == current_user.id` as a `WHERE` clause | `blueprints/account.py` |
| T-38 CSV formula injection | Cells starting `= + - @` prefixed with `'`; export always `Content-Disposition: attachment` + nosniff | `blueprints/account.py` |
| Unbounded serialisation | Feed pages at 50 rows; export capped at 10,000 | `validation.py` |
| Filter parameter tampering | Action filter checked against the known action set (allowlist) | `blueprints/account.py` |
| T-10 Mass assignment on profile | Fields assigned individually; `session_version` / `is_active` unbindable | `blueprints/account.py` |
| Excess data collection | Every profile field optional; email never used for delivery | `models.py`, `forms.py` |

### Custody and history

| Threat | Control | Where |
|---|---|---|
| T-15 Oversubscribed checkout under concurrency | `SELECT ... FOR UPDATE` on the item before availability is computed - the invariant spans two tables, so atomic arithmetic is not enough | `blueprints/items.py` |
| T-18 Returning another account's checkout | Checkout resolved scoped to an item already ownership-filtered | `blueprints/items.py` |
| T-16 Custody repudiation | Closed checkouts retained as evidence, never deleted | `models.py` |
| Unnoticed share access | Anonymous `share_viewed` events surfaced on the owner's timeline with source address | `timeline.py` |
| T-20 History leaking through a share page | Public serializer contains no history at all | `security/serializers.py` |
| Bounded output | Timeline capped at 40 entries per object | `validation.py` |

### Barcodes, lookup, and storage

| Threat | Control | Where |
|---|---|---|
| T-43 A printed barcode carrying a payload | Single choke point `^[0-9]{8,14}$` before any use; rejected not sanitised; never navigated to | `validation.py`, `forms.py`, `static/js/scan.js` |
| T-43 | Restated as a database `CHECK`, so no path can bypass it | `models.py` |
| T-40 SSRF via lookup | Provider from a dict in code; `allow_redirects=False`; private ranges blocked | `security/lookup.py` |
| T-41 Hostile upstream | Timeouts, 256 KB cap, expected keys only, own length limits | `security/lookup.py` |
| T-42 Third-party disclosure | Off by default; opt-in; every call audited | `config.py`, `blueprints/items.py` |
| T-46 Disk exhaustion | Per-account quota checked before write | `security/uploads.py` |
| T-47 Shared-blob inference | Dedup scoped per owner, never global | `security/uploads.py` |
| T-45 Audit tampering | Hash chain + `UPDATE`/`DELETE` revoked from the app role | `security/audit.py`, `db/init/01-roles.sh` |
| T-44 Search scope | Both halves built on `owned_query()` | `blueprints/search.py` |

**The barcode point, stated plainly for the demo:** a barcode is not a number.
Code128 and QR encode arbitrary bytes, anyone can print one, and it arrives
wearing the authority of a physical object — which is exactly why it gets
trusted when it should not be. `BarcodeDetector.rawValue` is as hostile as any
form field.

**The lookup point:** D-13 forbids fetching *a URL the user supplied*. The
lookup calls *a fixed URL template belonging to a provider chosen from a dict
in code*, with a validated numeric barcode substituted in. The user supplies a
parameter, never a destination. That is the whole difference between an API
client and an SSRF hole.

### SSRF, errors, logging

| Threat | Control | Where |
|---|---|---|
| T-25 SSRF | User URLs are **never fetched server-side**; link previews out of scope | `models.py`, `forms.py` |
| T-25 | Scheme allowlist `{http, https}`; embedded credentials rejected; DB `CHECK` restates it | `forms.py`, `models.py` |
| T-23 Stack traces | `DEBUG` forced off; startup raises if set | `config.py` |
| T-23 | Generic pages; user sees only a correlation ID | `blueprints/errors.py` |
| T-23 | Fallback page renders without Jinja, so a template fault cannot escape to a framework default | `blueprints/errors.py` |
| T-17 Log injection | Structured JSON; encoder escapes newlines | `security/logging.py` |
| Secret leakage into logs | Redaction filter on sensitive-looking keys | `security/logging.py` |
| T-16 Repudiation | `audit_log` + `movements`; denied access recorded too | `security/audit.py` |

### Infrastructure

| Threat | Control | Where |
|---|---|---|
| T-34 Container escape | Non-root uid 10001, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs | `docker-compose.yml`, `Dockerfile` |
| T-34 Network exposure | `db` and `cache` on an `internal: true` network; no published ports | `docker-compose.yml` |
| T-07 Rate-limit evasion | Caddy **overwrites** `X-Forwarded-For`; `ProxyFix(x_for=1)` | `Caddyfile`, `__init__.py` |
| T-14 Host header poisoning | Label URLs from `PUBLIC_BASE_URL`, never `request.host_url` | `blueprints/labels.py` |
| T-33 Limiter fails open | `swallow_errors=False` - a cache outage is a 503, not a silent bypass | `extensions.py` |
| T-27 Secret leakage | `.gitignore` / `.dockerignore`; `make init` generates; placeholders fail loudly | `.env.example`, `config.py` |
| T-15 Lost update | Atomic `UPDATE ... SET quantity = quantity + :delta` | `blueprints/items.py` |

**Verified** - `id` → `uid=10001(doom)`; writing to `/srv/doom` → *Read-only
file system*; `docker compose ps` shows no published port for `db` or `cache`.

---

## 2. Two controls worth dwelling on

### Defence in depth at the database

Most applications stop at "we use an ORM". DOOM adds a second layer that
assumes the first one failed: the application's database role holds only
`SELECT/INSERT/UPDATE/DELETE`. It is not superuser and does not own the
schema, so even a successful injection cannot drop a table, define a function,
or read `pg_shadow`.

This has a consequence that has to be designed for rather than discovered: a
DML-only role cannot run migrations either. Alembic therefore uses a separate
`ADMIN_DATABASE_URL` supplied only by `make upgrade`, and the running
application never holds those credentials.

### The control that is an absence

Share pages are rendered from plain dictionaries built by
`security/serializers.py`, not from ORM objects. The owner, the ancestor chain
and the movement history are not hidden behind template conditionals - they
are never put into the view model.

The difference matters because template guards fail silently. Add a field to a
shared page, forget the guard, and the page still renders and still looks
correct to whoever wrote it, while quietly publishing which site a bin
sits in. A field that was never passed cannot be rendered by mistake.

---

## 3. What the tests pin

`make test` runs the whole suite; the count is published once, in
[COMPLIANCE.md](COMPLIANCE.md) §6, and `make lint` fails if this file starts
quoting its own. The tests exist to stop a control regressing silently.

| Area | What is asserted |
|---|---|
| Validation | Limits hold; Unicode lookalikes collapse; allowlists reject |
| Passwords | Argon2id prefix, unique salts, breach-list, username-in-password |
| Lockout | Triggers at threshold, **expires unaided**, backoff is capped |
| Sessions | `session_version` bump invalidates an existing session |
| Enumeration | Unknown user and wrong password give identical responses |
| Access control | Cross-account read is **404 not 403**; malformed id takes the same path |
| Mass assignment | Injected `owner_id` / `visibility` / `share_token` ignored |
| Uploads | Disguised script, SVG and archive rejected; payload does not survive re-encode; EXIF stripped; stored name generated |
| Custody | Cannot oversubscribe; cannot return another account's checkout; closed rows retained |
| Timeline | Merges movements, custody and audit; anonymous share views flagged with source address; never on a shared page |
| Sharing | Serializer omits owner/ancestors/history; parent token does not unlock a child; rotation kills the old link; no index route |
| Redirects | `//evil.com`, `/\evil.com`, absolute URLs and `javascript:` all rejected; back-links validated against `PUBLIC_BASE_URL` |
| Address privacy | Never in a public serializer; never rendered on a shared page; rejected on non-site kinds |
| CSV export | Formula prefixes neutralised; export scoped to the signed-in user |
| Headers | CSP carries no `unsafe-inline`; `Referrer-Policy` permits same-origin referrers so CSRF keeps working |
| Breach corpus | Every entry clears `PASSWORD_MIN`, so the screen can actually fire; a 12+ character breached password is rejected |
| Strength meter | Served, referenced by both password forms, and not the authority — the server still rejects what it approves |
| Cookie prefix | The session cookie carries `__Host-`, and the attributes that prefix requires are all set |
| Route coverage | Every endpoint in `url_map` is classified; a new one fails the suite until its scoping is recorded |
| Denied access | A refused object access survives the 404 that follows it, on the locking path as well as the ordinary one |
| Share tokens | A capability token reaches neither the application log nor gunicorn's access log, in the path or the `Referer` |
| Database roles | `make verify-db-roles` - the app role exists, can do DML, and can do neither DDL nor anything to `audit_log` |

Several of these were written because the control is one that *fails quietly*:
session revocation (bump the column, forget the comparison, and it still looks
like it works), lockout expiry, and serializer omissions.

The last four rows exist because an audit found controls that were written but
not working. The breach corpus held 124 entries of which 123 were below the
length floor, so the screen could only ever match one string. The denied-access
audit record was added to the session and then rolled back by the 404 that
followed it, so the trail recorded no denials at all. Neither had a test, which
is why neither was noticed.

---

## 4. Accepted risk

Recorded rather than hidden. Full reasoning in [DECISIONS.md](DECISIONS.md).

1. **Registration reveals whether a username is taken.** Unavoidable - the
   form must say so. Mitigated by rate limiting.
2. **A valid unrevoked share token discloses that one node.** Inherent to
   printing a scannable label. Bounded by scope reduction, rate limits,
   `noindex`, an optional PIN, and rotation.
3. **A griefer can impose repeated 15-minute lockouts** on a username they
   know. Bounded, not eliminated.
4. **A compromised account exposes that user's whole inventory.** There is no
   inner boundary below the account.
5. **No antivirus scanning of uploads** (ASVS 12.4.2, Level 1). Images are
   decoded and re-encoded, which destroys an embedded payload — but PDF, text
   and Markdown uploads are stored byte for byte. Files are never executed and
   always served as attachments with `nosniff`. ClamAV is the answer and it is
   not implemented.
6. **No TLS between containers** (1.9.1, 1.9.2, 9.2.2). Three internal hops are
   plaintext. The compensating position — an `internal: true` network with no
   route off the host, and passwords on both services — is argued in
   [COMPLIANCE.md](COMPLIANCE.md) §3, not counted as a pass.
7. **Logs are not shipped off-host** (1.7.2). Structured JSON to stdout is what a
   collector consumes, but nothing collects it here.
8. **No SBOM** (14.2.5). Tracked separately.

Dependency CVE scanning is **no longer** on this list: `pip-audit`, Trivy and
Renovate all run, and the lockfile is hash-pinned. See
[PIPELINE-NOTES.md](PIPELINE-NOTES.md) for what runs where, and
[COMPLIANCE.md](COMPLIANCE.md) for the full ledger — these eight are the ones
worth reading in isolation, not the complete set.
