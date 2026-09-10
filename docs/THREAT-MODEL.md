# D.O.O.M. - Threat Model

*Written before the implementation. Every control in [SECURITY.md](SECURITY.md) traces back to a threat named here, and every deliberate gap is recorded in [DECISIONS.md](DECISIONS.md) rather than left silent.*

---

## 1. What the system is

A self-hosted inventory management system. A user registers an account and builds a tree of physical places - **sites** (a geographic location, usually with an address), **zones** (a building or open yard within a site), **shelves** (fixed storage), and **bins** (anything you can carry) - recording items at any node in that tree. Any location can hold items directly; the tiers describe scale, not permission. Items carry descriptions, quantities, photographs, uploaded documents, and links to external documentation. Physical labels - QR codes and NFC tags - point at a stable URL for a bin or an item so that scanning a tote in a garage opens a page listing its contents.

The system is designed to run on hardware the operator controls: a laptop, a homelab server, a Raspberry Pi in a workshop. There is no SaaS tenant, no billing, and no email infrastructure.

---

## 2. Assets - what is actually worth protecting

Ranked by what an attacker would want and what a loss would cost the operator.

| # | Asset | Why it matters | Loss impact |
|---|---|---|---|
| A1 | **The inventory catalogue itself** | A list of what a person owns, in what quantity, at which physical address | **Enables physical theft.** This is the highest-value asset and the one most people would overlook |
| A2 | **Site addresses** | A site records a postal address; the tree maps items down to a shelf | **The single most sensitive field.** Everything else says what someone owns; this says where to drive to take it |
| A3 | **User credentials** | Password hashes, session cookies | Account takeover; password reuse damages the user elsewhere |
| A4 | **Uploaded files** | Photographs of possessions and premises, receipts, manuals, warranties | Photos leak interiors, serial numbers, and - via EXIF - GPS coordinates |
| A5 | **Share tokens** | Capability URLs printed on physical labels | A leaked token exposes a slice of A1/A2 without authentication |
| A6 | **Audit and movement history** | Who moved what, when | Reveals occupancy patterns - when a location is visited, and therefore when it is not |
| A7 | **Service availability** | The app and its data | An operator locked out of their own inventory; unrecoverable data loss |
| A8 | **Host and network** | The Docker host and its internal network | Full compromise; pivot to other services on the operator's LAN |
| A9 | **The audit trail itself** | The record of who did what, and when | An insider who can edit history can hide having taken something — which is why warehouse operations treat this as a primary asset, not a log |

**The defining insight of this threat model:** conventional web apps treat the database as the crown jewel because it holds *account* data. Here, the database is a **map to physical property**. A breach does not merely embarrass the operator - it hands a burglar a shopping list with addresses. Every design tradeoff below resolves in favour of protecting A1 and A2.

---

## 3. Actors

### Trusted
- **Operator** - runs the deployment, holds the `.env`, has shell and database access. Trusted absolutely; the system cannot defend against its own root.
- **Authenticated user** - owns their inventory tree. Trusted only with **their own** data. Not trusted with anyone else's, and not trusted to send well-formed input.

### Untrusted
- **Anonymous internet visitor** - can reach the login page, the registration page, and share URLs. Assumed hostile.
- **Share-link holder** - possesses a capability URL. May have obtained it legitimately (scanned a tag) or illegitimately (found a photo of a label online, read it over someone's shoulder, scraped it from a search index).
- **Physical visitor** - stands in front of a bin. Can read, clone, or rewrite an unlocked NFC tag.

### Adversary profiles

| Adversary | Goal | Capability | Priority |
|---|---|---|---|
| **Opportunistic scanner** | Any exploitable host | Automated tooling, no interest in this specific target | High - constant background traffic |
| **Burglar / reconnaissance** | Find valuable goods and their addresses | Browses whatever is publicly reachable; may scrape | **Highest - this is the adversary the domain uniquely attracts** |
| **Curious acquaintance** | Snoop on another user's inventory | A valid account on the same instance; will edit URLs and IDs | High - the classic IDOR attacker |
| **Griefer** | Deny the operator access | Knows a username; can hammer the login form | Medium |
| **Passer-by with a phone** | Tamper with labels | Can rewrite unlocked NFC tags | Low impact, trivially easy |

---

## 4. Trust boundaries

```
┌─ INTERNET ─ untrusted ──────────────────────────────────────────┐
│  anonymous visitors · share-link holders · scanners             │
└───────────────────────────┬─────────────────────────────────────┘
                            │  ① TLS · the only published port
┌───────────────────────────▼─────────────────────────────────────┐
│  caddy - TLS termination, body size cap, XFF normalisation      │
└───────────────────────────┬─────────────────────────────────────┘
                            │  ② HTTP over the docker network
┌───────────────────────────▼─────────────────────────────────────┐
│  web (gunicorn / flask) - non-root, read-only rootfs            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ ③ authentication  → is this a known user?                │   │
│  │ ④ authorisation   → do they own THIS object?             │   │
│  │ ⑤ input validation → is this data acceptable at all?     │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────┬─────────────────────────┬──────────────────┬─────────────┘
       │ ⑥ DML-only role         │ ⑦ authenticated  │ ⑧ file I/O
┌──────▼──────────┐   ┌──────────▼────────┐   ┌─────▼───────────┐
│ db (postgres)   │   │ cache (redis)     │   │ uploads volume  │
│ internal net    │   │ internal net      │   │ outside webroot │
└─────────────────┘   └───────────────────┘   └─────────────────┘
```

| # | Boundary | Crossing rule |
|---|---|---|
| ① | Internet → Caddy | TLS only. The sole published port. Request bodies capped before reaching the app |
| ② | Caddy → web | `X-Forwarded-For` is **overwritten**, never appended - a client-supplied value must never be believed |
| ③ | Anonymous → authenticated | Argon2id verification, rate limited, timing-equalised |
| ④ | Authenticated → **this** object | Ownership is a `WHERE` clause on every query. **The single most important boundary in the system** |
| ⑤ | Request data → application | Allowlist validation; models never built from raw form data |
| ⑥ | App → database | App role holds DML only. Cannot `ALTER`, `DROP`, or read `pg_shadow` |
| ⑦ | App → cache | Password-protected on an internal-only network |
| ⑧ | App → filesystem | No user-controlled string ever reaches a filesystem path |

---

## 5. Threats - STRIDE against the boundaries

Each threat carries the control that answers it. `T-##` identifiers are cited by name in `SECURITY.md`.

### Spoofing

| ID | Threat | Control |
|---|---|---|
| T-01 | Credential brute force / password spraying | Argon2id (deliberately slow), 12-char minimum, common-password screening, per-IP rate limit, per-account lockout |
| T-02 | Username enumeration via error text or response timing | Identical error message both ways; a dummy hash verify runs when the user does not exist, equalising timing |
| T-03 | Session hijacking via cookie theft | `HttpOnly` (blocks JS access), `Secure` (blocks plaintext), `SameSite=Lax`, TLS everywhere |
| T-04 | Session fixation | Session ID rotated on every login |
| T-05 | Forged session cookie | `SECRET_KEY` required from the environment; startup **fails closed** if missing or default |
| T-06 | Stolen session outliving a password change | `session_version` compared in the user loader; a bump invalidates every existing session |
| T-07 | Rate-limit evasion by spoofing `X-Forwarded-For` | Caddy overwrites the header; `ProxyFix` trusts exactly one hop |

### Tampering

| ID | Threat | Control |
|---|---|---|
| T-08 | SQL injection | ORM with bound parameters throughout; the one raw query uses `text()` with bind params. **Second layer:** the DML-only role means even a successful injection cannot `DROP` or escalate |
| T-09 | Cross-site request forgery | `CSRFProtect` globally; `SameSite=Lax`; no state change on a GET |
| T-10 | Mass assignment of `owner_id` / `visibility` / `share_token` | Objects built field-by-field from validated forms; never `**request.form` |
| T-11 | Path traversal via filename | Stored names are generated UUIDs. No user string reaches a path - **prevented by construction, not by filtering** |
| T-12 | Malicious upload (polyglot, embedded script, web shell) | Magic-byte sniff, allowlist, full decode-and-re-encode. SVG and archives rejected outright |
| T-13 | NFC tag rewritten by a passer-by | `makeReadOnly()` offered after writing; tags are treated as untrusted input regardless |
| T-14 | Host header poisoning of generated label URLs | URLs built from a configured `PUBLIC_BASE_URL`, never `request.host_url` |
| T-15 | Lost quantity update under concurrent scans | Atomic `UPDATE … SET quantity = quantity + :delta`; never read-modify-write |
| T-39 | Oversubscribed checkout - two people signing out the last unit at once | The invariant spans two tables, so arithmetic in SQL cannot carry it: the item row is taken with `SELECT … FOR UPDATE` before availability is computed |
| T-40 | SSRF via the barcode lookup | Provider from a dict in code, never a request; no user-supplied URL; redirects refused; private, loopback and link-local ranges blocked (CWE-918) |
| T-41 | Hostile or broken lookup upstream | Connect and read timeouts, streamed body capped at 256 KB, only expected keys read, our own length limits applied (CWE-400) |
| T-42 | Inventory contents leaked to a third party | Lookup off by default, opt-in, stated in the UI, every call written to the audit log (CWE-200) |
| T-43 | **A printed barcode as an injection vector** | A barcode is arbitrary bytes anyone can print, arriving with the authority of a physical object. Single choke point `^[0-9]{8,14}$` (GS1 GTIN) before any use — form, database CHECK, and browser. A failing code is rejected, never stored. A scanned value is never navigated to (CWE-20, 89, 22) |
| T-44 | Search widening scope across accounts | Items and locations both start from `owned_query()`; ranking never relaxes the filter. Site addresses make this the worst case (CWE-639) |
| T-45 | Silent tampering with the audit trail | Rows hash-chained; `UPDATE` and `DELETE` revoked from the application role, so injection can append but never rewrite (CWE-117, 778) |
| T-46 | Disk exhaustion through uploads | Per-account quota checked before any write; identical files deduplicated (CWE-770) |
| T-47 | Cross-account inference through shared blobs | Deduplication scoped per owner, never globally — a shared blob would make deletion behaviour an oracle for who else holds the same file (CWE-200) |

### Repudiation

| ID | Threat | Control |
|---|---|---|
| T-16 | A user denies moving or deleting an item | `movements` ledger plus `audit_log` record actor, action, and time |
| T-17 | Forged log entries via newlines in user input | Structured JSON logging escapes field values |

### Information disclosure

| ID | Threat | Control |
|---|---|---|
| T-18 | **IDOR - reading another user's items, bins, or files** | Ownership filtered *inside* the query; a miss returns **404, never 403**, because 403 confirms existence |
| T-19 | XSS exfiltrating session or page content | Autoescaping on, zero `|safe` on user data (build-enforced), Markdown sanitised, CSP without `unsafe-inline` |
| T-20 | **A leaked share URL becoming a browsable catalogue of possessions** | Public views never render the parent chain or link to unshared nodes; no public index or search route exists; reduced serializer omits owner, address, and history; hard per-IP rate limits |
| T-21 | Search engines indexing shared pages | `X-Robots-Tag: noindex, nofollow` plus `robots.txt` disallow |
| T-37 | **A site address reaching a public share page** | `address` is absent from the public serializers by construction, not hidden by a template guard; a bin or shelf cannot hold an address at all |
| T-38 | Formula injection in the audit CSV export | Cells beginning `=`, `+`, `-`, `@` are prefixed so a spreadsheet treats them as text - the payload would otherwise execute on the machine of whoever opens the file |
| T-22 | GPS coordinates leaking from uploaded photographs | Re-encode through Pillow strips all EXIF |
| T-23 | Stack traces or DB errors exposing schema and paths | `DEBUG` forced off; generic error pages; users see only a correlation ID |
| T-24 | Direct URL access to the uploads volume bypassing authorisation | Caddy serves **no** file route for uploads; every file is fetched through an ownership-checked handler |
| T-25 | SSRF via the docs-link feature reaching `db`, `cache`, or metadata endpoints | User URLs are **never fetched server-side**. Link previews are out of scope for this reason |
| T-26 | Open redirect via `?next=` laundering a phishing link | `next` must be a single-slash relative path; protocol-relative `//evil.com` rejected |
| T-27 | Secrets committed to git or baked into an image layer | `.gitignore` / `.dockerignore` exclude `.env`, `*.pem`, `uploads/`; `.env.example` holds placeholders that fail loudly |

### Denial of service

| ID | Threat | Control |
|---|---|---|
| T-28 | Oversized upload exhausting disk or memory | Capped at the proxy *and* in the app, before the body is read |
| T-29 | Decompression bomb crashing the image pipeline | `Image.MAX_IMAGE_PIXELS` bounded |
| T-30 | Argon2 memory exhaustion via concurrent logins | Password length capped at 128; login rate-limited; worker count and container memory sized deliberately |
| T-31 | **Malicious account lockout - griefing a known username** | Lockout backoff **capped at 15 minutes** and self-expiring. Accepted tradeoff, reasoned in `DECISIONS.md` |
| T-32 | ReDoS via a pathological validation regex | Validation regexes are anchored and free of nested quantifiers |
| T-33 | Cache outage silently disabling rate limiting | Limiter **fails closed** on authentication and share routes; degraded mode logged loudly |

### Elevation of privilege

| ID | Threat | Control |
|---|---|---|
| T-34 | Container escape or host pivot after app compromise | Non-root uid 10001, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, `db`/`cache` on an internal-only network |
| T-35 | Database takeover following any injection | App role is neither superuser nor schema owner; migrations use a **separate** privileged DSN the app never holds |
| T-36 | A share token being mistaken for an authorisation grant | **The token identifies; the session authorizes.** Public routes resolve to a reduced view and expose no mutating endpoint |

---

## 6. Explicit non-goals

Stating these is part of the threat model. An undefended surface that has been reasoned about is a decision; one that has not is a vulnerability.

| Not defended | Why |
|---|---|
| A malicious operator or host root | Holds the keys and the disk. Out of any application's reach |
| Data at rest on a stolen disk | No application-level or disk encryption. Full-disk encryption is the operator's responsibility, and is documented as such |
| Compromised administrator workstation | Keylogged or session-stolen credentials are indistinguishable from legitimate use |
| Self-service password reset | Requires SMTP, which a self-hosted deployment cannot assume. Recovery is `make unlock-user`. **Adding email reset would introduce the single most-attacked flow in web authentication** |
| Multi-user organisations, roles, sharing between accounts | Access model is deliberately personal-plus-share-link. Roles would add a privilege-escalation surface with no current use case |
| Anti-automation on registration (CAPTCHA) | Self-hosted instances are not open registration targets at meaningful scale. Rate limiting is the proportionate answer |
| Username enumeration on the registration form | Unavoidable - the form must say a name is taken. Mitigated by rate limiting, accepted openly |
| NFC tag cloning | Physically unpreventable with cheap NDEF tags. Handled by making the URL a low-value capability rather than a credential |
| Antivirus scanning of uploads | ClamAV is the answer and it is not implemented. Images are re-encoded, which destroys an embedded payload; PDF, text and Markdown are stored byte for byte. Files are never executed and always served as attachments. Recorded as **Not met** against ASVS 12.4.2, which is Level 1 |
| Denial of service at network scale | Requires infrastructure the operator does not have. Application-layer limits only |

---

## 7. Residual risk

What remains after every control above is in place.

1. **A leaked share URL still discloses one node.** Mitigated by scope reduction, rate limiting, `noindex`, an optional PIN, and revocation by rotation - but a valid unrevoked token shows that bin's contents. This is inherent to printing a scannable label, and the optional PIN exists for cases where it is unacceptable.
2. **A determined griefer can impose repeated 15-minute lockouts** on a username they know. Bounded, not eliminated.
3. **A compromised user account exposes that user's entire inventory.** No inner boundary exists below the account.
4. **Photographs can leak context that EXIF stripping cannot reach** - a visible address on an envelope, a view through a window. No technical control addresses this; the demo documentation notes it as user guidance.
5. **The app is only as current as its dependencies.** `pip-audit`, Trivy and Renovate all run, and the lockfile is hash-pinned and drift-checked — but base images are pinned to a tag rather than a digest, so a re-pushed tag would go unnoticed. `PIPELINE-NOTES.md` records what runs where.
6. **Traffic between containers is unencrypted.** Three internal hops are plaintext, so an attacker with a foothold on the Docker bridge sees the database session and the Redis password. The `internal: true` network is the compensating position, argued in `COMPLIANCE.md` §3 and not counted as a pass.
7. **A share token reaches gunicorn's access log.** The application log scrubs the token from the request path; gunicorn's access log has no redaction hook and still records it, so log-read access is share-link-replay access until the token is rotated.

---

## 8. How to read this alongside the code

| Question | Document |
|---|---|
| What are we defending, and against whom? | This file |
| Which control answers threat `T-##`, and where does it live? | [SECURITY.md](SECURITY.md) |
| Why *that* limit, algorithm, or tradeoff? | [DECISIONS.md](DECISIONS.md) |
| What would I add next, given more time? | [PIPELINE-NOTES.md](PIPELINE-NOTES.md) |
