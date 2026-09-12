# Demo run-of-show

Roughly 12 minutes with questions. Everything here is reproducible from a cold
start; commands are copy-pasteable.

---

## Before the room

```bash
make init && make up && make upgrade && make seed
```

Demo account: `demo` / `correct-horse-battery-staple`

**Set `PUBLIC_BASE_URL` before printing any labels.** It is baked into every QR
code and NFC tag. A label printed against `localhost` is permanently useless.

### Phone connectivity - the one real risk

Web NFC needs a *genuine* secure context, and a phone reaching your laptop by
LAN IP is not one. Two options, in order of preference:

**Option A - Caddy's internal CA.**

```bash
make trust-cert
```

Transfer `certs/doom-root-ca.crt` to the phone and install it under
Settings → Security → Encryption & credentials → Install a certificate → CA
certificate. Android's user CA store is fussy and this sometimes will not take.

**Option B - a real certificate via tunnel (the reliable fallback).**

```bash
cloudflared tunnel --url https://localhost:8443
```

Set `PUBLIC_BASE_URL` to the tunnel hostname, `make restart`, then reprint. The
tunnel exposes the instance publicly for its lifetime - fine for a classroom
demo, and worth saying aloud that you know it.

**Have the QR path ready regardless.** Web NFC is Chromium-on-Android only.
There is no iOS support at all, so if the room's phone is an iPhone the NFC
segment simply cannot run. QR works everywhere.

---

## 1. Architecture (1 min)

```bash
docker compose ps
```

Four containers. Only Caddy publishes a port.

```bash
docker compose ps --format '{{.Service}}\t{{.Ports}}'
```

`db` and `cache` show nothing - they sit on an `internal: true` network with no
route off the host. Postgres is not reachable from the LAN even by accident.

---

## 2. The idea behind the whole project (1 min)

Open `app/doom/validation.py`.

> Every limit in the system is defined once, here. Forms, database columns,
> CHECK constraints and HTML attributes all read from this file. A limit
> cannot be tightened in one place and left loose in another, because there is
> only one place.

Then `app/migrations/versions/*_initial_schema.py`:

```
sa.CheckConstraint('char_length(username) BETWEEN 3 AND 32', ...)
sa.CheckConstraint('quantity BETWEEN 0 AND 1000000', ...)
```

> Those numbers were not typed here. They came from that constants file, which
> is also what the form validator and the HTML use.

---

## 3. Authentication (2 min)

Register with `password123` → rejected, with the reason.
Register with `administrator` → rejected as a breach-list password.

```bash
make db-shell
```
```sql
SELECT username, substring(password_hash, 1, 30) FROM users;
```

`$argon2id$v=19$m=65536,t=3,p=4` - the algorithm and its parameters travel with
the hash, which is what lets the cost be raised later and every account upgrade
silently on next login.

**The point worth making:**

> 64 MiB per hash is what makes offline cracking expensive. It is also 64 MiB
> on *our* server, so worker count, the container memory limit and the
> 128-character password cap are all consequences of that one number. Picking
> it without accounting for that would be a denial of service I inflicted on
> myself.

Then, six wrong passwords in a row:

> The account locks - and unlocks itself in fifteen minutes. That cap is
> deliberate. Lockout keyed on a username is a denial-of-service primitive:
> anyone who knows your username can trigger it. An admin-only unlock turns a
> nuisance into an outage the victim cannot clear.

---

## 4. Access control (2 min) - the centrepiece

Two browsers, two accounts. Copy an item UUID from A, paste into B.

**404, not 403.**

> 403 would be an admission: *this exists and it is not yours*. For an
> inventory system that is exactly the fact worth protecting. 404 says only
> "nothing here for you", which is equally true and tells them nothing.

Show `app/doom/security/authz.py`:

```python
select(model).where(model.id == parsed, model.owner_id == current_user.id)
```

> Ownership is a WHERE clause, not an if statement. Fetch-then-check loads the
> row and then decides - every line after that is one missing `if` away from
> disclosure. Filtering inside the query means the row is never loaded, so an
> unauthorised id and a nonexistent one are literally the same event: zero
> rows.

---

## 5. SQL injection - two layers (2 min)

Search for `' OR 1=1 --` → no results, no error.

Show the one raw query in `blueprints/items.py`, then the second layer:

```bash
make db-shell-app     # connects as the RESTRICTED role the app uses
```
```sql
DROP TABLE items;
SELECT * FROM pg_shadow;
CREATE TABLE pwned(x int);
```

```
ERROR:  must be owner of table items
ERROR:  permission denied for view pg_shadow
ERROR:  permission denied for schema public
```

> Most projects stop at "I used an ORM". This layer assumes the ORM failed.
> Even a successful injection is confined to rows the app could already reach.
>
> It has a consequence I had to design for: this role cannot run migrations
> either. Alembic uses a separate admin connection string that the running
> application never holds.

---

## 6. File uploads (2 min)

Have these ready:

- a `.txt` renamed to `.jpg`
- an SVG containing `<script>`
- a real JPEG with `<script>alert('xss')</script>` appended

First two rejected - *"is a text/x-shellscript file, which is not accepted"*.

> The filename and the Content-Type header are both attacker-controlled. Only
> the bytes are trustworthy, so the type comes from magic bytes. SVG is
> refused outright because it is an XML document that can carry script - it is
> stored XSS wearing a picture's clothes.

The polyglot uploads successfully. Then:

```bash
docker compose exec web ls -la /var/lib/doom/uploads
docker compose exec web sh -c "grep -c script /var/lib/doom/uploads/*.jpg"
```

Zero matches, and the file is byte-for-byte the size of a clean re-encode.

> Images are decoded and re-encoded rather than stored. The output is built
> from pixels into a new container, so nothing from the original survives. The
> same step strips EXIF - and EXIF is where photographs keep GPS coordinates.
> In an app whose whole dataset is "what I own and where it is", a photo that
> publishes the building's coordinates would undo the point of the system.

Note the filenames: UUIDs, mode `0600`.

> No user-controlled string ever reaches the filesystem. Path traversal isn't
> filtered - there is nothing to filter, because the name is one I generated.

---

## 7. Sharing (2 min) - the part that is specific to this domain

Share a bin. Open the link in a private window.

Contents are listed. The site above it, and its address, are not. No parent link, no navigation, no
search.

> The threat here is not someone holding the tag - they are already standing at
> the bin. It is a *leaked URL*: a photo of a label posted online, a link
> forwarded once too often, a page a crawler indexed.
>
> So a shared page is a leaf, not a doorway. It never renders the chain up to
> the site, because that chain - and the address on it - is where to drive to. There is no public
> index and no public search, so one leaked token yields exactly one node.

Show `security/serializers.py`:

> This is a control that is an *absence*. The share page is rendered from a
> plain dictionary, and the owner and ancestors are not in it. I could have
> used template conditionals - but a forgotten `{% if %}` fails silently and
> the page still looks correct to whoever wrote it. A field that was never
> passed cannot be rendered by mistake.

```bash
curl -skI https://localhost:8443/t/<token> | grep -i robots
```

`X-Robots-Tag: noindex, nofollow, noarchive`

Then rotate the token → the old link 404s.

---

## 8. Labels and NFC (1 min)

Print a sheet. Scan a QR with any phone camera.

> The label points at the bin's identity, not its contents, so refilling a
> tote never means reprinting. The short code under each QR exists because
> printed labels outlive domain names.

On Chrome for Android: write a tag, rescan, lock it.

> NFC tags are unauthenticated and clone in seconds. That is exactly why the
> URL only ever opens the public read-only view - a cloned tag grants what the
> original granted, which is a page the owner chose to publish.

---

## 9. Errors and evidence (1 min)

Trigger a 500. The page shows a correlation ID and nothing else.

```bash
make logs | grep <id>
```

Full traceback, server-side, against the same ID.

```bash
make test
```

All passing — the count is in COMPLIANCE.md §6, which is the only file that
publishes it.

> Several of these exist because the control fails *quietly*. Session
> revocation is the clearest: increment the version column, forget to compare
> it in the user loader, and the feature still looks like it works while every
> old cookie stays valid. The test is the only thing that notices.
>
> If you want the strongest version of that point, two controls in this codebase
> *were* written and *did* fail quietly, and an external audit found them: a
> 124-entry breach corpus of which 123 entries were below the 12-character
> minimum, so the length check rejected them first and the screen matched exactly
> one string; and the denied-access audit record, which was added to the session
> and then discarded by the 404 that followed it. Both now have tests.

---

## Questions you should expect

**"Why no password reset email?"** - Self-hosted can't assume SMTP, and a
reset flow is the most attacked path in web auth: an unauthenticated endpoint
whose purpose is handing out account access. Recovery is a shell command. See
D-12.

**"Isn't the 15-minute lockout cap weak?"** - Five attempts per quarter hour
against a 12-character minimum is not a viable attack. Uncapped lockout *is* a
viable attack - on availability. See D-04.

**"Can't someone guess a share token?"** - 256 bits. The realistic attack is
scraping leaked tokens, which is what the rate limits and `noindex` address.

**"What would you add next?"** - TLS between the containers (ASVS 1.9.1 and
9.2.2, the largest remaining L2 gap), then ClamAV on uploads for 12.4.2, then an
SBOM. `gitleaks`, `bandit`, `pip-audit`, `semgrep`, `hadolint`, Trivy and
Renovate are already running — PIPELINE-NOTES.md says which trigger on what.

**"What's still weak?"** - Registration reveals whether a username is taken; a
compromised account exposes that user's whole inventory; no antivirus scanning of
uploads; no TLS between containers. Nine accepted risks are written up in
SECURITY.md §4, and the complete picture — 36 requirements that are not a clean
pass, out of 253 — is the exception table in COMPLIANCE.md §1.

**"You claim ASVS Level 2. Do you meet it?"** - No, and the ledger says so. 65 of
126 L2 requirements met, 31 not applicable, 30 exceptions. L1 is 100 of 127 with
six exceptions. An earlier revision of COMPLIANCE.md claimed L1 "met in full"
and L2 "met with two compensating controls"; both were overstated, an audit said
so, and the document was rebuilt to enumerate every requirement rather than
curate the ones that passed. The scoreboard in COMPLIANCE.md is the honest
answer, and being able to give it is worth more than the claim was.
