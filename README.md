# D.O.O.M.

**Don't Organize Only Move** - a self-hosted inventory system for people with
more sites, shelves and bins than memory.

Label a container once. Scan it forever.

---

## What it does

Build a tree of physical places and record items anywhere in it:

| Kind | What it is | Examples |
|---|---|---|
| **Site** | A geographic place, usually with an address | North Yard, Workshop |
| **Zone** | A building or open yard within a site | Bay 1, Back Room |
| **Shelf** | Fixed storage: shelving, racking, a cabinet | Rack A, Cabinet 2 |
| **Bin** | Something you can carry | Tote A1, Crate 12 |

Any location can hold items directly, and the tiers need not nest in order - a
shelf can stand straight in a zone, which is how flammables end up racked in an
open yard.

Attach photographs, documents and links to manuals. Print QR labels or write
NFC tags, then scan a bin to see what is inside without opening it.

**Capture takes one action.** Photograph a thing and you are done - naming,
filing and counting are all optional and all later. That is the point of the
name: *Didn't Organize, Only Moved* is the ADHD term for the pile that migrates
from table to chair to floor because deciding where each item belongs is
expensive. Requiring a decision at capture time is how you get a pile.

Scan barcodes to find what you already have. An optional, off-by-default lookup
can suggest a product name; nothing leaves your machine unless you turn it on.

Sign things out to a person or a crew and check them back in - custody is
tracked without moving the item, so it still knows where it lives.

Every add, removal, move and checkout is written to a ledger, which is where
the name comes from. Each item and location shows one merged history:
movements, custody, edits, uploads, sharing changes, and every time a shared
link was opened.

---

## Quick start

```bash
cp .env.example .env
make init      # generates strong secrets with openssl
make up        # builds and starts caddy, web, db, cache
make upgrade   # applies database migrations
make seed      # optional: a demo account and a small site
```

Then open **https://localhost:8443** - the certificate is self-signed by
Caddy's internal CA, so expect a browser warning on first visit.

Demo account: `demo` / `correct-horse-battery-staple`

> **Set `PUBLIC_BASE_URL` in `.env` before printing labels.** It is encoded
> into every QR code and NFC tag, and a label printed against the wrong
> address is permanently useless.

`make help` lists everything else.

---

## Architecture

```
[browser / phone] ──HTTPS──▶ caddy ──HTTP──▶ web (gunicorn + flask)
                                               │
                                               ├──▶ db     (postgres)
                                               ├──▶ cache  (redis)
                                               └──▶ uploads volume
```

Only Caddy publishes a port. `db` and `cache` sit on an internal Docker
network with no route off the host.

TLS is a functional requirement rather than polish: Web NFC only runs in a
secure context, and a phone reaching this host by LAN IP is not one.

**Stack:** Python 3.12, Flask, SQLAlchemy, PostgreSQL 16, Redis, Caddy, Docker
Compose.

---

## Security

This was built as a secure-coding coursework project, so the reasoning is
documented as carefully as the code.

| Document | What it answers |
|---|---|
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | What is being defended, from whom, and what is explicitly *not* defended |
| [SECURITY.md](docs/SECURITY.md) | Which control answers which threat, and where it lives |
| [DECISIONS.md](docs/DECISIONS.md) | Why each limit, algorithm and tradeoff is what it is |
| [PIPELINE-NOTES.md](docs/PIPELINE-NOTES.md) | DevSecOps tooling roadmap |
| [DEMO.md](docs/DEMO.md) | Run-of-show for presenting it |
| [COMPLIANCE.md](docs/COMPLIANCE.md) | Every control mapped to OWASP ASVS 4.0 and tagged with its CWE |
| [INSPIRATION.md](docs/INSPIRATION.md) | What Sortly, Grocy, Homebox, Snipe-IT and real warehouse systems do differently, and what to borrow |

The threat model was written **before** the code, and every control traces
back to a threat named in it.

### The idea the design rests on

Most web applications treat the database as valuable because it holds account
data. Here it is **a map to physical property** - what someone owns, how much
of it, and which building it is in. A breach doesn't merely embarrass the
operator; it hands a burglar a shopping list with addresses. Every tradeoff
resolves in favour of protecting that.

Three consequences worth knowing before reading the code:

**Every limit lives in one file.** `app/doom/validation.py` is the single
source of truth. Forms, ORM columns, database CHECK constraints and HTML
attributes all read from it, so a bound cannot be tightened in one place and
left loose in another.

**Ownership is a `WHERE` clause, not an `if` statement.** Fetch-then-check
loads the row before deciding; filtering inside the query means it is never
loaded. A miss returns 404, never 403 - a 403 confirms the object exists.

**History can be added to but not rewritten.** The audit trail is hash-chained,
and `UPDATE` and `DELETE` are revoked from the application's database role - so
even a complete SQL injection can only append. `make audit-verify` proves it.

**A scanned barcode is hostile input.** Anyone can print a barcode, and it
arrives wearing the authority of a physical object. Everything hangs off one
choke point: eight to fourteen digits, or it is rejected outright.

**Shared pages omit rather than hide.** A public view is built from a reduced
dictionary that has no owner and no ancestor chain in it. A forgotten template
guard fails silently; a field that was never passed cannot leak.

### Verifying the claims

```bash
make test           # 213 tests pinning the security controls
make audit-verify   # walk the audit hash chain, print the head hash
make lint           # fails if any template could bypass autoescaping
make db-shell-app   # connect as the app's restricted role and try DROP TABLE
```

---

## Self-hosting notes

**Ports.** Defaults are 8080/8443 so the stack starts under rootless Docker,
which refuses to bind below 1024. On a rootful daemon, set `HTTP_PORT=80`
and `HTTPS_PORT=443` and drop the port from `PUBLIC_BASE_URL` - before
printing labels.

**A real domain.** Point `DOOM_DOMAIN` at it and add `email you@example.com`
to `caddy/Caddyfile`; Caddy handles Let's Encrypt from there.

**Backups.** `make backup` covers the database *and* the uploads volume. A
database dump alone is not a backup - every photo and document lives in the
volume. `make restore` takes both.

**NFC.** Web NFC is Chromium-on-Android only; there is no iOS support. QR
codes work everywhere and carry the same URL.

---

## Licence

Personal coursework project. Use it however you like.
