# D.O.O.M. - Security Decisions

Why each limit, algorithm and tradeoff is what it is. [SECURITY.md](SECURITY.md)
says *what* is enforced and where; this says *why*, including the places where
the answer was to accept a risk rather than remove it.

---

## D-01 - Every limit lives in one file

`app/doom/validation.py` holds every bound in the system. Forms, ORM columns,
database CHECK constraints and HTML attributes all read from it.

The alternative - a `maxlength` in a template, a `Length()` in a form, a
`String(120)` in a model - puts the same number in four places with no
mechanism keeping them equal. They drift. Someone raises the column and forgets
the validator, or tightens the validator while the database still accepts the
old width, and the disagreement surfaces as a 500 or, worse, as data the
application did not expect to be able to store.

One constant, referenced everywhere, cannot disagree with itself.

The layering is deliberate, not redundant. The HTML attribute is a
**usability hint** and is never treated as a control - a client that ignores
it still meets the server-side bound. The form validator produces a good error
message. The column bounds what the ORM will send. The `CHECK` constraint
binds anything that reaches the database by another route, including a future
script or a psql session.

---

## D-02 - Argon2id, and those parameters

`time_cost=3, memory_cost=65536 (64 MiB), parallelism=4, hash_len=32, salt_len=16`

**Why Argon2id over bcrypt or PBKDF2:** it is memory-hard. bcrypt and PBKDF2
are CPU-hard only, and CPU work parallelises onto GPUs and ASICs far more
cheaply than 64 MiB of RAM per guess does. Argon2id also won the Password
Hashing Competition and is the OWASP first recommendation.

**Why 64 MiB:** the OWASP floor is 19 MiB. At 64 MiB an attacker needs 64 GiB
of RAM to run a thousand guesses in parallel, which is what makes large-scale
offline cracking expensive rather than merely slow.

**The cost of that choice, stated plainly:** memory-hardness cuts both ways.
64 MiB is reserved *per hash in flight on our own server too*, so
`workers × threads × 64 MiB` has to fit the container limit. That is why
gunicorn concurrency is pinned in compose, the web container has a 1 GB limit,
login is rate limited, and passwords are capped at 128 characters. A parameter
chosen without accounting for that is a self-inflicted denial of service.

`check_needs_rehash()` runs on every successful login, so raising these values
later upgrades each account silently as its owner next signs in.

---

## D-03 - 12-character minimum, no composition rules

NIST SP 800-63B withdrew composition rules ("one uppercase, one digit, one
symbol") because they measurably fail. Faced with them, people produce
`Password1!` - which satisfies every rule and is in every cracking dictionary -
while genuinely strong passphrases get rejected for lacking a symbol. The rules
narrow the search space instead of widening it.

Length is what actually resists guessing, so the policy is: 12 characters
minimum, screened against a breach list, and rejected if it contains the
username. `correct horse battery staple` passes; `Passw0rd!` does not.

**The maximum is also a control.** 128 characters is not a storage limit - it
bounds the Argon2 work a single unauthenticated request can demand. Without a
cap, a one-megabyte password is a memory amplifier aimed at the login route.

---

## D-04 - Lockout is capped at 15 minutes, and expires unaided

Five consecutive failures lock an account; the backoff escalates 1 → 5 → 15
minutes and stops there.

The cap is the security decision, not the escalation. **Lockout keyed on a
username is itself a denial-of-service primitive.** Anyone who knows a
username can lock that account on demand by failing five logins - no
credentials required. An uncapped backoff, or an unlock that needs an
administrator, converts a trivial nuisance into an indefinite outage the
victim cannot clear.

Fifteen minutes keeps online guessing hopeless (five attempts per quarter hour
is not a viable attack against a 12-character minimum) while bounding what a
griefer achieves. The lock lifts itself. `make unlock-user` exists for the
operator who does not want to wait, not as the required path back in.

**Observed during testing, and worth knowing:** the per-IP limit (10 attempts
per 15 minutes) fires *before* an account reaches five failures from a single
address. That is the intended layering - the cheap check first - and it means
account lockout mainly defends distributed attacks from many IPs. It is also
why lockout is verified by unit test rather than through HTTP.

---

## D-05 - Registration reveals whether a username is taken

Accepted, not solved.

A registration form has to tell the user their chosen name is unavailable.
Every alternative is worse: silently creating nothing looks like a bug,
emailing instead requires SMTP this deployment does not have, and a delayed
"check your messages" flow trades a small disclosure for a much larger amount
of machinery.

Mitigated by a 5-per-hour rate limit on registration. Recorded here rather
than left as an unexamined gap, because the difference between an accepted
risk and a vulnerability is whether anyone thought about it.

---

## D-06 - 404, never 403

An unauthorised object and a nonexistent one return the same response.

`403 Forbidden` is an admission: *this exists, and it is not yours.* For an
inventory system that is precisely the fact worth protecting - confirming that
item `d067a821…` exists tells an attacker their guess landed on something real.
`404` says only "nothing here for you", which is also true.

The same reasoning covers malformed identifiers. `/items/not-a-uuid` returns
404 rather than 400, because a 400 would confirm that a well-formed id which
returned 404 was at least *shaped* like a real one.

---

## D-07 - Ownership is a WHERE clause

```python
# fetch, then check - rejected
obj = db.session.get(Item, item_id)
if obj.owner_id != current_user.id:
    abort(403)

# filter in the query - used
obj = get_owned_or_404(Item, item_id)
```

Fetch-then-check loads the row before deciding. Every line after that is one
missing `if` away from disclosure, and the two outcomes differ in timing and
in behaviour. Filtering inside the query means the row is never loaded at all:
an unauthorised id and a nonexistent one produce the identical event, zero
rows.

It also cannot be forgotten in the way an `if` can, because there is no
version of the call that returns someone else's object.

---

## D-08 - Two database roles

The application connects as `doom_app`, which holds `SELECT/INSERT/UPDATE/DELETE`
and nothing else. It is not superuser and does not own the schema.

This is the layer that assumes the ORM failed. If an injection ever succeeds,
it is confined to reading and writing rows the application could already
reach - no `DROP TABLE`, no `CREATE FUNCTION`, no `pg_shadow`.

**The consequence had to be designed for.** A DML-only role cannot `ALTER
TABLE` or `CREATE EXTENSION` either, so Alembic runs under a separate
privileged DSN passed only by `make upgrade`. Two connection strings is
slightly more machinery than one; the alternative is an application that
carries schema-modification rights every second of its life for the few
seconds a year it needs them.

---

## D-09 - SVG and archives rejected; images re-encoded

**SVG is refused** because it is not really an image. It is an XML document
that can carry `<script>`, and serving one same-origin executes it - stored
XSS wearing a picture's clothes. Sanitising SVG is possible and difficult;
refusing it costs nothing here.

**Archives are refused** because unpacking user-controlled paths is zip-slip,
and nothing in an inventory system needs a zip file.

**Images are decoded and re-encoded rather than stored as received.** This is
the step doing the most work. Output is written from decoded pixels into a new
container, so nothing from the original survives: a polyglot's trailing
payload, a comment segment full of HTML, a second format's header appended
after the JPEG data. Verified - a JPEG with `<script>` appended stores at
exactly the size of the clean re-encode, with no match for `script`.

It also strips EXIF, which matters more than it first appears. **EXIF is where
photographs keep GPS coordinates.** In an application whose entire dataset is
"what I own and where it is", a photo of a shelf that publishes the building's
coordinates undoes the point of the system.

**An allowlist, not a denylist.** SVG and zip are named above because they are
worth explaining, not because they are enumerated in code. Anything not on the
list is refused, so the next dangerous format did not have to be predicted.

---

## D-10 - Stored filenames are generated

`stored_name` is a UUID we produced. `original_name` is kept in the database
for display and never joined to a path.

Path traversal is therefore impossible **by construction** rather than by
filtering. There is no `../` to strip, no encoding trick to normalise, no
Unicode variant to catch, because no user-controlled string reaches the
filesystem at any point. `resolve_stored_path()` still checks the resolved
path stays inside the upload directory - a two-line defence should not depend
on a future maintainer preserving an invariant enforced elsewhere.

---

## D-11 - The token identifies; the session authorizes

A share token is a capability limited to a reduced read-only view. It never
authorises an edit, and possessing one grants exactly the page the owner chose
to publish.

**The threat is a leaked URL, not a stolen tag.** Someone holding the tag is
already standing at the bin - the tag tells them nothing they could not see by
opening it. What is dangerous is the URL escaping the physical world: a photo
of a label posted online, a link forwarded once too often, a page a crawler
indexed. That is what turns an inventory into a shopping list with addresses.

Hence:

- **Private by default.** A token exists once a label is printed; the node is
  not published until the owner says so.
- **No upward links.** A shared tote lists its contents. It never renders the
  chain to its warehouse, because that chain *is* the physical address.
- **Nothing to enumerate.** There is no public index, no public search, no
  listing route. One leaked token yields one node.
- **A child is a link only if separately shared.** A parent's token never
  confers access downward.
- **`noindex` everywhere** so a leaked link cannot become a search result.
- **Hard rate limits**, because scraping is the realistic attack, not guessing
  256 bits.
- **An optional PIN** for anything a leaked link alone should not open.

---

## D-12 - No password reset by email

There is none. Recovery is `flask set-password` from the operator's shell.

Self-hosted deployments cannot assume SMTP, and adding it would mean either a
mandatory external dependency or a relay to configure. More to the point, a
self-service reset flow is **the most attacked path in web authentication**:
an unauthenticated endpoint whose designed purpose is to hand out account
access, with a token lifecycle, a delivery channel and an enumeration surface
of its own.

For a single-operator system the shell already exists and is already trusted.
Declining to build the flow is a deliberate reduction in attack surface, not
an omission.

---

## D-13 - No server-side fetching of user URLs

`doc_links` stores URLs and renders them. It never requests them. No favicon
fetch, no title preview, no link checker, no "is this still alive" job.

Any of those would make the field a server-side request forgery primitive
pointed at the internal network, where `db` and `cache` resolve by hostname
and cloud metadata endpoints are one request away. Link previews are a nice
feature; they are not worth an SSRF pivot into the database host.

Validation is an allowlist of `{http, https}` with credentials rejected, and
the database restates the scheme rule as a `CHECK` so a direct write cannot
introduce `javascript:`.

---

## D-14 - Rate limiting fails closed

`swallow_errors=False`. If Redis is unreachable, requests to limited routes
return 503 rather than proceeding unlimited.

The alternative - swallow the error and serve anyway - turns a cache outage
into the silent removal of every brute-force protection in the application, at
exactly the moment nobody is watching. A visible 503 is recoverable; an
invisible bypass is not.

---

## D-15 - ProxyFix and the Caddyfile are one control in two halves

Caddy sets `header_up X-Forwarded-For {remote_host}`, **overwriting** rather
than appending. Flask runs `ProxyFix(x_for=1)`, trusting exactly one hop.

Both halves are required and the failure mode is silent either way:

- Without ProxyFix, `request.remote_addr` is Caddy's container address for
  every request. Every client on earth shares one rate-limit bucket, and per-IP
  limiting quietly means nothing.
- Without the overwrite, a client seeds `X-Forwarded-For` with a value of their
  choosing and mints a fresh bucket per request.

Nothing errors in either case. The application looks fine and the limiter is
decorative. That is why a test asserts the observed client address rather than
trusting the configuration to be right.

---

## D-16 - Label URLs come from configuration, never the request

`PUBLIC_BASE_URL` is required at startup. Share links are built from it and
never from `request.host_url`.

The security reason is Host header poisoning: an attacker who controls the
Host on a request that generates a link can point that link wherever they
like. The practical reason bites sooner - a QR code generated from a dev
session bakes in `localhost` and is printed onto physical labels that then
have to be thrown away. Configuration is the only source that is correct
regardless of who is asking.

Related: labels are bound to a node's **identity**, never its contents or
position. A tote's label survives being refilled, emptied or carried to
another building. The only thing that invalidates printed labels is a change
of base URL, which is why every label also carries a short human-readable code.

---

## D-17 - Errors say almost nothing

The user gets a sentence and a twelve-character correlation ID. The server
log gets the exception, the stack, the request and the same ID.

A default traceback page discloses the file layout, fragments of source, local
variables and often configuration. A database error discloses table and column
names - a free schema map for anyone probing for injection. Neither reaches
the browser.

The fallback page is rendered **without Jinja**. An error handler that can
itself raise is a real failure mode: if template rendering is what broke,
calling `render_template` again escapes to the framework's default handler and
replaces the carefully generic page with whatever that emits. This was not
theoretical - it happened during development, when a misconfigured extension
made every template render fail.

`DEBUG` is not a toggle. The Werkzeug debugger is a remote code execution
console, and configuration raises at startup if anything tries to enable it.

---

## D-18 - Quantity changes are computed by the database

```sql
UPDATE items SET quantity = quantity + :delta WHERE ...
```

Not read-modify-write. Two people with phones scanning the same bin is the
normal case in an inventory system, not an exotic one, and the read-then-write
version silently loses one of the two updates.

The bounds live in the `WHERE` clause as well, so an adjustment that would
take the count out of range matches no row and changes nothing - rather than
writing an invalid value and relying on the CHECK constraint to raise an
exception the user then has to see.

---

## D-19 - Redis runs as an unprivileged user rather than dropping capabilities

The stock Redis entrypoint starts as root and drops privileges with `setpriv`,
which needs `CAP_SETUID` and `CAP_SETGID`. Under `cap_drop: ALL` that fails
and the container crash-loops.

The tempting fix is to grant those two capabilities back. The better one is
`user: redis`, which starts unprivileged in the first place so the drop is
never needed. The result keeps **both** properties - zero capabilities and a
non-root process - instead of trading one for the other.

---

## D-20 - Unprivileged host ports by default

`8080` / `8443` rather than `80` / `443`, with `PUBLIC_BASE_URL` carrying the
port.

Rootless Docker refuses to bind below 1024, and a stack that fails to start on
the maintainer's own machine is worse than one on an unusual port. A rootful
daemon can set 80/443 in `.env` and drop the port from the URL - but do that
*before* printing labels, since the URL is what gets encoded.

---

## D-21 - `{hostport}`, not `{host}`, in the reverse proxy

Caddy forwards `X-Forwarded-Host {http.request.hostport}`. The obvious-looking
`{host}` is wrong, and wrong in a way that only appears off the default port.

`{host}` yields the hostname **without** the port. On `https://localhost:8443`
the application therefore believed it was serving `localhost` while the browser
was on `localhost:8443`. Flask-WTF's strict Referer check compared the two,
correctly concluded the request looked cross-origin, and rejected **every
POST** with `400 Bad Request` - login included.

Two things are worth taking from it.

The first is that the CSRF control behaved exactly as designed. It failed
closed on a host mismatch, which is what it is for. The bug was the proxy
lying about the host, not the check being wrong to care.

The second is why it was hard to see: the user-facing 400 says only "that
request could not be understood", by design (D-17). That is right for a
stranger and useless for an operator. So client errors are now logged with
their reason - `"reason": "The referrer does not match the host."` - while the
response stays generic. Detail belongs in the log, not the page; withholding it
from *both* is not security, just an outage nobody can diagnose.

---

## D-22 - `Referrer-Policy: same-origin`, not `no-referrer`

Two controls, each correct in isolation, that cancelled each other out.

`Referrer-Policy: no-referrer` was chosen to stop a share token in the URL
reaching any third-party site a user clicks through to (T-20). Separately,
`WTF_CSRF_SSL_STRICT` was left on, which makes Flask-WTF verify the `Referer`
header on every HTTPS POST to confirm the request originated here.

The browser obeyed the header. It sent no `Referer` - on outbound links *and*
on our own form submissions. The CSRF check saw a missing referrer, concluded
the request could not be shown to be same-origin, and returned **400 for every
POST in the application**, login and registration included.

`same-origin` satisfies both requirements: the browser sends a full referrer on
same-origin requests, so the CSRF check works, and sends nothing whatsoever
cross-origin, so the token still cannot leak. The share blueprint sets its own
policy and had the identical bug - a `no-referrer` there would have broken the
share PIN form the same way.

Three things worth taking from it.

**Stricter is not automatically safer.** The strictest available value disabled
a stronger control than the one it strengthened. A security header is a
tradeoff, not a score to maximise, and "pick the most locked-down option" is
not a substitute for knowing what depends on it.

**The failure was invisible to the test tooling.** Every curl-based check
passed, because passing `-e` sets the `Referer` explicitly and papers over
precisely the behaviour that was broken. The bug only appeared in a real
browser. Anything that simulates a client by supplying headers by hand can
mask a policy that tells clients not to supply them.

**It was diagnosable only because of D-17.** The user-facing page says "that
request could not be understood" and nothing more, which is correct. The
server log carries `"reason": "The referrer header is missing."`, which is
what actually located the bug. Withholding detail from the user is security;
withholding it from the operator as well is just an outage nobody can explain.

`app/tests/test_headers.py` now asserts the policy permits same-origin
referrers, still withholds them cross-origin, and holds on share routes too.

---

## D-23 - Four location tiers, and no hidden rule about which can hold items

The first vocabulary was warehouse / zone / rack / shelf / bin / tote. Six
terms, and two pairs of them described the same thing: a warehouse *is* a
zone with a roof, a tote *is* a bin you can carry. Choosing between them was a
coin flip rather than a decision, which is a sign the taxonomy was wrong
rather than merely undocumented - a distinction that needs a tooltip to
survive usually should not exist.

The replacement is four tiers, each answering a different question:

| Kind | Question it answers | Examples |
|---|---|---|
| **Site** | Is it a place with an address? | North Yard, Workshop |
| **Zone** | Is it a building or an outdoor area within that place? | Bay 1, Back Room, the yard |
| **Shelf** | Is it fixed storage furniture? | Rack A, Shelving 2, a cabinet |
| **Bin** | Can you pick it up and carry it? | Tote A1, Crate 12 |

The tiers do not have to nest in order. A shelf can sit directly in a zone,
which is exactly how flammables end up racked in an open yard rather than
inside a building invented to satisfy a hierarchy.

**The rule that had to go.** `ITEM_BEARING_KINDS` restricted items to shelves,
bins and totes. It was never stated anywhere in the interface, it does not
match the physical world - a pallet stands in a bay, a vehicle sits in a yard -
and its only visible effect was that anyone who had created a site and a zone
but no bin saw an **empty Location dropdown** with nothing on screen to explain
why. The same rule silently emptied the "Move to" dropdown. Any location can
hold items.

The lesson is not really about warehouses. It is that a constraint invented
for tidiness, enforced silently, and never surfaced in the UI reads to a user
as a broken feature - and there is no way to tell the two apart from outside.

---

## D-24 - Sites carry an address, and it is the most sensitive field in the system

A site is a geographic place, so it takes a postal address. Nothing below a
site does: a bin has a position, not an address, and the form rejects one.

This single column changes the threat model (T-37). Every other field records
*what* someone owns. This records *where to drive to take it*. An inventory
leak without an address is embarrassing; with one it is a shopping list with
directions.

Three consequences:

- It is **absent from the public serializers**, not hidden by a template
  guard. The share view is built from a dictionary that has no `address` key,
  so a template mistake cannot expose it.
- It is **rejected on non-site kinds**, because storing sensitive data
  somewhere it serves no purpose is the cheapest mistake to avoid.
- The owner-facing page **says so on screen**, so the person typing it knows
  the rule rather than having to trust it.

Two tests assert it: absent from the serializer, and absent from a rendered
shared page even when the shared node's ancestor has one.

---

## D-25 - The activity feed reads what was already being recorded

`audit_log` was written from the first commit; there was simply no window onto
it. The account page and `/account/activity` add the window, not the
collection. Nothing new is gathered to make the feature work.

Failed sign-ins and blocked access attempts appear alongside ordinary events,
deliberately. A single 404 is noise; forty in a minute against well-formed
UUIDs is enumeration, and the pattern is only visible if the misses are shown
next to the hits.

**Attribution.** Movements record `actor_id` and the history renders "by you".
In a single-account inventory the actor is always the owner, so this looks
redundant today - but the ledger records who acted rather than assuming it, so
the history stays truthful if the model ever grows past one user. On the
anonymised-identity idea: it applies where an audit trail is read by people who
should not learn who did what. Here the only reader is the account owner, and
pseudonymising your own actions from yourself adds nothing. It becomes worth
revisiting the moment a second person can read the same trail.

**Profile data is optional in full.** Display name, email and timezone are all
nullable and none is needed to run an inventory. Email is never used for
delivery - there is no SMTP and no reset flow (D-12) - and exists only so a
trail can name a person. Data that is not collected cannot leak.

---

## D-26 - CSV export escapes formula prefixes

A spreadsheet treats a cell beginning `=`, `+`, `-` or `@` as a formula and
runs it on open. Audit rows contain user-supplied text: location names, upload
filenames, movement reasons.

That makes an export a path from *"an attacker types a location name"* to
*"code executes on the machine of whoever opens the file"* - without the
application itself ever being exploited. The vulnerability is in the file, and
it detonates somewhere the application cannot see.

Affected cells are prefixed with a single quote so the spreadsheet reads them
as text. The quote is visible in the cell, which is the right trade: a slightly
ugly export beats a live formula. The response is always
`Content-Disposition: attachment` with `nosniff`, so it is never rendered
in-browser either.

---

## D-27 - `counts.items` is a Jinja trap

The account page rendered `<built-in method items of dict object at 0x…>`
where the item count should have been.

In Jinja, `counts.items` tries attribute access before subscript, and every
dict has an `.items` method. The template got the bound method rather than the
value - and **raised nothing**. Autoescaping rendered it harmlessly as text, so
the page looked fine at a glance and simply had a figure missing.

Fixed by naming the keys `item_count`, `location_count` and so on. Writing
`counts['items']` would also work, but a name that cannot collide is better
than a call site that has to remember not to. A test now asserts all four stat
tiles render as digits, because the failure mode is silence.

---

## D-28 - One history, not three ledgers

An item's history showed `movements` and nothing else, so the page reported
quantity changes and stayed silent about everything else that had happened to
it. All of it was already being recorded - creation, edits, uploads, link
changes, share settings, and every time a shared link was opened - it simply
had no window onto it.

`timeline.py` merges the three ledgers into one chronological view:
`movements` (where it went), `checkouts` (who had it), and `audit_log`
(everything else). Locations get the same treatment, including what moved in
and out, because "what came through this bin" is what an owner actually asks
of a place.

Two details worth defending.

**Anonymous events are shown, and highlighted.** `share_viewed` has no
signed-in actor, so a timeline that only rendered events with one would hide
the single most useful line an owner can read: *someone opened your shared
link, from this address, at this time.* Those entries are drawn differently
precisely because they are the ones to look at. The address is meaningful only
because ProxyFix reads it from the one hop Caddy controls (D-15) - without
that it would be Caddy's own container address on every row, which would look
like data and be worthless.

**Audit rows are matched on `object_id` alone.** That is safe rather than lax
because the caller has already resolved the object through
`get_owned_or_404`. Once ownership of a UUID is established, every row
referencing it is by definition about that object. Adding an
`actor_user_id == current_user.id` filter would have looked more careful and
would have hidden exactly the anonymous events that matter most.

None of this reaches a shared page. The public serializer has no history in
it at all (D-11) - visit timestamps describe when a place is occupied and
therefore when it is not.

---

## D-29 - Checkout is custody, not relocation

Signing an item out records **who has it**. It deliberately does not change
`location_id`.

The tempting implementation is to move the item to a "checked out" location,
or blank its location. Both lose the answer to *where does this live* - which
is the question the entire application exists to answer - and neither survives
the item being returned. Instead the item keeps its home, an open `Checkout`
row says who is holding it, and returning puts it back where it came from.

**Two quantities, both true.** `quantity` stays the number owned; checking
something out does not destroy it. `quantity_available` is what is on the
shelf right now. They answer different questions, and collapsing them into one
number would make at least one answer a lie.

**The holder is free text.** Whoever has the drill is usually not an account
on this instance - a contractor, a crew, a job number. Forcing them to be a
user would mean creating accounts for people who will never sign in, which is
worse for both usability and security than a bounded, escaped string.

**Closed checkouts are never deleted.** A returned row is evidence that the
loan happened, which is the whole point of an audit trail (T-16).

### The concurrency case this one needed

Quantity adjustment avoids lost updates with arithmetic in SQL
(`SET quantity = quantity + :delta`, D-18). That trick does not work here,
because the check spans two tables: *"is `items.quantity` minus the sum of
open `checkouts` at least what you asked for?"*

Without a lock, two people checking out the last drill simultaneously both
read "1 available" and both succeed, leaving the ledger claiming two are out
when one exists. So the item row is taken with `SELECT ... FOR UPDATE` before
availability is computed, which serialises concurrent checkouts of the same
item and nothing else.

Worth stating plainly in the write-up: the right concurrency control depends
on the shape of the invariant. A single-row counter wants atomic arithmetic; a
cross-table invariant wants a lock.

---

## D-30 - A test helper that made "another user cannot…" tests meaningless

`login(client, "bob")` on a client already signed in as alice did **nothing**.
`/login` redirects an authenticated visitor away rather than swapping
accounts, so the client stayed alice, and the test carried on believing it was
bob.

Every assertion of the form *"another user cannot return your checkout"* was
therefore exercising *"you can return your own checkout"* and passing for
entirely the wrong reason. It surfaced only because one such test asserted a
**404** and got a 302 - had it merely asserted "the row did not change", it
would have passed silently forever.

`login()` now drops the session cookie first, which is also what actually
happens in the world it is modelling: a different person, on a different
browser, with no cookie.

The general lesson, which belongs in the demo: **a security test that passes
is not evidence until you have seen it fail.** A negative test that cannot
distinguish "the control worked" from "the scenario never happened" is
decoration. This one had to be caught by an unrelated status-code assertion,
which is luck rather than method.

---

## D-31 — Capture requires nothing; filing is nudged, not forced

`Item.name` was `DataRequired()`. Nothing could be recorded until it had been
named, and naming is a decision — which is precisely the bottleneck the
product's name describes. Three decisions stood between a person and a recorded
object: name, quantity, location. That is how a doom pile forms.

Now: **a name or a photo, at least one.** Nothing else.

That invariant cannot live in the database. The photo is a row in
`attachments`, the name is a column on `items`, and no single `CHECK` sees
both, so it is enforced in the view. It is the **one deliberately
application-level rule** in a codebase whose organising principle is that
limits hold at every layer (D-01) — worth naming rather than leaving as a
silent exception.

**What did not change:** unfiled items are still counted and still surfaced.
The nudge stays; the friction goes. The wording is factual — `3 unfiled` with a
control next to it — because an app that performs concern about your mess is
worse than one that simply counts it.

The real fix for filing friction is not encouragement but **fewer decisions**,
so location dropdowns now lead with a `Recent` group drawn from the movement
ledger. Most filing goes somewhere used minutes ago, and that should be one
click rather than a scroll through a tree.

---

## D-32 — A barcode is attacker-controlled input arriving through a camera

The sharpest question asked of this project so far was: *what if I print and
scan a barcode containing an attack?*

The answer is that a barcode **is not a number**. Code128 and QR encode
arbitrary bytes. Anyone can print one. And it arrives wearing the authority of
a physical object, which is exactly why it gets trusted when it should not be —
a value that came off a real box *feels* more legitimate than the same string
typed into a form, and is not.

`BarcodeDetector.rawValue` is a hostile string. A printed label could carry
`'; DROP TABLE items;--`, `../../../etc/passwd`,
`http://169.254.169.254/latest/meta-data/`, `<script>alert(1)</script>`, or a
megabyte of padding.

**One choke point, before the value is used for anything:**

```
^[0-9]{8,14}$      # GS1 GTIN-8/12/13/14
```

Everything else follows from it. Digits cannot escape a URL path segment,
cannot reach SQL as anything but a bound parameter, cannot become markup, and
cannot be a URL. The same rule is applied in the browser, in the form, and as a
database `CHECK`, so no path reaches storage without passing it.

**A failing code is rejected, never stored.** There is deliberately no
"keep it anyway, we just won't use it" path — a stored hostile value is only a
delayed one, waiting for some future code path to be less careful than this
one.

**And a scanned value is never navigated to.** This one is easy to miss and
would be the most damaging: DOOM's own QR labels resolve to share URLs, so a
scanner that followed what it read would happily open an attacker's page from a
sticker on a box. Scanning looks up locally and does nothing else.

### The lookup, and why it does not contradict D-13

D-13 says user URLs are never fetched server-side. The barcode lookup is the
one deliberate exception, and the distinction is the entire justification:

> D-13 forbids fetching **a URL the user supplied**. This calls **a fixed URL
> template belonging to a provider chosen from a dict in code**, with a
> validated numeric barcode substituted in.

The user supplies a *parameter*. They never supply a *destination*. That is the
difference between an API client and an SSRF hole.

Layered on top: `allow_redirects=False` — a redirect is precisely how a pinned
host becomes an arbitrary one, and following them would make the allowlist
decorative. Hostnames are resolved first and refused if they land on private,
loopback or link-local addresses, because DNS is not ours even when the
hostname is. Timeouts and a 256 KB cap bound a hostile or merely broken
upstream. The response is parsed as untrusted input: expected keys only, our own
length limits, control characters stripped.

It is **off by default**, opt-in, and every call is audited so the user can see
what left the machine. Prefill is a *suggestion* — the name lands in an editable
field, and nothing from a third party is written unreviewed.

**Known limitation:** resolve-then-connect leaves a DNS rebinding window. The
complete fix is a transport adapter pinned to the validated IP. Recorded rather
than hidden.

---

## D-33 — Provable history: hash-chained and append-only

Asked what real warehouses do that a hobby inventory does not, the honest
answer is not a feature. It is that shrinkage investigations depend on history
nobody could have edited.

Two mechanisms, at different layers:

**Append-only at the database.** `UPDATE` and `DELETE` are revoked from the
application's role on `audit_log`. After this, a *complete* SQL injection
through the application can add to history but never rewrite it. This is the
load-bearing half, because it does not depend on the application behaving.

**Hash-chained rows.** Each row stores `seq`, `prev_hash` and
`row_hash = sha256(prev_hash ‖ canonical(row))`. Editing or removing any row
invalidates every hash after it. `make audit-verify` walks the chain and names
the first divergence. Appends are serialised with `pg_advisory_xact_lock`, so
two concurrent writers cannot fork the chain and make honest data look
tampered with.

**One schema change fell out, and it was correct anyway.** `actor_user_id` lost
its `ON DELETE SET NULL` foreign key — a cascade is an `UPDATE`, which the
revoke forbids — and gained a denormalised `actor_username`. Audit rows are now
self-contained and **outlive the accounts they describe**, which is what an
audit trail is supposed to do. Deleting a user must not rewrite what they did.

### What it actually proves

Tamper-**evident**, not tamper-**proof**. Someone holding both database access
and the source can recompute the entire chain, and there is a test that asserts
exactly that so the claim cannot quietly inflate.

What it defeats is *silent selective editing* — quietly deleting the row that
recorded an inconvenient action — which is the realistic insider threat and the
one warehouse operations actually design against. Closing the remaining gap
needs an external anchor; the account page shows the head hash so it can be
noted somewhere outside the system, which is the cheap version.

Maps to NIST SP 800-53 AU-9 and OWASP ASVS V7.3.

---

## D-34 — Storage: deduplicated, capped, and visible

Photographs were re-encoded and then simply accumulated. No dedup, no ceiling,
no usage display — so **disk exhaustion was an availability hole** (T-46), and
availability failures are security failures however well-formed each individual
file is.

**Deduplicated** on the `sha256` that was already being computed and then
ignored. Deleting an attachment now unlinks the blob only when nothing else
references it.

**Scoped per owner, never globally.** This is the part worth defending. A
global dedup table saves more disk and leaks information: sharing a blob
between accounts reveals that two people hold an identical file, and makes
deletion behaviour an oracle for it — whether the bytes survive *your* delete
tells you whether someone else has the same picture (T-47). Per-owner costs a
little disk and closes that entirely.

**Capped** by a per-account quota summed from `byte_size` and checked *before*
the write, so a refused upload costs no disk at all.

**Visible** on the account page, because a quota nobody can see is a surprise
outage.

One constraint had to go: `attachments.stored_name` was `unique=True`, which
was right when one row meant one file and wrong the moment two rows could share
a blob. Uniqueness of the *content* is what `sha256` provides; the column is a
pointer, and pointers repeat.

---

## D-35 — Search is the primary interface

You cannot navigate a hierarchy you could not face building. Recall is the weak
channel; recognition is the strong one. So search lives in the masthead on
every screen rather than on one page, and covers items and locations together
along with barcodes, notes, addresses and attachment filenames.

Postgres full-text search with `websearch_to_tsquery` and a **bound
parameter** — which is also better security than what it replaced. The old
version escaped `%` and `_` by hand to build an `ILIKE` pattern; now the
database parses the user's search syntax itself, and there is one less place to
get quoting wrong (CWE-89). Short terms still fall back to `ILIKE`, because
full-text search matches whole lexemes and would return nothing for `dri`.

**Ownership scoping is the load-bearing part** (T-44). Locations carry site
addresses (D-24) — the single most sensitive field in the schema — so a search
that widened scope would be worse than having no search at all. Both halves
start from `owned_query()`, ranking never relaxes the filter, and tests assert
that a second account's items *and* locations, including addresses, never
appear.

The index expression uses `||` rather than `concat_ws`, because `concat_ws` is
not `IMMUTABLE` and cannot appear in an index. The application builds the
identical expression, since an expression index is only used when the query
matches it exactly.
