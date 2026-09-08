# What other inventory tools do, and what DOOM should take

DOOM sits between two products that look similar and want opposite things.

A **warehouse management system** assumes the structure already exists and asks
you to file into it. A **doom-pile tool** has to accept that the structure is
precisely what the user could not face — "Didn't Organize, Only Moved" is a
description of executive-function cost, not laziness.

Most of this document is about which ideas survive that tension. The ones that
do tend to be the ones that reduce *decisions*, not clicks.

---

## 1. The field

### Sortly — photo-first

The single most transferable idea in the category: **a photograph is the item's
identity**, not a decoration attached to a text record. You shoot first and
label later, or never.

Everything else in consumer inventory asks for a name before the thing can
exist, which is a decision, which is the bottleneck. Sortly asks for a picture,
which is a reflex.

**Taken.** DOOM's capture flow now accepts a photo with no name at all, and the
item renders as *Unnamed · added 3 Sep* with its picture until you feel like
naming it.

### Grocy — inventory has a verb

Grocy models *consumption*: stock decreases, minimum levels trigger a shopping
list, things expire. Its insight is that most home inventory is not a static
catalogue of possessions but a flow of consumables.

DOOM currently tracks nouns. Quantity goes up and down but nothing knows that
800 wood screws is a supply which will run out, while one cordless drill is an
object which will not.

**Partly taken, partly deferred.** Barcode capture is in. Minimum-stock levels
and "running low" are on the deferred list — genuinely useful, but they need a
consumable/durable distinction that does not exist yet.

### Homebox — the closest sibling

Self-hosted, locations, labels, attachments; the nearest thing to DOOM that
already exists. Its real edge is **data portability**: CSV import and export
both ways. Nobody should trust a system they cannot leave, and for a
self-hosted tool that is close to a moral obligation.

**Deferred, with intent.** CSV import is on the next-sprint list. It needs
column mapping, missing-column and collision handling, row caps, and formula
escaping in *both* directions — the audit export already escapes on the way out
(D-26); an import path means the same problem arriving.

### Snipe-IT — custody as a first-class concept

Asset management rather than inventory: who has the laptop, since when, is it
overdue. Checkout and check-in are the core loop, not an add-on.

**Already taken.** DOOM's `Checkout` model, the availability split between
"owned" and "on the shelf", and returning-to-origin all come from this lineage
(D-29).

### Inventree, Koillection — custom fields per type

A resistor has a resistance; a book has an ISBN; a paint tin has a colour code.
Both let a collection define its own attributes.

**Not taken, deliberately.** Custom fields are a schema the user has to design
before they can record anything — the exact upfront-structure trap this product
exists to avoid. If it ever lands it should be *after* capture, as an optional
enrichment, never as a precondition.

---

## 2. What real warehouses do

Fishbowl, Odoo, SAP EWM, Manhattan, Blue Yonder. It is worth being clear that
the professional niche is not a softer security problem than the hobby one — it
is a *harder* one, because the adversary is often an insider with legitimate
access.

The transferable ideas are **controls, not features**:

| Practice | What it is | Status in DOOM |
|---|---|---|
| **Immutable audit trail** | History that cannot be quietly rewritten | **Taken** — hash-chained and append-only (§5 of the plan, D-33) |
| **Cycle counting** | Scheduled verification that a location's contents match the record | Deferred — maps neatly onto "check this bin is still what the label says" |
| **Segregation of duties** | The person who counts stock is not the person who adjusts it | Deferred — DOOM records *who*, but nothing prevents self-approval |
| **Adjustment approval thresholds** | A write-off above a value needs a second signature | Deferred — depends on segregation of duties and on value tracking |
| **GS1 barcode standards** | GTIN-8/12/13/14 as the identifier format | **Taken** — the validation regex is the GS1 shape, which is also what makes it safe |
| **Hazmat segregation + SDS** | Flammables stored apart, safety data sheets attached | Partly possible today: a shelf can already sit in an open yard, and documents attach to locations |
| **Directed putaway / picking** | The system tells you where to put things | Not taken — the opposite of this product's premise |

Two of these deserve emphasis because they are what a professional would ask
about first.

**Immutable audit trail.** Shrinkage investigations depend on history nobody
could have edited. That is why DOOM's audit table is now hash-chained *and* has
`UPDATE`/`DELETE` revoked from the application's database role — so even a total
SQL injection through the app can only append. It is tamper-**evident** rather
than tamper-proof, and the docs say so plainly.

**Segregation of duties.** The single biggest gap remaining. DOOM is
single-account by design, so it is not a defect today, but the moment a second
person can write to an inventory, "the same person can adjust stock and approve
the adjustment" becomes the top insider risk. Recorded as a known limitation
rather than pretended away.

---

## 3. ADHD design principles

These are the rules the doom-pile framing actually implies. They are not soft
UX preferences; they change what the software is allowed to require.

### Capture before categorisation

Every required field is a decision, and decisions are the scarce resource. The
honest metric is **decisions per capture**, not clicks per capture.

DOOM was at three before anything could be saved — name, quantity, location.
That is how you get a pile. It is now zero: a photo is enough.

### Object permanence

Out of sight is genuinely out of mind. A closed bin is a black hole, and a text
list of its contents does not fix that because reading is work and recognising a
picture is not.

Hence thumbnails on location rows, in the tree, and as a grid on the location
page. The QR label on the outside of the box is the same principle in the
physical world.

### Search beats browse

You cannot navigate a hierarchy you could not face building. Recall is the weak
channel; recognition is the strong one.

Search is now in the masthead on every screen rather than living on one page.

### Fewer decisions, not more encouragement

The fix for "filing is hard" is not a cheerful message. It is putting the four
places you last used at the top of the dropdown, so the common case is one click
and no thought.

### Plain copy

No congratulation, no scolding, no therapeutic voice. `3 unfiled` with a control
next to it. An app that performs concern about your mess is worse than one that
simply counts it.

### Interruption safety

Anything that can be abandoned mid-way should survive being abandoned mid-way.
This is why undo matters more here than in most software, and why it is the
deferred item most worth doing next.

---

## 4. Deferred, with reasons

Not dropped — sequenced. Each of these was considered and consciously held back.

| Idea | Why it waits |
|---|---|
| **Triage mode** — one item, three big destination buttons, skip | The highest-leverage ADHD feature and the best demo of the lot. Held only because capture had to come first: there is no point building a sorting flow before there is anything unsorted |
| **Doom piles as objects** — photograph a pile, itemise later or never | Makes the honest state representable. Needs a location kind with an "unprocessed" flag and a UI that does not treat it as a failure |
| **Undo / soft delete** | Deletion is currently immediate. ADHD and impulsivity mean mistakes, and permanent deletion punishes them. Changes data retention — "deleted" stops meaning gone — so it needs a threat-model entry before it lands |
| **CSV import/export** | Portability, per Homebox. Needs column mapping, collision and missing-column handling, row caps, and formula escaping on ingest as well as export |
| **Purchase price + value roll-ups** | Useful for insurance and for tracking cost over time with real evidence rather than a vendor's number. **Needs its own threat entry first**: total value per site makes the database materially more attractive to exactly the burglar the threat model names |
| **Warranty tracking** | A toggle plus an expiry date covers most cases, but manufacturer terms (90–365 days), extended warranties, and receipts-as-proof make it a larger design than it looks. Worth doing properly rather than half |
| **Minimum stock / running low** | Needs a consumable-versus-durable distinction that does not exist yet |
| **Cycle counting** | Straightforward once there is a reason to verify — pairs naturally with the audit chain |
| **Segregation of duties, approval thresholds** | Meaningless while the model is single-account; essential the moment it is not |

---

## 5. What DOOM will not do

Stating these keeps the product coherent.

- **No directed putaway.** Telling the user where to put things is a warehouse
  optimiser's job and the opposite of this product's premise.
- **No required taxonomy before capture.** Custom fields, categories and tags
  may enrich an item afterwards; none may block recording one.
- **No streaks, badges, or productivity scoring.** Gamifying tidiness turns a
  bad week into a broken streak, which is worse than no feature.
- **No cloud sync, no accounts service.** Self-hosted is the point; the data is
  a map to physical property (see the threat model).
