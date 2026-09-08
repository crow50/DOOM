"""Single source of truth for every limit the application enforces.

Nothing in DOOM invents a bound locally.  Forms, ORM columns, database CHECK
constraints, HTML attributes and the documentation table in docs/SECURITY.md
all read from the constants below, so a limit cannot be tightened in one place
and quietly left loose in another.

Each constant is enforced at *every* layer capable of enforcing it.  How many
layers that is depends on the kind of data:

    a text field   ->  HTML maxlength (hint) + WTForms Length + SQLAlchemy
                       column length + Postgres CHECK
    an upload      ->  Caddy body cap + Flask MAX_CONTENT_LENGTH + magic-byte
                       sniff + full decode/re-encode
    an integer     ->  WTForms NumberRange + column type + Postgres CHECK

The HTML attribute is a usability hint and is never treated as a control; a
client that ignores it still meets the server-side bound.  The principle is
that the browser cannot be trusted, so the same constant has to hold on the
server and again in the database.

Every list here is an ALLOWLIST.  Denylists fail open on the case nobody
thought of; allowlists fail closed.
"""

from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

USERNAME_MIN = 3
USERNAME_MAX = 32

#: Anchored, single character class, no nesting and no backtracking risk.
#: A pattern like ``^([a-z0-9]+)+$`` would be catastrophically slow on a
#: crafted input (T-32); this one is linear.
USERNAME_RE = re.compile(r"^[a-z0-9._-]+$")

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

#: NIST SP 800-63B: length is what actually resists guessing.  Composition
#: rules ("one uppercase, one symbol") measurably push users toward
#: "Password1!" and are deliberately NOT implemented.
PASSWORD_MIN = 12

#: An upper bound is a security control, not a convenience.  Argon2id reserves
#: 64 MiB per hash; without a cap, a megabyte password would let one request
#: consume real memory and CPU (T-30).
PASSWORD_MAX = 128

#: Share PINs protect a capability URL that is already unguessable, so they
#: defend against shoulder-surfing and casual forwarding rather than offline
#: cracking.  They are still Argon2id-hashed, never stored in the clear.
SHARE_PIN_MIN = 4
SHARE_PIN_MAX = 32

# ---------------------------------------------------------------------------
# Inventory content
# ---------------------------------------------------------------------------

LOCATION_NAME_MAX = 120

#: Free-text postal address for a site.
#:
#: This is the most sensitive single field in the application.  The rest of
#: the database says what someone owns; this says where to drive to take it.
#: It is excluded from the public share serializers by construction and must
#: stay that way (T-20, T-37).
ADDRESS_MAX = 500
ITEM_NAME_MAX = 120
DESCRIPTION_MAX = 4_000
NOTES_MAX = 4_000
LINK_LABEL_MAX = 120
URL_MAX = 2_000
SEARCH_QUERY_MAX = 100
MOVEMENT_REASON_MAX = 200

# ---------------------------------------------------------------------------
# Custody (checkout / return)
# ---------------------------------------------------------------------------

#: Who is holding the item.  Free text, because the holder is often not an
#: account on this instance - a contractor, a crew member, a job number.
HOLDER_NAME_MAX = 120
CHECKOUT_NOTE_MAX = 300

#: How far ahead a "due back" date may be set.  A bound rather than a rule:
#: it stops a typo becoming a due date in the year 9999, which then sorts
#: oddly and never alerts.
CHECKOUT_MAX_DAYS = 3650

#: Entries shown on an object's history panel before paging.
TIMELINE_PAGE_SIZE = 40

# ---------------------------------------------------------------------------
# Barcodes
# ---------------------------------------------------------------------------

#: GS1 GTIN-8, -12, -13 and -14. Digits only, anchored, no alternation.
#:
#: This is the single choke point for barcode input (T-43), and it deserves
#: more explanation than most constants here.
#:
#: A barcode is NOT a number. Code128 and QR encode arbitrary bytes, anyone can
#: print one, and it arrives wearing the authority of a physical object - which
#: is exactly why it gets trusted when it should not be. ``rawValue`` from the
#: browser's BarcodeDetector is as hostile as any form field, and a printed
#: label could carry:
#:
#:     '; DROP TABLE items;--
#:     ../../../etc/passwd
#:     http://169.254.169.254/latest/meta-data/
#:     <script>alert(1)</script>
#:
#: Constrained to digits, none of that survives: it cannot escape a URL path
#: segment, cannot reach SQL as anything but a bound parameter, cannot become
#: markup, and cannot be a URL.
#:
#: A code that fails this is REJECTED, never stored - a stored hostile value is
#: only a delayed one.
BARCODE_RE = re.compile(r"^[0-9]{8,14}$")
BARCODE_MAX = 14

#: Providers for the optional lookup. A dict in code, never a request
#: parameter: the user supplies the barcode, never the destination (T-40).
BARCODE_PROVIDERS = {
    "openfoodfacts": {
        "label": "Open Food Facts",
        "url": "https://world.openfoodfacts.org/api/v2/product/{barcode}.json",
        "note": "Open data, no account needed. Food and household goods.",
    },
    "upcitemdb": {
        "label": "UPCitemdb (trial)",
        "url": "https://api.upcitemdb.com/prod/trial/lookup?upc={barcode}",
        "note": "General merchandise. Rate limited.",
    },
}

#: Bounds on the outbound call. A hostile or merely broken upstream must not be
#: able to hold a worker open or stream us out of memory (T-41).
LOOKUP_CONNECT_TIMEOUT = 3.0
LOOKUP_READ_TIMEOUT = 5.0
LOOKUP_MAX_BYTES = 256 * 1024
LOOKUP_RATE_LIMIT = "20 per hour"

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

#: Per-account ceiling on stored attachments, checked BEFORE the write so a
#: refused upload costs nothing (T-46). Unbounded uploads are a disk-exhaustion
#: path, which is an availability problem however well-formed each file is.
STORAGE_QUOTA_BYTES = 2 * 1024 * 1024 * 1024

#: How many recently-used locations to offer at the top of a filing dropdown.
#: The fix for "filing is hard" is fewer decisions, not encouragement.
RECENT_LOCATION_COUNT = 5

#: Search
SEARCH_RESULT_LIMIT = 100
SEARCH_MIN_FTS_LENGTH = 3

QUANTITY_MIN = 0
QUANTITY_MAX = 1_000_000

#: How deep the warehouse -> zone -> rack -> shelf -> bin tree may nest.
#: Bounded so a cycle or a runaway script cannot produce a tree that is
#: expensive to render or traverse.
LOCATION_DEPTH_MAX = 12

#: Physical location kinds, coarsest to finest.  An allowlist, so an arbitrary
#: string can never reach the template or the database.
#:
#: Four tiers, each answering a different question, so no two overlap:
#:
#:   site   is it a place with an address?
#:   zone   is it a building or an outdoor area within that place?
#:   shelf  is it fixed storage furniture?
#:   bin    is it something you can pick up and carry?
#:
#: The earlier six-term set (warehouse/zone/rack/shelf/bin/tote) failed that
#: test twice over: "warehouse" and "zone" described the same thing, as did
#: "bin" and "tote", so choosing between them was a coin flip rather than a
#: decision.  Nesting is not enforced by kind - a shelf may sit directly in a
#: zone (flammables racked in an open yard) without inventing a building to
#: put it in.
LOCATION_KINDS = ("site", "zone", "shelf", "bin")

#: Shown beside each option in the form.  The distinction has to be visible at
#: the point of choosing, or it is not really a distinction.
LOCATION_KIND_LABELS = {
    "site": "Site",
    "zone": "Zone",
    "shelf": "Shelf",
    "bin": "Bin",
}

LOCATION_KIND_DESCRIPTIONS = {
    "site": "A geographic place, usually with an address",
    "zone": "A building or open yard within a site",
    "shelf": "Fixed storage: shelving, racking, a cabinet",
    "bin": "Something you can carry: a bin, tote, or crate",
}

#: Kinds for which an address makes sense.  Only a site is a place you could
#: drive to; a bin has a position, not an address.
ADDRESSABLE_KINDS = ("site",)

#: ITEM_BEARING_KINDS is deliberately gone.
#:
#: It used to restrict items to shelves, bins and totes, which was a rule the
#: interface never stated and the physical world does not obey - a pallet
#: stands in a bay, a vehicle sits in a yard.  Its only visible effect was an
#: empty "Location" dropdown for anyone who had created a site and a zone but
#: no bin, with nothing on screen explaining why.  Any location can hold items.

VISIBILITY_LEVELS = ("private", "shared")

# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------

#: Enforced by Flask's MAX_CONTENT_LENGTH before the body is buffered, and
#: again by Caddy at 12 MB so absurd bodies never reach Python at all (T-28).
UPLOAD_MAX_BYTES = 10 * 1024 * 1024

#: Content types are decided by inspecting magic bytes, never by trusting the
#: filename or the browser's Content-Type header (T-12).
ALLOWED_IMAGE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}

ALLOWED_DOC_TYPES = {
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "text/markdown": ".md",
}

ALLOWED_UPLOAD_TYPES = {**ALLOWED_IMAGE_TYPES, **ALLOWED_DOC_TYPES}

#: Deliberately absent, with reasons - see docs/DECISIONS.md:
#:
#:   image/svg+xml  SVG is an XSS vector.  It is a document format that can
#:                  carry <script>, and serving one same-origin executes it.
#:   application/zip and friends
#:                  Archives invite zip-slip, and nothing here needs them.
#:   anything else  Not on the list means rejected.

#: Pillow refuses to decode images above this many pixels, which stops a small
#: compressed file from expanding into gigabytes of RAM (T-29).
MAX_IMAGE_PIXELS = 50_000_000

#: Longest edge of a stored photograph.  Re-encoding to this size also strips
#: EXIF, which is where GPS coordinates hide (T-22).
IMAGE_MAX_DIMENSION = 2_400
THUMBNAIL_MAX_DIMENSION = 400
IMAGE_JPEG_QUALITY = 85

# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------

#: javascript: and data: are the obvious exclusions, but an allowlist means we
#: never have to enumerate the dangerous ones.  file: and gopher: are excluded
#: by the same silence.
URL_SCHEMES = frozenset({"http", "https"})

# ---------------------------------------------------------------------------
# Sharing and labels
# ---------------------------------------------------------------------------

#: 32 bytes -> 256 bits of entropy, URL-safe base64.  Not brute-forceable, and
#: the rate limits on share routes make even large-scale guessing pointless.
SHARE_TOKEN_BYTES = 32

#: Printed under each QR code so a bin stays findable by typing if the base
#: URL ever changes.  Unambiguous alphabet: no 0/O, no 1/I/L.
SHORT_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
SHORT_CODE_LENGTH = 8

# ---------------------------------------------------------------------------
# Authentication throttling
# ---------------------------------------------------------------------------

LOGIN_RATE_LIMIT = "10 per 15 minutes"
REGISTER_RATE_LIMIT = "5 per hour"
SHARE_RATE_LIMIT = "30 per minute;300 per hour"

#: ASVS 11.1.4 — anti-automation on high-value business flows, not just login.
#:
#: Rate limiting authentication and leaving everything else open protects the
#: front door and none of the windows. Mass creation, mass upload and bulk
#: enumeration of one's own data are all "excessive calls" in the sense the
#: requirement means, and uploads in particular are how you fill a disk.
#:
#: Set generously: these must never obstruct honest use, only bound automation.
WRITE_RATE_LIMIT = "120 per minute;2000 per hour"
UPLOAD_RATE_LIMIT = "30 per minute;300 per hour"

#: Consecutive failures before an account is locked.
LOCKOUT_THRESHOLD = 5

#: Escalating lockout, hard-capped.  The cap is the whole point: lockout keyed
#: on a username is itself a denial-of-service vector, because anyone who knows
#: your username can trigger it on demand (T-31).  Fifteen minutes keeps
#: brute force uneconomical while bounding what a griefer can do, and the lock
#: expires on its own with no operator involvement.
LOCKOUT_BACKOFF_SECONDS = (60, 300, 900)
LOCKOUT_MAX_SECONDS = 900

SESSION_LIFETIME_HOURS = 12

# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

DISPLAY_NAME_MAX = 80

#: Optional and never used for delivery - there is no SMTP in this deployment
#: and no password-reset flow (D-12).  Stored only so an activity trail can
#: name a person.  Collecting it at all is a small privacy cost, so it stays
#: optional and is never required to use the system.
EMAIL_MAX = 254

TIMEZONE_MAX = 64

#: Rows returned by the activity feed and the audit export.  Bounded so a
#: single request cannot be made to serialise an unbounded table.
ACTIVITY_PAGE_SIZE = 50
AUDIT_EXPORT_MAX_ROWS = 10_000


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def normalize_username(raw: str) -> str:
    """Fold a username to its canonical form before storage or comparison.

    NFKC normalisation collapses Unicode lookalikes to their ASCII
    equivalents, so the fullwidth "ａdmin" cannot be registered alongside
    "admin" as a visually identical impostor.  Case folding then makes the
    uniqueness constraint case-insensitive, which the citext column enforces
    at the database level as well.
    """
    return unicodedata.normalize("NFKC", raw or "").strip().casefold()


def is_valid_username(raw: str) -> bool:
    """Check a username against length and character allowlist."""
    name = normalize_username(raw)
    return (
        USERNAME_MIN <= len(name) <= USERNAME_MAX
        and USERNAME_RE.match(name) is not None
    )
