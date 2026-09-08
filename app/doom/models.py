"""Database models.

Two structural decisions carry most of the security weight here.

**UUID primary keys everywhere.**  There is no /items/1 to increment toward
/items/2.  Enumeration is not merely blocked by an authorisation check, it is
uninteresting: guessing a valid identifier is as hard as guessing a token.
This does not replace ownership filtering, it removes the cheap reconnaissance
that usually precedes it.

**One tree for every physical thing.**  A warehouse, a shelf and a tote are all
``Location`` rows differing by ``kind``.  A bin is simply a node that holds
items.  Because there is one type rather than two, labelling, sharing and
ownership checks have exactly one implementation each - and a control that
exists once cannot be applied inconsistently.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CITEXT, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from . import validation as v
from .extensions import db


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_share_token() -> str:
    """256 bits of entropy, URL-safe."""
    return secrets.token_urlsafe(v.SHARE_TOKEN_BYTES)


def new_short_code() -> str:
    """Human-readable label code, from an alphabet with no ambiguous glyphs."""
    return "".join(
        secrets.choice(v.SHORT_CODE_ALPHABET) for _ in range(v.SHORT_CODE_LENGTH)
    )


class UUIDMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=_uuid
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
        onupdate=func.now(),
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class User(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "users"

    # CITEXT makes the unique index itself case-insensitive.  Application code
    # also casefolds before writing, so "Admin" cannot be registered against
    # an existing "admin" even if a future code path forgets to normalise.
    username: Mapped[str] = mapped_column(CITEXT, unique=True, nullable=False)

    # Argon2id encoded string: algorithm, parameters and salt travel with the
    # hash, which is what lets check_needs_rehash upgrade cost silently later.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active_flag: Mapped[bool] = mapped_column(
        "is_active", Boolean, nullable=False, default=True
    )

    # Bumped on password change or "sign out everywhere".  The user loader
    # compares this against the value stored in the session, so every issued
    # cookie is invalidated at once without a server-side session store (T-06).
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- optional profile ---------------------------------------------------
    # All nullable. None of it is required to use the system, because none of
    # it is needed to use the system - data you do not hold cannot leak.
    # Email in particular is never used for delivery: there is no SMTP and no
    # password-reset flow (D-12). It exists so an activity trail can name a
    # person, and nothing else.
    display_name: Mapped[str | None] = mapped_column(String(v.DISPLAY_NAME_MAX))
    email: Mapped[str | None] = mapped_column(String(v.EMAIL_MAX))
    timezone: Mapped[str | None] = mapped_column(String(v.TIMEZONE_MAX))

    locations: Mapped[list["Location"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    items: Mapped[list["Item"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            f"char_length(username) BETWEEN {v.USERNAME_MIN} AND {v.USERNAME_MAX}",
            name="ck_users_username_length",
        ),
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_count"),
    )

    # --- Flask-Login interface ---------------------------------------------
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def is_active(self) -> bool:
        return self.is_active_flag

    def get_id(self) -> str:
        return str(self.id)

    # --- lockout ------------------------------------------------------------
    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return self.locked_until > utcnow()

    def lock_duration(self) -> timedelta:
        """Escalating backoff, hard-capped.

        The cap is the security decision, not the escalation (T-31).  Lockout
        keyed on a username is itself a denial-of-service primitive: anyone who
        knows a username can trigger it deliberately.  An uncapped or
        admin-only unlock turns that into an indefinite outage the victim
        cannot clear.  Capping at fifteen minutes keeps online guessing
        hopeless while bounding what a griefer achieves, and the lock lifts
        itself with no operator involvement.
        """
        steps = v.LOCKOUT_BACKOFF_SECONDS
        over = max(0, self.failed_login_count - v.LOCKOUT_THRESHOLD)
        seconds = steps[min(over, len(steps) - 1)]
        return timedelta(seconds=min(seconds, v.LOCKOUT_MAX_SECONDS))

    @property
    def label(self) -> str:
        """Name to show in activity trails."""
        return self.display_name or self.username

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class UserSession(UUIDMixin, db.Model):
    """One signed-in device or browser.

    ``session_version`` already gave a blunt "sign out everywhere" (T-06), but
    ASVS 3.3.4 asks for something finer: that a user can *see* their active
    sessions and end any one of them. You cannot revoke what you cannot
    enumerate, and "is anything else signed in as me right now?" is a question
    a person should be able to answer.

    The row is the authority. ``blueprints/auth.load_user`` checks it on every
    request, so revoking one takes effect immediately rather than at the next
    login.

    Only a truncated user-agent and the source address are kept — enough to
    recognise your own devices, and not a browsing history.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))

    #: Set rather than deleted, so "this session was ended, and when" survives
    #: as evidence.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_user_sessions_user", "user_id", "revoked_at"),
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @property
    def short_agent(self) -> str:
        """A recognisable label, not a fingerprint."""
        agent = self.user_agent or ""
        for name in ("Edg", "Chrome", "Firefox", "Safari", "curl"):
            if name in agent:
                platform = (
                    "Android" if "Android" in agent else
                    "iPhone" if "iPhone" in agent else
                    "Windows" if "Windows" in agent else
                    "Mac" if "Macintosh" in agent else
                    "Linux" if "Linux" in agent else ""
                )
                return f"{name}{' on ' + platform if platform else ''}"
        return "Unknown device"


# ---------------------------------------------------------------------------
# Shareable mixin
# ---------------------------------------------------------------------------

class ShareableMixin:
    """Capability-URL sharing for a node.

    The token identifies; the session authorizes.  Possession of a token
    resolves to a deliberately reduced public view and never to an editing
    surface - see security/serializers.py (T-36).
    """

    visibility: Mapped[str] = mapped_column(
        Enum(*v.VISIBILITY_LEVELS, name="visibility_level"),
        nullable=False,
        default="private",          # private unless explicitly shared
    )

    share_token: Mapped[str | None] = mapped_column(String(64), unique=True)
    short_code: Mapped[str | None] = mapped_column(String(16), unique=True)

    # Optional second factor for a shared URL.  Argon2id-hashed like any other
    # credential - a PIN stored in the clear would be worse than no PIN, since
    # it invites reuse of something the user already types elsewhere.
    share_pin_hash: Mapped[str | None] = mapped_column(String(255))

    @property
    def is_shared(self) -> bool:
        return self.visibility == "shared" and bool(self.share_token)


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

class Location(UUIDMixin, TimestampMixin, ShareableMixin, db.Model):
    """A node in the physical tree: warehouse, zone, rack, shelf, bin or tote.

    Multiple roots per owner is what "manage several warehouses" means: a
    Location with ``parent_id IS NULL`` is a top-level site.
    """

    __tablename__ = "locations"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="CASCADE")
    )

    kind: Mapped[str] = mapped_column(
        Enum(*v.LOCATION_KINDS, name="location_kind"), nullable=False, default="bin"
    )
    name: Mapped[str] = mapped_column(String(v.LOCATION_NAME_MAX), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    #: Postal address. Meaningful only on a site; a bin has a position, not an
    #: address.
    #:
    #: The most sensitive column in the schema. Everything else records what
    #: someone owns; this records where to drive to take it. It is absent from
    #: the public share serializers by construction, and a test asserts that it
    #: stays absent (T-37).
    address: Mapped[str | None] = mapped_column(String(v.ADDRESS_MAX))

    #: Cached tree depth, bounded so a runaway or cyclic structure cannot
    #: produce a tree that is expensive to walk or render.
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    owner: Mapped["User"] = relationship(back_populates="locations")
    parent: Mapped["Location | None"] = relationship(
        remote_side="Location.id", back_populates="children"
    )
    children: Mapped[list["Location"]] = relationship(
        back_populates="parent", cascade="all, delete-orphan",
        order_by="Location.name",
    )
    items: Mapped[list["Item"]] = relationship(
        back_populates="location", order_by="Item.name"
    )

    __table_args__ = (
        CheckConstraint(
            f"char_length(name) BETWEEN 1 AND {v.LOCATION_NAME_MAX}",
            name="ck_locations_name_length",
        ),
        CheckConstraint(
            f"notes IS NULL OR char_length(notes) <= {v.NOTES_MAX}",
            name="ck_locations_notes_length",
        ),
        CheckConstraint(
            f"depth BETWEEN 0 AND {v.LOCATION_DEPTH_MAX}", name="ck_locations_depth"
        ),
        CheckConstraint("id <> parent_id", name="ck_locations_not_self_parent"),
        # Every ownership-filtered lookup hits this pair, so it is the index
        # that matters most for the authorisation path.
        Index("ix_locations_owner_parent", "owner_id", "parent_id"),
    )

    @property
    def kind_label(self) -> str:
        return v.LOCATION_KIND_LABELS.get(self.kind, self.kind)

    @property
    def can_hold_items(self) -> bool:
        """Every location can hold items.

        Kept as a property so callers read declaratively, but there is no
        longer a rule behind it. The previous version restricted items to
        shelves, bins and totes - an invention the interface never explained
        and the physical world does not obey.
        """
        return True

    def __repr__(self) -> str:
        return f"<Location {self.kind}:{self.name}>"


# ---------------------------------------------------------------------------
# Items
# ---------------------------------------------------------------------------

class Item(UUIDMixin, TimestampMixin, ShareableMixin, db.Model):
    __tablename__ = "items"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="SET NULL")
    )

    #: Nullable on purpose.
    #:
    #: Requiring a name means requiring a decision before anything can be
    #: recorded, and the decision is the bottleneck this product exists to
    #: remove. An item needs a name OR a photo - see QuickCaptureForm.
    name: Mapped[str | None] = mapped_column(String(v.ITEM_NAME_MAX))
    description: Mapped[str | None] = mapped_column(Text)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    #: GS1 GTIN-8/12/13/14. Digits only, enforced at every entry point.
    #: A barcode is attacker-controlled input arriving through a camera
    #: (T-43) - anyone can print one.
    barcode: Mapped[str | None] = mapped_column(String(14), index=True)

    owner: Mapped["User"] = relationship(back_populates="items")
    location: Mapped["Location | None"] = relationship(back_populates="items")
    movements: Mapped[list["Movement"]] = relationship(
        back_populates="item", cascade="all, delete-orphan",
        order_by="Movement.created_at.desc()",
    )
    checkouts: Mapped[list["Checkout"]] = relationship(
        back_populates="item", cascade="all, delete-orphan",
        order_by="Checkout.checked_out_at.desc()",
    )
    attachments: Mapped[list["Attachment"]] = relationship(
        primaryjoin="Item.id == Attachment.item_id",
        viewonly=True, order_by="Attachment.created_at",
    )

    __table_args__ = (
        CheckConstraint(
            f"name IS NULL OR char_length(name) BETWEEN 1 AND {v.ITEM_NAME_MAX}",
            name="ck_items_name_length",
        ),
        # Digits only, at the database as well as the form. The regex is the
        # GS1 GTIN shape, which is also what makes it safe to interpolate
        # nowhere and bind everywhere.
        CheckConstraint(
            r"barcode IS NULL OR barcode ~ '^[0-9]{8,14}$'",
            name="ck_items_barcode_format",
        ),
        CheckConstraint(
            f"description IS NULL OR char_length(description) <= {v.DESCRIPTION_MAX}",
            name="ck_items_description_length",
        ),
        # The same bound the form enforces, restated where nothing can bypass
        # it - including a future script writing directly to the database.
        CheckConstraint(
            f"quantity BETWEEN {v.QUANTITY_MIN} AND {v.QUANTITY_MAX}",
            name="ck_items_quantity_range",
        ),
        Index("ix_items_owner_location", "owner_id", "location_id"),
    )

    @property
    def display_name(self) -> str:
        """What to show when the user has not named it yet.

        Presentation only. Every query still filters on ``owner_id``; this
        never participates in a lookup (T-43).
        """
        if self.name:
            return self.name
        when = self.created_at.strftime("%-d %b") if self.created_at else "recently"
        return f"Unnamed \u00b7 added {when}"

    @property
    def primary_photo(self) -> "Attachment | None":
        """First photo, used as the item's visual identity.

        Photographs are how an item is recognised when it has no name - the
        Sortly lesson. See docs/INSPIRATION.md.
        """
        for attachment in sorted(
            (a for a in self.attachments if a.kind == "photo"),
            key=lambda a: a.created_at,
        ):
            return attachment
        return None

    @property
    def open_checkouts(self) -> list["Checkout"]:
        return [c for c in self.checkouts if c.returned_at is None]

    @property
    def quantity_out(self) -> int:
        """How many are currently in someone's hands."""
        return sum(c.quantity for c in self.open_checkouts)

    @property
    def quantity_available(self) -> int:
        """Total owned minus what is signed out.

        ``quantity`` stays the number owned. Checking something out does not
        reduce it - the thing still exists, it is just elsewhere - so the two
        figures answer different questions and both stay truthful.
        """
        return max(0, self.quantity - self.quantity_out)

    @property
    def is_checked_out(self) -> bool:
        return self.quantity_out > 0

    def __repr__(self) -> str:
        return f"<Item {self.name}>"


# ---------------------------------------------------------------------------
# Movements - the ledger the project is named after
# ---------------------------------------------------------------------------

class Movement(UUIDMixin, db.Model):
    """One recorded change of place or count.

    Adding to or removing from a bin is written as a movement rather than an
    in-place edit, so the audit trail is a by-product of ordinary use rather
    than a separate thing to remember to write (T-16).
    """

    __tablename__ = "movements"

    item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE"), nullable=False
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    from_location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="SET NULL")
    )
    to_location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="SET NULL")
    )

    delta_qty: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reason: Mapped[str | None] = mapped_column(String(v.MOVEMENT_REASON_MAX))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    item: Mapped["Item"] = relationship(back_populates="movements")

    #: Who performed the movement. Nullable because a user may be deleted and
    #: the ledger outlives them - an entry with an unknown actor is still
    #: evidence that the change happened.
    actor: Mapped["User | None"] = relationship(foreign_keys=[actor_id])

    __table_args__ = (
        Index("ix_movements_item_created", "item_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Custody
# ---------------------------------------------------------------------------

class Checkout(UUIDMixin, db.Model):
    """One period during which some quantity of an item is in someone's hands.

    Custody is not location.  An item that has been signed out still *belongs*
    in its bin - that is where it returns to - so ``Item.location_id`` is left
    alone and this row records who has it in the meantime.  Overwriting the
    location instead would lose the answer to "where does this live", which is
    the question the whole application exists to answer.

    Open rows (``returned_at IS NULL``) are what make an item unavailable.
    Closed rows stay forever: the ledger is the audit trail, so a returned
    checkout is evidence, not garbage to clean up (T-16).
    """

    __tablename__ = "checkouts"

    item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE"), nullable=False
    )

    #: Who performed the action - always an account, always us.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: Who physically has it.  Free text, because the holder usually is not a
    #: user of this system: a contractor, a crew, a job number.
    holder_name: Mapped[str] = mapped_column(String(v.HOLDER_NAME_MAX), nullable=False)

    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    #: Where it was taken from, so a return can put it back without the user
    #: having to remember.
    from_location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="SET NULL")
    )

    checked_out_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    due_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    returned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    note: Mapped[str | None] = mapped_column(String(v.CHECKOUT_NOTE_MAX))

    item: Mapped["Item"] = relationship(back_populates="checkouts")
    actor: Mapped["User | None"] = relationship(foreign_keys=[actor_id])
    from_location: Mapped["Location | None"] = relationship(
        foreign_keys=[from_location_id]
    )

    __table_args__ = (
        CheckConstraint(
            f"quantity BETWEEN 1 AND {v.QUANTITY_MAX}", name="ck_checkouts_quantity"
        ),
        CheckConstraint(
            "returned_at IS NULL OR returned_at >= checked_out_at",
            name="ck_checkouts_return_after_issue",
        ),
        CheckConstraint(
            "char_length(holder_name) BETWEEN 1 AND "
            f"{v.HOLDER_NAME_MAX}",
            name="ck_checkouts_holder_length",
        ),
        # The index the availability calculation runs on.
        Index("ix_checkouts_item_open", "item_id", "returned_at"),
    )

    @property
    def is_open(self) -> bool:
        return self.returned_at is None

    @property
    def is_overdue(self) -> bool:
        if self.returned_at is not None or self.due_back_at is None:
            return False
        return self.due_back_at < utcnow()


# ---------------------------------------------------------------------------
# Attachments, links and tags - polymorphic over item OR location
# ---------------------------------------------------------------------------

class AttachedToMixin:
    """Attach a row to exactly one of an item or a location.

    Two nullable foreign keys with a CHECK enforcing exactly one, rather than
    a generic (object_type, object_id) pair.  The generic shape looks tidier
    and quietly discards referential integrity: nothing stops it pointing at a
    row that no longer exists, and no cascade can follow it.  Here the database
    still guarantees the target exists and still deletes children with it.
    """

    @staticmethod
    def _target_columns():
        return (
            mapped_column(
                UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE")
            ),
            mapped_column(
                UUID(as_uuid=True), ForeignKey("locations.id", ondelete="CASCADE")
            ),
        )


class Attachment(UUIDMixin, db.Model):
    """An uploaded photograph or document.

    Only ``stored_name`` ever reaches the filesystem, and it is a generated
    UUID.  ``original_name`` is retained purely for display and is never
    joined to a path - which is what makes traversal impossible by
    construction rather than by sanitising (T-11).
    """

    __tablename__ = "attachments"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    item_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE")
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="CASCADE")
    )

    kind: Mapped[str] = mapped_column(
        Enum("photo", "document", name="attachment_kind"), nullable=False
    )
    #: NOT unique. Deduplication means one file on disk can back several
    #: attachment rows — the same photo attached to two items costs one blob.
    #: Uniqueness of the *content* is what sha256 provides; this column is a
    #: pointer, and pointers repeat.
    stored_name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    thumbnail_name: Mapped[str | None] = mapped_column(String(80))
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)

    #: The type we determined by sniffing content, not the one the client
    #: claimed.  Responses are served with this value plus nosniff.
    content_type: Mapped[str] = mapped_column(String(80), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(item_id, location_id) = 1",
            name="ck_attachments_one_target",
        ),
        CheckConstraint(
            f"byte_size > 0 AND byte_size <= {v.UPLOAD_MAX_BYTES}",
            name="ck_attachments_size",
        ),
        Index("ix_attachments_item", "item_id"),
        Index("ix_attachments_location", "location_id"),
        # Dedup lookup: "has this owner already stored these exact bytes?"
        Index("ix_attachments_owner_sha", "owner_id", "sha256"),
    )


class DocLink(UUIDMixin, db.Model):
    """A link to external documentation - a manual, a how-to, a datasheet.

    The URL is stored and rendered, never fetched.  Fetching it server-side
    would make this field a request-forgery primitive pointed straight at the
    internal network, where ``db`` and ``cache`` resolve by hostname (T-25).
    """

    __tablename__ = "doc_links"

    item_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE")
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="CASCADE")
    )

    label: Mapped[str] = mapped_column(String(v.LINK_LABEL_MAX), nullable=False)
    url: Mapped[str] = mapped_column(String(v.URL_MAX), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(item_id, location_id) = 1", name="ck_doc_links_one_target"
        ),
        # Scheme allowlisting also happens in the form validator; restated here
        # so a direct database write cannot introduce a javascript: URL.
        CheckConstraint(
            "url LIKE 'http://%' OR url LIKE 'https://%'",
            name="ck_doc_links_url_scheme",
        ),
    )


class NfcTag(UUIDMixin, db.Model):
    """A physical NFC tag bound to a node.

    ``tag_uid`` is the serial number reported by the reader.  It is an
    identifier, never a credential: NDEF tags are cheap, unauthenticated and
    trivially cloned, so nothing is authorised on the strength of a UID alone
    (T-13).
    """

    __tablename__ = "nfc_tags"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    item_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="CASCADE")
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="CASCADE")
    )

    tag_uid: Mapped[str] = mapped_column(String(64), nullable=False)
    written_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(item_id, location_id) = 1", name="ck_nfc_tags_one_target"
        ),
        # Scoped per owner: two users may legitimately record the same cloned
        # UID, and a global unique constraint would leak that fact between them.
        UniqueConstraint("owner_id", "tag_uid", name="uq_nfc_tags_owner_uid"),
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

#: First link in the hash chain. A row whose ``prev_hash`` is this is claiming
#: to be the beginning of history, which is itself a checkable fact.
GENESIS_HASH = "0" * 64


class AuditLog(UUIDMixin, db.Model):
    """Append-only, tamper-evident record of security-relevant events.

    Denied access is recorded as well as granted: a run of 404s against
    identifiers belonging to another account is the signature of enumeration,
    and it is invisible unless the misses are written down (T-16, T-18).

    **Two mechanisms make this history hard to rewrite quietly (T-45).**

    *Append-only at the database.* ``UPDATE`` and ``DELETE`` are revoked from
    the application's role, so even a complete SQL injection through the app
    can only add rows. See ``db/init/01-roles.sh``.

    *Hash-chained.* Each row carries the hash of the one before it, so editing
    or removing any row invalidates every hash after it. ``flask audit-verify``
    walks the chain and names the first divergence.

    **Self-contained by design.** ``actor_user_id`` deliberately has no foreign
    key, and ``actor_username`` is denormalised at write time. A cascade would
    be an ``UPDATE`` — which the revoke above forbids — and, more importantly,
    an audit trail should outlive the accounts it describes. Deleting a user
    must not rewrite what they did.
    """

    __tablename__ = "audit_log"

    #: No ForeignKey, on purpose. See the class docstring.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    #: Captured at write time so the row still names a person after the account
    #: is gone.
    actor_username: Mapped[str | None] = mapped_column(String(v.USERNAME_MAX))

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(32))
    object_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(String(500))
    ip: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # --- chain ---------------------------------------------------------------
    #: Monotonic position. A gap in this sequence is evidence on its own, even
    #: before the hashes are checked.
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_audit_actor_created", "actor_user_id", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
        Index("ix_audit_seq", "seq"),
    )

    def canonical(self) -> str:
        """Deterministic serialisation of the fields the chain protects.

        Field order and separator are fixed, values are never omitted, and the
        separator is a character that cannot appear in a hex hash or a
        timestamp. Any ambiguity here would let two different rows produce the
        same digest, which is the whole property being relied on.
        """
        parts = [
            str(self.seq),
            self.created_at.isoformat() if self.created_at else "",
            str(self.actor_user_id or ""),
            self.actor_username or "",
            self.action or "",
            self.object_type or "",
            self.object_id or "",
            self.detail or "",
            self.ip or "",
        ]
        return "\x1f".join(parts)

    def compute_hash(self) -> str:
        payload = f"{self.prev_hash}\x1e{self.canonical()}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
