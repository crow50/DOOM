"""Unified history for a single item or location.

An object's history was previously only its ``movements``, which meant the
page showed quantity changes and nothing else.  Everything the application
already recorded - creation, edits, uploads, link changes, share settings,
and every time a shared link was opened - was written to ``audit_log`` and
never displayed anywhere object-specific.

This module merges the three ledgers into one chronological view:

* ``movements``  - where a thing went and how the count changed
* ``checkouts``  - who had it and when it came back
* ``audit_log``  - everything else that happened to it

**Scoping.**  Callers must resolve the object through ``get_owned_or_404``
*before* asking for its timeline.  Once ownership of the object is
established, every row referencing its id is by definition about that object,
so audit rows are matched on ``object_id`` alone.  That is deliberate rather
than lax: it is what lets an owner see anonymous events on their own things -
``share_viewed`` has no actor, and "someone opened your shared link, from this
address, at this time" is exactly the event an owner most needs to see (T-20).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import or_, select

from . import validation as v
from .extensions import db
from .models import AuditLog, Checkout, Item, Location, Movement

#: Audit actions already represented by a movement or checkout row. Showing
#: both would double every entry, so the richer row wins.
_REDUNDANT_ACTIONS = {
    "item_quantity_adjusted",
    "item_moved",
    "item_checked_out",
    "item_returned",
}

_AUDIT_LABELS = {
    "item_created": "Item created",
    "item_updated": "Details edited",
    "item_deleted": "Item deleted",
    "location_created": "Location created",
    "location_updated": "Details edited",
    "location_deleted": "Location deleted",
    "upload_stored": "File uploaded",
    "upload_rejected": "Upload rejected",
    "upload_deleted": "File deleted",
    "link_added": "Documentation link added",
    "share_updated": "Sharing settings changed",
    "share_token_rotated": "Share link rotated - previous labels stopped working",
    "share_viewed": "Shared link opened",
    "share_pin_accepted": "Share PIN accepted",
    "share_pin_rejected": "Share PIN rejected",
    "nfc_tag_registered": "NFC tag registered",
    "nfc_tag_reassigned": "NFC tag reassigned",
    "access_denied": "Blocked access attempt",
}


@dataclass(frozen=True)
class Event:
    """One entry in an object's history."""

    at: datetime
    kind: Literal["movement", "checkout", "audit"]
    summary: str
    detail: str | None = None
    actor: str | None = None
    delta: int | None = None
    ip: str | None = None
    #: Events nobody performed while signed in - a shared link being opened,
    #: an access attempt being blocked. Rendered differently because they are
    #: the ones an owner should actually look at.
    anonymous: bool = False


def _audit_actor_label(row, current_user_id) -> str:
    """Name the actor from the denormalised username.

    Audit rows hold no foreign key to ``users`` on purpose (T-45): the trail
    must outlive the accounts it describes, and a cascade would be an UPDATE on
    a table the application may only append to.
    """
    if row.actor_user_id and row.actor_user_id == current_user_id:
        return "you"
    return row.actor_username or "a removed account"


def _actor_label(actor, current_user_id) -> str:
    if actor is None:
        return "a removed account"
    if actor.id == current_user_id:
        return "you"
    return actor.label


def _movement_summary(m: Movement) -> str:
    if m.from_location_id and m.to_location_id and m.from_location_id != m.to_location_id:
        return "Moved"
    if m.delta_qty:
        return "Quantity adjusted"
    return "Movement recorded"


def item_timeline(item: Item, current_user_id, limit: int | None = None) -> list[Event]:
    """Every recorded event for one item, newest first."""
    limit = limit or v.TIMELINE_PAGE_SIZE
    events: list[Event] = []

    movements = db.session.execute(
        select(Movement)
        .where(Movement.item_id == item.id)
        .order_by(Movement.created_at.desc())
        .limit(limit)
    ).scalars().all()

    for m in movements:
        events.append(Event(
            at=m.created_at,
            kind="movement",
            summary=_movement_summary(m),
            detail=m.reason,
            actor=_actor_label(m.actor, current_user_id),
            delta=m.delta_qty or None,
        ))

    checkouts = db.session.execute(
        select(Checkout)
        .where(Checkout.item_id == item.id)
        .order_by(Checkout.checked_out_at.desc())
        .limit(limit)
    ).scalars().all()

    for c in checkouts:
        events.append(Event(
            at=c.checked_out_at,
            kind="checkout",
            summary=f"Checked out to {c.holder_name}",
            detail=c.note,
            actor=_actor_label(c.actor, current_user_id),
            delta=-c.quantity,
        ))
        if c.returned_at is not None:
            events.append(Event(
                at=c.returned_at,
                kind="checkout",
                summary=f"Returned by {c.holder_name}",
                detail=None,
                actor=_actor_label(c.actor, current_user_id),
                delta=c.quantity,
            ))

    events.extend(_audit_events(str(item.id), "item", current_user_id, limit))
    events.sort(key=lambda e: e.at, reverse=True)
    return events[:limit]


def location_timeline(location: Location, current_user_id, limit: int | None = None) -> list[Event]:
    """Every recorded event for one location.

    Includes movements in and out, because "what came through this bin" is the
    question an owner asks of a location - not just "when was it renamed".
    """
    limit = limit or v.TIMELINE_PAGE_SIZE
    events: list[Event] = []

    movements = db.session.execute(
        select(Movement)
        .where(or_(
            Movement.from_location_id == location.id,
            Movement.to_location_id == location.id,
        ))
        .order_by(Movement.created_at.desc())
        .limit(limit)
    ).scalars().all()

    for m in movements:
        name = m.item.name if m.item else "an item"
        if m.to_location_id == location.id and m.from_location_id != location.id:
            summary = f"{name} moved in"
        elif m.from_location_id == location.id and m.to_location_id != location.id:
            summary = f"{name} moved out"
        else:
            summary = f"{name} - quantity adjusted"
        events.append(Event(
            at=m.created_at,
            kind="movement",
            summary=summary,
            detail=m.reason,
            actor=_actor_label(m.actor, current_user_id),
            delta=m.delta_qty or None,
        ))

    checkouts = db.session.execute(
        select(Checkout)
        .where(Checkout.from_location_id == location.id)
        .order_by(Checkout.checked_out_at.desc())
        .limit(limit)
    ).scalars().all()

    for c in checkouts:
        name = c.item.name if c.item else "an item"
        events.append(Event(
            at=c.checked_out_at,
            kind="checkout",
            summary=f"{name} checked out to {c.holder_name}",
            detail=c.note,
            actor=_actor_label(c.actor, current_user_id),
            delta=-c.quantity,
        ))

    events.extend(_audit_events(str(location.id), "location", current_user_id, limit))
    events.sort(key=lambda e: e.at, reverse=True)
    return events[:limit]


def _audit_events(object_id: str, object_type: str, current_user_id, limit: int) -> list[Event]:
    """Audit rows for one object.

    Matched on object id, which is safe only because the caller has already
    resolved that object through an ownership-filtered query. The id is a
    UUID we generated, so it cannot collide with another account's row.
    """
    rows = db.session.execute(
        select(AuditLog)
        .where(
            AuditLog.object_id == object_id,
            AuditLog.object_type == object_type,
            AuditLog.action.notin_(_REDUNDANT_ACTIONS),
        )
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    ).scalars().all()

    events = []
    for row in rows:
        anonymous = row.actor_user_id is None
        events.append(Event(
            at=row.created_at,
            kind="audit",
            summary=_AUDIT_LABELS.get(
                row.action, row.action.replace("_", " ").capitalize()
            ),
            detail=row.detail,
            actor=None if anonymous else _audit_actor_label(row, current_user_id),
            # The address a shared link was opened from is the useful part of
            # an anonymous event, and it is meaningful only because ProxyFix
            # reads it from the one hop Caddy controls (T-07).
            ip=row.ip if anonymous else None,
            anonymous=anonymous,
        ))
    return events
