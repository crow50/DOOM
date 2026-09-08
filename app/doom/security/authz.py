"""Authorisation helpers.

One rule, applied everywhere: **ownership is a WHERE clause, not an if
statement.**

    # wrong - fetch, then check
    obj = db.session.get(Item, item_id)
    if obj.owner_id != current_user.id:
        abort(403)

    # right - the query cannot return someone else's row
    obj = get_owned_or_404(Item, item_id)

The difference is not stylistic.  Fetch-then-check loads the row before
deciding, so every branch after that point is one missing ``if`` away from
disclosure, and the two outcomes differ measurably in time and in behaviour.
Filtering inside the query means an unauthorised identifier and a
non-existent one are literally the same event: zero rows.

That is also why a miss is **404 and never 403** (T-18).  A 403 is an
admission that the object exists and belongs to someone else, which is exactly
the fact being protected.  404 says only "nothing here for you".
"""

from __future__ import annotations

import logging
import uuid
from typing import TypeVar

from flask import abort, request
from flask_login import current_user
from sqlalchemy import select

from ..extensions import db
from .audit import record_audit

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _coerce_uuid(value: str | uuid.UUID) -> uuid.UUID | None:
    """Parse a path parameter into a UUID, or None if it is not one.

    Returning None rather than raising keeps a malformed identifier on the
    same 404 path as a valid-but-unowned one, so probing with garbage reveals
    nothing that probing with a real UUID would not.
    """
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def get_owned_or_404(model: type[T], obj_id: str | uuid.UUID) -> T:
    """Fetch a row owned by the current user, or abort with 404.

    The ownership predicate is part of the SELECT.  There is no window between
    loading and checking, and no code path that reaches an object belonging to
    another account.
    """
    parsed = _coerce_uuid(obj_id)
    if parsed is None:
        abort(404)

    row = db.session.execute(
        select(model).where(
            model.id == parsed,
            model.owner_id == current_user.id,
        )
    ).scalar_one_or_none()

    if row is None:
        # A burst of these against valid-looking UUIDs is what enumeration
        # looks like from the inside.  Unrecorded, it is invisible.
        record_audit(
            action="access_denied",
            object_type=model.__name__.lower(),
            object_id=str(obj_id)[:64],
            detail="not found or not owned",
        )
        abort(404)

    return row


def owned_query(model: type[T]):
    """A SELECT already narrowed to the current user's rows.

    Use as the starting point for every listing, so scoping is the default
    rather than something each view has to remember to add.
    """
    return select(model).where(model.owner_id == current_user.id)


def assert_owned(*objects) -> None:
    """Verify ownership of already-loaded rows.

    Needed for operations spanning two objects - moving an item into a bin
    touches both, and validating only the item would let a user file their own
    property inside someone else's container.  Prefer ``get_owned_or_404``
    wherever a single lookup will do.
    """
    for obj in objects:
        if obj is None:
            abort(404)
        if getattr(obj, "owner_id", None) != current_user.id:
            record_audit(
                action="access_denied",
                object_type=type(obj).__name__.lower(),
                object_id=str(getattr(obj, "id", "")),
                detail=f"ownership assertion failed on {request.path}",
            )
            abort(404)
