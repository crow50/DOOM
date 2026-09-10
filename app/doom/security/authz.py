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

from flask import abort
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


def uuid_or_404(raw) -> uuid.UUID:
    """Parse a path parameter, treating garbage exactly like a miss.

    For the id of a row that is scoped through an already-checked parent rather
    than fetched by :func:`get_owned_or_404` - a link, a checkout - where the
    ownership predicate is the parent's but the id still has to be a UUID before
    it reaches a comparison.  Without this, an unparseable value raises a
    DataError and surfaces as a 500, which is both a different answer from every
    other bad id (D-06) and a needless stack trace.
    """
    parsed = _coerce_uuid(raw)
    if parsed is None:
        abort(404)
    return parsed


def record_access_denied(model: type, obj_id, detail: str) -> None:
    """Append the audit row for a refused object access.

    ``commit=True`` is load-bearing rather than incidental.  Every caller of
    this function raises immediately afterwards, so there is no later write for
    the row to ride along with, and the scoped session is rolled back when the
    app context tears down - which would discard the record entirely and leave
    enumeration exactly as invisible as the comment below says it must not be.
    Failed logins pass ``commit=True`` for the same reason (``blueprints/auth.py``).
    """
    record_audit(
        action="access_denied",
        object_type=model.__name__.lower(),
        object_id=str(obj_id)[:64],
        detail=detail,
        commit=True,
    )


def _owned_row(model: type[T], obj_id, *, for_update: bool):
    """Shared body of the two fetch helpers - one predicate, one denial path."""
    parsed = _coerce_uuid(obj_id)
    if parsed is None:
        # A malformed id is a miss, not a different answer (D-06) - and it is
        # deliberately not audited.  Only a well-formed id that addresses
        # someone else's row is evidence of enumeration; garbage in the path is
        # a broken link, and recording it would hand any authenticated user an
        # append-only table to flood.
        abort(404)

    statement = select(model).where(
        model.id == parsed,
        model.owner_id == current_user.id,
    )
    if for_update:
        statement = statement.with_for_update()

    row = db.session.execute(statement).scalar_one_or_none()

    if row is None:
        # A burst of these against valid-looking UUIDs is what enumeration
        # looks like from the inside.  Unrecorded, it is invisible.
        record_access_denied(model, obj_id, "not found or not owned")
        abort(404)

    return row


def get_owned_or_404(model: type[T], obj_id: str | uuid.UUID) -> T:
    """Fetch a row owned by the current user, or abort with 404.

    The ownership predicate is part of the SELECT.  There is no window between
    loading and checking, and no code path that reaches an object belonging to
    another account.
    """
    return _owned_row(model, obj_id, for_update=False)


def get_owned_for_update(model: type[T], obj_id: str | uuid.UUID) -> T:
    """``get_owned_or_404`` that also takes a row lock.

    Exists so that a view needing ``SELECT ... FOR UPDATE`` does not have to
    re-implement the ownership predicate inline to get it.  Checkout did exactly
    that, and in doing so skipped the denial audit above - the single vetted
    access-control mechanism ASVS 1.4.4 asks for has to cover the locking case
    too, or it is not single.
    """
    return _owned_row(model, obj_id, for_update=True)


def owned_query(model: type[T]):
    """A SELECT already narrowed to the current user's rows.

    Use as the starting point for every listing, so scoping is the default
    rather than something each view has to remember to add.
    """
    return select(model).where(model.owner_id == current_user.id)
