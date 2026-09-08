"""Locations - the warehouse → zone → rack → shelf → bin → tote tree.

Every query starts from ``owned_query`` or ``get_owned_or_404``, so scoping is
the default rather than something each view remembers to add.
"""

from __future__ import annotations

import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func, select

from .. import validation as v
from ..extensions import db, limiter
from ..forms import ConfirmForm, DocLinkForm, LocationForm
from ..models import Attachment, DocLink, Item, Location
from ..security.audit import record_audit
from ..security.authz import get_owned_or_404, owned_query
from ..timeline import location_timeline

logger = logging.getLogger(__name__)

bp = Blueprint("locations", __name__, url_prefix="/locations")


def _descendant_ids(root: Location) -> set:
    """Every id at or below ``root``, walking only rows this user owns.

    Used to keep a location out of its own subtree when re-parenting. Without
    it a user can make a node its own ancestor, producing a cycle that turns
    any recursive walk into an infinite loop - a self-inflicted denial of
    service that costs one dropdown selection.
    """
    seen: set = set()
    stack = [root]

    while stack:
        node = stack.pop()
        if node.id in seen:
            continue
        seen.add(node.id)

        children = db.session.execute(
            owned_query(Location).where(Location.parent_id == node.id)
        ).scalars().all()
        stack.extend(children)

    return seen


def _parent_choices(exclude: Location | None = None) -> list[tuple[str, str]]:
    """Build the "inside" dropdown from this user's own locations only.

    The choice list is itself an authorisation boundary: SelectField rejects
    any submitted value not present in it, so a forged parent_id pointing at
    another account's bin fails validation before the view runs.
    """
    blocked = _descendant_ids(exclude) if exclude is not None else set()

    rows = db.session.execute(
        owned_query(Location).order_by(Location.depth, Location.name)
    ).scalars().all()

    choices = [("", "- top level -")]
    for row in rows:
        if row.id in blocked:
            continue
        indent = " " * (row.depth * 3)
        choices.append((str(row.id), f"{indent}{row.name} ({row.kind})"))
    return choices


@bp.route("/")
@login_required
def index():
    roots = db.session.execute(
        owned_query(Location)
        .where(Location.parent_id.is_(None))
        .order_by(Location.name)
    ).scalars().all()

    # Unassigned items are deliberately NOT listed here. This page answers
    # "where are my things"; an item with no location has no answer to that
    # and belongs on the Items screen, which is where it is now surfaced.
    unassigned_count = db.session.scalar(
        select(func.count()).select_from(Item).where(
            Item.owner_id == current_user.id, Item.location_id.is_(None)
        )
    )

    # Contents preview for every node, so a closed container is not a black
    # hole. Object permanence is the whole reason this is here: a text list
    # requires reading, and recognising a photo does not.
    previews = _contents_previews()

    return render_template(
        "locations/index.html", roots=roots, unassigned_count=unassigned_count,
        previews=previews,
    )


def _contents_previews(limit_per_node: int = 4) -> dict:
    """Map location id -> (item count including descendants, photo thumbnails).

    Two queries for the whole tree rather than one per node.
    """
    locations = db.session.execute(owned_query(Location)).scalars().all()
    parents = {loc.id: loc.parent_id for loc in locations}

    counts: dict = {loc.id: 0 for loc in locations}
    photos: dict = {loc.id: [] for loc in locations}

    rows = db.session.execute(
        select(Item.id, Item.location_id)
        .where(Item.owner_id == current_user.id, Item.location_id.is_not(None))
    ).all()

    # Roll counts up the tree so a site shows everything beneath it.
    for _, location_id in rows:
        node, guard = location_id, 0
        while node is not None and guard <= v.LOCATION_DEPTH_MAX:
            guard += 1
            if node in counts:
                counts[node] += 1
            node = parents.get(node)

    thumbs = db.session.execute(
        select(Attachment.id, Item.location_id)
        .join(Item, Item.id == Attachment.item_id)
        .where(
            Attachment.owner_id == current_user.id,
            Attachment.kind == "photo",
            Item.location_id.is_not(None),
        )
        .order_by(Attachment.created_at.desc())
        .limit(400)
    ).all()

    for attachment_id, location_id in thumbs:
        node, guard = location_id, 0
        while node is not None and guard <= v.LOCATION_DEPTH_MAX:
            guard += 1
            bucket = photos.get(node)
            if bucket is not None and len(bucket) < limit_per_node:
                if attachment_id not in bucket:
                    bucket.append(attachment_id)
            node = parents.get(node)

    return {
        location_id: {"count": counts[location_id], "photos": photos[location_id]}
        for location_id in counts
    }


@bp.route("/<location_id>")
@login_required
def detail(location_id: str):
    location = get_owned_or_404(Location, location_id)

    children = db.session.execute(
        owned_query(Location)
        .where(Location.parent_id == location.id)
        .order_by(Location.name)
    ).scalars().all()

    items = db.session.execute(
        owned_query(Item)
        .where(Item.location_id == location.id)
        .order_by(Item.name)
    ).scalars().all()

    links = db.session.execute(
        select(DocLink).where(DocLink.location_id == location.id)
    ).scalars().all()

    attachments = db.session.execute(
        select(Attachment)
        .where(Attachment.location_id == location.id)
        .order_by(Attachment.created_at)
    ).scalars().all()

    # Locations get the same auditable history as items: what moved in and
    # out, what was checked out from here, plus edits, uploads, sharing
    # changes and every time this location's shared link was opened.
    events = location_timeline(location, current_user.id)

    return render_template(
        "locations/detail.html",
        location=location,
        events=events,
        attachments=attachments,
        children=children,
        items=items,
        links=links,
        trail=_ancestors(location),
        link_form=DocLinkForm(),
        confirm_form=ConfirmForm(),
    )


def _ancestors(node: Location) -> list[Location]:
    """Path from the root down to ``node``.

    Bounded by LOCATION_DEPTH_MAX so a malformed tree cannot loop forever.
    """
    trail: list[Location] = []
    seen: set = set()
    current: Location | None = node

    while current is not None and len(trail) <= v.LOCATION_DEPTH_MAX:
        if current.id in seen:
            logger.error(
                "location_cycle_detected",
                extra={"extra_fields": {"location_id": str(current.id)}},
            )
            break
        seen.add(current.id)
        trail.append(current)

        if current.parent_id is None:
            break
        current = db.session.execute(
            owned_query(Location).where(Location.id == current.parent_id)
        ).scalar_one_or_none()

    return list(reversed(trail))


@bp.route("/new", methods=["GET", "POST"])
@login_required
@limiter.limit(v.WRITE_RATE_LIMIT, methods=["POST"])
def create():
    form = LocationForm()
    form.parent_id.choices = _parent_choices()

    if form.validate_on_submit():
        parent = None
        if form.parent_id.data:
            # Ownership re-checked server-side. The dropdown is already
            # scoped, but a form field is client input and gets verified
            # regardless of where it appears to have come from.
            parent = get_owned_or_404(Location, form.parent_id.data)

        depth = (parent.depth + 1) if parent else 0
        if depth > v.LOCATION_DEPTH_MAX:
            flash(f"Locations can nest at most {v.LOCATION_DEPTH_MAX} deep.", "error")
            return render_template("locations/form.html", form=form, location=None)

        # Field by field, never **request.form. A submitted owner_id or
        # visibility simply has nothing to bind to (T-10).
        location = Location(
            owner_id=current_user.id,
            parent_id=parent.id if parent else None,
            kind=form.kind.data,
            name=form.name.data.strip(),
            notes=(form.notes.data or "").strip() or None,
            depth=depth,
        )
        db.session.add(location)
        record_audit(
            action="location_created", object_type="location", detail=location.name
        )
        db.session.commit()

        flash(f"Created {location.name}.", "success")
        return redirect(url_for("locations.detail", location_id=location.id))

    return render_template("locations/form.html", form=form, location=None)


@bp.route("/<location_id>/edit", methods=["GET", "POST"])
@login_required
def edit(location_id: str):
    location = get_owned_or_404(Location, location_id)

    form = LocationForm(obj=location)
    form.parent_id.choices = _parent_choices(exclude=location)

    if request.method == "GET":
        form.parent_id.data = str(location.parent_id) if location.parent_id else ""

    if form.validate_on_submit():
        parent = None
        if form.parent_id.data:
            parent = get_owned_or_404(Location, form.parent_id.data)

            # Belt and braces: _parent_choices already filtered the subtree,
            # but a cycle would be unrecoverable, so it is checked again here.
            if parent.id in _descendant_ids(location):
                flash("A location cannot be moved inside itself.", "error")
                return render_template(
                    "locations/form.html", form=form, location=location
                )

        location.name = form.name.data.strip()
        location.kind = form.kind.data
        location.notes = (form.notes.data or "").strip() or None
        location.parent_id = parent.id if parent else None
        location.depth = (parent.depth + 1) if parent else 0

        _reindex_depth(location)

        record_audit(
            action="location_updated", object_type="location",
            object_id=str(location.id), detail=location.name,
        )
        db.session.commit()

        flash("Location updated.", "success")
        return redirect(url_for("locations.detail", location_id=location.id))

    return render_template("locations/form.html", form=form, location=location)


def _reindex_depth(root: Location) -> None:
    """Recompute cached depth for a moved subtree."""
    stack = [root]
    guard = 0

    while stack and guard < 10_000:
        guard += 1
        node = stack.pop()
        children = db.session.execute(
            owned_query(Location).where(Location.parent_id == node.id)
        ).scalars().all()
        for child in children:
            child.depth = min(node.depth + 1, v.LOCATION_DEPTH_MAX)
            stack.append(child)


@bp.route("/<location_id>/delete", methods=["POST"])
@login_required
def delete(location_id: str):
    """POST with a CSRF token - never a GET link (T-09)."""
    location = get_owned_or_404(Location, location_id)
    form = ConfirmForm()

    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("locations.detail", location_id=location.id))

    parent_id = location.parent_id
    name = location.name

    record_audit(
        action="location_deleted", object_type="location",
        object_id=str(location.id), detail=name,
    )
    db.session.delete(location)
    db.session.commit()

    flash(f"Deleted {name}.", "info")
    if parent_id:
        return redirect(url_for("locations.detail", location_id=parent_id))
    return redirect(url_for("locations.index"))


@bp.route("/<location_id>/links", methods=["POST"])
@login_required
def add_link(location_id: str):
    location = get_owned_or_404(Location, location_id)
    form = DocLinkForm()

    if form.validate_on_submit():
        # Stored and rendered, never fetched. Fetching would aim a request
        # forgery primitive at db and cache, which resolve by hostname on this
        # network (T-25).
        db.session.add(
            DocLink(
                location_id=location.id,
                label=form.label.data.strip(),
                url=form.url.data.strip(),
            )
        )
        record_audit(
            action="link_added", object_type="location", object_id=str(location.id)
        )
        db.session.commit()
        flash("Link added.", "success")
    else:
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")

    return redirect(url_for("locations.detail", location_id=location.id))


@bp.route("/<location_id>/links/<link_id>/delete", methods=["POST"])
@login_required
def delete_link(location_id: str, link_id: str):
    location = get_owned_or_404(Location, location_id)
    form = ConfirmForm()

    if form.validate_on_submit():
        # Scoped by location_id, which was itself ownership-checked - a link
        # id belonging to another user's node matches nothing.
        link = db.session.execute(
            select(DocLink).where(
                DocLink.id == link_id, DocLink.location_id == location.id
            )
        ).scalar_one_or_none()

        if link is not None:
            db.session.delete(link)
            db.session.commit()
            flash("Link removed.", "info")

    return redirect(url_for("locations.detail", location_id=location.id))
