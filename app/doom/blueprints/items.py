"""Items, and the movement ledger the project is named after."""

from __future__ import annotations

import logging

from datetime import datetime, time, timezone

from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect, render_template,
    request, url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func, select, text, update

from .. import validation as v
from ..extensions import db, limiter
from ..forms import (
    CheckoutForm,
    QuickCaptureForm,
    ConfirmForm,
    DocLinkForm,
    ItemForm,
    MoveItemForm,
    QuantityAdjustForm,
    ReturnForm,
    SearchForm,
)
from ..models import Attachment, Checkout, DocLink, Item, Location, Movement, utcnow
from ..security.audit import record_audit
from ..security.authz import get_owned_or_404, owned_query
from ..security.lookup import LookupUnavailable, lookup_barcode
from ..security.redirects import safe_referrer_path
from ..security.uploads import UploadRejected, store_upload
from ..timeline import item_timeline

logger = logging.getLogger(__name__)

bp = Blueprint("items", __name__, url_prefix="/items")


def _uuid_or_404(raw: str):
    """Parse a path parameter, treating garbage exactly like a miss.

    A malformed id must take the same route as a valid-but-unowned one, or the
    difference becomes an oracle (D-06).
    """
    import uuid as _uuid_mod
    try:
        return _uuid_mod.UUID(str(raw))
    except (ValueError, AttributeError, TypeError):
        abort(404)


def _location_choices(include_unassigned: bool = True) -> list[tuple[str, str]]:
    """Every location this user owns, labelled with its path.

    Previously this filtered on a hardcoded set of "item-bearing" kinds, which
    meant anyone who had created a site and a zone but no bin saw an empty
    dropdown with nothing on screen explaining why. Any location can hold
    items - a pallet stands in a bay, a vehicle sits in a yard.

    Labels carry the ancestor path because two shelves called "Shelf 1" in
    different buildings are otherwise indistinguishable at the moment of
    choosing. The path is safe to show here: this is the owner's own view, not
    a public one.
    """
    rows = db.session.execute(
        owned_query(Location).order_by(Location.depth, Location.name)
    ).scalars().all()

    by_id = {row.id: row for row in rows}

    def path_label(row: Location) -> str:
        parts, node, guard = [], row, 0
        while node is not None and guard <= v.LOCATION_DEPTH_MAX:
            guard += 1
            parts.append(node.name)
            node = by_id.get(node.parent_id) if node.parent_id else None
        return " / ".join(reversed(parts))

    def option(r):
        return (
            str(r.id),
            f"{path_label(r)}  ({v.LOCATION_KIND_LABELS.get(r.kind, r.kind)})",
        )

    choices = [("", "- unassigned -")] if include_unassigned else []

    # Recently used destinations first.
    #
    # The fix for "filing is hard" is fewer decisions, not encouragement: most
    # filing goes somewhere used minutes ago, and that should be one click
    # rather than a scroll through a tree. Read from the movement ledger that
    # already exists.
    recent_ids = db.session.execute(
        select(Movement.to_location_id)
        .join(Item, Item.id == Movement.item_id)
        .where(
            Item.owner_id == current_user.id,
            Movement.to_location_id.is_not(None),
        )
        .order_by(Movement.created_at.desc())
        .limit(60)
    ).scalars().all()

    seen, recent = set(), []
    for location_id in recent_ids:
        if location_id in seen or location_id not in by_id:
            continue
        seen.add(location_id)
        recent.append(by_id[location_id])
        if len(recent) >= v.RECENT_LOCATION_COUNT:
            break

    if recent:
        choices.extend(option(r) for r in recent)
        # A disabled separator, so the repeat below is obviously a full list
        # rather than duplicates.
        choices.append(("", "- all locations -"))

    choices.extend(option(r) for r in rows)
    return choices


@bp.route("/")
@login_required
def index():
    form = SearchForm(request.args, meta={"csrf": False})
    query = owned_query(Item)

    if form.q.data:
        # The one raw-SQL construct in the application, and the worked example
        # for docs/SECURITY.md.
        #
        # The term is a BOUND PARAMETER (:term). SQLAlchemy sends the statement
        # and the value separately, so the database never parses user input as
        # SQL. Building this with an f-string is the whole of CWE-89:
        #
        #     text(f"... ILIKE '%{term}%'")   # <-- never
        #
        # Wildcards in the term are escaped so a search for "100%" is a
        # literal search rather than a match-everything scan.
        term = form.q.data.strip()[: v.SEARCH_QUERY_MAX]
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(
            text(
                "(items.name ILIKE :term ESCAPE '\\' "
                "OR coalesce(items.description, '') ILIKE :term ESCAPE '\\')"
            ).bindparams(term=f"%{escaped}%")
        )

    # Unassigned items are surfaced here rather than on the locations tree,
    # where they had no meaningful place to sit.
    if request.args.get("unassigned") == "1":
        query = query.where(Item.location_id.is_(None))

    unassigned_count = db.session.scalar(
        select(func.count()).select_from(Item).where(
            Item.owner_id == current_user.id, Item.location_id.is_(None)
        )
    )

    items = db.session.execute(query.order_by(Item.name).limit(200)).scalars().all()
    return render_template(
        "items/index.html",
        items=items,
        form=form,
        unassigned_count=unassigned_count,
        showing_unassigned=request.args.get("unassigned") == "1",
    )


@bp.route("/<item_id>")
@login_required
def detail(item_id: str):
    item = get_owned_or_404(Item, item_id)

    links = db.session.execute(
        select(DocLink).where(DocLink.item_id == item.id)
    ).scalars().all()

    # One chronological history rather than movements alone: creation, edits,
    # uploads, link changes, sharing, and every time a shared link was opened.
    events = item_timeline(item, current_user.id)

    open_checkouts = db.session.execute(
        select(Checkout)
        .where(Checkout.item_id == item.id, Checkout.returned_at.is_(None))
        .order_by(Checkout.checked_out_at)
    ).scalars().all()

    attachments = db.session.execute(
        select(Attachment)
        .where(Attachment.item_id == item.id)
        .order_by(Attachment.created_at)
    ).scalars().all()

    move_form = MoveItemForm()
    move_form.location_id.choices = _location_choices(include_unassigned=False)

    return render_template(
        "items/detail.html",
        item=item,
        links=links,
        events=events,
        open_checkouts=open_checkouts,
        attachments=attachments,
        adjust_form=QuantityAdjustForm(),
        move_form=move_form,
        link_form=DocLinkForm(),
        checkout_form=CheckoutForm(),
        return_form=ReturnForm(),
        confirm_form=ConfirmForm(),
    )


@bp.route("/barcode/<barcode>")
@login_required
@limiter.limit(v.LOOKUP_RATE_LIMIT)
def barcode_lookup(barcode: str):
    """Suggest a product name for a scanned barcode.

    Two things happen first, in order, and both matter:

    1. The barcode is validated to the GS1 shape. A value that fails is
       rejected outright — never stored, never sent (T-43).
    2. Any item this user already has with that barcode wins, with **no
       outbound request at all**. Local knowledge beats a third party, and the
       common case costs nothing and leaks nothing.

    Only then, and only if the operator has opted in, is a provider consulted.
    """
    candidate = (barcode or "").strip()
    if not v.BARCODE_RE.match(candidate):
        return jsonify({"error": "Barcodes are 8-14 digits."}), 400

    existing = db.session.execute(
        owned_query(Item).where(Item.barcode == candidate).limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        return jsonify({
            "source": "local",
            "name": existing.display_name,
            "item_url": url_for("items.detail", item_id=existing.id),
        })

    provider = current_app.config.get("BARCODE_LOOKUP_PROVIDER")
    if not provider:
        return jsonify({"source": "none"})

    try:
        suggestion = lookup_barcode(candidate, provider)
    except LookupUnavailable as exc:
        # Recorded so the user can see that something did leave the machine,
        # and what came back (T-42).
        record_audit(
            action="barcode_lookup_failed", object_type="item",
            detail=f"{provider}: {exc}"[:200], commit=True,
        )
        return jsonify({"source": "none", "note": str(exc)})

    record_audit(
        action="barcode_lookup", object_type="item",
        detail=f"{provider}: {candidate}", commit=True,
    )
    return jsonify({
        "source": "remote",
        "provider": suggestion.provider,
        "name": suggestion.name,
        "brand": suggestion.brand,
    })


@bp.route("/quick", methods=["GET", "POST"])
@login_required
@limiter.limit(v.UPLOAD_RATE_LIMIT, methods=["POST"])
def quick():
    """Capture something with as few decisions as possible.

    Nothing is required except that the result be identifiable: a name OR a
    photo. That invariant cannot live in the database - the photo is a row in
    ``attachments`` and the name is a column on ``items``, so no single CHECK
    sees both - which makes this the one deliberately application-level rule in
    the schema.

    Uploads go through the existing ``store_upload()``, so the magic-byte
    sniff, re-encode and EXIF stripping all apply unchanged. There is no second
    ingestion path.
    """
    form = QuickCaptureForm()
    form.location_id.choices = _location_choices()

    if form.validate_on_submit():
        files = [f for f in request.files.getlist("file") if f and f.filename]
        name = (form.name.data or "").strip()

        if not name and not files:
            flash("Add a photo or a name - either is enough.", "error")
            return render_template("items/quick.html", form=form)

        location = None
        if form.location_id.data:
            location = get_owned_or_404(Location, form.location_id.data)

        item = Item(
            owner_id=current_user.id,
            location_id=location.id if location else None,
            name=name or None,
            barcode=form.barcode.data or None,
            quantity=1,
        )
        db.session.add(item)
        db.session.flush()

        stored = 0
        upload_dir = current_app.config["UPLOAD_DIR"]
        for storage in files[:5]:
            try:
                result = store_upload(storage, upload_dir, owner_id=current_user.id)
            except UploadRejected as exc:
                flash(str(exc), "error")
                continue
            db.session.add(Attachment(
                owner_id=current_user.id,
                item_id=item.id,
                kind=result.kind,
                stored_name=result.stored_name,
                thumbnail_name=result.thumbnail_name,
                original_name=result.original_name,
                content_type=result.content_type,
                byte_size=result.byte_size,
                sha256=result.sha256,
            ))
            stored += 1

        if not name and not stored:
            # Every upload was rejected and there is no name, so nothing would
            # identify this item.
            db.session.rollback()
            return render_template("items/quick.html", form=form)

        db.session.add(Movement(
            item_id=item.id, actor_id=current_user.id,
            to_location_id=item.location_id, delta_qty=1, reason="captured",
        ))
        record_audit(action="item_created", object_type="item",
                     object_id=str(item.id), detail="quick capture")
        db.session.commit()

        flash(f"Captured {item.display_name}.", "success")
        return redirect(url_for("items.quick"))

    return render_template("items/quick.html", form=form)


@bp.route("/<item_id>/file", methods=["POST"])
@login_required
def file_item(item_id: str):
    """Assign a location from a list, without opening the full edit form."""
    item = get_owned_or_404(Item, item_id)

    form = MoveItemForm()
    form.location_id.choices = _location_choices(include_unassigned=False)

    if not form.validate_on_submit():
        flash("That location was not valid.", "error")
        return redirect(request.referrer or url_for("items.index"))

    destination = get_owned_or_404(Location, form.location_id.data)
    previous = item.location_id
    item.location_id = destination.id

    db.session.add(Movement(
        item_id=item.id, actor_id=current_user.id,
        from_location_id=previous, to_location_id=destination.id,
        reason="filed",
    ))
    record_audit(action="item_moved", object_type="item",
                 object_id=str(item.id), detail=f"filed to {destination.name}")
    db.session.commit()

    flash(f"Filed under {destination.name}.", "success")
    return redirect(safe_referrer_path("items.index"))


@bp.route("/new", methods=["GET", "POST"])
@login_required
@limiter.limit(v.WRITE_RATE_LIMIT, methods=["POST"])
def create():
    form = ItemForm()
    form.location_id.choices = _location_choices()

    if request.method == "GET" and request.args.get("location"):
        form.location_id.data = request.args.get("location")

    if form.validate_on_submit():
        location = None
        if form.location_id.data:
            location = get_owned_or_404(Location, form.location_id.data)

        item = Item(
            owner_id=current_user.id,
            location_id=location.id if location else None,
            name=(form.name.data or "").strip() or None,
            barcode=form.barcode.data or None,
            description=(form.description.data or "").strip() or None,
            quantity=form.quantity.data,
        )
        db.session.add(item)
        db.session.flush()  # assign the PK so the movement can reference it

        db.session.add(
            Movement(
                item_id=item.id,
                actor_id=current_user.id,
                to_location_id=item.location_id,
                delta_qty=item.quantity,
                reason="created",
            )
        )
        record_audit(action="item_created", object_type="item", object_id=str(item.id))
        db.session.commit()

        flash(f"Added {item.display_name}.", "success")
        return redirect(url_for("items.detail", item_id=item.id))

    return render_template("items/form.html", form=form, item=None)


@bp.route("/<item_id>/edit", methods=["GET", "POST"])
@login_required
def edit(item_id: str):
    item = get_owned_or_404(Item, item_id)

    form = ItemForm(obj=item)
    form.location_id.choices = _location_choices()

    if request.method == "GET":
        form.location_id.data = str(item.location_id) if item.location_id else ""

    if form.validate_on_submit():
        location = None
        if form.location_id.data:
            location = get_owned_or_404(Location, form.location_id.data)

        previous_location = item.location_id
        new_location = location.id if location else None

        item.name = (form.name.data or "").strip() or None
        item.barcode = form.barcode.data or None
        item.description = (form.description.data or "").strip() or None
        item.location_id = new_location

        # Quantity is edited here for correction, but every change is still
        # written to the ledger so the history stays complete.
        if form.quantity.data != item.quantity:
            db.session.add(
                Movement(
                    item_id=item.id,
                    actor_id=current_user.id,
                    delta_qty=form.quantity.data - item.quantity,
                    reason="corrected",
                )
            )
            item.quantity = form.quantity.data

        if previous_location != new_location:
            db.session.add(
                Movement(
                    item_id=item.id,
                    actor_id=current_user.id,
                    from_location_id=previous_location,
                    to_location_id=new_location,
                    reason="edited",
                )
            )

        record_audit(action="item_updated", object_type="item", object_id=str(item.id))
        db.session.commit()

        flash("Item updated.", "success")
        return redirect(url_for("items.detail", item_id=item.id))

    return render_template("items/form.html", form=form, item=item)


@bp.route("/<item_id>/adjust", methods=["POST"])
@login_required
@limiter.limit(v.WRITE_RATE_LIMIT)
def adjust(item_id: str):
    """Apply a signed quantity change atomically.

    The update is computed by the database, not by Python:

        UPDATE items SET quantity = quantity + :delta WHERE ...

    Read-modify-write loses updates whenever two requests overlap, which is
    the normal case here rather than an exotic one - two people with phones
    are scanning the same bin (T-15). The WHERE clause also enforces the
    bounds, so a decrement below zero or above the ceiling matches no row and
    changes nothing, instead of writing an out-of-range value and relying on
    the CHECK constraint to raise.
    """
    item = get_owned_or_404(Item, item_id)
    form = QuantityAdjustForm()

    if not form.validate_on_submit():
        flash("That adjustment was not valid.", "error")
        return redirect(url_for("items.detail", item_id=item.id))

    delta = form.delta.data

    result = db.session.execute(
        update(Item)
        .where(
            Item.id == item.id,
            Item.owner_id == current_user.id,          # ownership, again, in SQL
            Item.quantity + delta >= v.QUANTITY_MIN,
            Item.quantity + delta <= v.QUANTITY_MAX,
        )
        .values(quantity=Item.quantity + delta)
        .returning(Item.quantity)
    )
    updated = result.scalar_one_or_none()

    if updated is None:
        db.session.rollback()
        flash(
            f"That change would put the count outside "
            f"{v.QUANTITY_MIN}–{v.QUANTITY_MAX}.",
            "error",
        )
        return redirect(url_for("items.detail", item_id=item.id))

    db.session.add(
        Movement(
            item_id=item.id,
            actor_id=current_user.id,
            from_location_id=item.location_id,
            to_location_id=item.location_id,
            delta_qty=delta,
            reason=(form.reason.data or "").strip() or None,
        )
    )
    record_audit(
        action="item_quantity_adjusted", object_type="item",
        object_id=str(item.id), detail=f"delta {delta:+d} -> {updated}",
    )
    db.session.commit()

    flash(f"Count is now {updated}.", "success")
    return redirect(url_for("items.detail", item_id=item.id))


@bp.route("/<item_id>/move", methods=["POST"])
@login_required
def move(item_id: str):
    """Move an item to another container.

    Both ends are ownership-checked. Validating only the item would let a user
    file their own property inside someone else's bin - a write into another
    account's tree, which is Broken Access Control even though the row being
    written is legitimately theirs (T-18).
    """
    item = get_owned_or_404(Item, item_id)

    form = MoveItemForm()
    form.location_id.choices = _location_choices()[1:]

    if not form.validate_on_submit():
        flash("That move was not valid.", "error")
        return redirect(url_for("items.detail", item_id=item.id))

    destination = get_owned_or_404(Location, form.location_id.data)
    previous = item.location_id
    item.location_id = destination.id

    db.session.add(
        Movement(
            item_id=item.id,
            actor_id=current_user.id,
            from_location_id=previous,
            to_location_id=destination.id,
            reason=(form.reason.data or "").strip() or None,
        )
    )
    record_audit(
        action="item_moved", object_type="item", object_id=str(item.id),
        detail=f"to {destination.name}",
    )
    db.session.commit()

    flash(f"Moved to {destination.name}.", "success")
    return redirect(url_for("items.detail", item_id=item.id))


@bp.route("/<item_id>/checkout", methods=["POST"])
@login_required
@limiter.limit(v.WRITE_RATE_LIMIT)
def checkout(item_id: str):
    """Sign some quantity of an item out to a holder.

    Custody, not relocation: ``location_id`` is left alone so the item still
    knows where it lives and where a return puts it back.

    The row is locked with ``SELECT ... FOR UPDATE`` before availability is
    computed. Two people checking out the last drill at the same moment would
    otherwise both read "1 available" and both succeed, leaving the ledger
    claiming two are out when one exists - the same lost-update race the
    quantity adjustment avoids, but arithmetic in SQL cannot fix this one
    because the check spans two tables (T-15).
    """
    form = CheckoutForm()

    locked = db.session.execute(
        select(Item)
        .where(Item.id == _uuid_or_404(item_id), Item.owner_id == current_user.id)
        .with_for_update()
    ).scalar_one_or_none()

    if locked is None:
        db.session.rollback()
        abort(404)

    if not form.validate_on_submit():
        db.session.rollback()
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")
        return redirect(url_for("items.detail", item_id=item_id))

    outstanding = db.session.scalar(
        select(func.coalesce(func.sum(Checkout.quantity), 0)).where(
            Checkout.item_id == locked.id, Checkout.returned_at.is_(None)
        )
    )
    available = locked.quantity - int(outstanding or 0)

    if form.quantity.data > available:
        db.session.rollback()
        flash(
            f"Only {available} of {locked.quantity} available - "
            f"{outstanding} already checked out.",
            "error",
        )
        return redirect(url_for("items.detail", item_id=item_id))

    due = form.due_back_at.data
    record = Checkout(
        item_id=locked.id,
        actor_id=current_user.id,
        holder_name=form.holder_name.data.strip(),
        quantity=form.quantity.data,
        from_location_id=locked.location_id,
        due_back_at=(
            datetime.combine(due, time.max, tzinfo=timezone.utc) if due else None
        ),
        note=(form.note.data or "").strip() or None,
    )
    db.session.add(record)

    record_audit(
        action="item_checked_out", object_type="item", object_id=str(locked.id),
        detail=f"{form.quantity.data} to {record.holder_name}",
    )
    db.session.commit()

    flash(f"Checked out {form.quantity.data} to {record.holder_name}.", "success")
    return redirect(url_for("items.detail", item_id=item_id))


@bp.route("/<item_id>/return/<checkout_id>", methods=["POST"])
@login_required
def check_in(item_id: str, checkout_id: str):
    """Return a checked-out quantity.

    The checkout is looked up scoped to an item already resolved by ownership,
    so a checkout id belonging to another account matches nothing (T-18).
    """
    item = get_owned_or_404(Item, item_id)
    form = ReturnForm()

    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("items.detail", item_id=item.id))

    record = db.session.execute(
        select(Checkout).where(
            Checkout.id == _uuid_or_404(checkout_id),
            Checkout.item_id == item.id,
            Checkout.returned_at.is_(None),
        )
    ).scalar_one_or_none()

    if record is None:
        # Already returned, or never yours. Same response either way.
        abort(404)

    record.returned_at = utcnow()
    if form.note.data:
        suffix = f"returned: {form.note.data.strip()}"
        record.note = f"{record.note} / {suffix}" if record.note else suffix

    # Returning puts it back where it came from, if that is still known.
    if record.from_location_id and item.location_id != record.from_location_id:
        still_exists = db.session.execute(
            owned_query(Location).where(Location.id == record.from_location_id)
        ).scalar_one_or_none()
        if still_exists is not None:
            item.location_id = record.from_location_id

    record_audit(
        action="item_returned", object_type="item", object_id=str(item.id),
        detail=f"{record.quantity} from {record.holder_name}",
    )
    db.session.commit()

    flash(f"Returned {record.quantity} from {record.holder_name}.", "success")
    return redirect(url_for("items.detail", item_id=item.id))


@bp.route("/<item_id>/delete", methods=["POST"])
@login_required
def delete(item_id: str):
    item = get_owned_or_404(Item, item_id)
    form = ConfirmForm()

    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("items.detail", item_id=item.id))

    location_id = item.location_id
    name = item.display_name

    record_audit(
        action="item_deleted", object_type="item", object_id=str(item.id), detail=name
    )
    db.session.delete(item)
    db.session.commit()

    flash(f"Deleted {name}.", "info")
    if location_id:
        return redirect(url_for("locations.detail", location_id=location_id))
    return redirect(url_for("items.index"))


@bp.route("/<item_id>/links", methods=["POST"])
@login_required
def add_link(item_id: str):
    item = get_owned_or_404(Item, item_id)
    form = DocLinkForm()

    if form.validate_on_submit():
        db.session.add(
            DocLink(
                item_id=item.id,
                label=form.label.data.strip(),
                url=form.url.data.strip(),
            )
        )
        record_audit(action="link_added", object_type="item", object_id=str(item.id))
        db.session.commit()
        flash("Link added.", "success")
    else:
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")

    return redirect(url_for("items.detail", item_id=item.id))


@bp.route("/<item_id>/links/<link_id>/delete", methods=["POST"])
@login_required
def delete_link(item_id: str, link_id: str):
    item = get_owned_or_404(Item, item_id)
    form = ConfirmForm()

    if form.validate_on_submit():
        link = db.session.execute(
            select(DocLink).where(DocLink.id == link_id, DocLink.item_id == item.id)
        ).scalar_one_or_none()

        if link is not None:
            db.session.delete(link)
            db.session.commit()
            flash("Link removed.", "info")

    return redirect(url_for("items.detail", item_id=item.id))
