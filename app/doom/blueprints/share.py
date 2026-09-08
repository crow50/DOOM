"""Public share routes - the capability-URL surface.

Everything a QR code or NFC tag points at lands here.  This is the only part
of DOOM an unauthenticated stranger can reach with real data behind it, so the
rules are tighter than anywhere else:

* the token identifies, it does not authorize (T-36)
* responses are built from reduced serializers, never from ORM objects (T-20)
* nothing links upward or sideways - a shared page is a leaf, not a doorway
* no index, no search, no listing: there is no route that enumerates shares
* noindex on every response, so a leaked link cannot become a search result
* hard per-IP rate limits, because scraping is the realistic attack
* every route is read-only; there is no mutating endpoint in this file

The threat being designed against is not someone holding the tag - they are
already standing at the bin.  It is a *leaked URL*: a photo of a label posted
online, a link forwarded once too often, a page a crawler found.
"""

from __future__ import annotations

import logging

from flask import Blueprint, Response, abort, render_template, request, session
from sqlalchemy import select

from .. import validation as v
from ..extensions import db, limiter
from ..forms import SharePinForm
from ..models import Attachment, DocLink, Item, Location
from ..security.audit import record_audit
from ..security.passwords import verify_share_pin
from ..security.serializers import public_item, public_location

logger = logging.getLogger(__name__)

bp = Blueprint("share", __name__, url_prefix="/t")

#: Session key prefix recording which shares this visitor has unlocked.
_PIN_OK = "_share_ok:"


@bp.after_request
def _no_index(response: Response) -> Response:
    """Keep share pages out of search engines (T-21).

    robots.txt asks crawlers not to look; X-Robots-Tag tells the ones that
    looked anyway not to publish what they found. An inventory that was merely
    unlisted becoming searchable is precisely the reconnaissance path this
    application exists to close.
    """
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    # same-origin: the token never reaches an outbound link, but the PIN form
    # on this page can still POST - a bare "no-referrer" here would break it
    # exactly the way it broke login. See security/headers.py.
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "private, no-store"
    return response


def _resolve(token: str):
    """Find the shared node for a token, or 404.

    Both tables are searched because a token addresses a node without saying
    which kind it is. Only rows explicitly marked shared can match, so
    unsharing takes effect immediately and rotation invalidates the printed
    label at once.
    """
    if not token or len(token) > 128:
        abort(404)

    item = db.session.execute(
        select(Item).where(Item.share_token == token, Item.visibility == "shared")
    ).scalar_one_or_none()
    if item is not None:
        return item

    location = db.session.execute(
        select(Location).where(
            Location.share_token == token, Location.visibility == "shared"
        )
    ).scalar_one_or_none()
    if location is not None:
        return location

    abort(404)


def _pin_required(node) -> bool:
    if not node.share_pin_hash:
        return False
    return session.get(f"{_PIN_OK}{node.id}") is not True


@bp.route("/<token>", methods=["GET", "POST"])
@limiter.limit(v.SHARE_RATE_LIMIT)
def view(token: str):
    """Render a shared item or container.

    Rate limited hard. A 256-bit token is not guessable, but limits also cap
    what an attacker holding a handful of leaked tokens can harvest, and make
    bulk crawling of this surface impractical.
    """
    node = _resolve(token)
    form = SharePinForm()

    if _pin_required(node):
        if form.validate_on_submit():
            if verify_share_pin(node.share_pin_hash, form.pin.data):
                session[f"{_PIN_OK}{node.id}"] = True
                record_audit(
                    action="share_pin_accepted",
                    object_type=type(node).__name__.lower(),
                    object_id=str(node.id), commit=True,
                )
            else:
                record_audit(
                    action="share_pin_rejected",
                    object_type=type(node).__name__.lower(),
                    object_id=str(node.id), commit=True,
                )
                form.pin.errors.append("Incorrect PIN.")
                return render_template("share/pin.html", form=form), 401
        else:
            return render_template("share/pin.html", form=form)

    record_audit(
        action="share_viewed",
        object_type=type(node).__name__.lower(),
        object_id=str(node.id),
        commit=True,
    )

    if isinstance(node, Item):
        return _render_item(node)
    return _render_location(node)


def _render_item(item: Item):
    attachments = db.session.execute(
        select(Attachment).where(Attachment.item_id == item.id)
    ).scalars().all()
    links = db.session.execute(
        select(DocLink).where(DocLink.item_id == item.id)
    ).scalars().all()

    # A dict, not the ORM object. The template cannot reach item.owner or
    # item.location even by accident, because they are not in what it is given.
    view_model = public_item(item, attachments=attachments, links=links)
    return render_template("share/item.html", node=view_model, token=item.share_token)


def _render_location(location: Location):
    items = db.session.execute(
        select(Item)
        .where(Item.location_id == location.id)
        .order_by(Item.name)
        .limit(500)
    ).scalars().all()

    attachments = db.session.execute(
        select(Attachment).where(Attachment.location_id == location.id)
    ).scalars().all()
    links = db.session.execute(
        select(DocLink).where(DocLink.location_id == location.id)
    ).scalars().all()

    # Contents are listed one level down - that is what scanning a tote is
    # for. What is never included is the chain upward: the path from this bin
    # to its warehouse is the physical address, and it is not in the
    # serializer at all.
    view_model = public_location(
        location, items=items, attachments=attachments, links=links
    )
    return render_template(
        "share/location.html", node=view_model, token=location.share_token
    )
