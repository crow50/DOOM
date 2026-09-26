"""Public share routes - the capability-URL surface.

Everything a QR code or NFC tag points at lands here.  This is the only part
of DOOM an unauthenticated stranger can reach with real data behind it, so the
rules are tighter than anywhere else:

* the token never appears in a URL (ASVS 14.2.1).  A label encodes it in the
  fragment - ``https://host/t/#<token>`` - which browsers do not transmit, and
  the unlock page moves it into a POST body.  What the address bar, the browser
  history, the Referer header and every access log in between then hold is
  ``/t/`` and a per-session handle that is worthless without this visitor's
  own signed cookie
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
import re
import hashlib
import hmac
import secrets

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select

from .. import validation as v
from ..extensions import db, limiter
from ..forms import SharePinForm, ShareTokenForm
from ..models import Attachment, DocLink, Item, Location
from ..security.audit import record_audit
from ..security.passwords import verify_share_pin
from ..security.serializers import public_item, public_location

logger = logging.getLogger(__name__)

bp = Blueprint("share", __name__, url_prefix="/t")

#: Session key prefix recording which shares this visitor has unlocked.
_PIN_OK = "_share_ok:"

#: Session key holding ``[[handle, token], ...]`` for this visitor, oldest first.
#:
#: The handle is what goes in the URL once the token has been posted. It is
#: not a secret and confers nothing: it only names an entry in *this* visitor's
#: signed session cookie, so the same handle in anyone else's hands addresses
#: nothing at all.
#:
#: A list of pairs rather than the obvious ``{handle: token}`` dict, because
#: the eviction below has to drop the *oldest* entry and a dict cannot carry
#: that information through the cookie: Flask serialises session values with
#: ``json.dumps(..., sort_keys=True)``, so a dict comes back in alphabetical
#: order of its keys - which, for random handles, is an arbitrary order. The
#: first version of this evicted whichever handle happened to sort first and
#: left the genuinely oldest one live; the cap held, the ordering did not, and
#: only the test that walked past the cap noticed.
_SHARE_HANDLES = "_share_handles"

#: How many labels one visitor may hold open at once.
#:
#: The session is a cookie, and a cookie that grows past roughly 4 KB is
#: silently dropped by the browser - which would log the visitor out of every
#: share at once and look like a server fault. Eight handles plus their PIN
#: approvals stay an order of magnitude inside that, and walking round a
#: warehouse scanning labels must not be able to fill it.
_MAX_HANDLES = 8


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

    A miss on a well-formed token is audited; garbage is not. Every other
    object-scoped route already records ``access_denied`` for a plausible id
    that matches nothing (7.2.2), and this one did not, which left token
    guessing - the only attack this surface has - invisible in the ledger.
    The token itself is never written: a rotated-away token and a mistyped
    one look the same here, and a value that might be valid tomorrow does
    not belong in an append-only table. Twelve characters is enough to
    correlate a burst and far too few to reconstruct 256 bits.
    """
    if not token or not re.fullmatch(v.SHARE_TOKEN_PATTERN, token):
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

    record_audit(
        action="access_denied",
        object_type="share",
        object_id=f"{token[:12]}…",
        detail="unknown or revoked share token",
        commit=True,
    )
    abort(404)


def _pin_approval(node) -> str:
    """Bind approval to current credentials without exposing the PIN hash.

    Flask sessions are signed, not encrypted. A plain hash of a PIN hash
    would provide a verifier for guesses; use a server-keyed MAC instead.
    Changing either credential invalidates previously issued approvals.
    """
    key = current_app.secret_key
    if isinstance(key, str):
        key = key.encode()
    message = f"share-pin:{node.id}:{node.share_token}:{node.share_pin_hash}"
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def _pin_required(node) -> bool:
    if not node.share_pin_hash:
        return False
    approval = session.get(f"{_PIN_OK}{node.id}")
    return not (isinstance(approval, str) and hmac.compare_digest(approval, _pin_approval(node)))


def _remember(token: str) -> str:
    """Store a validated token in this visitor's session and name it.

    Re-scanning the same label returns the handle already issued for it rather
    than minting a second one, so refreshing a share page is stable and a
    warehouse round does not churn through the cap below.
    """
    held = _held()

    for existing, value in held:
        if hmac.compare_digest(value, token):
            return existing

    # 16 bytes, not 12: a handle is not a credential - it is useless without
    # the signed cookie that holds its entry - but sizing it at 128 bits means
    # nobody has to be persuaded of that before they can read the next line.
    handle = secrets.token_urlsafe(16)
    held.append([handle, token])

    # Oldest out first. The list is append-ordered, so this really is a queue.
    del held[:-_MAX_HANDLES]

    session[_SHARE_HANDLES] = held
    return handle


def _held() -> list[list[str]]:
    """This visitor's ``[handle, token]`` pairs, ignoring anything malformed.

    The session is signed, so a malformed entry is not an attacker's doing -
    it is this application's own older format, or a half-written value. Either
    way it is dropped rather than trusted.
    """
    raw = session.get(_SHARE_HANDLES)
    if not isinstance(raw, list):
        return []
    return [
        [entry[0], entry[1]] for entry in raw
        if isinstance(entry, (list, tuple)) and len(entry) == 2
        and isinstance(entry[0], str) and isinstance(entry[1], str)
    ]


def _token_for(handle: str) -> str:
    """The token this visitor's session filed under ``handle``, or 404.

    A handle nobody issued, a handle from somebody else's session, and a
    handle whose entry has aged out of the cap are the same answer, for the
    same reason every other miss in this application is a 404: the response
    must not distinguish "wrong" from "gone".
    """
    # hmac.compare_digest raises TypeError on a non-ASCII str, and a path
    # segment can carry any UTF-8 the client likes. Shape-checking first keeps
    # a hand-typed URL on the same 404 as every other miss instead of turning
    # it into a 500 (D-06).
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", handle):
        abort(404)

    for existing, token in _held():
        if hmac.compare_digest(existing, handle) and re.fullmatch(
            v.SHARE_TOKEN_PATTERN, token
        ):
            return token
    abort(404)


@bp.route("/", methods=["GET"])
def unlock():
    """The page every label points at.

    It carries no data of its own and lists nothing: there is still no route
    that enumerates shares. Its whole job is to take the token out of the
    fragment - which the browser kept to itself - and put it in a POST body.
    """
    return render_template("share/unlock.html", form=ShareTokenForm())


@bp.route("/", methods=["POST"])
@limiter.limit(v.SHARE_RATE_LIMIT)
def open_share():
    """Exchange a posted share code for a session handle.

    303 rather than rendering the page directly, so the browser lands on a GET
    it can refresh, bookmark and go back to without re-submitting the code -
    and so the code is not sitting in a form resubmission prompt.
    """
    form = ShareTokenForm()

    if not form.validate_on_submit():
        # A malformed code never reaches _resolve, so it is neither a database
        # lookup nor an audit row - exactly the split _resolve already makes
        # between a plausible miss and garbage.
        form.token.errors = ["That is not a valid share code."]
        return render_template("share/unlock.html", form=form), 400

    token = form.token.data.strip()
    _resolve(token)  # 404s, and audits a well-formed miss, before anything is stored
    return redirect(url_for("share.view", handle=_remember(token)), code=303)


@bp.route("/v/<handle>", methods=["GET", "POST"])
@limiter.limit(v.SHARE_RATE_LIMIT)
def view(handle: str):
    """Render a shared item or container.

    Rate limited hard. A 256-bit token is not guessable, but limits also cap
    what an attacker holding a handful of leaked tokens can harvest, and make
    bulk crawling of this surface impractical.

    The node is resolved from the token on every request rather than cached
    alongside the handle: unsharing, rotating the token or changing the PIN
    then takes effect on the visitor's next page view instead of whenever
    their session happens to end.
    """
    node = _resolve(_token_for(handle))
    form = SharePinForm()

    if _pin_required(node):
        if form.validate_on_submit():
            if verify_share_pin(node.share_pin_hash, form.pin.data):
                session[f"{_PIN_OK}{node.id}"] = _pin_approval(node)
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
    # No token in the template context. Nothing in share/ renders it, and a
    # value a template cannot reach is a value a template cannot leak (T-20).
    view_model = public_item(item, attachments=attachments, links=links)
    return render_template("share/item.html", node=view_model)


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
    return render_template("share/location.html", node=view_model)
