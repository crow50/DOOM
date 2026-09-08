"""QR codes, short codes, and printable label sheets.

A label is a permanent identifier for a node, bound to identity rather than to
contents or position.  A tote's label stays correct when the tote is refilled,
emptied, or carried to another building; an item's label stays correct when it
moves shelves.  Tags are therefore written once and never rewritten - what
changes is the page the URL resolves to, not the label.

The one thing that would invalidate printed labels is a change of base URL,
which is why every sheet also prints a short human-readable code.  A bin stays
findable by typing eight characters even if the domain moves.
"""

from __future__ import annotations

import base64
import io
import logging

import qrcode
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from qrcode.constants import ERROR_CORRECT_M
from sqlalchemy import select

from .. import validation as v
from ..extensions import db
from ..forms import ShareForm
from ..models import Item, Location, new_share_token, new_short_code
from ..security.audit import record_audit
from ..security.authz import get_owned_or_404
from ..security.passwords import hash_share_pin
from ..security.redirects import safe_referrer_path

logger = logging.getLogger(__name__)

bp = Blueprint("labels", __name__, url_prefix="/labels")

_MODELS = {"item": Item, "location": Location}


def _model_for(node_type: str):
    model = _MODELS.get(node_type)
    if model is None:
        abort(404)
    return model


def share_url(node) -> str:
    """Absolute URL for a node's label.

    Built from the configured PUBLIC_BASE_URL and never from request.host_url
    (T-14). Deriving it from the inbound Host header would let an attacker
    poison generated links, and - far more likely in practice - would bake
    "localhost" into a sheet of physical labels that then has to be reprinted.
    """
    base = current_app.config["PUBLIC_BASE_URL"].rstrip("/")
    return f"{base}/t/{node.share_token}"


def qr_data_uri(payload: str) -> str:
    """Render a QR code as an inline data: URI.

    Inline rather than a separate authenticated endpoint, so the print sheet
    is a single self-contained document that survives Ctrl-P without a burst
    of image requests. The CSP allows img-src data: for exactly this; images
    cannot execute, so it does not weaken script-src.
    """
    code = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,  # ~15% recoverable: labels get scuffed
        box_size=8,
        border=2,
    )
    code.add_data(payload)
    code.make(fit=True)

    image = code.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def ensure_label(node) -> None:
    """Assign a token and short code if the node has none.

    Assignment does not publish anything: visibility stays private until the
    owner explicitly shares. Having a token and being shared are separate
    states, so a label can be printed and stuck on a bin before any decision
    about publishing is made.
    """
    if not node.share_token:
        node.share_token = new_share_token()

    if not node.short_code:
        for _ in range(10):
            candidate = new_short_code()
            clash = db.session.execute(
                select(type(node)).where(type(node).short_code == candidate)
            ).scalar_one_or_none()
            if clash is None:
                node.short_code = candidate
                break
        else:
            logger.error("short_code_allocation_failed")


@bp.route("/<node_type>/<node_id>", methods=["GET", "POST"])
@login_required
def label(node_type: str, node_id: str):
    """Sharing controls and a single printable label for one node."""
    model = _model_for(node_type)
    node = get_owned_or_404(model, node_id)

    form = ShareForm()

    if form.validate_on_submit():
        if form.enabled.data:
            ensure_label(node)
            node.visibility = "shared"
        else:
            node.visibility = "private"

        if form.clear_pin.data:
            node.share_pin_hash = None
        elif form.pin.data:
            node.share_pin_hash = hash_share_pin(form.pin.data)

        record_audit(
            action="share_updated", object_type=node_type, object_id=str(node.id),
            detail=node.visibility,
        )
        db.session.commit()
        flash("Sharing settings saved.", "success")
        return redirect(url_for("labels.label", node_type=node_type, node_id=node.id))

    if request.method == "GET":
        form.enabled.data = node.is_shared

    # A label can be printed before anything is shared, so a token is minted
    # on first view.
    if not node.share_token:
        ensure_label(node)
        db.session.commit()

    url = share_url(node)
    return render_template(
        "labels/label.html",
        node=node,
        node_type=node_type,
        form=form,
        share_link=url,
        qr=qr_data_uri(url),
    )


@bp.route("/sheet")
@login_required
def sheet():
    """Printable sheet laid out for Avery 5160 (30 labels, 3 x 10).

    Selection comes from repeated ?location= and ?item= parameters. Every id
    is resolved through get_owned_or_404, so a sheet can only ever contain
    this user's own nodes regardless of what the query string asks for.
    """
    location_ids = request.args.getlist("location")[:60]
    item_ids = request.args.getlist("item")[:60]

    labels: list[dict] = []

    for raw_id in location_ids:
        node = get_owned_or_404(Location, raw_id)
        ensure_label(node)
        labels.append({
            "name": node.name,
            "subtitle": node.kind,
            "short_code": node.short_code,
            "qr": qr_data_uri(share_url(node)),
            "shared": node.is_shared,
        })

    for raw_id in item_ids:
        node = get_owned_or_404(Item, raw_id)
        ensure_label(node)
        labels.append({
            "name": node.name,
            "subtitle": "item",
            "short_code": node.short_code,
            "qr": qr_data_uri(share_url(node)),
            "shared": node.is_shared,
        })

    db.session.commit()

    if not labels:
        flash("Select at least one location or item to print.", "info")
        return redirect(url_for("locations.index"))

    # Send the user back where they came from rather than always to the
    # location list - the sheet is reachable from a location, an item, or a
    # label page. The referrer is validated against PUBLIC_BASE_URL and
    # reduced to a relative path before use.
    return render_template(
        "labels/sheet.html", labels=labels, back_url=safe_referrer_path()
    )


@bp.route("/<node_type>/<node_id>/rotate", methods=["POST"])
@login_required
def rotate(node_type: str, node_id: str):
    """Issue a new token, invalidating every printed label for this node.

    The revocation path for a leaked URL. Destructive in the physical world -
    existing labels stop resolving - so it is a deliberate POST behind a CSRF
    token, never something that can happen by following a link.
    """
    model = _model_for(node_type)
    node = get_owned_or_404(model, node_id)

    form = ShareForm()
    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("labels.label", node_type=node_type, node_id=node.id))

    node.share_token = new_share_token()
    node.short_code = None
    ensure_label(node)

    record_audit(
        action="share_token_rotated", object_type=node_type, object_id=str(node.id)
    )
    db.session.commit()

    flash("New link issued. Every previously printed label for this node is now dead.", "warning")
    return redirect(url_for("labels.label", node_type=node_type, node_id=node.id))
