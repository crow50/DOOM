"""NFC tag registration.

The writing and reading happens in the browser via the Web NFC API; this
module only records which physical tag was bound to which node, so a scanned
tag can be recognised later.

The security position, stated plainly because it drives the design: **an NDEF
tag is not a credential.**  Cheap NTAG stock is unauthenticated, readable by
anyone holding a phone to it, and clonable in seconds.  Nothing is authorised
on the strength of a tag UID (T-13).  What the tag carries is a URL, and that
URL is a capability limited to the reduced public share view - so a cloned tag
grants exactly what the original granted, which is a read-only page the owner
already chose to publish.

The UID is recorded for recognition and inventory purposes only: "this is the
tag I stuck on Tote A1", not "whoever presents this UID may act as the owner".
"""

from __future__ import annotations

import logging
import re

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import select

from ..extensions import db
from ..models import Item, Location, NfcTag
from ..security.audit import record_audit
from ..security.authz import get_owned_or_404

logger = logging.getLogger(__name__)

bp = Blueprint("nfc", __name__, url_prefix="/nfc")

_TARGETS = {"item": Item, "location": Location}

#: Tag serial numbers are colon-separated hex as reported by Web NFC.
#: Anchored and bounded - this value goes into the database and onto a page.
_UID_RE = re.compile(r"^[0-9a-fA-F:]{4,64}$")


@bp.route("/")
@login_required
def index():
    tags = db.session.execute(
        select(NfcTag)
        .where(NfcTag.owner_id == current_user.id)
        .order_by(NfcTag.written_at.desc())
        .limit(200)
    ).scalars().all()
    return render_template("nfc/index.html", tags=tags)


@bp.route("/register/<node_type>/<node_id>", methods=["POST"])
@login_required
def register(node_type: str, node_id: str):
    """Bind a scanned tag UID to a node.

    CSRF-protected like any other state change: the fetch() in nfc.js sends
    the token in a header. A JSON body does not exempt a request from CSRF -
    a form can be made to post JSON-ish content cross-origin.
    """
    model = _TARGETS.get(node_type)
    if model is None:
        abort(404)

    node = get_owned_or_404(model, node_id)

    payload = request.get_json(silent=True) or {}
    raw_uid = str(payload.get("uid", "")).strip()

    if not _UID_RE.match(raw_uid):
        return jsonify({"error": "That tag serial number was not recognised."}), 400

    uid = raw_uid.lower()

    # Scoped to this owner: two users may legitimately hold cloned tags with
    # the same UID, and a global constraint would tell one about the other.
    existing = db.session.execute(
        select(NfcTag).where(
            NfcTag.owner_id == current_user.id, NfcTag.tag_uid == uid
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.item_id = node.id if node_type == "item" else None
        existing.location_id = node.id if node_type == "location" else None
        action = "nfc_tag_reassigned"
    else:
        db.session.add(
            NfcTag(
                owner_id=current_user.id,
                item_id=node.id if node_type == "item" else None,
                location_id=node.id if node_type == "location" else None,
                tag_uid=uid,
            )
        )
        action = "nfc_tag_registered"

    record_audit(action=action, object_type=node_type, object_id=str(node.id))
    db.session.commit()

    return jsonify({"status": "ok", "uid": uid})
