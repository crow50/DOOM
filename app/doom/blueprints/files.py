"""Upload and download routes.

Serving is the half that is easy to get wrong.  Files live on a volume
outside any web root, and Caddy deliberately has no ``file_server`` directive
for it - if it did, every check below could be skipped with a direct URL
(T-24).  The only way to a stored file is through this module, which looks the
row up under an ownership filter first.
"""

from __future__ import annotations

import logging

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_, select

from .. import validation as v
from ..extensions import db, limiter
from ..forms import ConfirmForm
from ..models import Attachment, Item, Location
from ..security.audit import record_audit
from ..security.authz import get_owned_or_404
from ..security.uploads import (
    UploadRejected,
    delete_stored,
    resolve_stored_path,
    store_upload,
)

logger = logging.getLogger(__name__)

bp = Blueprint("files", __name__, url_prefix="/files")

_TARGETS = {"item": Item, "location": Location}


@bp.route("/upload/<node_type>/<node_id>", methods=["POST"])
@login_required
@limiter.limit(v.UPLOAD_RATE_LIMIT)
def upload(node_type: str, node_id: str):
    model = _TARGETS.get(node_type)
    if model is None:
        abort(404)

    node = get_owned_or_404(model, node_id)

    form = ConfirmForm()
    if not form.validate_on_submit():
        flash("That upload could not be verified.", "error")
        return redirect(_back(node_type, node_id))

    files = [f for f in request.files.getlist("file") if f and f.filename]
    if not files:
        flash("No file was selected.", "error")
        return redirect(_back(node_type, node_id))

    stored_count = 0
    upload_dir = current_app.config["UPLOAD_DIR"]

    for storage in files[:10]:
        try:
            result = store_upload(storage, upload_dir, owner_id=current_user.id)
        except UploadRejected as exc:
            # The message names what was wrong with the file, never anything
            # about the server's filesystem or configuration.
            flash(str(exc), "error")
            record_audit(
                action="upload_rejected", object_type=node_type,
                object_id=str(node.id), detail=str(exc)[:200], commit=True,
            )
            continue

        attachment = Attachment(
            owner_id=current_user.id,
            item_id=node.id if node_type == "item" else None,
            location_id=node.id if node_type == "location" else None,
            kind=result.kind,
            stored_name=result.stored_name,
            thumbnail_name=result.thumbnail_name,
            original_name=result.original_name,
            content_type=result.content_type,
            byte_size=result.byte_size,
            sha256=result.sha256,
        )
        db.session.add(attachment)
        stored_count += 1

    if stored_count:
        record_audit(
            action="upload_stored", object_type=node_type, object_id=str(node.id),
            detail=f"{stored_count} file(s)",
        )
        db.session.commit()
        flash(f"Uploaded {stored_count} file(s).", "success")

    return redirect(_back(node_type, node_id))


def _back(node_type: str, node_id: str) -> str:
    if node_type == "item":
        return url_for("items.detail", item_id=node_id)
    return url_for("locations.detail", location_id=node_id)


@bp.route("/<attachment_id>")
@login_required
def download(attachment_id: str):
    """Serve an attachment to its owner.

    Ownership is filtered inside the query, so another user's attachment id is
    indistinguishable from one that does not exist.
    """
    attachment = get_owned_or_404(Attachment, attachment_id)
    return _send(attachment, attachment.stored_name, attachment.content_type)


@bp.route("/<attachment_id>/thumb")
@login_required
def thumbnail(attachment_id: str):
    attachment = get_owned_or_404(Attachment, attachment_id)
    if not attachment.thumbnail_name:
        abort(404)
    return _send(attachment, attachment.thumbnail_name, "image/jpeg", inline=True)


def _send(attachment: Attachment, stored_name: str, content_type: str, *, inline: bool | None = None):
    """Return a stored file with a safe set of response headers.

    Note what is *not* here: ``send_from_directory`` with anything derived from
    the request. The filename comes from the database row we just fetched
    under an ownership filter, and is a UUID we generated.
    """
    path = resolve_stored_path(current_app.config["UPLOAD_DIR"], stored_name)

    # Images render inline; everything else downloads. A PDF rendered inline
    # runs in the origin's context in some viewers, so documents are always
    # attachments regardless of what the browser would prefer to do.
    if inline is None:
        inline = content_type.startswith("image/")

    response = send_file(
        path,
        # Our own sniffed value, not a guess from the extension.
        mimetype=content_type,
        as_attachment=not inline,
        download_name=attachment.original_name,
        conditional=True,
    )

    # Belt and braces with the global header hook: without nosniff a browser
    # may decide a text/plain file "looks like" HTML and render it, which
    # turns the upload path back into stored XSS (T-12).
    response.headers["X-Content-Type-Options"] = "nosniff"
    # A stored file must never be framed or treated as active content.
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response.headers["Cache-Control"] = "private, max-age=300"
    return response


@bp.route("/<attachment_id>/delete", methods=["POST"])
@login_required
def delete(attachment_id: str):
    attachment = get_owned_or_404(Attachment, attachment_id)
    form = ConfirmForm()

    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("locations.index"))

    node_type = "item" if attachment.item_id else "location"
    node_id = attachment.item_id or attachment.location_id

    def still_referenced(name: str) -> bool:
        """True when another attachment row points at the same blob.

        Deduplication means one file can back several rows; deleting a row must
        not pull the bytes out from under the others (T-47).
        """
        return db.session.execute(
            select(Attachment.id).where(
                Attachment.id != attachment.id,
                or_(
                    Attachment.stored_name == name,
                    Attachment.thumbnail_name == name,
                ),
            ).limit(1)
        ).scalar_one_or_none() is not None

    delete_stored(
        current_app.config["UPLOAD_DIR"],
        attachment.stored_name,
        attachment.thumbnail_name,
        still_referenced=still_referenced,
    )

    record_audit(
        action="upload_deleted", object_type="attachment", object_id=str(attachment.id)
    )
    db.session.delete(attachment)
    db.session.commit()

    flash("File removed.", "info")
    return redirect(_back(node_type, str(node_id)))
