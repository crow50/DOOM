"""Account profile, activity feed, and audit export.

The activity feed reads ``audit_log``, which the application was already
writing.  Nothing new is collected to build it - the events existed, they just
had no window onto them.

Two constraints shape every query here:

* **Scoped to the signed-in user.**  ``actor_user_id == current_user.id`` is a
  WHERE clause, exactly as ownership is everywhere else (T-18).  There is no
  route that shows another account's activity.
* **Bounded.**  The feed pages and the export caps its row count, so no single
  request can be made to serialise an unbounded table.
"""

from __future__ import annotations

import csv
import io
import logging

from flask import (
    Blueprint, Response, flash, redirect, render_template, request,
    session as flask_session, url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func, select

from .. import validation as v
from ..extensions import db
from ..forms import ChangePasswordForm, ProfileForm, RevokeSessionForm
from ..models import Attachment, AuditLog, Item, Location, UserSession, utcnow
from ..security.audit import chain_head_hash, record_audit
from ..security.passwords import verify_password
from ..security.uploads import storage_used

logger = logging.getLogger(__name__)

bp = Blueprint("account", __name__, url_prefix="/account")

#: Audit actions rendered as readable sentences. Anything not listed falls
#: back to the raw action name rather than being hidden - an activity feed
#: that silently drops events it does not recognise is worse than an ugly one.
ACTION_LABELS = {
    "login": "Signed in",
    "logout": "Signed out",
    "login_failed": "Failed sign-in attempt",
    "login_blocked": "Sign-in blocked (account locked)",
    "account_locked": "Account locked after repeated failures",
    "register": "Account created",
    "password_changed": "Password changed",
    "password_change_failed": "Failed password change",
    "location_created": "Created a location",
    "location_updated": "Updated a location",
    "location_deleted": "Deleted a location",
    "item_created": "Added an item",
    "item_updated": "Updated an item",
    "item_deleted": "Deleted an item",
    "item_moved": "Moved an item",
    "item_quantity_adjusted": "Adjusted a quantity",
    "upload_stored": "Uploaded a file",
    "upload_rejected": "Upload rejected",
    "upload_deleted": "Deleted a file",
    "link_added": "Added a documentation link",
    "share_updated": "Changed sharing settings",
    "share_token_rotated": "Issued a new share link",
    "share_viewed": "A shared link was opened",
    "share_pin_accepted": "Share PIN accepted",
    "share_pin_rejected": "Share PIN rejected",
    "nfc_tag_registered": "Registered an NFC tag",
    "nfc_tag_reassigned": "Reassigned an NFC tag",
    "access_denied": "Blocked access attempt",
}


def _describe(entry: AuditLog) -> str:
    return ACTION_LABELS.get(entry.action, entry.action.replace("_", " ").capitalize())


@bp.route("/", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm(obj=current_user)

    if form.validate_on_submit():
        # Field by field from a validated form, never **request.form - the
        # same rule as everywhere else, and the reason a posted `is_active`
        # or `session_version` has nothing to bind to (T-10).
        current_user.display_name = (form.display_name.data or "").strip() or None
        current_user.email = (form.email.data or "").strip() or None
        current_user.timezone = (form.timezone.data or "").strip() or None

        record_audit(
            action="profile_updated", object_type="user",
            object_id=str(current_user.id),
        )
        db.session.commit()
        flash("Profile saved.", "success")
        return redirect(url_for("account.profile"))

    # Keys are suffixed rather than named "items"/"locations".
    #
    # In Jinja, `counts.items` resolves to dict.items - the built-in method,
    # not the key - because attribute access is tried before subscript. The
    # template then renders a bound method instead of a number, and does so
    # silently: no error, just a missing figure nobody notices. Names that
    # cannot collide remove the trap rather than relying on everyone
    # remembering it.
    counts = {
        "location_count": db.session.scalar(
            select(func.count()).select_from(Location)
            .where(Location.owner_id == current_user.id)
        ),
        "item_count": db.session.scalar(
            select(func.count()).select_from(Item)
            .where(Item.owner_id == current_user.id)
        ),
        "file_count": db.session.scalar(
            select(func.count()).select_from(Attachment)
            .where(Attachment.owner_id == current_user.id)
        ),
        "event_count": db.session.scalar(
            select(func.count()).select_from(AuditLog)
            .where(AuditLog.actor_user_id == current_user.id)
        ),
    }

    recent = db.session.execute(
        select(AuditLog)
        .where(AuditLog.actor_user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
    ).scalars().all()

    # ASVS 3.3.4 — you cannot revoke what you cannot enumerate.
    sessions = db.session.execute(
        select(UserSession)
        .where(UserSession.user_id == current_user.id,
               UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
    ).scalars().all()

    from ..blueprints.auth import SESSION_ID_KEY

    return render_template(
        "account/profile.html",
        form=form,
        sessions=sessions,
        current_session_id=flask_session.get(SESSION_ID_KEY),
        revoke_form=RevokeSessionForm(),
        password_form=ChangePasswordForm(),
        counts=counts,
        chain_head=chain_head_hash(),
        storage={
            "used": storage_used(current_user.id),
            "quota": v.STORAGE_QUOTA_BYTES,
        },
        recent=[(e, _describe(e)) for e in recent],
    )


@bp.route("/sessions/revoke", methods=["POST"])
@login_required
def revoke_session():
    """End one session, or every other session.

    Requires the password (ASVS 3.3.4). Sessions are scoped to the signed-in
    user in the WHERE clause, so another account's session id matches nothing.
    """
    from ..blueprints.auth import SESSION_ID_KEY

    form = RevokeSessionForm()
    if not form.validate_on_submit():
        flash("That request could not be verified.", "error")
        return redirect(url_for("account.profile"))

    if not verify_password(current_user.password_hash, form.password.data):
        record_audit(
            action="session_revoke_failed", object_type="user",
            object_id=str(current_user.id), commit=True,
        )
        flash("That password was not correct.", "error")
        return redirect(url_for("account.profile"))

    target = (form.session_id.data or "").strip()
    this_session = flask_session.get(SESSION_ID_KEY)

    query = select(UserSession).where(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None),
    )
    if target == "others":
        # Everything except the device being used to ask.
        if this_session:
            query = query.where(UserSession.id != _as_uuid(this_session))
    else:
        parsed = _as_uuid(target)
        if parsed is None:
            flash("That session was not found.", "error")
            return redirect(url_for("account.profile"))
        query = query.where(UserSession.id == parsed)

    rows = db.session.execute(query).scalars().all()
    for row in rows:
        row.revoked_at = utcnow()

    record_audit(
        action="session_revoked", object_type="user",
        object_id=str(current_user.id), detail=f"{len(rows)} session(s)",
    )
    db.session.commit()

    if target != "others" and str(this_session) == target:
        flash("That was this device — you have been signed out.", "info")
        return redirect(url_for("main.index"))

    flash(f"Ended {len(rows)} session{'s' if len(rows) != 1 else ''}.", "success")
    return redirect(url_for("account.profile"))


def _as_uuid(raw):
    import uuid

    try:
        return uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError):
        return None


@bp.route("/activity")
@login_required
def activity():
    """Paged activity feed, filterable by action."""
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    # Filter value is checked against the known set rather than passed to the
    # query as given - an allowlist, like every other user-chosen enum here.
    action = request.args.get("action") or ""
    if action and action not in ACTION_LABELS:
        action = ""

    query = select(AuditLog).where(AuditLog.actor_user_id == current_user.id)
    if action:
        query = query.where(AuditLog.action == action)

    total = db.session.scalar(
        select(func.count()).select_from(query.subquery())
    )

    size = v.ACTIVITY_PAGE_SIZE
    rows = db.session.execute(
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    ).scalars().all()

    present = db.session.execute(
        select(AuditLog.action)
        .where(AuditLog.actor_user_id == current_user.id)
        .group_by(AuditLog.action)
        .order_by(AuditLog.action)
    ).scalars().all()

    return render_template(
        "account/activity.html",
        entries=[(e, _describe(e)) for e in rows],
        page=page,
        pages=max(1, (total + size - 1) // size),
        total=total,
        action=action,
        actions=[(a, ACTION_LABELS.get(a, a)) for a in present],
    )


#: Characters that make a spreadsheet treat a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutralise CSV formula injection.

    A cell beginning with =, +, - or @ is executed as a formula when the file
    is opened in Excel, LibreOffice or Sheets. Since audit rows contain
    user-supplied text - location names, upload filenames - an export is a
    path from "attacker types a location name" to "code runs on the machine of
    whoever opens the export", without the application ever being exploited
    itself.

    Prefixing with a single quote makes the spreadsheet treat it as text. The
    quote is visible in the cell, which is the correct tradeoff: a slightly
    ugly export beats a live formula.
    """
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


@bp.route("/activity.csv")
@login_required
def export_csv():
    """Export this account's audit trail.

    Scoped by actor_user_id in the WHERE clause and capped in row count.
    """
    rows = db.session.execute(
        select(AuditLog)
        .where(AuditLog.actor_user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(v.AUDIT_EXPORT_MAX_ROWS)
    ).scalars().all()

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow(
        ["timestamp_utc", "actor", "action", "description", "object_type",
         "object_id", "detail", "ip"]
    )
    for entry in rows:
        writer.writerow([
            _csv_safe(entry.created_at.isoformat()),
            _csv_safe(current_user.username),
            _csv_safe(entry.action),
            _csv_safe(_describe(entry)),
            _csv_safe(entry.object_type),
            _csv_safe(entry.object_id),
            _csv_safe(entry.detail),
            _csv_safe(entry.ip),
        ])

    record_audit(
        action="audit_exported", object_type="user",
        object_id=str(current_user.id), detail=f"{len(rows)} rows", commit=True,
    )

    response = Response(buffer.getvalue(), mimetype="text/csv")
    # Always a download, never rendered inline, and nosniff so a browser
    # cannot decide the text "looks like" HTML (T-12).
    response.headers["Content-Disposition"] = (
        'attachment; filename="doom-activity.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response
