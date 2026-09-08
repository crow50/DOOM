"""Registration, sign-in, sign-out, password change."""

from __future__ import annotations

import logging

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select

from .. import validation as v
from ..extensions import db, limiter, login_manager
from ..forms import ChangePasswordForm, LoginForm, RegisterForm
from ..models import User, UserSession, utcnow
from ..security.audit import record_audit
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.redirects import safe_redirect_target

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__)

#: One message for every failure mode.  "No such user" and "wrong password"
#: must be indistinguishable, or the login form becomes a free oracle for
#: which accounts exist (T-02).
GENERIC_LOGIN_FAILURE = "Incorrect username or password."

#: Session key holding the user's session_version at sign-in.
SESSION_VERSION_KEY = "_doom_sv"

#: Session key holding this device's UserSession id, so a single device can be
#: revoked without touching the others (ASVS 3.3.4).
SESSION_ID_KEY = "_doom_sid"


@login_manager.user_loader
def load_user(user_id: str):
    """Resolve the signed session cookie into a User.

    The session_version comparison is what makes "sign out everywhere" real
    (T-06).  Flask's session cookie is signed but stateless: it stays valid
    until it expires, so a stolen cookie normally survives a password change.
    Storing a counter in the cookie and comparing it here means bumping the
    column invalidates every cookie ever issued, with no server-side session
    store to run.

    Getting this half-right is a silent failure: omit the comparison and the
    column still increments, the feature still appears to work, and every old
    session quietly stays alive. There is a test for exactly that.
    """
    try:
        user = db.session.get(User, user_id)
    except Exception:
        logger.exception("user_loader_failed")
        return None

    if user is None or not user.is_active:
        return None

    if session.get(SESSION_VERSION_KEY) != user.session_version:
        logger.info(
            "session_version_mismatch",
            extra={"extra_fields": {"user_id": str(user.id)}},
        )
        return None

    # Per-device revocation (ASVS 3.3.4). Checked on every request rather than
    # at login, so ending a session takes effect immediately — a revocation
    # that waits for the next sign-in is not a revocation.
    session_id = session.get(SESSION_ID_KEY)
    if session_id is not None:
        record = db.session.get(UserSession, session_id)
        if record is None or record.revoked_at is not None:
            logger.info(
                "session_revoked",
                extra={"extra_fields": {"user_id": str(user.id)}},
            )
            return None
        _touch(record)

    return user


def _touch(record) -> None:
    """Update last-seen, at most once a minute.

    Writing on every request would turn every page view into a database write
    for no benefit.
    """
    now = utcnow()
    if (now - record.last_seen_at).total_seconds() < 60:
        return
    try:
        record.last_seen_at = now
        db.session.commit()
    except Exception:
        db.session.rollback()


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit(v.REGISTER_RATE_LIMIT, methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("locations.index"))

    form = RegisterForm()

    if form.validate_on_submit():
        username = v.normalize_username(form.username.data)

        existing = db.session.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()

        if existing is not None:
            # Accepted disclosure, reasoned in docs/DECISIONS.md: a
            # registration form must tell the user a name is taken, which
            # inevitably confirms it exists. Rate limiting is the
            # proportionate mitigation; pretending otherwise would break
            # registration for honest users to little benefit.
            form.username.errors.append("That username is already taken.")
            record_audit(
                action="register_conflict", object_type="user",
                detail="username already exists", commit=True,
            )
        else:
            user = User(
                username=username,
                password_hash=hash_password(form.password.data),
            )
            db.session.add(user)
            record_audit(
                action="register", object_type="user", actor_id=None,
                detail=f"created {username}",
            )
            db.session.commit()

            logger.info(
                "user_registered",
                extra={"extra_fields": {"user_id": str(user.id)}},
            )
            flash("Account created. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(v.LOGIN_RATE_LIMIT, methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("locations.index"))

    form = LoginForm()

    if form.validate_on_submit():
        username = v.normalize_username(form.username.data)

        user = db.session.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()

        # A locked account is reported as an ordinary failure. Saying "this
        # account is locked" would confirm the username exists and hand a
        # griefer confirmation that their lockout landed.
        if user is not None and user.is_locked:
            record_audit(
                action="login_blocked", object_type="user",
                object_id=str(user.id), detail="account locked", commit=True,
            )
            form.password.errors.append(GENERIC_LOGIN_FAILURE)
            return render_template("auth/login.html", form=form)

        # Runs a dummy hash when user is None, so an unknown username costs
        # the same time as a known one.
        stored = user.password_hash if user else None
        if verify_password(stored, form.password.data) and user is not None:
            _finish_login(user, form.password.data)
            return redirect(safe_redirect_target("locations.index"))

        if user is not None:
            _record_failure(user)

        record_audit(action="login_failed", detail="bad credentials", commit=True)
        form.password.errors.append(GENERIC_LOGIN_FAILURE)

    return render_template("auth/login.html", form=form)


def _finish_login(user: User, plaintext: str) -> None:
    """Establish an authenticated session."""
    # Session fixation defence (T-04): discard anything an attacker may have
    # planted in the pre-login session before writing the authenticated
    # identity into it.
    session.clear()

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    # The plaintext is available only here. If the cost parameters have been
    # raised since this hash was written, upgrade it now - no reset email, no
    # forced rotation, the user notices nothing.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(plaintext)
        logger.info(
            "password_hash_upgraded",
            extra={"extra_fields": {"user_id": str(user.id)}},
        )

    record = UserSession(
        user_id=user.id,
        ip=request.remote_addr,
        user_agent=(request.headers.get("User-Agent") or "")[:200],
    )
    db.session.add(record)
    db.session.flush()

    login_user(user, remember=False)
    session[SESSION_VERSION_KEY] = user.session_version
    session[SESSION_ID_KEY] = str(record.id)
    session.permanent = True

    record_audit(
        action="login", object_type="user", object_id=str(user.id), actor_id=user.id
    )
    db.session.commit()


def _record_failure(user: User) -> None:
    """Count a failed attempt and lock the account past the threshold."""
    user.failed_login_count = (user.failed_login_count or 0) + 1

    if user.failed_login_count >= v.LOCKOUT_THRESHOLD:
        user.locked_until = utcnow() + user.lock_duration()
        record_audit(
            action="account_locked", object_type="user", object_id=str(user.id),
            detail=f"after {user.failed_login_count} failures", actor_id=user.id,
        )
        logger.warning(
            "account_locked",
            extra={"extra_fields": {
                "user_id": str(user.id),
                "failures": user.failed_login_count,
                "until": user.locked_until.isoformat(),
            }},
        )

    db.session.commit()


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """POST only.

    A GET /logout can be fired by any <img src> on any page the user visits.
    That is only a nuisance rather than a breach, but it is CSRF all the same,
    and the fix costs one form.
    """
    # Mark this device's session ended rather than only dropping the cookie,
    # so the account page stops listing it as active.
    session_id = session.get(SESSION_ID_KEY)
    if session_id:
        record = db.session.get(UserSession, session_id)
        if record is not None and record.user_id == current_user.id:
            record.revoked_at = utcnow()
            db.session.commit()

    record_audit(
        action="logout", object_type="user", object_id=str(current_user.id), commit=True
    )
    logout_user()
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not verify_password(current_user.password_hash, form.current_password.data):
            form.current_password.errors.append("That is not your current password.")
            record_audit(
                action="password_change_failed", object_type="user",
                object_id=str(current_user.id), commit=True,
            )
        else:
            current_user.password_hash = hash_password(form.new_password.data)

            # Invalidate every session issued before this moment (T-06). If
            # the password is being changed because it may have leaked, the
            # attacker's existing cookie has to die with it.
            current_user.session_version += 1

            record_audit(
                action="password_changed", object_type="user",
                object_id=str(current_user.id),
            )
            db.session.commit()

            # Ours included - so re-stamp the current session rather than
            # signing the user out of the tab they are standing in.
            session[SESSION_VERSION_KEY] = current_user.session_version

            flash("Password changed. Other devices have been signed out.", "success")
            return redirect(url_for("locations.index"))

    return render_template("auth/change_password.html", form=form)
