"""Landing page, health check, and robots.txt."""

from __future__ import annotations

from flask import Blueprint, Response, redirect, render_template, url_for
from flask_login import current_user

from ..extensions import limiter

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    # Clicking the wordmark while signed in used to land on the sign-up page,
    # which reads as "you have been logged out" even though the session is
    # perfectly valid.
    if current_user.is_authenticated:
        return redirect(url_for("locations.index"))
    return render_template("index.html")


@bp.route("/healthz")
@limiter.exempt
def healthz() -> Response:
    """Container health probe.

    Deliberately says nothing beyond "the process is up".  Health endpoints
    that report database versions or dependency status are a free
    reconnaissance surface for an unauthenticated caller.
    """
    return Response("ok", mimetype="text/plain")


@bp.route("/robots.txt")
@limiter.exempt
def robots() -> Response:
    """Keep shared pages out of search indexes (T-21).

    A share token printed on a label is a capability.  If a crawler reaches
    one and the page gets indexed, an inventory that was merely unlisted
    becomes searchable - which is exactly the reconnaissance path this
    application exists to close off.  Belt and braces: share responses also
    carry X-Robots-Tag: noindex.
    """
    body = "User-agent: *\nDisallow: /\n"
    return Response(body, mimetype="text/plain")
