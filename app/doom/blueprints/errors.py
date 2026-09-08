"""Error handling.

The user gets a plain sentence and a correlation ID.  The server gets the
stack trace, the request, and the exception type.

That split is the whole control (T-23).  A default Flask traceback page
discloses the file layout, fragments of source, local variables, and often
configuration; a database error discloses table and column names, which is a
free schema map for anyone probing for injection.  Neither ever reaches the
browser, and the correlation ID means nothing is lost operationally - the user
quotes twelve characters and the operator finds the exact event.
"""

from __future__ import annotations

import logging

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

#: Messages are generic on purpose.  "No such user" versus "wrong password",
#: or "item 41 not found" versus "forbidden", are both small oracles.
_MESSAGES = {
    400: ("Bad request", "That request could not be understood."),
    401: ("Sign in required", "You need to sign in to view this."),
    403: ("Not allowed", "You do not have permission to do that."),
    404: ("Not found", "There is nothing here."),
    405: ("Not allowed", "That method is not supported on this page."),
    413: ("File too large", "That upload exceeds the size limit."),
    429: ("Too many requests", "Slow down and try again shortly."),
    500: ("Something went wrong", "The error has been logged."),
    503: ("Temporarily unavailable", "A required service is not responding."),
}


def _wants_json() -> bool:
    return request.accept_mimetypes.best == "application/json" or request.path.startswith("/api/")


#: Last-resort page, built without touching Jinja.
#:
#: An error handler that can itself raise is a real failure mode: if template
#: rendering is what broke, calling render_template again either loops or
#: escapes to the framework's default handler, and the carefully generic page
#: is replaced by whatever the framework felt like emitting.  This fallback
#: uses no templates, no context processors and no database, so there is
#: always something safe to return.
_FALLBACK_HTML = (
    "<!doctype html><html lang=en><head><meta charset=utf-8>"
    "<title>{status}</title></head><body>"
    "<h1>{title}</h1><p>{detail}</p>{reference}</body></html>"
)


def _render(status: int, correlation_id: str | None = None):
    title, detail = _MESSAGES.get(status, _MESSAGES[500])

    if _wants_json():
        body = {"error": title, "detail": detail}
        if correlation_id:
            body["reference"] = correlation_id
        return jsonify(body), status

    try:
        return (
            render_template(
                "error.html",
                status=status,
                title=title,
                detail=detail,
                correlation_id=correlation_id,
            ),
            status,
        )
    except Exception:
        logger.exception("error_template_failed")
        reference = (
            f"<p>Error reference <code>{correlation_id}</code></p>"
            if correlation_id
            else ""
        )
        # Values are ours, not the user's - no injection surface in this format.
        return (
            _FALLBACK_HTML.format(
                status=status, title=title, detail=detail, reference=reference
            ),
            status,
            {"Content-Type": "text/html; charset=utf-8"},
        )


def init_app(app: Flask) -> None:

    @app.errorhandler(HTTPException)
    def handle_http_exception(exc: HTTPException):
        """Normalise every raised HTTP error into our own page.

        Werkzeug's stock descriptions occasionally name the offending
        parameter or path; ours never do.
        """
        status = exc.code or 500
        if status >= 500:
            correlation_id = getattr(g, "correlation_id", None)
            logger.error(
                "http_exception",
                extra={"extra_fields": {"status": status, "name": exc.name}},
                exc_info=exc,
            )
            return _render(status, correlation_id)

        # Client errors are logged with their reason but never shown one.
        # Without this a 400 is indistinguishable from any other 400 when
        # something is misconfigured, and the operator has nothing to work
        # from. The description stays server-side; the user still gets the
        # generic page (T-23).
        logger.info(
            "client_error",
            extra={"extra_fields": {
                "status": status,
                "name": exc.name,
                "reason": str(exc.description)[:300],
            }},
        )
        return _render(status)

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        """Catch-all for anything not already an HTTPException.

        This is where a DB error, a None dereference, or a library bug lands.
        The full trace goes to the log against the correlation ID; the browser
        gets a generic 500 that reveals nothing about why.
        """
        correlation_id = getattr(g, "correlation_id", None)
        logger.exception(
            "unhandled_exception",
            extra={"extra_fields": {"type": type(exc).__name__}},
        )
        return _render(500, correlation_id)
