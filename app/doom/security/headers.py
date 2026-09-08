"""Response security headers.

Applied to every response through a single ``after_request`` hook, so a new
route cannot forget them.
"""

from __future__ import annotations

from flask import Flask, Response

#: Content Security Policy.
#:
#: The important absence is ``unsafe-inline``.  All JavaScript in DOOM lives in
#: external files under /static, which means ``script-src 'self'`` holds
#: without nonces or hashes, and an injected <script> tag simply will not
#: execute (T-19).  That constraint is why the templates carry no inline
#: handlers and no inline <style> blocks - it is a design rule, not an
#: oversight.
#:
#: img-src allows data: because QR codes are rendered inline as data URIs.
#: Images cannot execute, so this does not weaken the script defence.
CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",       # a stolen form cannot POST off-site
        "frame-ancestors 'none'",   # clickjacking: nothing may frame us
        "base-uri 'none'",          # <base> cannot be injected to hijack URLs
        "object-src 'none'",        # no Flash/applet/embed surface at all
    )
)

PERMISSIONS_POLICY = ", ".join(
    (
        "accelerometer=()",
        "camera=(self)",       # QR scanning happens in the browser
        "geolocation=()",
        "gyroscope=()",
        "magnetometer=()",
        "microphone=()",
        "payment=()",
        "usb=()",
    )
)


def _is_authenticated() -> bool:
    """True when a signed-in user is looking at this response."""
    try:
        from flask_login import current_user

        return bool(getattr(current_user, "is_authenticated", False))
    except Exception:
        return False


def _is_static(response: Response) -> bool:
    from flask import request

    return bool(request.endpoint and request.endpoint.endswith("static"))


def apply_security_headers(response: Response) -> Response:
    """Attach the standard header set to an outgoing response."""
    response.headers.setdefault("Content-Security-Policy", CSP)

    # Stops a browser from second-guessing our declared Content-Type.  Without
    # it, a stored .txt whose bytes look like HTML can be sniffed and rendered
    # as HTML, reintroducing XSS through the upload path (T-12).
    response.headers.setdefault("X-Content-Type-Options", "nosniff")

    # "same-origin", NOT "no-referrer".
    #
    # The goal is to stop a share token in the URL reaching any third party a
    # user clicks through to (T-20), and "same-origin" does that completely:
    # cross-origin requests carry no referrer at all.
    #
    # "no-referrer" looks stricter and actively breaks the application. It
    # suppresses the header on *our own* requests too, and Flask-WTF's strict
    # SSL mode checks the Referer on every HTTPS POST to confirm the request
    # came from us. With no-referrer the browser dutifully sends nothing, that
    # check fails, and every form submission - login and registration included
    # - returns 400.
    #
    # Two controls, each correct alone, that cancel each other out. The lesson
    # is that "pick the strictest value" is not the same as "pick the right
    # one": the strictest setting here disables a stronger control than the
    # one it strengthens.
    response.headers.setdefault("Referrer-Policy", "same-origin")

    # ASVS 8.1.1 / 8.2.1 — anti-caching on anything a signed-in user sees.
    #
    # Without this, an inventory page can sit in the browser cache (and in any
    # intermediary cache) after the user walks away from a shared machine. The
    # data here is a map to physical property, so "someone hit Back on a
    # library computer" is a real disclosure path, not a theoretical one.
    #
    # Deliberately no-store rather than private+max-age, including for image
    # thumbnails. That costs a re-fetch on every page view, which is the right
    # trade for this dataset; a deployment that needs the caching can relax it
    # to `private, max-age=…` and justify that as a deviation.
    #
    # Static assets are exempt: they contain no user data and are served by
    # Flask's own static handler.
    if _is_authenticated() and not _is_static(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"          # HTTP/1.0 caches
        response.headers.setdefault("Vary", "Cookie")

    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    # Caddy also sets HSTS at the edge; setting it here too means the header
    # survives a change of reverse proxy.
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
    )

    response.headers.pop("Server", None)
    return response


def init_app(app: Flask) -> None:
    app.after_request(apply_security_headers)
