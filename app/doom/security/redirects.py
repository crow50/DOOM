"""Safe redirect handling.

The ``?next=`` parameter on a login form is the classic open-redirect vector
(T-26).  An attacker sends a victim to a genuine link on this host:

    https://doom.example/login?next=https://doom-example.evil/login

The domain in the address bar is real, the certificate is real, the login page
is real - and after signing in the user is bounced to a pixel-perfect copy
that asks them to "sign in again".  The application has lent its credibility
to a phishing page.

An allowlist of shapes rather than a denylist of bad strings is the only
approach that survives contact with URL parsing quirks.
"""

from __future__ import annotations

from urllib.parse import urlparse

from flask import request, url_for


def is_safe_redirect(target: str | None) -> bool:
    """True only for a same-application relative path.

    Rejects, in order of how often each is missed:

    * ``//evil.com`` - protocol-relative. Browsers treat it as absolute, while
      a naive ``startswith("/")`` check waves it through. This is the single
      most commonly missed case.
    * ``/\\evil.com`` - backslash variant, normalised to ``//`` by some
      browsers.
    * ``https://evil.com`` - any absolute URL, even one pointing back at us;
      accepting our own hostname invites a bypass via an open redirect
      elsewhere on the domain.
    * ``javascript:`` and ``data:`` - no netloc, so a scheme check alone is
      not enough.
    """
    if not target:
        return False

    target = target.strip()

    if not target.startswith("/"):
        return False

    # "//host" and "/\host" both escape the current origin.
    if target.startswith("//") or target.startswith("/\\"):
        return False

    parsed = urlparse(target)

    # A relative path has neither of these. Anything that does is absolute.
    if parsed.scheme or parsed.netloc:
        return False

    return True


def safe_redirect_target(fallback_endpoint: str = "main.index") -> str:
    """Return a validated ``next`` target, or a known-safe fallback."""
    candidate = request.args.get("next") or request.form.get("next")
    if is_safe_redirect(candidate):
        return candidate
    return url_for(fallback_endpoint)


def safe_referrer_path(fallback_endpoint: str = "locations.index", **values) -> str:
    """Return the referring page as a relative path, or a safe fallback.

    Used for "back" links whose destination depends on where the user came
    from - the label sheet, for instance, is reachable from a location, an
    item, or a list, and always sending them to the same place is wrong.

    ``request.referrer`` is attacker-influenced, so it is not used directly.
    The host is compared against the configured ``PUBLIC_BASE_URL`` - not
    against ``request.host``, which a Host header can steer (T-14) - and only
    the path and query survive. Anything off-origin, malformed, or absent
    falls back.

    Note this works only because ``Referrer-Policy`` is ``same-origin`` rather
    than ``no-referrer``; see D-22 for why that value was chosen.
    """
    from flask import current_app

    referrer = request.referrer
    if not referrer:
        return url_for(fallback_endpoint, **values)

    try:
        parsed = urlparse(referrer)
        expected = urlparse(current_app.config["PUBLIC_BASE_URL"])
    except ValueError:
        return url_for(fallback_endpoint, **values)

    if parsed.scheme != expected.scheme or parsed.netloc != expected.netloc:
        return url_for(fallback_endpoint, **values)

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Run the result back through the same allowlist every other redirect
    # target passes through, so there is one definition of "safe" (T-26).
    if not is_safe_redirect(path):
        return url_for(fallback_endpoint, **values)

    return path
