"""Gunicorn access logging: scrubbed, and in the same shape as everything else.

Two problems, one class.

**A capability token was being logged.**  ``/t/<token>`` puts the credential in
the path (T-36), and gunicorn's access log records the raw request line.  So did
``Referer``: ``Referrer-Policy`` is ``same-origin``, so following any link from a
shared page hands the server the full ``https://host/t/<token>``.  The
application log has scrubbed both since the audit; gunicorn's had not, which
left anyone with log-read access able to replay every live share link.

**The stack logged in two formats.**  The application emits JSON
(``security/logging.py``); gunicorn emitted Apache combined format.  ASVS 1.7.1
asks for "a common logging format and approach across the system", and two
formats in one stack is not that.  Overriding ``access`` rather than only
``atoms`` costs nothing extra and fixes both at once.

Wired up by ``--logger-class`` in the Dockerfile's gunicorn command.  Gunicorn
puts the working directory on ``sys.path`` before loading this, the same way it
resolves ``wsgi:app``.
"""

from __future__ import annotations

import json
import time

from gunicorn import glogging

from .logging import scrub_path, scrub_url


class JsonAccessLogger(glogging.Logger):
    """Gunicorn's logger, emitting scrubbed JSON access records."""

    def access(self, resp, req, environ, request_time) -> None:
        """Write one JSON object per request.

        Deliberately built from ``environ`` rather than from ``self.atoms()``:
        the atoms dict bakes the URI into a preformatted request line (``r``,
        from ``RAW_URI``, which carries the query string too), so scrubbing
        afterwards would mean parsing that string back apart.  Reading the
        fields directly means the token never reaches a buffer.
        """
        if not self.access_log_enabled:
            return

        try:
            status = getattr(resp, "status", None)
            if isinstance(status, str):          # gunicorn hands over "200 OK"
                status = status.split(None, 1)[0]

            record = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "level": "INFO",
                "logger": "gunicorn.access",
                "message": "request",
                "method": environ.get("REQUEST_METHOD"),
                # The query string is dropped rather than scrubbed: nothing here
                # needs it in a log, and it is the other place a token could
                # appear.  This matches what the application log already does.
                "path": scrub_path(environ.get("PATH_INFO", "")),
                "status": int(status) if status is not None else None,
                "bytes": getattr(resp, "sent", None),
                "duration_ms": round(request_time.total_seconds() * 1000, 1),
                # Caddy overwrites X-Forwarded-For with the real peer and
                # ProxyFix trusts exactly that one hop (T-07).
                "ip": environ.get("HTTP_X_FORWARDED_FOR") or environ.get("REMOTE_ADDR"),
                "referer": scrub_url(environ.get("HTTP_REFERER")),
                "user_agent": environ.get("HTTP_USER_AGENT"),
            }
            self.access_log.info(json.dumps(record, default=str))
        except Exception:
            # An access-logging bug must not be able to fail the request it is
            # describing - the same rule record_audit follows.
            self.error_log.exception("access_log_failed")
