"""Structured logging with redaction.

Two problems are solved here at once.

Log injection: a user who puts a newline into a field can otherwise forge
whole log lines and fabricate events (T-17).  Emitting JSON means every value
is escaped by the encoder and a newline stays inside the string where it
belongs.

Secret leakage: request data reaches logs through several accidental paths.
The filter below scrubs anything whose key looks sensitive, so a stray
``logger.info("payload=%s", form)`` cannot spill a password or a share token
into a file someone later pastes into a bug report.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from flask import Flask, g, has_request_context, request

#: Substring match, deliberately broad.  A false positive costs a redacted log
#: line; a false negative costs a leaked credential.
SENSITIVE_KEY_FRAGMENTS = (
    "password", "passwd", "secret", "token", "cookie", "session",
    "authorization", "auth", "csrf", "pin", "hash", "key",
)

REDACTED = "[redacted]"


def _looks_sensitive(key: str) -> bool:
    lowered = str(key).lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


#: Path prefixes whose next segment is a secret rather than an identifier.
#:
#: ``/t/<token>`` is a capability URL: the token in it *is* the credential, so a
#: request path is not safe to log verbatim the way ``/items/<uuid>`` is.  An
#: object id identifies a row that still requires a session to reach; a share
#: token grants access on its own to anyone who reads it back out of a log.
SECRET_PATH_PREFIXES = ("/t/",)


def scrub_path(path: str) -> str:
    """Replace a secret path segment with a placeholder.

    Keeps the shape of the URL - which route was hit, and that it carried a
    token - while removing the only part that is worth stealing.
    """
    for prefix in SECRET_PATH_PREFIXES:
        if path.startswith(prefix):
            rest = path[len(prefix):]
            tail = rest.split("/", 1)
            remainder = f"/{tail[1]}" if len(tail) > 1 else ""
            return f"{prefix}{REDACTED}{remainder}"
    return path


def scrub_url(value: str | None) -> str | None:
    """Scrub a whole URL, not just a path.

    ``Referer`` arrives as an absolute URL, and ``Referrer-Policy`` is
    ``same-origin`` - so following any link from a shared page sends
    ``https://host/t/<token>`` to the server, where gunicorn would otherwise log
    it verbatim.  The path component gets the same treatment as
    :func:`scrub_path`, and the query string is dropped entirely, matching what
    the application log already does with it.
    """
    if not value:
        return value

    try:
        split = urlsplit(value)
    except ValueError:
        return REDACTED
    # Referer is still URL-encoded, unlike request.path. /%74/<token>
    # addresses the same Flask route as /t/<token> and needs the same scrub.
    scrubbed = scrub_path(unquote(split.path))
    if scrubbed == split.path and not split.query:
        return value

    return urlunsplit((split.scheme, split.netloc, scrubbed, "", ""))


#: A value shaped like a share token: 43 characters of URL-safe base64, which
#: is what ``secrets.token_urlsafe(32)`` produces.  Bounded on both sides so a
#: longer run of the same alphabet - a base64 body, a JWT segment - is not
#: half-redacted into something that looks like a different token.
_TOKEN_SHAPED = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")

#: ``password=hunter2``, ``token: abc``, ``Authorization="Bearer …"``.  The key
#: list is the same one :func:`_looks_sensitive` uses for structured fields, so
#: a name that would be redacted as a dictionary key is also redacted when it
#: turns up inside a sentence.
_ASSIGNMENT = re.compile(
    r"(?i)\b(" + "|".join(SENSITIVE_KEY_FRAGMENTS) + r")\w*\s*[=:]\s*"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;)\]}]+)"
)


def scrub_text(text: str) -> str:
    """Redact secrets from a free-form string.

    Structured ``extra_fields`` are redacted by key, which works because the
    caller chose the key.  A log *message* has no keys: it is whatever string
    the call site passed, and an exception's text is whatever the library that
    raised it decided to say.  Both reach the same log file, so both need the
    same treatment - ASVS 5.0.0-16.2.5 asks that data be logged according to
    its protection level, not according to how it happened to be passed.

    Two patterns, deliberately narrow.  Anything broader starts redacting the
    parts of a message that make it useful, and a log nobody can read is
    replaced by one nobody redacts.
    """
    if not text:
        return text
    text = _TOKEN_SHAPED.sub(REDACTED, text)
    text = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return scrub_path(text) if text.startswith("/t/") else text


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively replace sensitive-looking values with a placeholder."""
    if _depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            k: (REDACTED if _looks_sensitive(k) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """Render records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            # Scrubbed, not passed through: a message is a string the call
            # site composed, and an exception's text is a string a library
            # composed. Neither is covered by the key-based redaction below.
            "message": scrub_text(record.getMessage()),
        }

        if has_request_context():
            payload["method"] = request.method
            # The query string is dropped outright, and the path is scrubbed:
            # a share token travels as a path segment (``/t/<token>``), so
            # recording request.path verbatim wrote a live capability
            # credential into every log line that a shared page produced.
            payload["path"] = scrub_path(request.path)
            # Meaningful only because ProxyFix rewrote remote_addr from the
            # one X-Forwarded-For hop Caddy controls (T-07).
            payload["ip"] = request.remote_addr
            correlation = getattr(g, "correlation_id", None)
            if correlation:
                payload["correlation_id"] = correlation

        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))

        if record.exc_info:
            # A traceback carries whatever the failing call was holding: a DSN
            # in a connection error, a token in a request that raised. The
            # trace is worth keeping; the values in it are not.
            payload["exception"] = scrub_text(self.formatException(record.exc_info))

        return json.dumps(payload, default=str)


def new_correlation_id() -> str:
    """Identifier shared between a user-facing error page and the server log.

    The user is given this and nothing else.  It lets them report a fault
    precisely while the stack trace, the query, and the schema stay on the
    server where they belong (T-23).
    """
    return uuid.uuid4().hex[:12]


def init_app(app: Flask) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(app.config["LOG_LEVEL"])

    app.logger.handlers.clear()
    app.logger.propagate = True

    # Werkzeug's own request log duplicates gunicorn's access log.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    @app.before_request
    def _assign_correlation_id() -> None:
        g.correlation_id = new_correlation_id()


def log_event(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    """Emit a structured event with redacted extra fields."""
    logger.log(level, message, extra={"extra_fields": fields})
