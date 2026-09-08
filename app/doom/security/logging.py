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
import sys
import uuid
from typing import Any

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
            "message": record.getMessage(),
        }

        if has_request_context():
            payload["method"] = request.method
            # request.path only; the query string can carry a share token.
            payload["path"] = request.path
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
            payload["exception"] = self.formatException(record.exc_info)

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
