"""Application configuration - fails closed.

Every setting that matters to security is read from the environment and
validated here, at import time.  If something required is missing, weak, or
still holds a placeholder, the process raises and the container never starts.

That is deliberate.  A misconfigured deployment that boots anyway is worse
than one that refuses to: a guessable SECRET_KEY silently makes every session
cookie forgeable (T-05), and nobody notices until it is exploited.  A crash
loop is loud.
"""

from __future__ import annotations

import os
from datetime import timedelta

from . import validation as v


class ConfigError(RuntimeError):
    """Raised when the environment cannot support a safe boot."""


#: Values that mean "nobody has set this yet".
_PLACEHOLDERS = {
    "",
    "CHANGE_ME",
    "changeme",
    "secret",
    "dev",
    "development",
    "test",
    "password",
}


def _read_secret(name: str) -> str:
    """Read a secret from a file if one is configured, else the environment.

    ASVS 6.4.1 asks for secrets to be created, stored and access-controlled
    outside the application. Environment variables are the weakest common
    option: they are inherited by every child process, appear in
    ``docker inspect``, and are trivially dumped by anything that can read
    ``/proc/<pid>/environ``.

    A file read once at startup is strictly better — it can be mode 0400,
    owned by one user, mounted read-only, and it never lands in a process
    listing. ``<NAME>_FILE`` therefore wins over ``<NAME>`` when both are set,
    which is also the convention Docker secrets and Kubernetes use, so moving
    to a real vault later is a mount change rather than a code change.
    """
    path = os.environ.get(f"{name}_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            raise ConfigError(
                f"{name}_FILE points at {path!r}, which could not be read: {exc}. "
                f"Refusing to fall back to the environment — a secret that "
                f"silently comes from somewhere other than where you configured "
                f"it is worse than no secret at all."
            ) from exc

    return os.environ.get(name, "").strip()


def _require(name: str, *, min_length: int = 1) -> str:
    """Read a required secret or setting, rejecting placeholder values."""
    value = _read_secret(name)

    if value in _PLACEHOLDERS:
        raise ConfigError(
            f"{name} is unset or still holds a placeholder value. "
            f"Run `make init` to generate real secrets. "
            f"Refusing to start rather than run with a guessable {name}."
        )
    if len(value) < min_length:
        raise ConfigError(
            f"{name} must be at least {min_length} characters; got {len(value)}."
        )
    return value


def _flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration shared by every environment."""

    # --- identity -----------------------------------------------------------
    # 64 hex characters is what `make init` produces (openssl rand -hex 32).
    # Anything materially shorter is rejected outright.
    SECRET_KEY = _require("SECRET_KEY", min_length=32)

    # --- database -----------------------------------------------------------
    # This is the RESTRICTED role.  The application never receives credentials
    # capable of ALTER or DROP; migrations use a separate admin DSN supplied
    # only by `make upgrade` (T-35).
    SQLALCHEMY_DATABASE_URI = _require("DATABASE_URL", min_length=10)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # --- rate limiting ------------------------------------------------------
    REDIS_URL = _require("REDIS_URL", min_length=10)
    RATELIMIT_STORAGE_URI = REDIS_URL
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True

    # --- public identity ----------------------------------------------------
    # Every QR code and NFC tag is built from this value and never from the
    # inbound Host header.  Trusting the request would let an attacker poison
    # generated links, and would bake "localhost" into physical labels that
    # then have to be reprinted (T-14).
    PUBLIC_BASE_URL = _require("PUBLIC_BASE_URL", min_length=8).rstrip("/")

    # --- sessions -----------------------------------------------------------
    SESSION_COOKIE_NAME = "doom_session"
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read it (T-03)
    SESSION_COOKIE_SECURE = True            # never sent over plaintext (T-03)
    SESSION_COOKIE_SAMESITE = "Lax"         # cross-site POSTs drop the cookie
    PERMANENT_SESSION_LIFETIME = timedelta(hours=v.SESSION_LIFETIME_HOURS)
    SESSION_REFRESH_EACH_REQUEST = False

    # --- CSRF ---------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None              # tied to session lifetime instead
    WTF_CSRF_SSL_STRICT = True

    # --- uploads ------------------------------------------------------------
    # Werkzeug refuses a larger body before buffering it, so an oversized
    # upload costs almost nothing to reject (T-28).
    MAX_CONTENT_LENGTH = v.UPLOAD_MAX_BYTES
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/var/lib/doom/uploads")

    # --- barcode lookup (opt-in, off by default) ----------------------------
    # The application's only outbound call, and a deliberate, narrow exception
    # to D-13. Unset means no network access is attempted at all.
    #
    # The value names a provider in validation.BARCODE_PROVIDERS - a dict in
    # code. It is not a URL, and no request can make it one: the user supplies
    # a barcode (a parameter), never a destination (T-40).
    BARCODE_LOOKUP_PROVIDER = os.environ.get("BARCODE_LOOKUP_PROVIDER", "").strip() or None

    # --- logging ------------------------------------------------------------
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

    # --- hard invariants ----------------------------------------------------
    # A stack trace in the browser hands an attacker the schema, the file
    # layout, and often fragments of configuration (T-23).  DEBUG is not a
    # toggle in this application; the debugger is also a remote code execution
    # console, which has no place in anything reachable over a network.
    DEBUG = False
    TESTING = False

    @staticmethod
    def verify_runtime() -> None:
        """Final guard against a debug-enabled boot.

        Checked at application-factory time as well as here, because
        FLASK_DEBUG in the environment would otherwise switch on the
        interactive debugger without touching this class at all.
        """
        if _flag("FLASK_DEBUG") or _flag("DEBUG"):
            raise ConfigError(
                "FLASK_DEBUG/DEBUG is set. The Werkzeug debugger is a remote "
                "code execution console and must never run in a container "
                "that serves real traffic. Unset it and restart."
            )


class TestConfig(Config):
    """Used only by the pytest suite."""

    TESTING = True
    WTF_CSRF_ENABLED = False        # forms are exercised directly
    SESSION_COOKIE_SECURE = False   # the test client speaks plain HTTP
    RATELIMIT_ENABLED = False
