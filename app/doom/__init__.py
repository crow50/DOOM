"""Application factory."""

from __future__ import annotations

import logging

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from . import validation as v
from .config import Config, ConfigError
from .extensions import csrf, db, limiter, login_manager, migrate
from .security import headers as security_headers
from .security import logging as structured_logging

__version__ = "0.1.0"

logger = logging.getLogger(__name__)


def create_app(config_object: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    # Raises before a single request is served if the environment is unsafe.
    Config.verify_runtime()
    if app.config.get("DEBUG"):
        raise ConfigError("DEBUG must remain off; refusing to start.")

    _apply_proxy_fix(app)

    structured_logging.init_app(app)
    _init_extensions(app)
    security_headers.init_app(app)
    _register_blueprints(app)
    _register_template_globals(app)
    _register_cli(app)

    logger.info(
        "doom_started",
        extra={"extra_fields": {
            "version": __version__,
            "public_base_url": app.config["PUBLIC_BASE_URL"],
        }},
    )
    return app


def _apply_proxy_fix(app: Flask) -> None:
    """Trust exactly one reverse-proxy hop.

    Without this, ``request.remote_addr`` is Caddy's container address for
    every request.  Every client would then share a single rate-limit bucket,
    and per-IP limiting would silently stop meaning anything - the failure is
    invisible, which is what makes it dangerous (T-07).

    The count matters as much as the flag.  ``x_for=1`` takes the *last* entry
    in X-Forwarded-For, which is the value Caddy itself wrote.  Trusting more
    hops than actually exist would let a client prepend a forged address and
    mint themselves a fresh bucket per request.  This pairs with the
    ``header_up X-Forwarded-For {remote_host}`` line in the Caddyfile, which
    overwrites rather than appends; both halves are required.
    """
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)


def _register_blueprints(app: Flask) -> None:
    from .blueprints import (
        account, auth, errors, files, items, labels, locations, main, nfc,
        search, share,
    )

    errors.init_app(app)
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(locations.bp)
    app.register_blueprint(items.bp)
    app.register_blueprint(labels.bp)
    app.register_blueprint(share.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(nfc.bp)
    app.register_blueprint(account.bp)
    app.register_blueprint(search.bp)


def _register_template_globals(app: Flask) -> None:
    """Expose validation constants to templates.

    Templates render limits from the same module the validators use, so an
    HTML hint cannot drift out of step with the rule it is advertising.
    """

    @app.context_processor
    def inject_limits() -> dict:
        return {
            "password_min": v.PASSWORD_MIN,
            "username_min": v.USERNAME_MIN,
            "username_max": v.USERNAME_MAX,
            "upload_max_mb": v.UPLOAD_MAX_BYTES // (1024 * 1024),
            "quantity_max": v.QUANTITY_MAX,
            "search_max": v.SEARCH_QUERY_MAX,
            "lookup_enabled": bool(app.config.get("BARCODE_LOOKUP_PROVIDER")),
        }


def _register_cli(app: Flask) -> None:
    from .cli import register_cli

    register_cli(app)
