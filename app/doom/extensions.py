"""Flask extension singletons, instantiated unbound and initialised by the
application factory.
"""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()

#: Applied to every state-changing form in the application (T-09).  Registered
#: globally rather than per-view, so a new POST route is protected by default
#: and has to opt *out* deliberately.
csrf = CSRFProtect()

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"

#: "strong" makes Flask-Login bind the session to a client fingerprint and
#: drop it when that changes, which shortens the useful life of a stolen
#: cookie (T-03).
login_manager.session_protection = "strong"


#: Rate limiting fails CLOSED (T-33).
#:
#: ``swallow_errors=False`` means that if Redis is unreachable the limiter
#: raises instead of quietly allowing the request.  The alternative - swallow
#: the error and serve anyway - turns a cache outage into a silent removal of
#: every brute-force protection in the application, which is precisely the
#: moment they matter most.  A visible 503 is the correct failure.
#:
#: ``get_remote_address`` reads ``request.remote_addr``, which is only
#: trustworthy because ProxyFix rewrites it from the single X-Forwarded-For
#: hop that Caddy overwrites.  Without both halves, every client shares one
#: bucket or spoofs its way into unlimited ones (T-07).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["600 per hour"],
    swallow_errors=False,
    headers_enabled=True,
)
