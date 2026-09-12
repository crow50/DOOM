"""Test fixtures.

Tests run against a real PostgreSQL database rather than SQLite, because
several controls being verified exist only in Postgres: the CITEXT
case-insensitive unique index, and the ``num_nonnulls`` CHECK constraints that
keep an attachment bound to exactly one parent.  Testing those against a
different engine would verify nothing.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from flask.testing import FlaskClient

os.environ.setdefault("SECRET_KEY", "x" * 64)
os.environ.setdefault("PUBLIC_BASE_URL", "https://test.invalid")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/9")

from doom import create_app          # noqa: E402
from doom.config import TestConfig   # noqa: E402
from doom.extensions import db       # noqa: E402
from doom.models import Item, Location, User  # noqa: E402
from doom.security.passwords import hash_password  # noqa: E402


@pytest.fixture(scope="session")
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.drop_all()
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture(autouse=True)
def app_context(app):
    """A FRESH application context per test.

    Holding one context open for the whole session looks tidier and is a trap:
    Flask-Login caches the resolved user on ``g``, and ``g`` belongs to the
    application context. A single long-lived context therefore carries one
    test's authenticated identity into the next, so tests that assert
    "anonymous user cannot reach this" silently pass while logged in as
    whoever ran before them.

    A per-test context makes each test start genuinely unauthenticated.
    """
    with app.app_context():
        yield

        db.session.rollback()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()


class IsolatedClient(FlaskClient):
    """A test client that gives every request its own application context.

    Flask reuses an already-pushed application context rather than creating a
    new one, and ``g`` lives on that context. Because Flask-Login caches the
    resolved user as ``g._login_user``, two requests made inside one context
    share that cache - the second never calls the user loader at all.

    That silently breaks any test of session invalidation: revoke a session,
    make another request, and it succeeds from cache while the loader that
    would have rejected it is skipped. In production each request genuinely
    gets its own context, so this restores the real behaviour rather than
    working around it.
    """

    def open(self, *args, **kwargs):
        with self.application.app_context():
            return super().open(*args, **kwargs)


@pytest.fixture
def client(app):
    app.test_client_class = IsolatedClient
    return app.test_client()


def make_user(username: str = "alice", password: str = "a-long-enough-passphrase") -> User:
    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def alice():
    return make_user("alice")


@pytest.fixture
def bob():
    return make_user("bob")


@pytest.fixture
def alice_bin(alice):
    node = Location(owner_id=alice.id, kind="bin", name="Alice's tote", depth=0)
    db.session.add(node)
    db.session.commit()
    return node


@pytest.fixture
def alice_item(alice, alice_bin):
    item = Item(
        owner_id=alice.id, location_id=alice_bin.id, name="Cordless drill", quantity=3
    )
    db.session.add(item)
    db.session.commit()
    return item


def audit(action: str, *, actor=None, object_type=None, object_id=None,
          detail=None, ip=None):
    """Append an audit row through the real code path.

    Tests must not construct ``AuditLog`` directly any more: rows carry a hash
    chain, and a hand-built row would either violate the NOT NULL columns or —
    worse — insert an unchained row that quietly makes the fixture data look
    tampered with.
    """
    from doom.security.audit import record_audit

    record_audit(
        action=action,
        object_type=object_type,
        object_id=object_id,
        detail=detail,
        actor_id=actor.id if actor is not None else None,
        commit=True,
    )

    if ip is not None:
        # ip is normally taken from the request; a few tests need a specific
        # value, so it is set afterwards through the privileged test session.
        from doom.models import AuditLog
        row = db.session.execute(
            db.select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
        ).scalar_one()
        row.ip = ip
        row.row_hash = row.compute_hash()
        db.session.commit()


def sync():
    """Discard everything this test session has cached.

    Requests made through the test client run in their own application
    context, and therefore their own SQLAlchemy session. Objects the test
    already loaded stay in its identity map at their pre-request values, so a
    relationship like ``item.checkouts`` can report stale rows even after the
    request has committed. ``db.session.refresh(obj)`` is not enough - it
    reloads that row's own columns but re-resolves relationships through the
    same stale identity map.

    Expiring everything makes the next attribute access hit the database,
    which is what the assertion actually wants to check.
    """
    db.session.expire_all()


def login(client, username: str, password: str = "a-long-enough-passphrase"):
    """Sign in through the real login view, so session_version is set.

    The existing session cookie is dropped first. Without that, calling
    ``login(client, "bob")`` on a client already signed in as alice silently
    does nothing - ``/login`` redirects an authenticated visitor away rather
    than swapping accounts - and the test carries on believing it is bob while
    still holding alice's session. Any "another user cannot do X" assertion
    then passes or fails for entirely the wrong reason.

    Clearing first models what actually happens: a different person, on a
    different browser, with no cookie.
    """
    try:
        client.delete_cookie("doom_session")
    except TypeError:                      # older Werkzeug signature
        client.delete_cookie("localhost", "doom_session")

    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )

def pytest_collection_modifyitems(session, config, items):
    """Fail collection if docs/COMPLIANCE.md publishes the wrong test count.

    An audit found four files claiming four different test counts, none of them
    right. The count now lives in exactly one place, ``tools/check_docs.py``
    fails the build if a second file starts quoting one, and this hook is what
    keeps the surviving number honest - it is the only place that knows the real
    figure, and it runs on every ``make test``.
    """
    import re

    ledger = pathlib.Path(__file__).resolve().parents[2] / "docs" / "COMPLIANCE.md"
    if not ledger.exists():
        return

    published = re.findall(
        r"(\d{2,5})\s+tests? pinning", ledger.read_text(encoding="utf-8")
    )
    if not published:
        return

    claimed, actual = int(published[0]), len(items)
    if claimed != actual:
        raise pytest.UsageError(
            f"docs/COMPLIANCE.md claims {claimed} tests, but {actual} were "
            f"collected. Update the count in COMPLIANCE.md §6 - it is the one "
            f"place that publishes it."
        )
