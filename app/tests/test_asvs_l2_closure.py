"""Acceptance tests for the ASVS 5.0 Level 2 controls closed in this review.

Cited by line from ``docs/security/asvs-5.0.0.json``. The same rule applies
here as at Level 1: a requirement is Met when something fails if the control
is removed, not when a document says it is there.
"""

from __future__ import annotations

import io
import json
import logging
import re

import pytest
from conftest import login
from doom import validation as v
from doom.extensions import db
from doom.models import UserSession, User, utcnow


def _sessions(user, *, live=True):
    query = db.select(UserSession).where(UserSession.user_id == user.id)
    if live:
        query = query.where(UserSession.revoked_at.is_(None))
    return db.session.execute(query).scalars().all()


# ---------------------------------------------------------------------------
# V7.3.1 - inactivity timeout
# ---------------------------------------------------------------------------

class TestInactivityTimeout:
    def test_an_idle_session_stops_working(self, client, alice):
        import datetime

        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=v.SESSION_IDLE_MINUTES + 1
        )
        db.session.commit()

        response = client.get("/locations/")
        assert response.status_code == 302
        assert b"Cordless drill" not in response.data

    def test_the_idle_session_is_revoked_rather_than_merely_refused(
        self, client, alice
    ):
        """A refusal that leaves the row live is retryable; this is not."""
        import datetime

        login(client, "alice")
        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=v.SESSION_IDLE_MINUTES + 1
        )
        db.session.commit()

        client.get("/locations/")
        db.session.expire_all()
        assert _sessions(alice, live=True) == []

    def test_activity_inside_the_window_keeps_the_session(self, client, alice):
        import datetime

        login(client, "alice")
        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=max(v.SESSION_IDLE_MINUTES - 5, 1)
        )
        db.session.commit()

        assert client.get("/locations/").status_code == 200


# ---------------------------------------------------------------------------
# V7.1.2 - a documented concurrent-session limit, enforced
# ---------------------------------------------------------------------------

class TestConcurrentSessionLimit:
    def test_the_limit_holds_however_many_times_you_sign_in(self, app, alice):
        for _ in range(v.MAX_CONCURRENT_SESSIONS + 4):
            login(app.test_client(), "alice")
            db.session.expire_all()

        assert len(_sessions(alice)) <= v.MAX_CONCURRENT_SESSIONS

    def test_the_least_recently_used_session_is_the_one_that_goes(
        self, app, alice
    ):
        import datetime

        first = app.test_client()
        login(first, "alice")
        db.session.expire_all()
        oldest = _sessions(alice)[0]
        oldest.last_seen_at = utcnow() - datetime.timedelta(days=30)
        db.session.commit()
        oldest_id = oldest.id

        for _ in range(v.MAX_CONCURRENT_SESSIONS):
            login(app.test_client(), "alice")
            db.session.expire_all()

        assert db.session.get(UserSession, oldest_id).revoked_at is not None

    def test_a_revoked_session_cannot_be_used_afterwards(self, app, alice):
        evicted = app.test_client()
        login(evicted, "alice")
        assert evicted.get("/locations/").status_code == 200

        for _ in range(v.MAX_CONCURRENT_SESSIONS):
            login(app.test_client(), "alice")

        assert evicted.get("/locations/").status_code == 302


# ---------------------------------------------------------------------------
# V6.1.2 / V6.2.11 - a documented context-specific word list, used
# ---------------------------------------------------------------------------

class TestContextWordScreen:
    def test_the_list_is_not_empty_and_names_this_application(self):
        assert v.CONTEXT_WORDS
        assert "doom" in v.CONTEXT_WORDS

    @pytest.mark.parametrize("candidate", [
        "doominventory2026",
        "MyWarehousePassphrase",
        "correct-horse-STORAGE-battery",
    ])
    def test_a_context_word_is_refused_however_it_is_cased(self, candidate):
        from doom.security.passwords import PasswordPolicyError, check_policy

        with pytest.raises(PasswordPolicyError):
            check_policy(candidate)

    def test_an_unrelated_passphrase_is_still_accepted(self):
        from doom.security.passwords import check_policy

        check_policy("relentless-kettle-mango-ribbon")

    def test_registration_refuses_a_context_word(self, client):
        response = client.post("/register", data={
            "username": "newcomer",
            "password": "doom-inventory-passphrase",
            "confirm": "doom-inventory-passphrase",
        })
        assert response.status_code == 200
        assert db.session.query(User).filter_by(username="newcomer").count() == 0


# ---------------------------------------------------------------------------
# V5.2.4 - a file count quota as well as a byte quota
# ---------------------------------------------------------------------------

class TestFileCountQuota:
    def test_the_count_ceiling_is_enforced_independently_of_the_byte_ceiling(
        self, alice, alice_bin, monkeypatch
    ):
        from doom.models import Attachment
        from doom.security.uploads import UploadRejected, check_quota

        monkeypatch.setattr(v, "MAX_ATTACHMENTS_PER_OWNER", 2)
        for index in range(2):
            db.session.add(Attachment(
                owner_id=alice.id, kind="document",
                stored_name=f"{index}.txt", original_name=f"{index}.txt",
                content_type="text/plain", byte_size=1, sha256=f"{index:064d}",
                location_id=alice_bin.id,
            ))
        db.session.commit()

        # Well inside the 2 GB byte quota, and refused anyway.
        with pytest.raises(UploadRejected) as raised:
            check_quota(alice.id, 1)
        assert "stored files" in str(raised.value)


# ---------------------------------------------------------------------------
# V16.2.5 - log according to the data's protection level
# ---------------------------------------------------------------------------

class TestLogMessageSanitisation:
    @staticmethod
    def _emit(message, **kwargs):
        from doom.security.logging import JsonFormatter

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname=__file__, lineno=1,
            msg=message, args=(), exc_info=kwargs.get("exc_info"),
        )
        return json.loads(JsonFormatter().format(record))

    def test_a_share_code_in_a_message_is_redacted(self):
        from doom.models import new_share_token

        token = new_share_token()
        payload = self._emit(f"could not resolve {token}")
        assert token not in payload["message"]
        assert "[redacted]" in payload["message"]

    @pytest.mark.parametrize("message", [
        "connect failed: password=hunter2trombone",
        "upstream said token: abc123def456",
        'header Authorization="Bearer sk-live-xyz"',
        "session_key = deadbeefcafe",
    ])
    def test_a_labelled_secret_in_a_message_is_redacted(self, message):
        payload = self._emit(message)
        for leaked in ("hunter2trombone", "abc123def456", "sk-live-xyz",
                       "deadbeefcafe"):
            assert leaked not in payload["message"]

    def test_an_exception_traceback_is_redacted_too(self):
        from doom.models import new_share_token

        token = new_share_token()
        try:
            raise RuntimeError(f"upstream rejected {token}")
        except RuntimeError:
            import sys

            payload = self._emit("request failed", exc_info=sys.exc_info())

        assert token not in payload["exception"]
        assert "RuntimeError" in payload["exception"]

    def test_an_ordinary_message_survives_intact(self):
        """A log nobody can read is replaced by a log nobody redacts."""
        payload = self._emit("upload_stored kind=photo bytes=20481")
        assert payload["message"] == "upload_stored kind=photo bytes=20481"


# ---------------------------------------------------------------------------
# V13.4.2 / V13.4.3 / V13.4.4 / V13.4.5 - what production must not expose
# ---------------------------------------------------------------------------

class TestProductionSurface:
    def test_debug_is_not_a_toggle(self, app):
        """V13.4.2 - the Werkzeug debugger is a remote shell."""
        from doom.config import Config, ConfigError

        assert app.config["DEBUG"] is False
        assert app.jinja_env.auto_reload is False or app.config["TESTING"]

        import os
        for variable in ("FLASK_DEBUG", "DEBUG"):
            os.environ[variable] = "1"
            try:
                with pytest.raises(ConfigError):
                    Config.verify_runtime()
            finally:
                os.environ.pop(variable, None)

    def test_no_route_lists_a_directory(self, app, client, alice):
        """V13.4.3 - there is no file_server at all, at either layer."""
        login(client, "alice")
        for path in ("/files/", "/static/", "/static/css/", "/uploads/"):
            assert client.get(path).status_code in (404, 405), path

    def test_trace_is_not_answered(self, client):
        """V13.4.4 - a TRACE echo reflects headers a script cannot read."""
        response = client.open("/", method="TRACE")
        assert response.status_code in (405, 501)

    def test_the_health_probe_says_nothing_it_does_not_have_to(self, client):
        """V13.4.5 - a monitoring endpoint is an unauthenticated reader."""
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.data.strip() == b"ok"

        lowered = response.data.lower()
        for leak in (b"postgres", b"redis", b"version", b"python", b"flask"):
            assert leak not in lowered

    def test_no_documentation_or_introspection_endpoint_is_registered(self, app):
        """V13.4.5, V4.3.2 - nothing to enumerate the API with."""
        paths = {rule.rule for rule in app.url_map.iter_rules()}
        for probe in ("/graphql", "/openapi.json", "/swagger", "/docs",
                      "/redoc", "/metrics", "/debug", "/console"):
            assert probe not in paths


# ---------------------------------------------------------------------------
# V15.3.3 / V15.3.7 / V4.1.3 / V15.3.4 - request handling
# ---------------------------------------------------------------------------

class TestRequestHandling:
    def test_a_posted_field_that_is_not_on_the_form_binds_to_nothing(
        self, client, alice
    ):
        """V15.3.3 - mass assignment, and the reason nothing uses **request.form."""
        login(client, "alice")
        before = alice.session_version

        client.post("/account/", data={
            "display_name": "Sam", "email": "", "timezone": "UTC",
            # None of these are fields on ProfileForm.
            "is_active": "false", "session_version": "9999",
            "password_hash": "x", "id": "00000000-0000-0000-0000-000000000000",
            "totp_secret": "AAAA",
        }, follow_redirects=True)

        db.session.refresh(alice)
        assert alice.is_active is True
        assert alice.session_version == before
        assert alice.totp_secret is None
        assert alice.display_name == "Sam"

    def test_a_repeated_parameter_does_not_change_which_value_is_used(
        self, client, alice
    ):
        """V15.3.7 - parameter pollution.

        Werkzeug's MultiDict returns the first value for a repeated key, and
        WTForms reads through it, so the answer does not depend on where in
        the request the duplicate sits.
        """
        login(client, "alice")
        response = client.post(
            "/account/?display_name=from-query",
            data={"display_name": ["first", "second"], "email": "",
                  "timezone": "UTC"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        db.session.refresh(alice)
        # The body wins over the query string, and the first body value wins
        # over the second. Neither answer depends on ordering by accident.
        assert alice.display_name == "first"

    def test_a_client_cannot_forge_the_address_used_for_rate_limiting(self, app):
        """V4.1.3 and V15.3.4 - the two halves of one control.

        ProxyFix trusts exactly one hop, which is the value Caddy writes; the
        Caddyfile overwrites rather than appends. Trusting more hops than
        exist would let a client prepend an address and mint itself a fresh
        rate-limit bucket per request.
        """
        from werkzeug.middleware.proxy_fix import ProxyFix
        from werkzeug.test import Client
        from werkzeug.wrappers import Response

        configured = app.wsgi_app
        assert isinstance(configured, ProxyFix)
        assert configured.x_for == 1
        assert configured.x_port == 0

        def echo(environ, start_response):
            return Response(environ.get("REMOTE_ADDR", ""))(environ, start_response)

        middleware = ProxyFix(echo, x_for=configured.x_for,
                              x_proto=configured.x_proto,
                              x_host=configured.x_host, x_port=configured.x_port)
        # A forged chain, with the real peer appended last by the proxy.
        response = Client(middleware).get("/", headers={
            "X-Forwarded-For": "9.9.9.9, 8.8.8.8, 203.0.113.7",
        })
        assert response.text == "203.0.113.7"


# ---------------------------------------------------------------------------
# V16.5.1 / V16.5.2 / V16.5.3 - failing safely
# ---------------------------------------------------------------------------

class TestFailureBehaviour:
    def test_an_unexpected_error_returns_a_correlation_id_and_nothing_else(self):
        """V16.5.1 - no stack trace, no query, no key.

        Built on its own application rather than the session one: a route has
        to be registered before the first request, and the suite's app has
        served several thousand by now. PROPAGATE_EXCEPTIONS is turned off so
        the handler runs instead of the exception escaping to pytest - which
        is what TESTING would otherwise cause, and is the opposite of the
        behaviour under test.
        """
        from doom import create_app
        from doom.config import TestConfig

        class ErrorConfig(TestConfig):
            PROPAGATE_EXCEPTIONS = False

        failing = create_app(ErrorConfig)

        @failing.route("/__boom")
        def boom():
            raise RuntimeError("secret-internal-detail sk-live-canary")

        response = failing.test_client().get("/__boom")

        assert response.status_code == 500
        body = response.data.lower()
        for leak in (b"secret-internal-detail", b"sk-live-canary", b"traceback",
                     b"runtimeerror", b"/srv/doom", b"select "):
            assert leak not in body

        # A correlation id, so the report is precise without the page being.
        assert re.search(rb"[0-9a-f]{12}", response.data)

    def test_an_external_lookup_failure_degrades_rather_than_breaks(
        self, client, alice, app, monkeypatch
    ):
        """V16.5.2 - the one external dependency, when it is not there."""
        from doom.security.lookup import LookupUnavailable

        def unreachable(*args):
            raise LookupUnavailable("connection refused to 10.0.0.1:443")

        monkeypatch.setattr("doom.blueprints.items.lookup_barcode", unreachable)
        monkeypatch.setitem(app.config, "BARCODE_LOOKUP_PROVIDER", "openfoodfacts")
        login(client, "alice")

        response = client.get("/items/barcode/4006381333931")
        assert response.status_code == 200
        assert response.json["source"] == "none"
        assert b"10.0.0.1" not in response.data

        # And the rest of the application is unaffected.
        assert client.get("/items/").status_code == 200

    def test_validation_failure_does_not_fall_through_to_the_write(
        self, client, alice, alice_bin
    ):
        """V16.5.3 - no fail-open: a refused form writes nothing."""
        from doom.models import Item

        login(client, "alice")
        before = db.session.query(Item).count()

        client.post("/items/new", data={
            "name": "", "quantity": "-5", "location_id": str(alice_bin.id),
        })
        assert db.session.query(Item).count() == before
