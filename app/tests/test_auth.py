"""Authentication: lockout, session revocation, enumeration resistance."""

from __future__ import annotations

from datetime import timedelta

from conftest import login, make_user
from doom import validation as v
from doom.extensions import db
from doom.models import User, utcnow


class TestLockout:
    """Verified at model level.

    Over HTTP the per-IP rate limit fires first and the account never reaches
    five failures from a single address - which is the intended layering, and
    exactly why the account-level rule needs its own test.
    """

    def test_locks_after_threshold(self, alice):
        alice.failed_login_count = v.LOCKOUT_THRESHOLD
        alice.locked_until = utcnow() + alice.lock_duration()
        db.session.commit()
        assert alice.is_locked

    def test_lock_expires_on_its_own(self, alice):
        """No operator action required.

        An admin-only unlock would turn a griefer's five failed logins into an
        indefinite outage for the victim (T-31).
        """
        alice.locked_until = utcnow() - timedelta(seconds=1)
        db.session.commit()
        assert not alice.is_locked

    def test_backoff_is_capped(self, alice):
        """The cap is the security property.

        Lockout keyed on a username is a denial-of-service primitive: anyone
        who knows the name can trigger it. Capping bounds the damage.
        """
        alice.failed_login_count = 500
        assert alice.lock_duration() <= timedelta(seconds=v.LOCKOUT_MAX_SECONDS)

    def test_correct_password_rejected_while_locked(self, client, alice):
        alice.failed_login_count = v.LOCKOUT_THRESHOLD
        alice.locked_until = utcnow() + timedelta(minutes=10)
        db.session.commit()

        response = client.post(
            "/login",
            data={"username": "alice", "password": "a-long-enough-passphrase"},
        )
        assert response.status_code == 200          # re-rendered form, not a redirect
        assert b"Incorrect username or password" in response.data
        # The message must not reveal that the account is locked - that would
        # confirm the username exists and tell a griefer their lockout landed.
        assert b"locked" not in response.data.lower()


class TestSessionRevocation:
    def test_session_version_bump_invalidates_existing_session(self, client, alice):
        """The half that is easy to omit.

        Increment the column but forget to compare it in the user loader and
        the feature still *looks* like it works, while every old cookie stays
        valid. This test is the reason that cannot happen silently (T-06).
        """
        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        user = db.session.get(User, alice.id)
        user.session_version += 1
        db.session.commit()

        response = client.get("/locations/")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


class TestEnumerationResistance:
    def test_same_message_for_unknown_user_and_wrong_password(self, client, alice):
        unknown = client.post(
            "/login", data={"username": "nobody-here", "password": "whatever-long"}
        )
        wrong = client.post(
            "/login", data={"username": "alice", "password": "wrong-but-long-enough"}
        )
        assert b"Incorrect username or password" in unknown.data
        assert b"Incorrect username or password" in wrong.data

    def test_login_form_does_not_validate_username_shape(self, client):
        """No strict validation on the login username field.

        Rejecting a malformed username before checking the password would
        produce a different response for "not a valid username" than for
        "wrong password" - an enumeration oracle in the error path.
        """
        response = client.post(
            "/login", data={"username": "!!!not-valid!!!", "password": "whatever-long"}
        )
        assert b"Incorrect username or password" in response.data


class TestRegistration:
    def test_username_is_normalised_before_uniqueness_check(self, client):
        make_user("alice")
        response = client.post(
            "/register",
            data={
                "username": "ALICE",
                "password": "a-different-passphrase",
                "confirm": "a-different-passphrase",
            },
        )
        assert b"already taken" in response.data

    def test_weak_password_rejected_with_a_reason(self, client):
        response = client.post(
            "/register",
            data={"username": "newbie", "password": "short", "confirm": "short"},
        )
        assert db.session.query(User).filter_by(username="newbie").first() is None
        assert b"characters" in response.data
