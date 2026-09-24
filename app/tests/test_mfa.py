"""The second factor, end to end.

security/totp.py is pinned to the RFC vectors in test_totp.py. This file is
about the flow around it: that the factor is actually required, that a
half-finished sign-in is not a session, that a code cannot be replayed, that
losing the phone is survivable, and that neither factor alone can remove it.
"""

from __future__ import annotations

import re

import pytest
from conftest import login
from doom.extensions import db
from doom.models import RecoveryCode, UserSession
from doom.security import mfa, totp

PASSWORD = "a-long-enough-passphrase"


def enrol(user) -> str:
    """Put an account into the enrolled-and-confirmed state. Returns the secret."""
    from doom.models import utcnow

    secret = totp.new_secret()
    user.totp_secret = secret
    user.totp_confirmed_at = utcnow()
    user.totp_last_step = None
    db.session.commit()
    return secret


def password_step(client, username: str = "alice"):
    try:
        client.delete_cookie("doom_session")
    except TypeError:
        client.delete_cookie("localhost", "doom_session")
    return client.post("/login", data={"username": username, "password": PASSWORD})


class TestTheFactorIsRequired:
    def test_the_password_alone_does_not_sign_you_in(self, client, alice):
        enrol(alice)
        response = password_step(client)

        assert response.status_code == 302
        assert "/login/verify" in response.headers["Location"]
        # And the half-finished state is not a session.
        assert client.get("/locations/").status_code == 302

    def test_the_code_completes_it(self, client, alice, alice_item):
        secret = enrol(alice)
        password_step(client)

        response = client.post(
            "/login/verify", data={"code": totp.code_at(secret)},
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Signed in for real: a page that only an authenticated session sees,
        # showing this account's own row.
        assert b"Cordless drill" in client.get("/items/").data

    def test_a_wrong_code_does_not(self, client, alice):
        enrol(alice)
        password_step(client)

        response = client.post("/login/verify", data={"code": "000000"})
        assert response.status_code == 200
        assert client.get("/locations/").status_code == 302

    def test_the_verify_page_is_useless_without_the_password_step(self, client, alice):
        enrol(alice)
        response = client.get("/login/verify")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_another_account_s_code_is_not_accepted(self, client, alice, bob):
        enrol(alice)
        theirs = enrol(bob)
        password_step(client, "alice")

        client.post("/login/verify", data={"code": totp.code_at(theirs)})
        assert client.get("/locations/").status_code == 302

    def test_an_account_without_a_factor_still_signs_in_with_one_step(
        self, client, alice, alice_item
    ):
        """Enrolment is opt-in; it must not become a wall for everybody else."""
        response = password_step(client)
        assert response.status_code == 302
        assert "/login/verify" not in response.headers["Location"]
        assert client.get("/locations/").status_code == 200


class TestPendingStateIsNotASession:
    def test_it_expires(self, client, alice, monkeypatch):
        from doom import validation as v

        enrol(alice)
        password_step(client)
        monkeypatch.setattr(v, "MFA_PENDING_SECONDS", -1)

        response = client.post("/login/verify", data={"code": "123456"})
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_it_is_dropped_if_the_account_is_deactivated_in_between(
        self, client, alice
    ):
        secret = enrol(alice)
        password_step(client)

        alice.is_active_flag = False
        db.session.commit()

        response = client.post("/login/verify", data={"code": totp.code_at(secret)})
        assert response.status_code == 302
        assert client.get("/locations/").status_code == 302

    def test_it_is_dropped_if_the_factor_is_removed_in_between(self, client, alice):
        secret = enrol(alice)
        password_step(client)

        alice.totp_secret = None
        alice.totp_confirmed_at = None
        db.session.commit()

        response = client.post("/login/verify", data={"code": totp.code_at(secret)})
        assert response.status_code == 302
        assert client.get("/locations/").status_code == 302


class TestReplay:
    def test_a_code_cannot_be_used_twice(self, app, alice, alice_item):
        """The drift tolerance is a replay window; this is what closes it."""
        secret = enrol(alice)

        first = app.test_client()
        password_step(first)
        code = totp.code_at(secret)
        first.post("/login/verify", data={"code": code})
        assert first.get("/locations/").status_code == 200

        second = app.test_client()
        password_step(second)
        second.post("/login/verify", data={"code": code})
        assert second.get("/locations/").status_code == 302

    def test_a_failed_code_counts_toward_the_lockout(self, client, alice):
        """Otherwise the second factor is the one credential you can grind."""
        from doom import validation as v

        enrol(alice)
        for _ in range(v.LOCKOUT_THRESHOLD):
            password_step(client)
            client.post("/login/verify", data={"code": "000000"})

        db.session.refresh(alice)
        assert alice.is_locked


class TestRecoveryCodes:
    def test_a_recovery_code_signs_you_in(self, client, alice, alice_item):
        enrol(alice)
        codes = mfa.issue(alice)
        db.session.commit()
        password_step(client)

        response = client.post(
            "/login/verify", data={"recovery_code": codes[0]}, follow_redirects=True
        )
        assert response.status_code == 200
        assert b"Cordless drill" in client.get("/items/").data

    def test_each_one_works_exactly_once(self, app, alice):
        enrol(alice)
        codes = mfa.issue(alice)
        db.session.commit()

        first = app.test_client()
        password_step(first)
        first.post("/login/verify", data={"recovery_code": codes[0]})
        assert first.get("/locations/").status_code == 200

        second = app.test_client()
        password_step(second)
        second.post("/login/verify", data={"recovery_code": codes[0]})
        assert second.get("/locations/").status_code == 302

    def test_using_one_does_not_turn_the_factor_off(self, client, alice):
        enrol(alice)
        codes = mfa.issue(alice)
        db.session.commit()
        password_step(client)
        client.post("/login/verify", data={"recovery_code": codes[0]})

        db.session.refresh(alice)
        assert alice.has_totp

    def test_a_spent_code_is_marked_rather_than_deleted(self, alice):
        """A stolen set looks like nothing at all if the rows disappear."""
        enrol(alice)
        codes = mfa.issue(alice)
        db.session.commit()

        assert mfa.consume(alice, codes[0])
        db.session.commit()

        rows = db.session.execute(
            db.select(RecoveryCode).where(RecoveryCode.user_id == alice.id)
        ).scalars().all()
        assert len(rows) == mfa.CODE_COUNT
        assert sum(1 for row in rows if row.is_spent) == 1

    def test_formatting_a_user_might_add_is_tolerated(self, alice):
        enrol(alice)
        codes = mfa.issue(alice)
        db.session.commit()
        assert mfa.consume(alice, codes[0].lower().replace("-", " "))

    def test_a_wrong_code_spends_nothing(self, alice):
        enrol(alice)
        mfa.issue(alice)
        db.session.commit()
        assert not mfa.consume(alice, "AAAA-AAAA-AAAA")
        assert mfa.remaining(alice) == mfa.CODE_COUNT

    def test_regenerating_invalidates_the_previous_set(self, alice):
        enrol(alice)
        old = mfa.issue(alice)
        db.session.commit()
        mfa.issue(alice)
        db.session.commit()

        assert not mfa.consume(alice, old[0])
        assert mfa.remaining(alice) == mfa.CODE_COUNT


class TestEnrolment:
    def test_starting_enrolment_needs_the_password(self, client, alice):
        login(client, "alice")
        client.post("/account/two-factor/begin", data={"current_password": "wrong"})

        db.session.refresh(alice)
        assert alice.totp_secret is None

    def test_a_pending_secret_is_not_yet_a_factor(self, client, alice):
        """Scanning a QR code must not lock you out before you prove it works."""
        login(client, "alice")
        client.post("/account/two-factor/begin",
                    data={"current_password": PASSWORD})

        db.session.refresh(alice)
        assert alice.totp_secret is not None
        assert not alice.has_totp

        # Still a one-step sign-in until it is confirmed.
        response = password_step(client)
        assert "/login/verify" not in response.headers["Location"]

    def test_confirming_turns_it_on_and_issues_recovery_codes(self, client, alice):
        login(client, "alice")
        client.post("/account/two-factor/begin",
                    data={"current_password": PASSWORD})
        db.session.refresh(alice)

        response = client.post("/account/two-factor/confirm", data={
            "code": totp.code_at(alice.totp_secret),
        })
        assert response.status_code == 200
        db.session.refresh(alice)
        assert alice.has_totp
        assert mfa.remaining(alice) == mfa.CODE_COUNT
        # Shown once, on this page, and nowhere else afterwards.
        assert len(re.findall(rb"<code>[A-Z0-9-]{14}</code>", response.data)) == \
            mfa.CODE_COUNT

    def test_a_wrong_confirmation_code_leaves_it_off(self, client, alice):
        login(client, "alice")
        client.post("/account/two-factor/begin",
                    data={"current_password": PASSWORD})
        client.post("/account/two-factor/confirm", data={"code": "000000"})

        db.session.refresh(alice)
        assert not alice.has_totp

    def test_confirming_can_end_the_other_devices(self, app, alice):
        """ASVS 7.4.3 - offered, and it works when taken."""
        other = app.test_client()
        login(other, "alice")
        assert other.get("/locations/").status_code == 200

        mine = app.test_client()
        login(mine, "alice")
        mine.post("/account/two-factor/begin", data={"current_password": PASSWORD})
        db.session.expire_all()
        secret = db.session.get(type(alice), alice.id).totp_secret
        mine.post("/account/two-factor/confirm", data={
            "code": totp.code_at(secret), "sign_out_others": "y",
        })

        assert other.get("/locations/").status_code == 302
        assert mine.get("/locations/").status_code == 200

    def test_declining_that_option_leaves_them_alone(self, app, alice):
        other = app.test_client()
        login(other, "alice")

        mine = app.test_client()
        login(mine, "alice")
        mine.post("/account/two-factor/begin", data={"current_password": PASSWORD})
        db.session.expire_all()
        secret = db.session.get(type(alice), alice.id).totp_secret
        mine.post("/account/two-factor/confirm", data={"code": totp.code_at(secret)})

        assert other.get("/locations/").status_code == 200


class TestRemoval:
    def _signed_in_with_factor(self, app, alice):
        secret = enrol(alice)
        client = app.test_client()
        password_step(client)
        client.post("/login/verify", data={"code": totp.code_at(secret)})
        return client, secret

    def test_the_password_alone_cannot_remove_it(self, app, alice):
        client, _ = self._signed_in_with_factor(app, alice)
        client.post("/account/two-factor/disable", data={
            "current_password": PASSWORD, "code": "000000",
        })
        db.session.expire_all()
        assert db.session.get(type(alice), alice.id).has_totp

    def test_a_code_alone_cannot_remove_it(self, app, alice):
        client, secret = self._signed_in_with_factor(app, alice)
        client.post("/account/two-factor/disable", data={
            "current_password": "not-the-password", "code": totp.code_at(secret),
        })
        db.session.expire_all()
        assert db.session.get(type(alice), alice.id).has_totp

    def test_both_together_remove_it_and_destroy_the_recovery_codes(
        self, app, alice
    ):
        client, secret = self._signed_in_with_factor(app, alice)
        mfa.issue(alice)
        db.session.commit()

        # A step past the one the sign-in consumed, since a code is single use.
        client.post("/account/two-factor/disable", data={
            "current_password": PASSWORD,
            "code": totp.code_at(secret, at=__import__("time").time() + 30),
        })

        db.session.expire_all()
        refreshed = db.session.get(type(alice), alice.id)
        assert not refreshed.has_totp
        assert refreshed.totp_secret is None
        assert db.session.execute(
            db.select(RecoveryCode).where(RecoveryCode.user_id == alice.id)
        ).scalars().all() == []
