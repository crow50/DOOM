"""The controls an ASVS audit found missing, pinned so they cannot go missing again.

Each class here corresponds to a requirement that ``docs/COMPLIANCE.md`` either
claimed without an implementation behind it, or did not mention at all.  The
ledger now cites these tests as the evidence for those rows, so the claim and the
check live and die together.
"""

from __future__ import annotations

import pytest
from conftest import login

from doom.extensions import db
from doom.models import AuditLog
from doom.security import passwords
from doom.security.logging import scrub_path


class TestBreachCorpusIsReachable:
    """ASVS 2.1.7 - the screen has to be able to fire.

    The previous corpus held 124 entries of which 123 were shorter than
    PASSWORD_MIN, so the length check rejected them first and the breach screen
    could only ever match one string.  A corpus that cannot be reached is not a
    control, which is why the length floor is asserted here rather than assumed.
    """

    def test_every_entry_satisfies_the_length_policy(self):
        corpus = passwords.common_passwords()
        too_short = [pw for pw in corpus if len(pw) < 12]
        assert not too_short, (
            f"{len(too_short)} corpus entries are below PASSWORD_MIN and can "
            "never be reached by the check"
        )

    def test_corpus_is_the_size_asvs_asks_for(self):
        # "the top 1,000 or 10,000 most common passwords which match the
        # system's password policy" - ASVS 4.0.3 V2.1.7.
        assert len(passwords.common_passwords()) >= 1000

    @pytest.mark.parametrize(
        "breached",
        ["qwertyqwerty", "123456654321", "administrator", "QwertyQwerty"],
    )
    def test_a_long_breached_password_is_rejected(self, breached):
        with pytest.raises(passwords.PasswordPolicyError):
            passwords.check_policy(breached)

    def test_a_strong_passphrase_is_accepted(self):
        passwords.check_policy("gannet-shelf-brisket-nine")


class TestPasswordStrengthMeter:
    """ASVS 2.1.8 and 2.1.12 - a meter and a reveal toggle are served."""

    def test_script_is_served(self, client):
        response = client.get("/static/js/password-meter.js")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "pw-meter" in body and "pw-reveal" in body

    @pytest.mark.parametrize("path", ["/register", "/account/password"])
    def test_forms_load_the_meter(self, client, alice, path):
        if path != "/register":
            login(client, "alice")
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "js/password-meter.js" in html
        assert "data-password-meter" in html

    def test_meter_is_not_the_authority(self, client):
        """The server rejects a weak password even though the meter is advisory."""
        response = client.post(
            "/register",
            data={"username": "carol", "password": "qwertyqwerty",
                  "confirm": "qwertyqwerty"},
            follow_redirects=True,
        )
        assert b"breach" in response.data.lower() or b"choose something else" in response.data.lower()


class TestHostCookiePrefix:
    """ASVS 3.4.4 - the session cookie carries the __Host- prefix."""

    def test_production_config_uses_the_prefix(self):
        from doom.config import Config

        assert Config.SESSION_COOKIE_NAME.startswith("__Host-")

    def test_the_prefix_preconditions_hold(self):
        """__Host- is only honoured with Secure and Path=/, and no Domain."""
        from doom.config import Config

        assert Config.SESSION_COOKIE_SECURE is True
        assert getattr(Config, "SESSION_COOKIE_DOMAIN", None) in (None, False)
        assert getattr(Config, "SESSION_COOKIE_PATH", "/") == "/"


class TestDeniedAccessIsPersisted:
    """ASVS 7.2.2 - a refused object access survives the 404 that follows it.

    ``record_audit`` defaults to riding along with the caller's transaction, and
    every denial path ends in ``abort(404)``.  Nothing else in that request
    commits, so the row was added to the session and then rolled back at teardown
    - the audit trail recorded no denials at all while claiming to.
    """

    def _denials(self):
        return db.session.execute(
            db.select(AuditLog).where(AuditLog.action == "access_denied")
        ).scalars().all()

    def test_reading_another_users_item_is_recorded(
        self, client, alice, bob, alice_item
    ):
        login(client, "bob")
        assert client.get(f"/items/{alice_item.id}").status_code == 404

        db.session.expire_all()
        rows = self._denials()
        assert rows, "a denied access left no audit row"
        assert any(str(alice_item.id) in (row.object_id or "") for row in rows)

    def test_checkout_denial_is_recorded(self, client, alice, bob, alice_item):
        """The locking path used to skip the audit by re-implementing the query."""
        login(client, "bob")
        assert client.post(f"/items/{alice_item.id}/checkout").status_code == 404

        db.session.expire_all()
        assert self._denials(), "a denied checkout left no audit row"

    def test_malformed_link_id_is_a_404_not_a_500(
        self, client, alice, alice_item
    ):
        login(client, "alice")
        response = client.post(f"/items/{alice_item.id}/links/not-a-uuid/delete")
        assert response.status_code in (404, 302), response.status_code


class TestShareTokenIsNotLogged:
    """ASVS 7.1.1 / 13.1.3 - a capability token must not reach the log.

    ``/t/<token>`` puts the credential in the path, and the JSON formatter logged
    request.path verbatim, so every visit to a shared page wrote a live share
    token into the log stream.
    """

    def test_the_token_segment_is_scrubbed(self):
        assert scrub_path("/t/AbCdEf0123456789") == "/t/[redacted]"
        assert scrub_path("/t/AbCdEf0123456789/pin") == "/t/[redacted]/pin"

    def test_ordinary_paths_are_untouched(self):
        for path in ("/", "/items/", "/account/activity.csv"):
            assert scrub_path(path) == path

    def test_a_real_share_request_logs_no_token(self, app, client, alice, caplog):
        from doom.security.logging import JsonFormatter

        token = "z" * 43
        with caplog.at_level("INFO"):
            client.get(f"/t/{token}")

        formatter = JsonFormatter()
        rendered = " ".join(formatter.format(r) for r in caplog.records)
        assert token not in rendered
