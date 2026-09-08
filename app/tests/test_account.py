"""Profile, activity feed, and audit export."""

from __future__ import annotations

from conftest import audit, login, make_user
from doom.blueprints.account import _csv_safe
from doom.extensions import db


class TestCsvInjection:
    """Formula injection in the audit export.

    A CSV cell beginning with =, +, - or @ is executed as a formula when the
    file is opened in Excel, LibreOffice or Sheets. Audit rows contain
    user-supplied text - location names, upload filenames - so an export is a
    path from "attacker types a location name" to "code runs on the machine of
    whoever opens the export", without the application itself ever being
    exploited.
    """

    def test_formula_prefixes_are_neutralised(self):
        for payload in (
            '=cmd|\'/c calc\'!A0',
            '+1+1',
            '-2+3',
            '@SUM(1:9)',
        ):
            assert _csv_safe(payload).startswith("'")

    def test_ordinary_text_is_untouched(self):
        assert _csv_safe("Tote A1") == "Tote A1"
        assert _csv_safe("Bay 1 / Rack A") == "Bay 1 / Rack A"

    def test_none_becomes_empty(self):
        assert _csv_safe(None) == ""


class TestActivityScoping:
    def test_feed_shows_only_your_own_events(self, client, alice, bob):
        audit("item_created", actor=alice, detail="alice-only-detail")
        audit("item_created", actor=bob, detail="bob-only-detail")

        login(client, "alice")
        body = client.get("/account/activity").data
        assert b"alice-only-detail" in body
        assert b"bob-only-detail" not in body

    def test_export_is_scoped_to_the_signed_in_user(self, client, alice, bob):
        audit("item_created", actor=alice, detail="alice-row")
        audit("item_created", actor=bob, detail="bob-row")

        login(client, "alice")
        response = client.get("/account/activity.csv")
        assert response.status_code == 200
        assert b"alice-row" in response.data
        assert b"bob-row" not in response.data

    def test_export_downloads_and_never_renders_inline(self, client, alice):
        login(client, "alice")
        response = client.get("/account/activity.csv")
        assert "attachment" in response.headers["Content-Disposition"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_activity_requires_authentication(self, client):
        assert client.get("/account/activity").status_code == 302
        assert client.get("/account/activity.csv").status_code == 302

    def test_unknown_action_filter_is_ignored_not_passed_through(self, client, alice):
        # The filter is checked against the known action set - an allowlist,
        # like every other user-chosen enum in the app.
        login(client, "alice")
        assert client.get("/account/activity?action=' OR 1=1 --").status_code == 200


class TestStatTiles:
    def test_every_stat_renders_as_a_number(self, client, alice, alice_item):
        """Guards a Jinja trap that fails silently.

        `counts.items` in a template resolves to dict.items - the built-in
        method - because attribute access is tried before subscript. The page
        then renders "<built-in method items of dict object...>" where a
        figure should be, with no error raised anywhere. Autoescaping made it
        harmless; it did not make it correct.
        """
        import re

        login(client, "alice")
        body = client.get("/account/").data.decode()
        values = re.findall(r'stat-num">([^<]*)</span>', body)

        assert len(values) == 4
        for value in values:
            assert value.strip().isdigit(), f"stat tile rendered {value!r}"

    def test_counts_reflect_reality(self, client, alice, alice_bin, alice_item):
        import re

        login(client, "alice")
        body = client.get("/account/").data.decode()
        values = [int(x) for x in re.findall(r'stat-num">(\d+)</span>', body)]
        assert values[0] >= 1   # locations
        assert values[1] >= 1   # items


class TestProfile:
    def test_profile_fields_save(self, client, alice):
        login(client, "alice")
        client.post("/account/", data={
            "display_name": "Sam Baker",
            "email": "sam@example.com",
            "timezone": "America/New_York",
        }, follow_redirects=True)

        db.session.refresh(alice)
        assert alice.display_name == "Sam Baker"
        assert alice.label == "Sam Baker"

    def test_profile_is_entirely_optional(self, client, alice):
        """None of it is required to use the system.

        Data that is not collected cannot leak, so the form must accept being
        left blank rather than forcing an email address on someone.
        """
        login(client, "alice")
        response = client.post("/account/", data={
            "display_name": "", "email": "", "timezone": "",
        }, follow_redirects=True)
        assert response.status_code == 200

        db.session.refresh(alice)
        assert alice.display_name is None
        assert alice.email is None
        assert alice.label == "alice"

    def test_cannot_set_privileged_fields_through_the_profile_form(self, client, alice):
        login(client, "alice")
        original_version = alice.session_version

        client.post("/account/", data={
            "display_name": "Sam",
            "session_version": 999,     # ignored
            "is_active": "false",       # ignored
            "password_hash": "x",       # ignored
        }, follow_redirects=True)

        db.session.refresh(alice)
        assert alice.session_version == original_version
        assert alice.is_active_flag is True
        assert alice.password_hash != "x"
