"""Location taxonomy, item placement, and the address field."""

from __future__ import annotations

import pytest

from conftest import login
from doom import validation as v
from doom.extensions import db
from doom.models import Item, Location, new_share_token
from doom.security.serializers import public_location


class TestTaxonomy:
    def test_four_distinct_kinds(self):
        assert v.LOCATION_KINDS == ("site", "zone", "shelf", "bin")

    def test_every_kind_has_a_description_shown_to_the_user(self):
        # A distinction the interface never explains is not a distinction.
        for kind in v.LOCATION_KINDS:
            assert v.LOCATION_KIND_DESCRIPTIONS.get(kind)
            assert v.LOCATION_KIND_LABELS.get(kind)

    def test_any_location_can_hold_items(self, alice):
        """The old ITEM_BEARING_KINDS rule is gone.

        It restricted items to shelves, bins and totes - never explained in
        the UI, and its only visible effect was an empty dropdown.
        """
        for kind in v.LOCATION_KINDS:
            node = Location(owner_id=alice.id, kind=kind, name=f"a {kind}", depth=0)
            assert node.can_hold_items

    def test_item_location_dropdown_offers_every_owned_location(self, client, alice):
        for kind in v.LOCATION_KINDS:
            db.session.add(
                Location(owner_id=alice.id, kind=kind, name=f"My {kind}", depth=0)
            )
        db.session.commit()

        login(client, "alice")
        body = client.get("/items/new").data
        for kind in v.LOCATION_KINDS:
            assert f"My {kind}".encode() in body

    def test_item_can_be_placed_in_a_zone(self, client, alice):
        """The exact case that was broken: a site and a zone, no bin."""
        zone = Location(owner_id=alice.id, kind="zone", name="Shed", depth=0)
        db.session.add(zone)
        db.session.commit()

        login(client, "alice")
        client.post("/items/new", data={
            "name": "Ride-on mower", "quantity": 1, "location_id": str(zone.id),
        }, follow_redirects=True)

        item = db.session.query(Item).filter_by(name="Ride-on mower").one()
        assert item.location_id == zone.id


class TestAddress:
    """The address is the most sensitive field in the schema.

    Everything else records what someone owns. This records where to drive to
    take it, so it must never appear on a page a stranger can open (T-37).
    """

    def test_address_absent_from_public_serializer(self, alice):
        site = Location(
            owner_id=alice.id, kind="site", name="Home",
            address="12 Elm Street, Springfield", depth=0,
        )
        db.session.add(site)
        db.session.commit()

        model = public_location(site, items=[], attachments=[], links=[])
        assert "address" not in model
        assert "Elm Street" not in str(model)

    def test_address_never_rendered_on_a_shared_page(self, client, alice):
        site = Location(
            owner_id=alice.id, kind="site", name="Home",
            address="12 Elm Street, Springfield", depth=0,
            visibility="shared", share_token=new_share_token(),
        )
        db.session.add(site)
        db.session.commit()

        response = client.get(f"/t/{site.share_token}")
        assert response.status_code == 200
        assert b"Elm Street" not in response.data
        assert b"Springfield" not in response.data

    def test_address_visible_to_the_owner(self, client, alice):
        site = Location(
            owner_id=alice.id, kind="site", name="Home",
            address="12 Elm Street, Springfield", depth=0,
        )
        db.session.add(site)
        db.session.commit()

        login(client, "alice")
        assert b"Elm Street" in client.get(f"/locations/{site.id}").data

    def test_address_rejected_on_a_non_site(self, client, alice):
        """Storing sensitive data where it serves no purpose is avoidable."""
        login(client, "alice")
        client.post("/locations/new", data={
            "name": "A bin", "kind": "bin",
            "address": "12 Elm Street", "parent_id": "",
        }, follow_redirects=True)

        node = db.session.query(Location).filter_by(name="A bin").first()
        assert node is None or node.address is None


class TestRedirects:
    def test_authenticated_root_goes_to_the_app_not_the_signup_page(
        self, client, alice
    ):
        login(client, "alice")
        response = client.get("/")
        assert response.status_code == 302
        assert "/locations/" in response.headers["Location"]

    def test_anonymous_root_still_shows_the_landing_page(self, client):
        assert client.get("/").status_code == 200


class TestSafeReferrer:
    """The 'back' link is built from the referrer, which is client-supplied.

    It is validated against the configured PUBLIC_BASE_URL rather than
    request.host, because a Host header can be steered by an attacker (T-14).
    """

    def test_offsite_referrers_fall_back(self, app):
        from doom.security.redirects import safe_referrer_path

        base = app.config["PUBLIC_BASE_URL"]
        host = base.split("://", 1)[1]

        offsite = [
            "https://evil.com/locations/",
            f"http://{host}/locations/",        # downgraded scheme
            f"https://{host}.evil.com/x",       # suffix trick
            None,                                # no referrer at all
        ]

        for referrer in offsite:
            headers = {"Referer": referrer} if referrer else {}
            with app.test_request_context("/labels/sheet", headers=headers):
                assert safe_referrer_path() == "/locations/", referrer

    def test_same_origin_referrer_is_used(self, app):
        from doom.security.redirects import safe_referrer_path

        base = app.config["PUBLIC_BASE_URL"].rstrip("/")
        with app.test_request_context(
            "/labels/sheet",
            headers={"Referer": f"{base}/locations/abc?x=1"},
        ):
            assert safe_referrer_path() == "/locations/abc?x=1"
