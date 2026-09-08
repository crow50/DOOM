"""Broken Access Control - the boundary that matters most here.

The catalogue is a map to physical property, so cross-account disclosure is
the highest-impact failure in the system.
"""

from __future__ import annotations

from conftest import login


class TestHorizontalIsolation:
    def test_owner_can_read_own_item(self, client, alice, alice_item):
        login(client, "alice")
        assert client.get(f"/items/{alice_item.id}").status_code == 200

    def test_other_user_gets_404_not_403(self, client, alice, bob, alice_item):
        """404, never 403.

        A 403 means "this exists and belongs to someone else", which confirms
        the very fact being protected. 404 is indistinguishable from a
        nonexistent id, so probing yields nothing (T-18).
        """
        login(client, "bob")
        assert client.get(f"/items/{alice_item.id}").status_code == 404

    def test_other_user_cannot_read_location(self, client, alice, bob, alice_bin):
        login(client, "bob")
        assert client.get(f"/locations/{alice_bin.id}").status_code == 404

    def test_other_user_cannot_edit(self, client, alice, bob, alice_item):
        login(client, "bob")
        assert client.get(f"/items/{alice_item.id}/edit").status_code == 404

    def test_malformed_id_also_404s(self, client, bob):
        """A garbage id takes the same path as an unowned one.

        If a malformed UUID produced a 400 while an unowned one produced a
        404, the difference would confirm that the unowned id was at least
        well-formed and real.
        """
        login(client, "bob")
        assert client.get("/items/not-a-uuid").status_code == 404

    def test_anonymous_is_redirected_to_login(self, client, alice_item):
        response = client.get(f"/items/{alice_item.id}")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


class TestCrossAccountWrite:
    def test_cannot_move_own_item_into_another_users_bin(
        self, client, alice, bob, alice_bin
    ):
        """Both ends of a move are checked.

        Validating only the item would let a user write into someone else's
        tree - Broken Access Control even though the row being moved is
        legitimately theirs.
        """
        from doom.extensions import db
        from doom.models import Item

        bobs_item = Item(owner_id=bob.id, name="Bob's hammer", quantity=1)
        db.session.add(bobs_item)
        db.session.commit()

        login(client, "bob")
        response = client.post(
            f"/items/{bobs_item.id}/move",
            data={"location_id": str(alice_bin.id)},
            follow_redirects=False,
        )
        # The destination is not in bob's choice list, so the form rejects it.
        assert response.status_code in (302, 404)

        db.session.refresh(bobs_item)
        assert bobs_item.location_id is None


class TestMassAssignment:
    def test_cannot_set_owner_or_visibility_through_the_form(self, client, alice, bob):
        """Extra form fields have nothing to bind to (T-10).

        Objects are built field by field from a validated form, never by
        splatting request.form, so an injected owner_id is simply not read.
        """
        from doom.extensions import db
        from doom.models import Item

        login(client, "alice")
        client.post(
            "/items/new",
            data={
                "name": "Injected item",
                "quantity": 1,
                "owner_id": str(bob.id),      # ignored
                "visibility": "shared",       # ignored
                "share_token": "attacker-chosen-token",  # ignored
            },
            follow_redirects=True,
        )

        item = db.session.query(Item).filter_by(name="Injected item").one()
        assert item.owner_id == alice.id
        assert item.visibility == "private"
        assert item.share_token is None
