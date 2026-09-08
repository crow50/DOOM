"""Public sharing: the reduced view, and what must never appear in it."""

from __future__ import annotations

from conftest import login
from doom.extensions import db
from doom.models import Item, Location, new_share_token
from doom.security.serializers import public_item, public_location


def _share(node) -> str:
    node.share_token = new_share_token()
    node.visibility = "shared"
    db.session.commit()
    return node.share_token


class TestSerializerOmissions:
    """The control is absence, not filtering.

    A template guard can be forgotten and fails silently. A field that was
    never put into the view model cannot be rendered by mistake (T-20).
    """

    def test_item_view_model_has_no_owner_or_location(self, alice_item):
        model = public_item(alice_item, attachments=[], links=[])
        assert "owner" not in model
        assert "owner_id" not in model
        assert "location" not in model
        assert "location_id" not in model

    def test_location_view_model_has_no_ancestors(self, alice_bin):
        """The parent chain is the physical address.

        A shared tote may say what is inside it. It must never say which
        warehouse - and therefore which building - it stands in.
        """
        model = public_location(alice_bin, items=[], attachments=[], links=[])
        assert "parent" not in model
        assert "parent_id" not in model
        assert "ancestors" not in model
        assert "owner" not in model

    def test_location_view_model_has_no_movement_history(self, alice_bin):
        # Timestamps of visits describe when a location is occupied, and
        # therefore when it is not.
        model = public_location(alice_bin, items=[], attachments=[], links=[])
        assert "movements" not in model

    def test_child_link_only_present_when_child_is_itself_shared(self, alice, alice_bin):
        shared = Item(owner_id=alice.id, location_id=alice_bin.id, name="Shared drill",
                      quantity=1, visibility="shared", share_token=new_share_token())
        private = Item(owner_id=alice.id, location_id=alice_bin.id, name="Private safe",
                       quantity=1)
        db.session.add_all([shared, private])
        db.session.commit()

        model = public_location(
            alice_bin, items=[shared, private], attachments=[], links=[]
        )
        by_name = {entry["name"]: entry for entry in model["contents"]}

        # A parent's token never confers access to a child (T-36).
        assert by_name["Shared drill"]["share_token"] is not None
        assert by_name["Private safe"]["share_token"] is None


class TestShareRoutes:
    def test_private_node_token_does_not_resolve(self, client, alice_item):
        alice_item.share_token = new_share_token()
        alice_item.visibility = "private"
        db.session.commit()
        assert client.get(f"/t/{alice_item.share_token}").status_code == 404

    def test_shared_node_resolves_anonymously(self, client, alice_item):
        token = _share(alice_item)
        response = client.get(f"/t/{token}")
        assert response.status_code == 200
        assert b"Cordless drill" in response.data

    def test_share_page_carries_noindex(self, client, alice_item):
        """A leaked link must not become a search result (T-21)."""
        token = _share(alice_item)
        response = client.get(f"/t/{token}")
        assert "noindex" in response.headers.get("X-Robots-Tag", "")

    def test_share_page_does_not_leak_owner(self, client, alice, alice_item):
        token = _share(alice_item)
        response = client.get(f"/t/{token}")
        assert b"alice" not in response.data.lower()

    def test_shared_bin_does_not_leak_parent_chain(self, client, alice):
        warehouse = Location(owner_id=alice.id, kind="site",
                             name="Elm Street Warehouse",
                             address="12 Elm Street, Springfield", depth=0)
        db.session.add(warehouse)
        db.session.flush()
        tote = Location(owner_id=alice.id, parent_id=warehouse.id, kind="bin",
                        name="Tote 7", depth=1)
        db.session.add(tote)
        db.session.commit()

        token = _share(tote)
        response = client.get(f"/t/{token}")
        assert response.status_code == 200
        assert b"Tote 7" in response.data
        assert b"Elm Street Warehouse" not in response.data
        # And the address on that ancestor is doubly absent.
        assert b"Springfield" not in response.data

    def test_rotation_kills_the_old_link(self, client, alice_item):
        old = _share(alice_item)
        assert client.get(f"/t/{old}").status_code == 200

        alice_item.share_token = new_share_token()
        db.session.commit()
        assert client.get(f"/t/{old}").status_code == 404

    def test_no_public_index_route_exists(self, client):
        """There is nothing to enumerate.

        A listing route would turn one leaked token into a catalogue.
        """
        assert client.get("/t/").status_code in (404, 405)


class TestRobots:
    def test_robots_disallows_everything(self, client):
        response = client.get("/robots.txt")
        assert b"Disallow: /" in response.data
