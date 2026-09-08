"""The unified history shown on items and locations."""

from __future__ import annotations

from conftest import audit, login
from doom.extensions import db
from doom.models import Checkout, Location, Movement, new_share_token
from doom.timeline import item_timeline, location_timeline


class TestItemTimeline:
    def test_merges_movements_checkouts_and_audit(self, client, alice, alice_item):
        db.session.add_all([
            Movement(item_id=alice_item.id, actor_id=alice.id, delta_qty=2,
                     reason="restocked"),
            Checkout(item_id=alice_item.id, actor_id=alice.id,
                     holder_name="Sam Baker", quantity=1),
        ])
        db.session.commit()
        audit("upload_stored", actor=alice, object_type="item",
              object_id=str(alice_item.id), detail="1 file(s)")

        events = item_timeline(alice_item, alice.id)
        kinds = {e.kind for e in events}
        assert kinds == {"movement", "checkout", "audit"}

        summaries = " ".join(e.summary for e in events)
        assert "Sam Baker" in summaries
        assert "File uploaded" in summaries

    def test_newest_first(self, alice, alice_item):
        audit("item_created", actor=alice, object_type="item",
              object_id=str(alice_item.id))
        audit("item_updated", actor=alice, object_type="item",
              object_id=str(alice_item.id))

        events = item_timeline(alice_item, alice.id)
        assert [e.at for e in events] == sorted(
            (e.at for e in events), reverse=True
        )

    def test_anonymous_share_view_is_flagged_and_keeps_its_ip(self, alice, alice_item):
        """The event an owner most needs to see.

        A shared link being opened has no signed-in actor, so it would be
        invisible if the timeline only showed events with one.
        """
        audit("share_viewed", object_type="item",
              object_id=str(alice_item.id), ip="203.0.113.9")

        events = item_timeline(alice_item, alice.id)
        anon = [e for e in events if e.anonymous]
        assert len(anon) == 1
        assert anon[0].ip == "203.0.113.9"
        assert "Shared link opened" in anon[0].summary

    def test_does_not_double_count_movement_backed_audit_rows(self, alice, alice_item):
        db.session.add(Movement(item_id=alice_item.id, actor_id=alice.id,
                                delta_qty=1))
        db.session.commit()
        audit("item_quantity_adjusted", actor=alice, object_type="item",
              object_id=str(alice_item.id))

        events = item_timeline(alice_item, alice.id)
        assert len(events) == 1

    def test_only_this_object(self, alice, alice_item):
        audit("item_updated", actor=alice, object_type="item",
              object_id="00000000-0000-0000-0000-000000000000",
              detail="a different item")

        events = item_timeline(alice_item, alice.id)
        assert all("different item" != e.detail for e in events)


class TestLocationTimeline:
    def test_shows_what_moved_through(self, alice, alice_bin, alice_item):
        db.session.add(Movement(
            item_id=alice_item.id, actor_id=alice.id,
            to_location_id=alice_bin.id, delta_qty=1, reason="filed",
        ))
        db.session.commit()

        events = location_timeline(alice_bin, alice.id)
        assert any("moved in" in e.summary for e in events)
        assert any(alice_item.name in e.summary for e in events)

    def test_shows_checkouts_taken_from_here(self, alice, alice_bin, alice_item):
        db.session.add(Checkout(
            item_id=alice_item.id, actor_id=alice.id, holder_name="Crew 2",
            quantity=1, from_location_id=alice_bin.id,
        ))
        db.session.commit()

        events = location_timeline(alice_bin, alice.id)
        assert any("Crew 2" in e.summary for e in events)

    def test_shows_its_own_audit_events(self, alice, alice_bin):
        audit("share_updated", actor=alice, object_type="location",
              object_id=str(alice_bin.id), detail="shared")

        events = location_timeline(alice_bin, alice.id)
        assert any("Sharing settings changed" in e.summary for e in events)


class TestRendered:
    def test_item_page_renders_history(self, client, alice, alice_item):
        audit("item_created", actor=alice, object_type="item",
              object_id=str(alice_item.id))

        login(client, "alice")
        body = client.get(f"/items/{alice_item.id}").data
        assert b"Item created" in body

    def test_location_page_renders_history(self, client, alice, alice_bin):
        audit("location_created", actor=alice, object_type="location",
              object_id=str(alice_bin.id))

        login(client, "alice")
        body = client.get(f"/locations/{alice_bin.id}").data
        assert b"Location created" in body

    def test_history_is_not_exposed_on_a_shared_page(self, client, alice, alice_bin):
        """Timestamps of visits describe when a place is occupied.

        The public serializer omits history entirely (T-20).
        """
        audit("location_updated", actor=alice, object_type="location",
              object_id=str(alice_bin.id), detail="renamed-marker")
        alice_bin.visibility = "shared"
        alice_bin.share_token = new_share_token()
        db.session.commit()

        response = client.get(f"/t/{alice_bin.share_token}")
        assert response.status_code == 200
        assert b"renamed-marker" not in response.data
        assert b"History" not in response.data
