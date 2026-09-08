"""Frictionless capture, storage limits, and search scoping."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from conftest import login
from doom import validation as v
from doom.extensions import db
from doom.models import Attachment, Item, Location, Movement


def _jpeg(colour=(120, 80, 40), size=(320, 240)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, colour).save(buffer, format="JPEG")
    return buffer.getvalue()


class TestQuickCapture:
    def test_photo_alone_is_enough(self, client, alice):
        """The whole premise: a decision is not required to record something."""
        login(client, "alice")
        client.post("/items/quick", data={
            "file": (io.BytesIO(_jpeg()), "shelf.jpg"),
        }, content_type="multipart/form-data", follow_redirects=True)

        item = db.session.query(Item).filter_by(owner_id=alice.id).one()
        assert item.name is None
        assert item.primary_photo is not None
        assert "Unnamed" in item.display_name

    def test_name_alone_is_enough(self, client, alice):
        login(client, "alice")
        client.post("/items/quick", data={"name": "Blue tote"},
                    follow_redirects=True)

        item = db.session.query(Item).filter_by(owner_id=alice.id).one()
        assert item.name == "Blue tote"
        assert item.location_id is None      # unfiled is a resting state

    def test_neither_is_refused(self, client, alice):
        """The one deliberately application-level rule.

        No single CHECK can see both the name column and the attachments
        table, so this invariant cannot live in the database.
        """
        login(client, "alice")
        response = client.post("/items/quick", data={"name": ""},
                               follow_redirects=True)

        assert db.session.query(Item).count() == 0
        assert b"photo or a name" in response.data

    def test_capture_still_records_movement_and_audit(self, client, alice):
        from doom.models import AuditLog

        login(client, "alice")
        client.post("/items/quick", data={"name": "Thing"}, follow_redirects=True)

        item = db.session.query(Item).one()
        assert db.session.query(Movement).filter_by(item_id=item.id).count() == 1
        assert db.session.query(AuditLog).filter_by(
            object_id=str(item.id), action="item_created"
        ).count() == 1

    def test_uploads_go_through_the_same_validation(self, client, alice):
        """No second ingestion path — the sniff and re-encode still apply."""
        login(client, "alice")
        client.post("/items/quick", data={
            "name": "Nice try",
            "file": (io.BytesIO(b"#!/bin/sh\necho no\n"), "photo.jpg"),
        }, content_type="multipart/form-data", follow_redirects=True)

        assert db.session.query(Attachment).count() == 0


class TestDisplayName:
    def test_named_item_uses_its_name(self, alice):
        item = Item(owner_id=alice.id, name="Drill", quantity=1)
        db.session.add(item)
        db.session.commit()
        assert item.display_name == "Drill"

    def test_display_name_is_presentation_only(self, client, alice, bob):
        """It never participates in a lookup (T-43)."""
        item = Item(owner_id=alice.id, quantity=1)
        db.session.add(item)
        db.session.commit()

        login(client, "bob")
        assert client.get(f"/items/{item.id}").status_code == 404


class TestStorageQuota:
    def test_identical_files_are_stored_once(self, client, alice, tmp_path):
        """Dedup on the sha256 that was already being computed and ignored."""
        login(client, "alice")
        payload = _jpeg()

        for name in ("first.jpg", "second.jpg"):
            client.post("/items/quick", data={
                "name": name, "file": (io.BytesIO(payload), name),
            }, content_type="multipart/form-data", follow_redirects=True)

        rows = db.session.query(Attachment).all()
        assert len(rows) == 2
        assert rows[0].stored_name == rows[1].stored_name   # one blob
        assert rows[0].original_name != rows[1].original_name

    def test_dedup_is_scoped_per_owner(self, client, alice, bob):
        """Never global.

        A shared blob would leak that two accounts hold an identical file, and
        make deletion behaviour an oracle for it (T-47).
        """
        payload = _jpeg()

        login(client, "alice")
        client.post("/items/quick", data={
            "name": "a", "file": (io.BytesIO(payload), "a.jpg"),
        }, content_type="multipart/form-data", follow_redirects=True)

        login(client, "bob")
        client.post("/items/quick", data={
            "name": "b", "file": (io.BytesIO(payload), "b.jpg"),
        }, content_type="multipart/form-data", follow_redirects=True)

        alice_row = db.session.query(Attachment).filter_by(owner_id=alice.id).one()
        bob_row = db.session.query(Attachment).filter_by(owner_id=bob.id).one()
        assert alice_row.sha256 == bob_row.sha256
        assert alice_row.stored_name != bob_row.stored_name

    def test_quota_refuses_before_writing(self, client, alice, monkeypatch):
        from doom.security import uploads

        monkeypatch.setattr(uploads.v, "STORAGE_QUOTA_BYTES", 1)
        login(client, "alice")
        response = client.post("/items/quick", data={
            "name": "too big", "file": (io.BytesIO(_jpeg()), "big.jpg"),
        }, content_type="multipart/form-data", follow_redirects=True)

        assert db.session.query(Attachment).count() == 0
        assert b"storage limit" in response.data


class TestSearchScoping:
    def test_finds_items_by_description(self, client, alice):
        db.session.add(Item(owner_id=alice.id, name="Drill",
                            description="18V cordless with two batteries",
                            quantity=1))
        db.session.commit()

        login(client, "alice")
        assert b"Drill" in client.get("/search?q=cordless").data

    def test_finds_locations_by_notes(self, client, alice):
        db.session.add(Location(owner_id=alice.id, kind="bin", name="Tote 9",
                                notes="winter gear and boots", depth=0))
        db.session.commit()

        login(client, "alice")
        assert b"Tote 9" in client.get("/search?q=boots").data

    def test_owner_can_search_their_own_address(self, client, alice):
        db.session.add(Location(owner_id=alice.id, kind="site", name="Yard",
                                address="12 Elm Street", depth=0))
        db.session.commit()

        login(client, "alice")
        assert b"Yard" in client.get("/search?q=Elm").data

    def test_never_returns_another_account_items(self, client, alice, bob):
        db.session.add(Item(owner_id=bob.id, name="Bob's crowbar",
                            description="distinctive marker", quantity=1))
        db.session.commit()

        login(client, "alice")
        body = client.get("/search?q=distinctive").data
        assert b"crowbar" not in body

    def test_never_returns_another_account_locations_or_addresses(
        self, client, alice, bob
    ):
        """Locations carry addresses, so widening scope here is the worst case."""
        db.session.add(Location(owner_id=bob.id, kind="site", name="Bob's Yard",
                                address="99 Secret Lane", depth=0))
        db.session.commit()

        login(client, "alice")
        body = client.get("/search?q=Secret").data
        assert b"Secret Lane" not in body
        assert b"Bob's Yard" not in body

    def test_wildcards_are_literal(self, client, alice):
        db.session.add_all([
            Item(owner_id=alice.id, name="100% cotton", quantity=1),
            Item(owner_id=alice.id, name="Unrelated thing", quantity=1),
        ])
        db.session.commit()

        login(client, "alice")
        body = client.get("/search?q=100%25").data
        assert b"Unrelated thing" not in body

    def test_requires_authentication(self, client):
        assert client.get("/search?q=anything").status_code == 302
