"""Checkout and return."""

from __future__ import annotations

from datetime import date, timedelta

from conftest import login, sync
from doom.extensions import db
from doom.models import Checkout, Item, Location, utcnow


def _checkout(client, item, holder="Sam Baker", qty=1, **extra):
    data = {"holder_name": holder, "quantity": qty}
    data.update(extra)
    return client.post(f"/items/{item.id}/checkout", data=data, follow_redirects=True)


class TestCheckout:
    def test_checkout_records_custody_without_moving_the_item(
        self, client, alice, alice_bin, alice_item
    ):
        """Custody is not location.

        A signed-out item still belongs in its bin - that is where it returns
        to. Overwriting location_id would lose the answer to "where does this
        live", which is the question the whole application exists to answer.
        """
        login(client, "alice")
        _checkout(client, alice_item, qty=2)

        sync()
        assert alice_item.location_id == alice_bin.id      # unchanged
        assert alice_item.quantity == 3                    # still owned
        assert alice_item.quantity_out == 2
        assert alice_item.quantity_available == 1

    def test_cannot_check_out_more_than_available(self, client, alice, alice_item):
        login(client, "alice")
        response = _checkout(client, alice_item, qty=99)

        assert b"available" in response.data
        sync()
        assert alice_item.quantity_out == 0

    def test_cannot_oversubscribe_across_two_checkouts(self, client, alice, alice_item):
        login(client, "alice")
        _checkout(client, alice_item, holder="First", qty=2)
        response = _checkout(client, alice_item, holder="Second", qty=2)

        assert b"already checked out" in response.data
        sync()
        assert alice_item.quantity_out == 2

    def test_quantity_must_be_positive(self, client, alice, alice_item):
        login(client, "alice")
        _checkout(client, alice_item, qty=0)
        _checkout(client, alice_item, qty=-5)

        sync()
        assert alice_item.quantity_out == 0

    def test_absurd_due_date_rejected(self, client, alice, alice_item):
        login(client, "alice")
        far = (date.today() + timedelta(days=40_000)).isoformat()
        _checkout(client, alice_item, due_back_at=far)

        sync()
        assert alice_item.quantity_out == 0

    def test_another_user_cannot_check_out_your_item(self, client, alice, bob, alice_item):
        login(client, "bob")
        response = client.post(
            f"/items/{alice_item.id}/checkout",
            data={"holder_name": "Mallory", "quantity": 1},
        )
        assert response.status_code == 404

        sync()
        assert alice_item.quantity_out == 0


class TestReturn:
    def test_return_restores_availability(self, client, alice, alice_item):
        login(client, "alice")
        _checkout(client, alice_item, qty=2)

        record = db.session.query(Checkout).filter_by(item_id=alice_item.id).one()
        client.post(
            f"/items/{alice_item.id}/return/{record.id}", follow_redirects=True
        )

        sync()
        assert alice_item.quantity_out == 0
        assert alice_item.quantity_available == 3

    def test_closed_checkout_is_kept_as_evidence(self, client, alice, alice_item):
        """A returned checkout is a record, not garbage to delete (T-16)."""
        login(client, "alice")
        _checkout(client, alice_item)
        record = db.session.query(Checkout).filter_by(item_id=alice_item.id).one()
        client.post(f"/items/{alice_item.id}/return/{record.id}", follow_redirects=True)

        sync()
        assert record.returned_at is not None
        assert db.session.query(Checkout).count() == 1

    def test_returning_twice_is_a_404(self, client, alice, alice_item):
        login(client, "alice")
        _checkout(client, alice_item)
        record = db.session.query(Checkout).filter_by(item_id=alice_item.id).one()

        client.post(f"/items/{alice_item.id}/return/{record.id}", follow_redirects=True)
        again = client.post(f"/items/{alice_item.id}/return/{record.id}")
        assert again.status_code == 404

    def test_another_user_cannot_return_your_checkout(
        self, client, alice, bob, alice_item
    ):
        login(client, "alice")
        _checkout(client, alice_item)
        record = db.session.query(Checkout).filter_by(item_id=alice_item.id).one()

        login(client, "bob")
        response = client.post(f"/items/{alice_item.id}/return/{record.id}")
        assert response.status_code == 404

        sync()
        assert record.returned_at is None

    def test_return_puts_the_item_back_where_it_came_from(
        self, client, alice, alice_bin, alice_item
    ):
        elsewhere = Location(owner_id=alice.id, kind="zone", name="Van", depth=0)
        db.session.add(elsewhere)
        db.session.commit()

        login(client, "alice")
        _checkout(client, alice_item)
        record = db.session.query(Checkout).filter_by(item_id=alice_item.id).one()

        alice_item.location_id = elsewhere.id
        db.session.commit()

        client.post(f"/items/{alice_item.id}/return/{record.id}", follow_redirects=True)
        sync()
        assert alice_item.location_id == alice_bin.id


class TestOverdue:
    def test_overdue_only_while_outstanding(self, alice, alice_item):
        record = Checkout(
            item_id=alice_item.id, holder_name="Sam", quantity=1,
            due_back_at=utcnow() - timedelta(days=1),
        )
        db.session.add(record)
        db.session.commit()
        assert record.is_overdue

        record.returned_at = utcnow()
        db.session.commit()
        assert not record.is_overdue
