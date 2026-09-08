"""Tamper-evidence of the audit trail.

The chain's value is that *silent selective editing* becomes detectable —
quietly removing the row that recorded an inconvenient action. These tests
assert exactly that, and are careful not to overclaim: the chain does not stop
someone who can recompute it, and one test says so explicitly.
"""

from __future__ import annotations

from conftest import audit
from doom.extensions import db
from doom.models import GENESIS_HASH, AuditLog
from doom.security.audit import chain_head_hash, verify_chain


def _rows():
    return db.session.execute(
        db.select(AuditLog).order_by(AuditLog.seq)
    ).scalars().all()


class TestChainConstruction:
    def test_first_row_starts_from_genesis(self, alice):
        audit("item_created", actor=alice)
        first = _rows()[0]
        assert first.seq == 1
        assert first.prev_hash == GENESIS_HASH

    def test_each_row_links_to_the_one_before(self, alice):
        for i in range(4):
            audit("item_created", actor=alice, detail=f"row {i}")

        rows = _rows()
        for previous, current in zip(rows, rows[1:]):
            assert current.prev_hash == previous.row_hash
            assert current.seq == previous.seq + 1

    def test_actor_username_is_denormalised(self, alice):
        """The trail must outlive the account it describes."""
        audit("item_created", actor=alice)
        assert _rows()[-1].actor_username == "alice"

    def test_audit_log_has_no_foreign_key_to_users(self):
        """A cascade would be an UPDATE on an append-only table.

        It is also wrong on its own terms: deleting a user must not rewrite
        what they did.
        """
        assert AuditLog.__table__.foreign_keys == set()

    def test_verification_passes_on_an_untouched_chain(self, alice):
        audit("item_created", actor=alice)
        audit("item_updated", actor=alice)

        result = verify_chain()
        assert result["ok"] is True
        assert result["problem"] is None
        assert result["head"] == chain_head_hash()


class TestTamperDetection:
    def test_editing_a_row_is_detected(self, alice):
        audit("item_created", actor=alice, detail="original")
        audit("item_updated", actor=alice)

        target = _rows()[0]
        target.detail = "quietly changed"
        db.session.commit()

        result = verify_chain()
        assert result["ok"] is False
        assert "content altered" in result["problem"]

    def test_deleting_a_row_is_detected(self, alice):
        for i in range(3):
            audit("item_created", actor=alice, detail=f"row {i}")

        db.session.delete(_rows()[1])
        db.session.commit()

        result = verify_chain()
        assert result["ok"] is False
        assert "sequence break" in result["problem"]

    def test_appending_a_forged_row_is_detected(self, alice):
        """The realistic case once UPDATE and DELETE are revoked.

        An attacker limited to INSERT can still add rows — but not ones that
        link correctly, because they would have to match the running hash.
        """
        audit("item_created", actor=alice)

        head = _rows()[-1]
        db.session.add(AuditLog(
            action="something_that_never_happened",
            seq=head.seq + 1,
            prev_hash="0" * 64,          # not the real predecessor
            row_hash="f" * 64,
            created_at=head.created_at,
        ))
        db.session.commit()

        result = verify_chain()
        assert result["ok"] is False
        assert "broken link" in result["problem"]

    def test_rewriting_the_whole_chain_is_NOT_detected(self, alice):
        """Stating the limit, so the claim stays honest.

        Someone with database write access *and* the source can recompute every
        hash. The protection is tamper-evident, not tamper-proof; an externally
        recorded head hash is what closes this, which is why the account page
        shows one.
        """
        audit("item_created", actor=alice, detail="original")
        audit("item_updated", actor=alice)

        rows = _rows()
        rows[0].detail = "rewritten"

        previous = GENESIS_HASH
        for row in rows:
            row.prev_hash = previous
            row.row_hash = row.compute_hash()
            previous = row.row_hash
        db.session.commit()

        # Verification passes. That is the point of the test.
        assert verify_chain()["ok"] is True


class TestOrdering:
    def test_chain_survives_many_sequential_appends(self, alice):
        for i in range(25):
            audit("item_updated", actor=alice, detail=str(i))

        result = verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 25
