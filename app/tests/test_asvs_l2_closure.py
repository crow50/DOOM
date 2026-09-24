"""Acceptance tests for the ASVS 5.0 Level 2 controls closed in this review.

Cited by line from ``docs/security/asvs-5.0.0.json``. The same rule applies
here as at Level 1: a requirement is Met when something fails if the control
is removed, not when a document says it is there.
"""

from __future__ import annotations

import io
import json
import logging

import pytest
from conftest import login
from doom import validation as v
from doom.extensions import db
from doom.models import UserSession, User, utcnow


def _sessions(user, *, live=True):
    query = db.select(UserSession).where(UserSession.user_id == user.id)
    if live:
        query = query.where(UserSession.revoked_at.is_(None))
    return db.session.execute(query).scalars().all()


# ---------------------------------------------------------------------------
# V7.3.1 - inactivity timeout
# ---------------------------------------------------------------------------

class TestInactivityTimeout:
    def test_an_idle_session_stops_working(self, client, alice):
        import datetime

        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=v.SESSION_IDLE_MINUTES + 1
        )
        db.session.commit()

        response = client.get("/locations/")
        assert response.status_code == 302
        assert b"Cordless drill" not in response.data

    def test_the_idle_session_is_revoked_rather_than_merely_refused(
        self, client, alice
    ):
        """A refusal that leaves the row live is retryable; this is not."""
        import datetime

        login(client, "alice")
        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=v.SESSION_IDLE_MINUTES + 1
        )
        db.session.commit()

        client.get("/locations/")
        db.session.expire_all()
        assert _sessions(alice, live=True) == []

    def test_activity_inside_the_window_keeps_the_session(self, client, alice):
        import datetime

        login(client, "alice")
        record = _sessions(alice)[0]
        record.last_seen_at = utcnow() - datetime.timedelta(
            minutes=max(v.SESSION_IDLE_MINUTES - 5, 1)
        )
        db.session.commit()

        assert client.get("/locations/").status_code == 200


# ---------------------------------------------------------------------------
# V7.1.2 - a documented concurrent-session limit, enforced
# ---------------------------------------------------------------------------

class TestConcurrentSessionLimit:
    def test_the_limit_holds_however_many_times_you_sign_in(self, app, alice):
        for _ in range(v.MAX_CONCURRENT_SESSIONS + 4):
            login(app.test_client(), "alice")
            db.session.expire_all()

        assert len(_sessions(alice)) <= v.MAX_CONCURRENT_SESSIONS

    def test_the_least_recently_used_session_is_the_one_that_goes(
        self, app, alice
    ):
        import datetime

        first = app.test_client()
        login(first, "alice")
        db.session.expire_all()
        oldest = _sessions(alice)[0]
        oldest.last_seen_at = utcnow() - datetime.timedelta(days=30)
        db.session.commit()
        oldest_id = oldest.id

        for _ in range(v.MAX_CONCURRENT_SESSIONS):
            login(app.test_client(), "alice")
            db.session.expire_all()

        assert db.session.get(UserSession, oldest_id).revoked_at is not None

    def test_a_revoked_session_cannot_be_used_afterwards(self, app, alice):
        evicted = app.test_client()
        login(evicted, "alice")
        assert evicted.get("/locations/").status_code == 200

        for _ in range(v.MAX_CONCURRENT_SESSIONS):
            login(app.test_client(), "alice")

        assert evicted.get("/locations/").status_code == 302


# ---------------------------------------------------------------------------
# V6.1.2 / V6.2.11 - a documented context-specific word list, used
# ---------------------------------------------------------------------------

class TestContextWordScreen:
    def test_the_list_is_not_empty_and_names_this_application(self):
        assert v.CONTEXT_WORDS
        assert "doom" in v.CONTEXT_WORDS

    @pytest.mark.parametrize("candidate", [
        "doominventory2026",
        "MyWarehousePassphrase",
        "correct-horse-STORAGE-battery",
    ])
    def test_a_context_word_is_refused_however_it_is_cased(self, candidate):
        from doom.security.passwords import PasswordPolicyError, check_policy

        with pytest.raises(PasswordPolicyError):
            check_policy(candidate)

    def test_an_unrelated_passphrase_is_still_accepted(self):
        from doom.security.passwords import check_policy

        check_policy("relentless-kettle-mango-ribbon")

    def test_registration_refuses_a_context_word(self, client):
        response = client.post("/register", data={
            "username": "newcomer",
            "password": "doom-inventory-passphrase",
            "confirm": "doom-inventory-passphrase",
        })
        assert response.status_code == 200
        assert db.session.query(User).filter_by(username="newcomer").count() == 0


# ---------------------------------------------------------------------------
# V5.2.4 - a file count quota as well as a byte quota
# ---------------------------------------------------------------------------

class TestFileCountQuota:
    def test_the_count_ceiling_is_enforced_independently_of_the_byte_ceiling(
        self, alice, alice_bin, monkeypatch
    ):
        from doom.models import Attachment
        from doom.security.uploads import UploadRejected, check_quota

        monkeypatch.setattr(v, "MAX_ATTACHMENTS_PER_OWNER", 2)
        for index in range(2):
            db.session.add(Attachment(
                owner_id=alice.id, kind="document",
                stored_name=f"{index}.txt", original_name=f"{index}.txt",
                content_type="text/plain", byte_size=1, sha256=f"{index:064d}",
                location_id=alice_bin.id,
            ))
        db.session.commit()

        # Well inside the 2 GB byte quota, and refused anyway.
        with pytest.raises(UploadRejected) as raised:
            check_quota(alice.id, 1)
        assert "stored files" in str(raised.value)


# ---------------------------------------------------------------------------
# V16.2.5 - log according to the data's protection level
# ---------------------------------------------------------------------------

class TestLogMessageSanitisation:
    @staticmethod
    def _emit(message, **kwargs):
        from doom.security.logging import JsonFormatter

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname=__file__, lineno=1,
            msg=message, args=(), exc_info=kwargs.get("exc_info"),
        )
        return json.loads(JsonFormatter().format(record))

    def test_a_share_code_in_a_message_is_redacted(self):
        from doom.models import new_share_token

        token = new_share_token()
        payload = self._emit(f"could not resolve {token}")
        assert token not in payload["message"]
        assert "[redacted]" in payload["message"]

    @pytest.mark.parametrize("message", [
        "connect failed: password=hunter2trombone",
        "upstream said token: abc123def456",
        'header Authorization="Bearer sk-live-xyz"',
        "session_key = deadbeefcafe",
    ])
    def test_a_labelled_secret_in_a_message_is_redacted(self, message):
        payload = self._emit(message)
        for leaked in ("hunter2trombone", "abc123def456", "sk-live-xyz",
                       "deadbeefcafe"):
            assert leaked not in payload["message"]

    def test_an_exception_traceback_is_redacted_too(self):
        from doom.models import new_share_token

        token = new_share_token()
        try:
            raise RuntimeError(f"upstream rejected {token}")
        except RuntimeError:
            import sys

            payload = self._emit("request failed", exc_info=sys.exc_info())

        assert token not in payload["exception"]
        assert "RuntimeError" in payload["exception"]

    def test_an_ordinary_message_survives_intact(self):
        """A log nobody can read is replaced by a log nobody redacts."""
        payload = self._emit("upload_stored kind=photo bytes=20481")
        assert payload["message"] == "upload_stored kind=photo bytes=20481"
