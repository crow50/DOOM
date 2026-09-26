"""Controls added to reach ASVS Level 2."""

from __future__ import annotations

from conftest import login
from doom import validation as v
from doom.blueprints.auth import SESSION_ID_KEY
from doom.extensions import db
from doom.models import UserSession, utcnow


class TestAntiCaching:
    """ASVS 8.1.1, 8.2.1.

    Inventory pages are a map to physical property. "Someone pressed Back on a
    shared machine" is a real disclosure path, not a theoretical one.
    """

    def test_authenticated_responses_are_not_stored(self, client, alice):
        login(client, "alice")
        response = client.get("/locations/")
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers.get("Pragma") == "no-cache"

    def test_vary_on_cookie(self, client, alice):
        """Otherwise a shared cache could serve one user's page to another."""
        login(client, "alice")
        assert "Cookie" in client.get("/locations/").headers.get("Vary", "")

    def test_anonymous_pages_are_not_forced_to_no_store(self, client):
        # The login page holds nothing sensitive; forcing no-store everywhere
        # would be cargo-culting rather than a control.
        assert client.get("/login").headers.get("Cache-Control") != "no-store"

    def test_authenticated_json_is_not_stored(self, client, alice):
        login(client, "alice")
        response = client.get("/items/barcode/12345670")
        assert response.headers["Cache-Control"] == "no-store"


class TestAntiAutomation:
    """ASVS 11.1.4 — high-value flows, not just authentication.

    Rate limiting the login and leaving creation and upload open protects the
    front door and none of the windows.
    """

    def test_write_flows_carry_limits(self):
        assert v.WRITE_RATE_LIMIT
        assert v.UPLOAD_RATE_LIMIT

    def test_upload_limit_is_tighter_than_general_writes(self):
        # Uploads consume disk, so they are bounded harder than ordinary rows.
        upload_per_min = int(v.UPLOAD_RATE_LIMIT.split(" per minute")[0])
        write_per_min = int(v.WRITE_RATE_LIMIT.split(" per minute")[0])
        assert upload_per_min < write_per_min


class TestSessionManagement:
    """ASVS 3.3.4 — view and terminate active sessions."""

    def test_login_records_a_session(self, client, alice):
        login(client, "alice")
        rows = db.session.query(UserSession).filter_by(user_id=alice.id).all()
        assert len(rows) == 1
        assert rows[0].revoked_at is None

    def test_sessions_are_listed_on_the_account_page(self, client, alice):
        login(client, "alice")
        body = client.get("/account/").data
        assert b"Signed-in devices" in body
        assert b"this device" in body

    def test_revocation_requires_the_password(self, client, alice):
        """The reason re-authentication matters here.

        Ending sessions is exactly what someone holding a stolen cookie would
        want to do: lock the real owner out while keeping their own foothold.
        A stolen cookie alone must not be enough.
        """
        login(client, "alice")
        response = client.post("/account/sessions/revoke", data={
            "password": "wrong-but-long-enough", "session_id": "others",
        }, follow_redirects=True)

        assert b"password was not correct" in response.data
        assert db.session.query(UserSession).filter_by(
            user_id=alice.id, revoked_at=None
        ).count() == 1

    def test_revoked_session_is_refused_on_its_next_request(self, client, alice):
        """Immediately, not at next sign-in — otherwise it is not revocation."""
        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        row = db.session.query(UserSession).filter_by(user_id=alice.id).one()
        row.revoked_at = utcnow()
        db.session.commit()

        response = client.get("/locations/")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_cannot_revoke_another_users_session(self, client, alice, bob):
        """Scoped in the WHERE clause like every other lookup (T-18)."""
        login(client, "bob")
        bobs = db.session.query(UserSession).filter_by(user_id=bob.id).one()
        bobs_id = bobs.id

        login(client, "alice")
        client.post("/account/sessions/revoke", data={
            "password": "a-long-enough-passphrase",
            "session_id": str(bobs_id),
        }, follow_redirects=True)

        db.session.expire_all()
        assert db.session.get(UserSession, bobs_id).revoked_at is None

    def test_logout_marks_the_session_ended(self, client, alice):
        login(client, "alice")
        with client.session_transaction() as sess:
            session_id = sess[SESSION_ID_KEY]

        client.post("/logout", follow_redirects=True)

        db.session.expire_all()
        assert db.session.get(UserSession, session_id).revoked_at is not None


class TestSecretsFromFiles:
    """ASVS 6.4.1 — secrets read from files, never the environment."""

    def test_file_beats_environment(self, tmp_path, monkeypatch):
        from doom.config import _read_secret

        secret = tmp_path / "value"
        secret.write_text("from-the-file\n")

        monkeypatch.setenv("DOOM_TEST_SECRET", "from-the-environment")
        monkeypatch.setenv("DOOM_TEST_SECRET_FILE", str(secret))

        assert _read_secret("DOOM_TEST_SECRET") == "from-the-file"

    def test_unreadable_file_raises_rather_than_falling_back(self, monkeypatch):
        """Silent fallback would be the dangerous behaviour.

        A secret that quietly comes from somewhere other than where it was
        configured is worse than no secret: the operator believes the file is
        in use while the process runs on whatever was left in the environment.
        """
        import pytest

        from doom.config import ConfigError, _read_secret

        monkeypatch.setenv("DOOM_TEST_SECRET", "from-the-environment")
        monkeypatch.setenv("DOOM_TEST_SECRET_FILE", "/nonexistent/path")

        with pytest.raises(ConfigError, match="could not be read"):
            _read_secret("DOOM_TEST_SECRET")

    def test_environment_still_works_when_no_file_is_configured(self, monkeypatch):
        from doom.config import _read_secret

        monkeypatch.delenv("DOOM_TEST_SECRET_FILE", raising=False)
        monkeypatch.setenv("DOOM_TEST_SECRET", "plain-env")
        assert _read_secret("DOOM_TEST_SECRET") == "plain-env"


class TestDsnsAreAssembledInProcess:
    """ASVS 6.4.1 — the finished DSNs exist only inside the Python process.

    A shell entrypoint used to build them and ``export`` them before exec'ing
    gunicorn, which put both passwords into PID 1's environment and every
    worker's.  These pin the replacement: the URL is derived from the ``*_FILE``
    values, an explicit URL still wins (that is how the admin role reaches
    ``make upgrade``), and a placeholder password refuses to boot.
    """

    def test_database_url_is_built_from_the_password_file(self, tmp_path, monkeypatch):
        from doom.config import _database_url

        secret = tmp_path / "app_db_password"
        secret.write_text("f" * 64 + "\n")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("APP_DB_USER", "doom_app")
        monkeypatch.setenv("POSTGRES_DB", "doom")
        monkeypatch.setenv("APP_DB_PASSWORD_FILE", str(secret))

        assert _database_url() == (
            f"postgresql+psycopg://doom_app:{'f' * 64}@db:5432/doom"
            "?sslmode=verify-full&sslrootcert=/run/secrets/doom_internal_ca_cert"
        )

    def test_password_is_url_quoted(self, tmp_path, monkeypatch):
        """A password is data, not URL structure - it cannot add a host or a query."""
        from doom.config import _database_url

        secret = tmp_path / "app_db_password"
        secret.write_text("p@ss/word?with#odd:chars-and-length")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("APP_DB_PASSWORD_FILE", str(secret))

        url = _database_url()
        assert "@db:5432/" in url
        assert url.count("@") == 1
        assert "p%40ss%2Fword%3Fwith%23odd%3Achars" in url

    def test_explicit_url_wins(self, monkeypatch):
        from doom.config import _database_url, _redis_url

        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://admin:x@db/doom_test")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/9")
        monkeypatch.delenv("APP_DB_PASSWORD_FILE", raising=False)
        monkeypatch.delenv("REDIS_PASSWORD_FILE", raising=False)

        assert _database_url() == "postgresql+psycopg://admin:x@db/doom_test"
        assert _redis_url() == "redis://localhost:6379/9"

    def test_placeholder_password_refuses_to_boot(self, tmp_path, monkeypatch):
        import pytest

        from doom.config import ConfigError, _database_url

        secret = tmp_path / "app_db_password"
        secret.write_text("CHANGE_ME")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("APP_DB_PASSWORD_FILE", str(secret))

        with pytest.raises(ConfigError, match="placeholder"):
            _database_url()

    def test_redis_url_is_built_from_the_password_file(self, tmp_path, monkeypatch):
        from doom.config import _redis_url

        secret = tmp_path / "redis_password"
        secret.write_text("e" * 64)
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_PASSWORD_FILE", str(secret))

        assert _redis_url() == (
            f"rediss://:{'e' * 64}@cache:6379/0"
            "?ssl_cert_reqs=required&ssl_check_hostname=true"
            "&ssl_ca_certs=/run/secrets/doom_internal_ca_cert"
        )
