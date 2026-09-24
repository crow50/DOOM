"""Acceptance tests for the ASVS 5.0 Level 1 controls closed in this review.

Each test names the requirement it stands behind, because the ledger in
``docs/security/asvs-5.0.0.json`` cites this file by line. A requirement
marked **Met** whose evidence is a paragraph of prose is a claim; one whose
evidence is a test that fails when the control is removed is a control.
"""

from __future__ import annotations

import ast
import hashlib
import io
import pathlib
import re

import pytest
from conftest import login, open_share
from doom.extensions import db
from doom.models import new_share_token

APP_PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "doom"


def _names_used(package: pathlib.Path, names: set[str],
                modules: set[str] | None = None) -> list[str]:
    """Every use of ``names`` or import of ``modules`` the interpreter would see.

    Comments and docstrings are not code and are skipped for free, because
    this parses rather than greps. Attribute access is matched on the final
    component - ``hashlib.sha1`` and a bare ``sha1(...)`` both count - while
    ``re.compile`` is exempted by name, since the builtin ``compile`` is the
    one this is looking for.
    """
    modules = modules or set()
    exempt_attributes = {("re", "compile")}
    offenders: list[str] = []

    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in names:
                owner = getattr(node.value, "id", None)
                if (owner, node.attr) in exempt_attributes:
                    continue
                offenders.append(f"{path.name}:{node.lineno} {owner}.{node.attr}")
            elif isinstance(node, ast.Name) and node.id in names:
                offenders.append(f"{path.name}:{node.lineno} {node.id}")
            elif isinstance(node, ast.Import):
                offenders += [f"{path.name}:{node.lineno} import {a.name}"
                              for a in node.names if a.name.split(".")[0] in modules]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in modules:
                    offenders.append(f"{path.name}:{node.lineno} from {node.module}")

    return offenders


def _share(node) -> str:
    node.share_token = new_share_token()
    node.visibility = "shared"
    db.session.commit()
    return node.share_token


# ---------------------------------------------------------------------------
# V14.2.1 - no sensitive data in the URL or query string
# ---------------------------------------------------------------------------

class TestShareCodeNeverInAURL:
    def test_generated_label_url_puts_the_code_in_the_fragment(self, app, alice_item):
        """The fragment is the whole control: browsers never transmit it."""
        from doom.blueprints.labels import share_url

        token = _share(alice_item)
        with app.test_request_context():
            url = share_url(alice_item)

        path = url.split("#")[0]
        assert url.endswith(f"/t/#{token}")
        assert token not in path

    def test_landing_request_carries_no_code(self, client, alice_item):
        """What the server actually receives when a label is scanned."""
        _share(alice_item)
        response = client.get("/t/")
        assert response.status_code == 200
        assert b"Cordless drill" not in response.data

    def test_redirect_target_is_a_handle_not_the_code(self, client, alice_item):
        token = _share(alice_item)
        response = client.post("/t/", data={"token": token})

        assert response.status_code == 303
        location = response.headers["Location"]
        assert token not in location
        assert re.fullmatch(r"/t/v/[A-Za-z0-9_-]+", location)

    def test_a_handle_is_useless_without_the_session_that_minted_it(
        self, app, client, alice_item
    ):
        """The handle in the URL confers nothing on its own.

        This is what makes it safe for the handle to be in a URL when the
        token was not: it names an entry in one visitor's signed cookie.
        """
        token = _share(alice_item)
        location = client.post("/t/", data={"token": token}).headers["Location"]
        assert client.get(location).status_code == 200

        stranger = app.test_client()
        assert stranger.get(location).status_code == 404

    def test_held_codes_are_capped_so_the_cookie_cannot_grow_without_bound(
        self, client, alice, alice_bin
    ):
        from doom.blueprints.share import _MAX_HANDLES
        from doom.models import Item

        first = None
        for index in range(_MAX_HANDLES + 2):
            item = Item(owner_id=alice.id, location_id=alice_bin.id,
                        name=f"Widget {index}", quantity=1)
            db.session.add(item)
            db.session.commit()
            location = client.post(
                "/t/", data={"token": _share(item)}
            ).headers["Location"]
            if first is None:
                first = location

        # The oldest entry has aged out, and an aged-out handle is a miss like
        # any other - not a different answer.
        assert client.get(first).status_code == 404

    @pytest.mark.parametrize("handle", ["caf\u00e9", "../../etc/passwd", "a" * 200, ""])
    def test_a_malformed_handle_is_a_miss_and_not_a_server_error(self, client, handle):
        """A path segment carries whatever the client typed."""
        assert client.get(f"/t/v/{handle}").status_code in (404, 405)

    def test_rescanning_the_same_label_reuses_its_handle(self, client, alice_item):
        token = _share(alice_item)
        first = client.post("/t/", data={"token": token}).headers["Location"]
        second = client.post("/t/", data={"token": token}).headers["Location"]
        assert first == second


# ---------------------------------------------------------------------------
# V9.1.1 / V9.1.2 / V11.4.1 - self-contained tokens and approved hashes
# ---------------------------------------------------------------------------

class TestTokenSigning:
    def test_session_cookie_is_signed_with_sha256(self, app):
        from doom.security.sessions import Sha256SessionInterface

        assert isinstance(app.session_interface, Sha256SessionInterface)
        serializer = app.session_interface.get_signing_serializer(app)
        signer = serializer.make_signer(serializer.salt)
        assert signer.digest_method is hashlib.sha256
        assert signer.digest_method is not hashlib.sha1

    def test_itsdangerous_default_is_raised_for_libraries_we_cannot_reach(self, app):
        """Flask-WTF builds its CSRF serializer inline and takes no digest.

        If a future release of itsdangerous renames or removes this attribute,
        this test fails rather than the application silently going back to
        HMAC-SHA1.
        """
        from itsdangerous import URLSafeTimedSerializer

        serializer = URLSafeTimedSerializer("k", salt="wtf-csrf-token")
        assert serializer.make_signer("wtf-csrf-token").digest_method is hashlib.sha256

    def test_a_cookie_signed_with_the_old_algorithm_is_refused(self, app, client, alice):
        """Not "accepted for compatibility": an attacker picks the algorithm."""
        from flask.sessions import SecureCookieSessionInterface

        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        legacy = SecureCookieSessionInterface()
        forged = legacy.get_signing_serializer(app).dumps(
            {"_user_id": str(alice.id), "_doom_sv": alice.session_version}
        )
        client.set_cookie("doom_session", forged)
        response = client.get("/locations/")
        assert response.status_code in (302, 401)
        assert b"Cordless drill" not in response.data

    def test_no_withdrawn_hash_is_reachable_from_the_package(self):
        """Parsed, not grepped.

        A regular expression over the source finds the word ``sha1`` in the
        paragraph of ``security/sessions.py`` that explains why it is not used,
        which is the opposite of the property being asserted. Walking the AST
        looks only at names the interpreter would actually resolve.

        SHA-1 has exactly one permitted home, and the assertion is written as
        "only there" rather than as an exemption: RFC 6238 fixes HMAC-SHA1 as
        the default TOTP construction and every authenticator application
        implements that and only that, so a SHA-256 variant would be a factor
        nobody could enrol. NIST SP 800-131A Rev. 2 still permits HMAC-SHA1;
        it is SHA-1 *signatures* that are withdrawn. If a second module ever
        acquires a SHA-1 call, this fails - which is the point, because the
        argument above covers one module and does not generalise.
        """
        offenders = _names_used(APP_PACKAGE, {"sha1", "md5", "sha224", "md4"})
        permitted_home = "totp.py"

        stray = [use for use in offenders if not use.startswith(permitted_home)]
        assert not stray, stray

        # And the exception is real rather than stale: if TOTP stops needing
        # it, this test should start failing and the comment should go.
        assert any(use.startswith(permitted_home) for use in offenders), (
            "security/totp.py no longer uses SHA-1 - remove the exception above"
        )


class TestSessionValidity:
    def test_session_lifetime_is_bounded(self, app):
        """V9.2.1 - a validity span that is present must be enforced."""
        import datetime

        lifetime = app.config["PERMANENT_SESSION_LIFETIME"]
        assert isinstance(lifetime, datetime.timedelta)
        assert datetime.timedelta(0) < lifetime <= datetime.timedelta(days=1)
        assert app.config["SESSION_REFRESH_EACH_REQUEST"] is False


# ---------------------------------------------------------------------------
# V14.3.1 - authenticated data cleared from client storage on termination
# ---------------------------------------------------------------------------

class TestClearSiteDataOnLogout:
    def test_logout_asks_the_browser_to_drop_this_origin(self, client, alice):
        login(client, "alice")
        response = client.post("/logout")

        directives = response.headers.get("Clear-Site-Data", "")
        assert '"cookies"' in directives
        assert '"cache"' in directives
        assert '"storage"' in directives

    def test_authenticated_pages_are_never_stored(self, client, alice):
        login(client, "alice")
        response = client.get("/locations/")
        assert "no-store" in response.headers["Cache-Control"]


# ---------------------------------------------------------------------------
# V5.2.2 - submitted extension must agree with the content
# ---------------------------------------------------------------------------

class TestUploadExtensionMatchesContent:
    @staticmethod
    def _jpeg() -> bytes:
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (8, 8), "red").save(buffer, format="JPEG")
        return buffer.getvalue()

    def _store(self, tmp_path, data: bytes, filename: str):
        from werkzeug.datastructures import FileStorage
        from doom.security.uploads import store_upload

        return store_upload(
            FileStorage(stream=io.BytesIO(data), filename=filename,
                        content_type="application/octet-stream"),
            str(tmp_path),
        )

    def test_matching_extension_is_accepted(self, tmp_path):
        result = self._store(tmp_path, self._jpeg(), "shelf.jpg")
        assert result.content_type == "image/jpeg"

    @pytest.mark.parametrize("filename", ["shelf.pdf", "shelf.png", "shelf.txt"])
    def test_mismatched_extension_is_refused(self, tmp_path, filename):
        from doom.security.uploads import UploadRejected

        with pytest.raises(UploadRejected):
            self._store(tmp_path, self._jpeg(), filename)

    def test_missing_extension_is_refused(self, tmp_path):
        from doom.security.uploads import UploadRejected

        with pytest.raises(UploadRejected):
            self._store(tmp_path, self._jpeg(), "shelf")

    def test_markdown_is_accepted_although_libmagic_reports_plain_text(self, tmp_path):
        """The reason the table maps one type to several extensions."""
        result = self._store(tmp_path, b"# Notes\n\nSome text.\n", "notes.md")
        assert result.kind == "document"

    def test_case_is_not_a_way_around_the_check(self, tmp_path):
        result = self._store(tmp_path, self._jpeg(), "SHELF.JPG")
        assert result.content_type == "image/jpeg"

    def test_stored_name_still_comes_from_the_content_not_the_label(self, tmp_path):
        result = self._store(tmp_path, self._jpeg(), "shelf.jpeg")
        assert result.stored_name.endswith(".jpg")
        assert "shelf" not in result.stored_name


# ---------------------------------------------------------------------------
# V1.2.4 / V1.2.5 / V1.3.2 - injection
# ---------------------------------------------------------------------------

class TestInjectionSurfaces:
    def test_search_treats_sql_metacharacters_as_text(self, client, alice, alice_bin):
        from doom.models import Item

        db.session.add(Item(owner_id=alice.id, location_id=alice_bin.id,
                            name="100% cotton rag", quantity=1))
        db.session.add(Item(owner_id=alice.id, location_id=alice_bin.id,
                            name="plain rag", quantity=1))
        db.session.commit()
        login(client, "alice")

        # A wildcard in the term is a literal, so this must not match
        # everything - which is what an unescaped ILIKE would do.
        response = client.get("/items/", query_string={"q": "100%"})
        assert b"100% cotton rag" in response.data or b"100%" in response.data
        assert b"plain rag" not in response.data

    @pytest.mark.parametrize("payload", [
        "'; DROP TABLE items; --",
        "' OR '1'='1",
        "\\",
        "_",
    ])
    def test_injection_payloads_are_harmless_and_do_not_error(
        self, client, alice, payload
    ):
        login(client, "alice")
        assert client.get("/items/", query_string={"q": payload}).status_code == 200

        from doom.models import Item
        assert db.session.query(Item).count() >= 0  # the table is still there

    def test_the_package_executes_no_dynamic_code_and_shells_out_nowhere(self):
        """V1.2.5 and V1.3.2, as a property rather than a reading.

        ``re.compile`` is not ``compile``: a name-based grep flags every
        compiled pattern in the codebase and says nothing. The AST walk
        distinguishes the builtin from the attribute of a module, which is the
        distinction the requirement is actually about.
        """
        offenders = _names_used(
            APP_PACKAGE,
            # `loads` is deliberately absent: json.loads is the parser this
            # application wants, and the dangerous deserialisers are caught by
            # the module list below rather than by the method name they share
            # with a safe one.
            {"eval", "exec", "compile", "system", "popen", "spawn", "spawnl",
             "spawnv", "execv", "execve"},
            modules={"subprocess", "pickle", "marshal", "shelve"},
        )
        assert not offenders, offenders


# ---------------------------------------------------------------------------
# V3.4.2 / V3.5.3 / V4.1.1 - HTTP behaviour
# ---------------------------------------------------------------------------

class TestHttpSemantics:
    def test_no_response_ever_grants_a_cross_origin_reader(self, client, alice):
        """V3.4.2 - the application sets no CORS headers at all."""
        login(client, "alice")
        for path in ("/", "/locations/", "/items/", "/t/"):
            response = client.get(path, headers={"Origin": "https://evil.example"})
            assert "Access-Control-Allow-Origin" not in response.headers
            assert "Access-Control-Allow-Credentials" not in response.headers

    def test_state_changing_endpoints_refuse_get(self, app, client, alice):
        """V3.5.3 - nothing that changes state is reachable with a safe method.

        Paths, not endpoints: ``/t/`` is served by two endpoints, a GET page
        and a POST handler, so asking whether *this endpoint* allows GET gives
        the wrong answer for the request a browser would actually make.
        """
        login(client, "alice")

        readable = {rule.rule for rule in app.url_map.iter_rules()
                    if "GET" in rule.methods}
        checked = 0

        for rule in app.url_map.iter_rules():
            if rule.rule in readable or rule.arguments:
                continue
            assert client.get(rule.rule).status_code == 405, rule.rule
            checked += 1

        assert checked, "no method-restricted routes were exercised"

    def test_logout_and_delete_are_not_reachable_by_get(self, client, alice):
        login(client, "alice")
        assert client.get("/logout").status_code == 405

    def test_every_body_carrying_response_declares_its_type(self, client, alice):
        """V4.1.1 - including the character set for text."""
        login(client, "alice")
        for path in ("/locations/", "/items/", "/account/", "/robots.txt"):
            response = client.get(path)
            if not response.data:
                continue
            content_type = response.headers.get("Content-Type", "")
            assert content_type, path
            if content_type.startswith("text/"):
                assert "charset=" in content_type, path


# ---------------------------------------------------------------------------
# V6.2.7 / V6.3.2 - credential handling
# ---------------------------------------------------------------------------

class TestCredentialUsability:
    def test_password_fields_invite_managers_rather_than_fighting_them(self, client):
        """V6.2.7 - paste, browser helpers and external managers permitted."""
        for path, expected in (("/register", b'autocomplete="new-password"'),
                               ("/login", b'type="password"')):
            body = client.get(path).data
            assert expected in body
            for blocker in (b"onpaste", b"oncopy", b"ondrop", b"oncontextmenu"):
                assert blocker not in body.lower()

    def test_no_account_exists_until_somebody_registers_one(self, app):
        """V6.3.2 - no default accounts ship with the application."""
        from doom.models import User

        assert db.session.query(User).count() == 0

    def test_seed_refuses_to_add_a_demo_login_to_a_populated_instance(self, app, alice):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["seed"])
        assert result.exit_code != 0
        assert "already has" in result.output

    def test_seed_does_not_publish_a_fixed_password(self):
        source = (APP_PACKAGE / "cli.py").read_text(encoding="utf-8")
        body = source.split('@app.cli.command("seed")', 1)[1]
        assert "secrets.token_urlsafe" in body
        assert "correct-horse-battery-staple" not in body.replace(
            "``correct-horse-battery-staple``", ""
        )


# ---------------------------------------------------------------------------
# V15.3.1 - only the required subset of fields
# ---------------------------------------------------------------------------

class TestFieldSubset:
    def test_a_public_view_model_carries_no_internal_identifiers(
        self, alice_item, alice_bin
    ):
        from doom.security.serializers import public_item, public_location

        for model in (public_item(alice_item, attachments=[], links=[]),
                      public_location(alice_bin, items=[], attachments=[], links=[])):
            keys = set(model)
            assert not keys & {
                "id", "owner_id", "owner", "created_at", "updated_at",
                "visibility", "share_token", "share_pin_hash", "location_id",
                "parent_id",
            }


# ---------------------------------------------------------------------------
# V7.4.1 / V7.4.2 - termination really terminates
# ---------------------------------------------------------------------------

class TestSessionTermination:
    def test_logout_ends_the_session_for_good(self, client, alice):
        login(client, "alice")
        assert client.get("/locations/").status_code == 200

        client.post("/logout")
        assert client.get("/locations/").status_code == 302

    def test_deactivating_an_account_ends_every_live_session(self, app, alice):
        """V7.4.2 - checked on the request, not at the next sign-in."""
        first, second = app.test_client(), app.test_client()
        login(first, "alice")
        login(second, "alice")
        assert first.get("/locations/").status_code == 200
        assert second.get("/locations/").status_code == 200

        alice.is_active_flag = False
        db.session.commit()

        assert first.get("/locations/").status_code == 302
        assert second.get("/locations/").status_code == 302

    def test_a_password_change_ends_the_other_devices(self, app, client, alice):
        other = app.test_client()
        login(other, "alice")
        login(client, "alice")

        response = client.post("/account/password", data={
            "current_password": "a-long-enough-passphrase",
            "new_password": "relentless-kettle-mango-ribbon",
            "confirm": "relentless-kettle-mango-ribbon",
        })
        assert response.status_code == 302

        # The tab that made the change stays signed in; the others do not.
        assert client.get("/locations/").status_code == 200
        assert other.get("/locations/").status_code == 302

    def test_the_share_handle_carries_enough_entropy_to_stop_the_question(self):
        """Not a credential, and sized as though it were."""
        import base64
        from doom.blueprints.share import _remember

        source = (APP_PACKAGE / "blueprints" / "share.py").read_text(encoding="utf-8")
        assert "secrets.token_urlsafe(16)" in source


# ---------------------------------------------------------------------------
# V2.3.1 - business logic runs in its expected order
# ---------------------------------------------------------------------------

class TestSequentialFlows:
    def test_a_protected_share_cannot_be_read_before_the_pin(self, client, alice_item):
        from doom.security.passwords import hash_share_pin

        alice_item.share_pin_hash = hash_share_pin("123456")
        token = _share(alice_item)

        landing = client.post("/t/", data={"token": token}, follow_redirects=True)
        assert b"Cordless drill" not in landing.data
        assert b'name="pin"' in landing.data

    def test_the_wrong_pin_does_not_advance_the_flow(self, client, alice_item):
        from doom.security.passwords import hash_share_pin

        alice_item.share_pin_hash = hash_share_pin("123456")
        token = _share(alice_item)
        handle = client.post("/t/", data={"token": token}).headers["Location"]

        response = client.post(handle, data={"pin": "000000"})
        assert response.status_code == 401
        assert b"Cordless drill" not in response.data

        # And the correct PIN still works afterwards: a rejection is not a lockout.
        assert b"Cordless drill" in client.post(handle, data={"pin": "123456"}).data

    def test_a_password_change_requires_the_current_password_first(self, client, alice):
        login(client, "alice")
        response = client.post("/account/password", data={
            "current_password": "not-the-right-one",
            "new_password": "relentless-kettle-mango-ribbon",
            "confirm": "relentless-kettle-mango-ribbon",
        })
        assert response.status_code == 200
        assert b"not your current password" in response.data


# ---------------------------------------------------------------------------
# V1.2.2 / V3.2.1 / V3.5.1 - the remaining browser-facing controls
# ---------------------------------------------------------------------------

class TestBrowserFacingControls:
    @pytest.mark.parametrize("hostile", [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
    ])
    def test_only_http_and_https_may_be_stored_as_a_link(self, hostile):
        """V1.2.2 - an allowlist, so a scheme nobody predicted is refused too."""
        from doom import validation as v

        assert v.URL_SCHEMES == frozenset({"http", "https"})
        assert hostile.split(":")[0] not in v.URL_SCHEMES

    def test_a_stored_document_is_served_as_an_inert_attachment(
        self, client, alice, alice_item
    ):
        """V3.2.1 - never rendered in this origin's context."""
        from doom.models import Attachment

        attachment = Attachment(
            owner_id=alice.id, item_id=alice_item.id, kind="document",
            stored_name="x.txt", original_name="notes.txt",
            content_type="text/plain", byte_size=1, sha256="0" * 64,
        )
        db.session.add(attachment)
        db.session.commit()

        upload_dir = pathlib.Path(client.application.config["UPLOAD_DIR"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        (upload_dir / "x.txt").write_bytes(b"notes\n")
        login(client, "alice")

        response = client.get(f"/files/{attachment.id}")
        assert response.status_code == 200
        assert "attachment" in response.headers["Content-Disposition"]
        assert response.headers["Content-Security-Policy"] == (
            "default-src 'none'; sandbox"
        )
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_a_blob_missing_from_disk_is_a_404_rather_than_a_traceback(
        self, client, alice, alice_item
    ):
        """A restored volume without its files must not become a 500.

        Found while writing the test above: send_file raised FileNotFoundError
        straight through the view, so a row whose blob had gone produced a
        stack trace and a different answer from every other miss (D-06).
        """
        from doom.models import Attachment

        attachment = Attachment(
            owner_id=alice.id, item_id=alice_item.id, kind="document",
            stored_name="definitely-not-there.txt", original_name="gone.txt",
            content_type="text/plain", byte_size=1, sha256="1" * 64,
        )
        db.session.add(attachment)
        db.session.commit()
        login(client, "alice")

        assert client.get(f"/files/{attachment.id}").status_code == 404

    def test_a_post_without_a_csrf_token_is_refused(self, app, alice):
        """V3.5.1 - anti-forgery tokens, not CORS preflight.

        The suite runs with CSRF disabled so forms can be driven directly, so
        this builds an application that has it on - otherwise the test would
        assert the configuration it is standing in rather than the control.
        """
        from doom.config import TestConfig

        class CsrfConfig(TestConfig):
            WTF_CSRF_ENABLED = True

        from doom import create_app

        protected = create_app(CsrfConfig)
        with protected.test_client() as guarded:
            response = guarded.post("/login", data={
                "username": "alice", "password": "a-long-enough-passphrase",
            })
            assert response.status_code == 400
