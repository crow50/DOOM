"""Regressions found during the release/ASVS 5 security review."""
import pytest
from conftest import login, sync
from doom.extensions import db
from doom.models import new_share_token
from doom.security.passwords import hash_share_pin
from doom.security.redirects import is_safe_redirect


@pytest.mark.parametrize("target", ["/\t\\evil.example", "/\n\\evil.example", "/\r\\evil.example", " /items/", "/items/\x00"])
def test_redirect_rejects_browser_normalization(target):
    assert not is_safe_redirect(target)


def test_login_rejects_control_backslash_redirect(client, alice):
    response = client.post("/login", query_string={"next": "/\t\\evil.example"},
                           data={"username": "alice", "password": "a-long-enough-passphrase"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/locations/"


@pytest.mark.parametrize("change", ["pin", "token"])
def test_share_approval_revoked_when_credentials_change(client, alice_item, change):
    alice_item.visibility = "shared"
    alice_item.share_token = new_share_token()
    alice_item.share_pin_hash = hash_share_pin("123456")
    db.session.commit()
    token = alice_item.share_token
    response = client.post(f"/t/{token}", data={"pin": "123456"})
    assert b"Cordless drill" in response.data
    sync()
    if change == "pin":
        alice_item.share_pin_hash = hash_share_pin("654321")
    else:
        alice_item.share_token = new_share_token()
    db.session.commit()
    response = client.get(f"/t/{alice_item.share_token}")
    assert b"Cordless drill" not in response.data
    assert b'name="pin"' in response.data


def test_lookup_failure_does_not_disclose_internal_details(client, alice, app, monkeypatch):
    from doom.security.lookup import LookupUnavailable
    def fail(*args):
        raise LookupUnavailable("internal-host password=canary-secret")
    monkeypatch.setattr("doom.blueprints.items.lookup_barcode", fail)
    monkeypatch.setitem(app.config, "BARCODE_LOOKUP_PROVIDER", "openfoodfacts")
    login(client, "alice")
    response = client.get("/items/barcode/4006381333931")
    assert response.status_code == 200
    assert b"canary-secret" not in response.data
    assert response.json["source"] == "none"


def test_encoded_share_referrer_does_not_leak_token():
    from doom.security.logging import scrub_url
    token = "canary-share-credential"
    assert token not in scrub_url(f"https://doom.example/%74/{token}")
    assert token not in scrub_url(f"https://doom.example/t/{token}?pin=1234")
    assert scrub_url("http://[invalid") == "[redacted]"


def test_untrusted_forwarded_port_cannot_override_proxy_host(app):
    from werkzeug.test import Client
    from werkzeug.wrappers import Response
    from werkzeug.middleware.proxy_fix import ProxyFix
    # Exercise the configured middleware around an endpoint reporting the
    # effective host; no database or client-supplied Host is trusted here.
    configured = app.wsgi_app
    assert isinstance(configured, ProxyFix)
    def host(environ, start_response):
        return Response(environ["HTTP_HOST"])(environ, start_response)
    middleware = ProxyFix(host, x_for=configured.x_for, x_proto=configured.x_proto,
                          x_host=configured.x_host, x_port=configured.x_port)
    response = Client(middleware).get("/", headers={
        "X-Forwarded-Host": "doom.example:18443", "X-Forwarded-Port": "6666"})
    assert response.text == "doom.example:18443"


def test_image_pixel_limit_is_a_hard_limit(monkeypatch):
    import io
    from PIL import Image
    from doom.security.uploads import _process_image, UploadRejected
    data = io.BytesIO()
    Image.new("RGB", (11, 10)).save(data, format="PNG")
    monkeypatch.setattr("doom.security.uploads.v.MAX_IMAGE_PIXELS", 100)
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 100)
    with pytest.raises(UploadRejected):
        _process_image(data.getvalue(), "image/png")


def test_jinja_templates_compile_with_autoescape(app):
    """Semgrep's HTML parser cannot parse Jinja syntax; enforce its key guards here."""
    from jinja2 import nodes

    names = app.jinja_env.list_templates()
    assert names
    for name in names:
        assert app.jinja_env.autoescape(name), f"autoescape disabled for {name}"
        source, _, _ = app.jinja_env.loader.get_source(app.jinja_env, name)
        syntax = app.jinja_env.parse(source)
        app.jinja_env.compile(source, name=name)
        unsafe_filters = [node.lineno for node in syntax.find_all(nodes.Filter)
                          if node.name == "safe"]
        assert not unsafe_filters, f"unsafe |safe filter in {name}:{unsafe_filters}"
        for modifier in syntax.find_all(nodes.EvalContextModifier):
            disabled = [option for option in modifier.options
                        if option.key == "autoescape"
                        and isinstance(option.value, nodes.Const)
                        and option.value.value is False]
            assert not disabled, f"autoescape disabled inside {name}"
