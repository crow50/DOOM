"""The one deliberate outbound request, and its guard rails."""

from __future__ import annotations

from unittest import mock

import pytest

from doom import validation as v
from doom.security.lookup import (
    LookupUnavailable,
    _assert_public_address,
    _clean,
    _extract,
    lookup_barcode,
)


class TestDestinationIsNeverUserControlled:
    def test_provider_comes_from_code_not_a_request(self):
        """The distinction that separates this from D-13's SSRF hole (T-40).

        The user supplies a barcode. They never supply a destination.
        """
        for config in v.BARCODE_PROVIDERS.values():
            assert config["url"].startswith("https://")
            assert "{barcode}" in config["url"]

    def test_unknown_provider_is_refused(self):
        with pytest.raises(LookupUnavailable, match="unknown lookup provider"):
            lookup_barcode("4006381333931", "http://evil.example/")

    def test_invalid_barcode_never_reaches_the_network(self):
        with mock.patch("doom.security.lookup.requests.get") as get:
            with pytest.raises(LookupUnavailable):
                lookup_barcode("'; DROP TABLE items;--", "openfoodfacts")
            get.assert_not_called()


class TestInternalAddressBlocking:
    @pytest.mark.parametrize("address", [
        "127.0.0.1",        # loopback
        "169.254.169.254",  # cloud metadata
        "10.0.0.5",         # private
        "192.168.1.10",     # private
        "172.19.0.2",       # the docker network db and cache live on
        "0.0.0.0",
    ])
    def test_internal_resolution_is_refused(self, address):
        """DNS is not ours, even when the hostname is pinned."""
        info = [(2, 1, 6, "", (address, 443))]
        with mock.patch("doom.security.lookup.socket.getaddrinfo", return_value=info):
            with pytest.raises(LookupUnavailable, match="internal address"):
                _assert_public_address("world.openfoodfacts.org")

    def test_public_resolution_is_allowed(self):
        info = [(2, 1, 6, "", ("104.18.32.1", 443))]
        with mock.patch("doom.security.lookup.socket.getaddrinfo", return_value=info):
            _assert_public_address("world.openfoodfacts.org")

    def test_one_bad_answer_fails_the_whole_lookup(self):
        """A mixed answer is still hostile; it must not be partially accepted."""
        info = [
            (2, 1, 6, "", ("104.18.32.1", 443)),
            (2, 1, 6, "", ("169.254.169.254", 443)),
        ]
        with mock.patch("doom.security.lookup.socket.getaddrinfo", return_value=info):
            with pytest.raises(LookupUnavailable):
                _assert_public_address("world.openfoodfacts.org")


class TestRedirectsRefused:
    def test_redirect_is_not_followed(self):
        """The critical flag.

        Follow redirects and the code-level allowlist is decorative, because
        the provider then chooses the real destination.
        """
        response = mock.Mock(status_code=302, is_redirect=True)
        response.close = mock.Mock()

        with mock.patch("doom.security.lookup._assert_public_address"), \
             mock.patch("doom.security.lookup.requests.get", return_value=response) as get:
            with pytest.raises(LookupUnavailable, match="redirect"):
                lookup_barcode("4006381333931", "openfoodfacts")

        assert get.call_args.kwargs["allow_redirects"] is False

    def test_timeouts_are_always_passed(self):
        response = mock.Mock(status_code=404, is_redirect=False)
        response.close = mock.Mock()

        with mock.patch("doom.security.lookup._assert_public_address"), \
             mock.patch("doom.security.lookup.requests.get", return_value=response) as get:
            with pytest.raises(LookupUnavailable):
                lookup_barcode("4006381333931", "openfoodfacts")

        assert get.call_args.kwargs["timeout"] == (
            v.LOOKUP_CONNECT_TIMEOUT, v.LOOKUP_READ_TIMEOUT,
        )


class TestOversizedResponse:
    def test_body_is_capped(self):
        """Content-Length is a claim; the stream is capped as it is read."""
        flood = [b"x" * 8192] * (v.LOOKUP_MAX_BYTES // 8192 + 5)
        response = mock.Mock(status_code=200, is_redirect=False)
        response.iter_content = mock.Mock(return_value=iter(flood))
        response.close = mock.Mock()

        with mock.patch("doom.security.lookup._assert_public_address"), \
             mock.patch("doom.security.lookup.requests.get", return_value=response):
            with pytest.raises(LookupUnavailable, match="too large"):
                lookup_barcode("4006381333931", "openfoodfacts")


class TestResponseTreatedAsUntrusted:
    def test_only_expected_fields_are_read(self):
        payload = {
            "product": {
                "product_name": "Baked Beans",
                "brands": "Acme",
                "unexpected": "<script>alert(1)</script>",
                "huge": "x" * 100_000,
            }
        }
        result = _extract(payload, "openfoodfacts")
        assert result.name == "Baked Beans"
        assert not hasattr(result, "unexpected")

    def test_values_are_bounded_and_stripped(self):
        assert len(_clean("x" * 5000, v.ITEM_NAME_MAX)) <= v.ITEM_NAME_MAX
        assert "\n" not in (_clean("evil\nname", 100) or "")
        assert _clean(12345, 100) is None
        assert _clean(None, 100) is None

    @pytest.mark.parametrize("payload", [
        None, [], "a string", {}, {"product": "not a dict"},
        {"items": "not a list"}, {"items": []},
    ])
    def test_malformed_documents_yield_nothing(self, payload):
        assert _extract(payload, "openfoodfacts") is None
        assert _extract(payload, "upcitemdb") is None
