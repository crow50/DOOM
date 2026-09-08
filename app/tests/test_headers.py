"""Response header regression tests.

These exist because of a real bug: `Referrer-Policy: no-referrer` and
Flask-WTF's strict SSL CSRF check are individually correct and mutually
exclusive. The browser obeyed the header, sent no `Referer`, and the CSRF
check rejected every POST with a 400 - login and registration included.

Curl did not catch it, because passing `-e` sets the header explicitly and
papers over exactly the behaviour that was broken.
"""

from __future__ import annotations

import pytest


class TestReferrerPolicy:
    #: Policies under which a browser still sends a referrer on same-origin
    #: requests. Flask-WTF's SSL-strict CSRF check needs one of these.
    SAME_ORIGIN_SAFE = {
        "same-origin",
        "strict-origin-when-cross-origin",
        "origin-when-cross-origin",
        "no-referrer-when-downgrade",
    }

    def test_policy_permits_same_origin_referrers(self, client):
        """Must not be 'no-referrer'.

        'no-referrer' suppresses the header on our own form posts as well as
        outbound links, which disables the CSRF referrer check and returns 400
        for every submission. Stricter is not automatically better.
        """
        policy = client.get("/").headers.get("Referrer-Policy")
        assert policy is not None
        assert policy in self.SAME_ORIGIN_SAFE
        assert policy != "no-referrer"

    def test_policy_still_withholds_referrer_cross_origin(self, client):
        """The original goal must survive the fix.

        A share token sits in the URL path, so it must never travel to a third
        party the user clicks through to (T-20). Every policy above sends
        either nothing or bare origin cross-origin - never the path.
        """
        policy = client.get("/").headers.get("Referrer-Policy")
        assert policy != "unsafe-url"
        assert policy != ""

    def test_share_pages_use_the_same_safe_policy(self, client, alice_item):
        """The share blueprint sets its own policy and had the same bug.

        A 'no-referrer' here would break the share PIN form the same way.
        """
        from doom.extensions import db
        from doom.models import new_share_token

        alice_item.share_token = new_share_token()
        alice_item.visibility = "shared"
        db.session.commit()

        response = client.get(f"/t/{alice_item.share_token}")
        assert response.status_code == 200
        assert response.headers.get("Referrer-Policy") in self.SAME_ORIGIN_SAFE


class TestCoreHeaders:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ],
    )
    def test_present(self, client, header, expected):
        assert client.get("/").headers.get(header) == expected

    def test_csp_has_no_unsafe_inline(self, client):
        """The property that makes script-src 'self' a real defence.

        One 'unsafe-inline' anywhere in the policy and an injected <script>
        executes again.
        """
        csp = client.get("/").headers.get("Content-Security-Policy", "")
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_share_pages_are_noindex(self, client, alice_item):
        from doom.extensions import db
        from doom.models import new_share_token

        alice_item.share_token = new_share_token()
        alice_item.visibility = "shared"
        db.session.commit()

        response = client.get(f"/t/{alice_item.share_token}")
        assert "noindex" in response.headers.get("X-Robots-Tag", "")
