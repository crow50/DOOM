"""Open redirect prevention."""

from __future__ import annotations

import pytest

from doom.security.redirects import is_safe_redirect


class TestSafeRedirect:
    @pytest.mark.parametrize("target", ["/locations/", "/items/abc", "/"])
    def test_relative_paths_allowed(self, target):
        assert is_safe_redirect(target)

    @pytest.mark.parametrize(
        "target",
        [
            "//evil.com",           # protocol-relative: the most-missed case
            "/\\evil.com",          # backslash variant some browsers normalise
            "https://evil.com",
            "http://evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "evil.com",
            "",
            None,
        ],
    )
    def test_everything_else_rejected(self, target):
        assert not is_safe_redirect(target)

    def test_absolute_url_to_own_host_still_rejected(self):
        """Accepting our own hostname would invite a bypass.

        Any open redirect elsewhere on the domain would become a way through
        this check, so only relative paths are allowed.
        """
        assert not is_safe_redirect("https://localhost/locations/")
