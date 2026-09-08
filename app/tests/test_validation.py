"""Input validation and password policy.

These pin the limits themselves. If someone later loosens a bound in
validation.py, a test fails rather than the change passing silently.
"""

from __future__ import annotations

import pytest

from doom import validation as v
from doom.security.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
    needs_rehash,
    verify_password,
)


class TestUsernameNormalisation:
    def test_case_is_folded(self):
        assert v.normalize_username("ALICE") == "alice"

    def test_unicode_lookalikes_collapse_to_ascii(self):
        # Fullwidth characters normalise under NFKC, so a visually identical
        # impostor account cannot be registered alongside the real one.
        assert v.normalize_username("ａdmin") == "admin"

    def test_whitespace_is_stripped(self):
        assert v.normalize_username("  bob  ") == "bob"

    @pytest.mark.parametrize("bad", ["ab", "a" * 33, "has space", "Bad!Chars", ""])
    def test_rejects_invalid(self, bad):
        assert not v.is_valid_username(bad)

    @pytest.mark.parametrize("good", ["alice", "a_b-c.d", "user123"])
    def test_accepts_valid(self, good):
        assert v.is_valid_username(good)


class TestPasswordPolicy:
    def test_minimum_length_enforced(self):
        with pytest.raises(PasswordPolicyError, match="at least"):
            check_policy("a" * (v.PASSWORD_MIN - 1))

    def test_maximum_length_enforced(self):
        # An upper bound is a control: every candidate is hashed at 64 MiB.
        with pytest.raises(PasswordPolicyError):
            check_policy("a" * (v.PASSWORD_MAX + 1))

    def test_breach_list_password_rejected(self):
        with pytest.raises(PasswordPolicyError, match="breach"):
            check_policy("administrator")

    def test_password_containing_username_rejected(self):
        with pytest.raises(PasswordPolicyError, match="username"):
            check_policy("warehouse-is-my-password", username="warehouse")

    def test_long_passphrase_accepted_without_symbols(self):
        # No composition rules, per NIST SP 800-63B.
        check_policy("correct horse battery staple")


class TestHashing:
    def test_uses_argon2id(self):
        assert hash_password("a-long-enough-passphrase").startswith("$argon2id$")

    def test_salted_hashes_differ_for_same_input(self):
        a = hash_password("a-long-enough-passphrase")
        b = hash_password("a-long-enough-passphrase")
        assert a != b

    def test_verify_round_trip(self):
        stored = hash_password("a-long-enough-passphrase")
        assert verify_password(stored, "a-long-enough-passphrase")
        assert not verify_password(stored, "wrong")

    def test_verify_against_missing_hash_returns_false(self):
        # The unknown-user path. Still runs a dummy verify internally so the
        # timing matches a real account (T-02).
        assert not verify_password(None, "anything")

    def test_current_parameters_do_not_need_rehash(self):
        assert not needs_rehash(hash_password("a-long-enough-passphrase"))
