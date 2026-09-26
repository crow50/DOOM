"""RFC 4226 and RFC 6238 test vectors, run against security/totp.py.

The argument for implementing TOTP rather than importing it rests entirely on
this file: thirty lines of standard-library arithmetic is the right trade only
if "did I get it right" has a published answer. These are those answers.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from doom.security import totp


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii")


#: RFC 4226 Appendix D - HOTP with the ASCII secret "12345678901234567890".
HOTP_SECRET = b"12345678901234567890"
HOTP_VECTORS = [
    (0, "755224"), (1, "287082"), (2, "359152"), (3, "969429"), (4, "338314"),
    (5, "254676"), (6, "287922"), (7, "162583"), (8, "399871"), (9, "520489"),
]

#: RFC 6238 Appendix B, the SHA-1 rows. The RFC prints eight digits; an
#: authenticator shows six, so the expected values are the last six.
TOTP_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("counter,expected", HOTP_VECTORS)
def test_rfc4226_hotp_vectors(counter, expected):
    assert totp._hotp(HOTP_SECRET, counter) == expected


@pytest.mark.parametrize("when,expected", TOTP_VECTORS)
def test_rfc6238_totp_vectors(when, expected):
    """The eight-digit RFC value, and the six digits an authenticator shows."""
    secret = _b32(HOTP_SECRET)
    assert totp.code_at(secret, at=when, digits=8) == expected
    assert totp.code_at(secret, at=when) == expected[-6:]


class TestVerification:
    def test_the_current_code_is_accepted(self):
        secret = totp.new_secret()
        now = 1_700_000_000
        assert totp.verify(secret, totp.code_at(secret, at=now), at=now) is not None

    @pytest.mark.parametrize("drift", [-30, 30])
    def test_one_step_of_clock_drift_is_tolerated(self, drift):
        secret = totp.new_secret()
        now = 1_700_000_000
        code = totp.code_at(secret, at=now + drift)
        assert totp.verify(secret, code, at=now) is not None

    @pytest.mark.parametrize("drift", [-90, 90, 3600])
    def test_further_drift_is_not(self, drift):
        secret = totp.new_secret()
        now = 1_700_000_000
        code = totp.code_at(secret, at=now + drift)
        assert totp.verify(secret, code, at=now) is None

    def test_a_consumed_step_cannot_be_replayed(self):
        """The window a tolerance opens is the window a replay needs."""
        secret = totp.new_secret()
        now = 1_700_000_000
        code = totp.code_at(secret, at=now)

        step = totp.verify(secret, code, at=now)
        assert step is not None
        assert totp.verify(secret, code, at=now, last_step=step) is None

    def test_an_older_step_is_refused_once_a_newer_one_has_been_used(self):
        secret = totp.new_secret()
        now = 1_700_000_000
        previous = totp.code_at(secret, at=now - 30)
        current_step = totp.verify(secret, totp.code_at(secret, at=now), at=now)
        assert totp.verify(secret, previous, at=now, last_step=current_step) is None

    @pytest.mark.parametrize("candidate", ["", "12345", "1234567", "abcdef", None])
    def test_a_malformed_code_is_refused_without_raising(self, candidate):
        assert totp.verify(totp.new_secret(), candidate) is None

    def test_another_account_s_code_does_not_work(self):
        now = 1_700_000_000
        mine, theirs = totp.new_secret(), totp.new_secret()
        assert totp.verify(mine, totp.code_at(theirs, at=now), at=now) is None


class TestSecrets:
    def test_a_secret_is_160_bits_from_the_csprng(self):
        secret = totp.new_secret()
        assert len(totp._decode(secret)) == 20
        assert totp.new_secret() != secret

    def test_a_secret_survives_the_formatting_a_user_might_paste(self):
        secret = totp.new_secret()
        now = 1_700_000_000
        spaced = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
        assert totp.code_at(spaced.lower(), at=now) == totp.code_at(secret, at=now)


class TestProvisioningUri:
    def test_the_label_cannot_be_restructured_by_a_username(self):
        """A colon in an account name moves the issuer/account boundary."""
        uri = totp.provisioning_uri("ABCDEFGH", account="a:b/c", issuer="DOOM")
        assert "a:b/c" not in uri
        assert "a%3Ab%2Fc" in uri
        assert uri.startswith("otpauth://totp/DOOM:")

    def test_it_carries_the_parameters_authenticators_need(self):
        uri = totp.provisioning_uri("ABCDEFGH", account="alice", issuer="DOOM")
        for parameter in ("secret=ABCDEFGH", "issuer=DOOM", "algorithm=SHA1",
                          "digits=6", "period=30"):
            assert parameter in uri
