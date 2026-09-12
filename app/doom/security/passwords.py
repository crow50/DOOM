"""Password hashing and policy.

Argon2id is the current recommendation of the OWASP Password Storage Cheat
Sheet and the winner of the Password Hashing Competition.  It is memory-hard,
which is the property that matters: bcrypt and PBKDF2 are CPU-hard only, and
a GPU or ASIC farm parallelises CPU work far more cheaply than it
parallelises 64 MiB of RAM per guess.
"""

from __future__ import annotations

import functools
import hmac
import logging
import pathlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .. import validation as v

logger = logging.getLogger(__name__)

#: Parameters exceed the OWASP floor of 19 MiB / t=2 / p=1.
#:
#: memory_cost is the load-bearing figure.  At 64 MiB per hash an attacker
#: needs 64 GiB of RAM to run a thousand guesses in parallel, which is what
#: makes large-scale offline cracking expensive rather than merely slow.
#:
#: The same figure is a capacity constraint on our side, and the two are in
#: direct tension: workers x threads x 64 MiB must fit the container memory
#: limit, which is why gunicorn concurrency is pinned in compose and the
#: password length is capped (T-30).
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

#: A pre-computed hash of a value nobody will submit.
#:
#: Verified against when the supplied username does not exist, so that a login
#: attempt for an unknown account costs the same ~50ms as one for a real
#: account.  Without it, response time answers "does this user exist?" for
#: free, and an attacker enumerates the whole user table before trying a
#: single password (T-02).
_DUMMY_HASH = _hasher.hash("doom-timing-equalisation-placeholder")


#: The breach corpus, screened against by :func:`check_policy`.
#:
#: ASVS 4.0.3 V2.1.7 permits a local list, but is specific about which one:
#: "the top 1,000 or 10,000 most common passwords **which match the system's
#: password policy**".  That qualifier is the whole requirement here.  Because
#: :data:`validation.PASSWORD_MIN` is 12, a conventional top-10,000 list is
#: almost entirely under the length floor, and every one of those entries is
#: rejected by the length check below before this set is ever consulted - so
#: such a list screens nothing at all.
#:
#: The file therefore holds the top 10,000 breached passwords *of at least 12
#: characters*, drawn from a 1,000,000-entry corpus.  See the header of
#: ``data/common_passwords.txt`` for provenance, and D-03 for the reasoning.
#:
#: Loaded once, lazily, so importing this module for hashing alone does not pay
#: for the file, and so a missing file is a startup-time error in one place.
_CORPUS_PATH = pathlib.Path(__file__).with_name("data") / "common_passwords.txt"


@functools.lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    """Return the lowercased breach corpus, reading it on first use."""
    with _CORPUS_PATH.open(encoding="utf-8") as handle:
        return frozenset(
            line.strip()
            for line in handle
            if line.strip() and not line.startswith("#")
        )


class PasswordPolicyError(ValueError):
    """Raised when a candidate password fails policy."""


def check_policy(password: str, *, username: str | None = None) -> None:
    """Validate a candidate password, raising on the first failure.

    Deliberately absent: character composition rules.  NIST SP 800-63B
    withdrew them because they reliably produce "Password1!" rather than
    genuinely unpredictable secrets, while blocking strong passphrases.
    Length, a breach-corpus screen, and a context check do the real work.
    """
    if not password:
        raise PasswordPolicyError("Enter a password.")

    if len(password) < v.PASSWORD_MIN:
        raise PasswordPolicyError(
            f"Use at least {v.PASSWORD_MIN} characters. "
            f"A passphrase of a few unrelated words is both stronger and "
            f"easier to remember than a short complex string."
        )

    # An upper bound is a control, not an inconvenience: every submitted
    # candidate is hashed at 64 MiB, so unbounded input is a memory amplifier.
    if len(password) > v.PASSWORD_MAX:
        raise PasswordPolicyError(
            f"Keep it under {v.PASSWORD_MAX} characters."
        )

    if password.lower() in common_passwords():
        raise PasswordPolicyError(
            "That password appears in well-known breach lists and would be "
            "among the first guesses tried. Choose something else."
        )

    if username:
        folded = v.normalize_username(username)
        if folded and folded in password.lower():
            raise PasswordPolicyError(
                "Your password must not contain your username."
            )


def hash_password(password: str) -> str:
    """Hash a password for storage.

    The returned string embeds the algorithm, its parameters and the salt, so
    stored hashes remain verifiable after the cost settings above are raised.
    """
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, candidate: str) -> bool:
    """Verify a candidate against a stored hash in constant-ish time.

    When ``stored_hash`` is None - the username does not exist - a dummy
    verification still runs.  The caller gets False either way, but the two
    paths take comparable time, so timing cannot be used to enumerate accounts
    (T-02).
    """
    if stored_hash is None:
        try:
            _hasher.verify(_DUMMY_HASH, candidate)
        except Exception:
            pass
        return False

    try:
        _hasher.verify(stored_hash, candidate)
        return True
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        logger.error("invalid_password_hash_in_database")
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when a hash predates the current cost parameters.

    Called after a successful login, while the plaintext is briefly available,
    so raising the cost settings silently upgrades every account as its owner
    next signs in - no reset email, no forced rotation.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# ---------------------------------------------------------------------------
# Share PINs
# ---------------------------------------------------------------------------

def hash_share_pin(pin: str) -> str:
    return _hasher.hash(pin)


def verify_share_pin(stored_hash: str | None, candidate: str) -> bool:
    if not stored_hash:
        return False
    try:
        _hasher.verify(stored_hash, candidate)
        return True
    except Exception:
        return False


def constant_time_equals(a: str, b: str) -> bool:
    """Compare two secrets without leaking their common prefix length.

    A plain ``==`` on strings short-circuits at the first differing byte.
    Used for share tokens, where the value is looked up rather than guessed,
    but the habit is worth keeping consistent.
    """
    return hmac.compare_digest(a.encode(), b.encode())
