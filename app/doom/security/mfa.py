"""Second-factor helpers: recovery codes, and the rules around them.

TOTP arithmetic lives in :mod:`doom.security.totp`. This module is about the
part that decides whether a second factor is usable in practice rather than
merely present: what happens when the phone is gone.

Recovery codes are credentials and are treated as such - Argon2id hashed, one
row each, shown exactly once, single use. Two properties are worth stating
because both are easy to lose:

* a spent code is **marked**, not deleted, so "this account burned four
  recovery codes last night" survives as evidence. A stolen set looks like
  nothing at all if the rows disappear as they are used;
* verification walks every unspent row rather than stopping at the first
  mismatch, so the time a rejection takes does not depend on how far down the
  list a near-miss sat.
"""

from __future__ import annotations

import logging
import secrets

from argon2.exceptions import InvalidHashError, VerifyMismatchError

from ..extensions import db
from ..models import RecoveryCode, utcnow
from .passwords import _hasher

logger = logging.getLogger(__name__)

#: How many codes are issued at a time.
#:
#: Ten. Enough that losing a printout mid-set is not an emergency, few enough
#: that the whole set fits on one line of a wallet card and a user notices if
#: several are already gone.
CODE_COUNT = 10

#: Bytes of entropy per code. 8 bytes is 64 bits, rendered as 13 base32-ish
#: characters. These are rate-limited, server-side, single-use secrets rather
#: than offline-crackable ones, and a code a person has to read off paper and
#: type on a phone has a usability ceiling that 64 bits sits comfortably under.
CODE_BYTES = 8

#: Characters that survive being read off paper. No 0/O, no 1/l/I.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _format(raw: bytes) -> str:
    """Render bytes as a grouped, unambiguous string: XXXX-XXXX-XXXX."""
    value = int.from_bytes(raw, "big")
    characters = []
    for _ in range(12):
        value, index = divmod(value, len(_ALPHABET))
        characters.append(_ALPHABET[index])
    body = "".join(characters)
    return "-".join(body[i:i + 4] for i in range(0, 12, 4))


def normalize(candidate: str) -> str:
    """What the user typed, reduced to what was issued.

    Dashes, spaces and case are all things a person adds or drops while copying
    twelve characters off paper, and none of them carries meaning.
    """
    return "".join(
        character for character in (candidate or "").upper()
        if character in _ALPHABET
    )


def issue(user) -> list[str]:
    """Replace this account's recovery codes, returning the new plaintext set.

    Replace, not append: a fresh set means the old ones stop working, which is
    the behaviour somebody regenerating them after a scare is asking for. The
    caller is responsible for showing the returned list once and never storing
    it - it is not recoverable from the database afterwards.
    """
    for existing in list(user.recovery_codes):
        db.session.delete(existing)

    plaintext = [_format(secrets.token_bytes(CODE_BYTES)) for _ in range(CODE_COUNT)]
    for code in plaintext:
        db.session.add(
            RecoveryCode(user_id=user.id, code_hash=_hasher.hash(normalize(code)))
        )

    logger.info(
        "recovery_codes_issued",
        extra={"extra_fields": {"user_id": str(user.id), "count": len(plaintext)}},
    )
    return plaintext


def remaining(user) -> int:
    """How many unspent codes this account still has."""
    return sum(1 for code in user.recovery_codes if not code.is_spent)


def consume(user, candidate: str) -> bool:
    """Spend one recovery code, or return False.

    Every unspent row is checked even after a match, so the work done does not
    reveal the matching row's position. That costs one Argon2id verification
    per unspent code - ten at most, and only on a path that is already rate
    limited - which is the right price for not leaking it.
    """
    cleaned = normalize(candidate)
    if not cleaned:
        return False

    matched = None
    for row in user.recovery_codes:
        if row.is_spent:
            continue
        try:
            if _hasher.verify(row.code_hash, cleaned) and matched is None:
                matched = row
        except VerifyMismatchError:
            continue
        except InvalidHashError:
            # Same distinction verify_password() draws: a mismatch is this
            # row not being the one, expected on every failed guess. A
            # malformed hash is data corruption, not a wrong guess, and
            # silently treating the two alike would hide the difference
            # between "no recovery code matched" and "a stored one is
            # unreadable" behind an identical False.
            logger.error(
                "invalid_recovery_code_hash",
                extra={"extra_fields": {"user_id": str(user.id)}},
            )
            continue

    if matched is None:
        return False

    matched.used_at = utcnow()
    logger.info(
        "recovery_code_consumed",
        extra={"extra_fields": {
            "user_id": str(user.id), "remaining": remaining(user) - 1,
        }},
    )
    return True
