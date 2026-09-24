"""Time-based one-time passwords (RFC 6238), implemented here rather than added.

**Why not a library.** The whole of TOTP is an HMAC, a counter and a modulo,
and every part of it is in the standard library. A dependency for thirty lines
buys a supply-chain surface, a lockfile entry to keep current and a transitive
tree to scan, in exchange for code that is shorter than the code that would
import it. The reason this is safe to write by hand is that RFC 4226 and
RFC 6238 publish test vectors, so "did I get it right" is a question with an
answer rather than an opinion - see tests/test_totp.py, which runs all of them.

**What this is and is not.** A TOTP code is a second factor: something the user
has, in the sense that it is derived from a secret their authenticator holds.
It is not phishing-resistant - a user can be talked into reading a code aloud,
which is why ASVS reserves hardware-backed factors for L3 - and it is not a
substitute for the password, which is still verified first.

**The replay window is the part people get wrong.** A code is valid for a
thirty-second step, and clocks drift, so verification has to accept a small
number of neighbouring steps. Every accepted step is also a window in which a
captured code can be replayed, so the tolerance is one step either side - the
RFC's own recommendation - and the caller records the step that was consumed so
the same code cannot be used twice even inside its own validity period.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

#: Seconds per step. RFC 6238's default, and what every authenticator assumes.
STEP_SECONDS = 30

#: Digits in a code. Six, because that is what authenticators display.
DIGITS = 6

#: How many steps either side of the current one are accepted.
#:
#: One. That tolerates roughly thirty seconds of clock drift in each direction,
#: which covers a phone that has not synchronised recently, and keeps the
#: replay window to ninety seconds rather than the several minutes a larger
#: tolerance would open.
DRIFT_STEPS = 1

#: 160 bits, which is the RFC 4226 recommendation and the size HMAC-SHA1's
#: block structure is built around. Note that the *secret* is 160 bits; the
#: MAC below is SHA-1 because every authenticator application implements
#: exactly that and interoperability is the point - a TOTP secret is not a
#: signing key, and HMAC-SHA1 is not broken as a MAC. This is the one place in
#: the codebase where SHA-1 appears, it is confined to this function, and
#: docs/security/POLICIES.md section 6 records why.
SECRET_BYTES = 20


def new_secret() -> str:
    """A fresh base32 secret, in the form authenticators expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _hotp(key: bytes, counter: int, *, digits: int = DIGITS,
          digest=hashlib.sha1) -> str:
    """RFC 4226 HOTP. The dynamic truncation is the fiddly half."""
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def _decode(secret: str) -> bytes:
    """Base32 without requiring the caller to have kept the padding."""
    cleaned = secret.strip().replace(" ", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def code_at(secret: str, *, at: float | None = None, step: int | None = None,
            digits: int = DIGITS, digest=hashlib.sha1) -> str:
    """The code for one step. Exposed for tests and for enrolment confirmation."""
    if step is None:
        step = int((time.time() if at is None else at) // STEP_SECONDS)
    return _hotp(_decode(secret), step, digits=digits, digest=digest)


def verify(secret: str, candidate: str, *, at: float | None = None,
           last_step: int | None = None) -> int | None:
    """Check a submitted code; return the step it consumed, or None.

    Returning the step rather than a boolean is what lets the caller close the
    replay window: it stores the value and refuses anything at or below it next
    time, so a code observed over a shoulder - or read out of a phishing page -
    cannot be presented a second time while it is still nominally valid.

    Comparison is constant-time. The value being compared is short-lived and
    guessable at one in a million, so a timing oracle on it is not the most
    pressing risk here, but a non-constant comparison in an authentication path
    is the kind of thing that is correct until the code around it changes.
    """
    if not secret or not candidate:
        return None

    cleaned = "".join(character for character in candidate if character.isdigit())
    if len(cleaned) != DIGITS:
        return None

    now = time.time() if at is None else at
    current = int(now // STEP_SECONDS)

    for offset in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        step = current + offset
        if last_step is not None and step <= last_step:
            # Already used, or older than one that was. Not an error the user
            # can act on, and deliberately indistinguishable from a wrong code.
            continue
        if hmac.compare_digest(code_at(secret, step=step), cleaned):
            return step
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The otpauth:// URI an authenticator reads out of a QR code.

    Both labels are percent-encoded: a username reaches this function from the
    database, and a colon or a slash in one would otherwise restructure the URI
    - the label is issuer-colon-account by convention, so a colon in the
    account name moves the boundary.
    """
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={quote(secret, safe='')}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
