"""Signing algorithms for the application's self-contained tokens.

Flask's session cookie *is* a self-contained token in the ASVS V9 sense: the
server keeps no session store, so everything the user's identity depends on
travels in the cookie and is trusted because of the MAC over it.  That makes
the MAC's hash function a security parameter rather than an implementation
detail.

Two libraries pick that function for us, and both still default to SHA-1:

* ``flask.sessions.SecureCookieSessionInterface.digest_method`` is
  ``hashlib.sha1``, so the session cookie is signed with HMAC-SHA1;
* ``itsdangerous.Signer.default_digest_method`` is the same, which is what
  Flask-WTF's CSRF serializer inherits when it constructs its own
  ``URLSafeTimedSerializer`` internally - there is no setting to reach it.

HMAC-SHA1 is not *broken* the way bare SHA-1 signatures are: the collision
attacks that killed SHA-1 for certificates do not transfer to HMAC, which is
why NIST still permits HMAC-SHA1.  The reason to move anyway is ASVS 11.4.1,
which asks that only approved hash functions be used for HMAC and digital
signatures, and an auditor reading ``sha1`` in a signing path is right to stop
there.  SHA-256 costs nothing measurable here and removes the question.

**Upgrading logs everybody out once.**  A cookie signed with the old algorithm
fails verification under the new one and is discarded as tampered, which is
the correct outcome - it is not a silent downgrade.  There is deliberately no
"accept either" fallback, because an attacker who can choose the algorithm can
choose the weaker one.
"""

from __future__ import annotations

import hashlib

import itsdangerous
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

#: What every signer in this process must use.
DIGEST = hashlib.sha256
DIGEST_NAME = "sha256"


class Sha256SessionInterface(SecureCookieSessionInterface):
    """The stock cookie session, signed with HMAC-SHA256 instead of HMAC-SHA1."""

    digest_method = staticmethod(DIGEST)

    #: A distinct salt as well as a distinct digest.  Changing only the digest
    #: would leave old and new cookies addressing the same derived key; a new
    #: salt means a pre-upgrade cookie cannot even be evaluated against the
    #: post-upgrade key, so "verify it under the old algorithm" is not a thing
    #: an attacker can ask this application to do.
    salt = "doom-cookie-session-v2"


def init_app(app: Flask) -> None:
    """Install SHA-256 signing for the session cookie and for itsdangerous.

    The second half is a class-level default rather than an argument because
    Flask-WTF builds its CSRF serializer inline
    (``URLSafeTimedSerializer(secret_key, salt="wtf-csrf-token")``) and accepts
    no digest parameter.  Raising the library default is the only seam, so it
    is done explicitly, in one place, with a regression test that fails if a
    future release moves the attribute.
    """
    itsdangerous.Signer.default_digest_method = staticmethod(DIGEST)
    app.session_interface = Sha256SessionInterface()
