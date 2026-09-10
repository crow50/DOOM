"""Tamper-evident audit trail.

Records security-relevant events to the database, not only to the log stream.
Logs rotate and are often shipped elsewhere; the audit table is queryable
alongside the data it describes, which is what makes "who moved this, and when"
answerable after the fact (T-16).

Denied access is recorded as well as granted.  A single 404 is noise; forty in
a minute against well-formed UUIDs is enumeration, and that pattern only exists
if the misses were written down.

**Why the rows are chained (T-45).**

An audit trail that the application can rewrite proves very little.  Two
mechanisms harden it, and they work at different layers:

* ``UPDATE`` and ``DELETE`` are revoked on ``audit_log`` for the application's
  database role, so even a complete SQL injection through the app cannot rewrite
  history — only append to it.  The revoke lives in migration
  ``a1c4e7b90d21``, **not** in ``db/init/01-roles.sh``: that script grants the
  role the broad SELECT/INSERT/UPDATE/DELETE default, and this table is the one
  exception carved out of it afterwards.  Two consequences worth knowing: a
  deployment that initialises the database but never migrates leaves the role
  holding both verbs, and that migration's ``downgrade()`` re-grants them.
  Scope is exactly this table; every other table keeps full DML.
* Each row stores the hash of the previous one, so removing or editing any row
  invalidates every hash after it.  ``flask audit-verify`` finds the break.

This is tamper-**evident**, not tamper-**proof**.  Someone holding both database
access and the source can recompute the entire chain.  What it defeats is
*silent selective editing* — quietly deleting the row that recorded an
inconvenient action — which is the realistic insider threat and the one
warehouse operations actually design against.  Noting the head hash somewhere
outside the system closes the remaining gap cheaply; the account page shows it
for that purpose.

Maps to NIST SP 800-53 AU-9 and OWASP ASVS V7.3.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import has_request_context, request
from flask_login import current_user
from sqlalchemy import func, select, text

from ..extensions import db

logger = logging.getLogger(__name__)

#: Advisory lock key for serialising chain appends. Any constant works; it only
#: has to be the same everywhere.
_CHAIN_LOCK_KEY = 0x0D00_4D17


def _chain_head():
    """Current tail of the chain, or None when the log is empty."""
    from ..models import AuditLog

    return db.session.execute(
        select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
    ).scalar_one_or_none()


def record_audit(
    *,
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    detail: str | None = None,
    actor_id=None,
    commit: bool = False,
) -> None:
    """Append an audit row, linked to the one before it.

    Never raises.  An audit failure must not be able to break the request it is
    describing — a logging bug that turns a successful login into a 500 would
    be a self-inflicted denial of service.
    """
    from ..models import GENESIS_HASH, AuditLog, utcnow

    try:
        actor_username = None
        if actor_id is None and has_request_context():
            if getattr(current_user, "is_authenticated", False):
                actor_id = current_user.id
                actor_username = current_user.username
        elif actor_id is not None:
            actor_username = _username_for(actor_id)

        # Serialise appends. Two concurrent writers would otherwise read the
        # same head and produce two rows claiming the same predecessor, forking
        # the chain and making verification fail on honest data. The lock is
        # transaction-scoped, so it releases on commit or rollback either way.
        db.session.execute(
            text("SELECT pg_advisory_xact_lock(:key)").bindparams(
                key=_CHAIN_LOCK_KEY
            )
        )

        head = _chain_head()
        next_seq = (head.seq + 1) if head else 1
        prev_hash = head.row_hash if head else GENESIS_HASH

        entry = AuditLog(
            actor_user_id=actor_id,
            actor_username=(actor_username or None),
            action=action[:64],
            object_type=object_type[:32] if object_type else None,
            object_id=object_id[:64] if object_id else None,
            detail=detail[:500] if detail else None,
            # Trustworthy only because ProxyFix rewrites remote_addr from the
            # single X-Forwarded-For hop Caddy overwrites (T-07).
            ip=request.remote_addr if has_request_context() else None,
            seq=next_seq,
            prev_hash=prev_hash,
            created_at=utcnow(),
        )
        # Hashed before insert: the digest covers the values actually written.
        entry.row_hash = entry.compute_hash()

        db.session.add(entry)

        # Usually left to the caller's transaction so the audit row commits
        # atomically with the change it describes. Failed logins pass
        # commit=True because there is no other write to ride along with.
        if commit:
            db.session.commit()

    except Exception:
        logger.exception(
            "audit_write_failed", extra={"extra_fields": {"action": action}}
        )
        try:
            db.session.rollback()
        except Exception:
            pass


def _username_for(actor_id) -> str | None:
    from ..models import User

    try:
        user = db.session.get(User, actor_id)
        return user.username if user else None
    except Exception:
        return None


def verify_chain(limit: int | None = None) -> dict[str, Any]:
    """Walk the chain and report the first divergence.

    Returns a summary rather than raising, so the CLI can print something
    useful either way.
    """
    from ..models import GENESIS_HASH, AuditLog

    query = select(AuditLog).order_by(AuditLog.seq)
    if limit:
        query = query.limit(limit)

    rows = db.session.execute(query).scalars().all()

    total = db.session.scalar(select(func.count()).select_from(AuditLog)) or 0
    if not rows:
        return {"ok": True, "checked": 0, "total": total, "head": None, "problem": None}

    expected_prev = GENESIS_HASH
    expected_seq = rows[0].seq

    for row in rows:
        if row.seq != expected_seq:
            return {
                "ok": False, "checked": expected_seq, "total": total, "head": None,
                "problem": (
                    f"sequence break at {row.seq}: expected {expected_seq}. "
                    f"Either a row was removed, or one was appended with a "
                    f"forged sequence number."
                ),
            }
        if row.prev_hash != expected_prev:
            return {
                "ok": False, "checked": row.seq, "total": total, "head": None,
                "problem": (
                    f"broken link at seq {row.seq}: this row names a "
                    f"predecessor hash that is not the previous row. It was "
                    f"written outside the application."
                ),
            }
        if row.compute_hash() != row.row_hash:
            return {
                "ok": False, "checked": row.seq, "total": total, "head": None,
                "problem": (
                    f"content altered at seq {row.seq} "
                    f"({row.created_at.isoformat()}, action '{row.action}'): "
                    f"the stored hash does not match the row's contents."
                ),
            }
        expected_prev = row.row_hash
        expected_seq = row.seq + 1

    return {
        "ok": True,
        "checked": len(rows),
        "total": total,
        "head": rows[-1].row_hash,
        "problem": None,
    }


def chain_head_hash() -> str | None:
    """Head hash, for the user to note somewhere outside the system.

    That external note is what upgrades this from "detects careless tampering"
    to "detects tampering by someone who can also rewrite the chain".
    """
    head = _chain_head()
    return head.row_hash if head else None
