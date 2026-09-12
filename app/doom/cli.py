"""Operator commands.

Recovery lives here rather than in an email flow.  DOOM is self-hosted and
cannot assume SMTP, and a self-service password reset is the most attacked
path in web authentication - it is an unauthenticated endpoint that, by
design, hands out account access.  Declining to build one and pointing the
operator at a shell command is a deliberate reduction in attack surface,
recorded in docs/DECISIONS.md.
"""

from __future__ import annotations

import click
from flask import Flask
from sqlalchemy import select

from . import validation as v
from .extensions import db
from .models import Item, Location, User, utcnow
from .security.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
)


def register_cli(app: Flask) -> None:

    @app.cli.command("unlock-user")
    @click.argument("username")
    def unlock_user(username: str) -> None:
        """Clear a lockout immediately.

        Rarely needed: lockouts expire on their own within fifteen minutes by
        design (T-31).  This exists for the operator who does not want to
        wait.
        """
        name = v.normalize_username(username)
        user = db.session.execute(
            select(User).where(User.username == name)
        ).scalar_one_or_none()

        if user is None:
            click.echo(f"No such user: {name}")
            raise SystemExit(1)

        user.failed_login_count = 0
        user.locked_until = None
        db.session.commit()
        click.echo(f"Unlocked {name}.")

    @app.cli.command("set-password")
    @click.argument("username")
    @click.password_option()
    def set_password(username: str, password: str) -> None:
        """Set a password directly. The operator's recovery path."""
        name = v.normalize_username(username)
        user = db.session.execute(
            select(User).where(User.username == name)
        ).scalar_one_or_none()

        if user is None:
            click.echo(f"No such user: {name}")
            raise SystemExit(1)

        try:
            check_policy(password, username=name)
        except PasswordPolicyError as exc:
            click.echo(f"Rejected: {exc}")
            raise SystemExit(1) from exc

        user.password_hash = hash_password(password)
        # Every existing session dies with the old password (T-06).
        user.session_version += 1
        user.failed_login_count = 0
        user.locked_until = None
        db.session.commit()
        click.echo(f"Password updated for {name}. All sessions invalidated.")

    @app.cli.command("audit-verify")
    @click.option("--limit", type=int, default=None,
                  help="Check only the first N rows.")
    def audit_verify(limit: int | None) -> None:
        """Verify the audit hash chain.

        Reports the first divergence, if any, and prints the head hash. Note
        that hash somewhere outside this system: doing so is what makes the
        chain evidence against someone who could otherwise recompute it.
        """
        from .security.audit import verify_chain

        result = verify_chain(limit=limit)

        if result["ok"]:
            click.echo(f"Audit chain intact: {result['checked']} of "
                       f"{result['total']} rows verified.")
            if result["head"]:
                click.echo(f"Head hash: {result['head']}")
                click.echo("Record that hash somewhere outside this system.")
            return

        click.echo("AUDIT CHAIN BROKEN")
        click.echo(f"  {result['problem']}")
        click.echo(f"  verified {result['checked']} of {result['total']} rows")
        raise SystemExit(2)

    @app.cli.command("db-grants")
    def db_grants() -> None:
        """Apply the privilege rules that are not schema.

        These used to live inside a schema migration, which was a bad home for
        them in two ways.  They depended on a *particular revision*
        having run, so a database initialised but never migrated had a fully
        writable audit log; and that revision's ``downgrade()`` handed the verbs
        back, so rolling back one schema change quietly removed a security
        control.  Now that the migration history is a single regenerable
        baseline (D-38), anything durable has to live outside it entirely.

        Idempotent by construction, and run by ``make upgrade`` after
        ``flask db upgrade``.  ``make verify-db-roles`` proves the outcome.
        """
        import os

        from sqlalchemy import text

        app_user = os.environ.get("APP_DB_USER", "doom_app")

        # citext is created by db/init/01-roles.sh at first initialisation, but
        # the users table declares a CITEXT column, so saying it here too costs
        # nothing and removes a hidden ordering dependency between the two.
        db.session.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))

        # The load-bearing one (T-45, D-33).  REVOKE is idempotent: revoking a
        # privilege the role does not hold is a no-op, not an error.
        db.session.execute(
            text(f'REVOKE UPDATE, DELETE ON audit_log FROM "{app_user}"')
        )
        db.session.commit()

        click.echo(f"Applied privilege rules: audit_log is append-only for '{app_user}'.")

    @app.cli.command("seed")
    def seed() -> None:
        """Create a demo account and a small warehouse tree."""
        existing = db.session.execute(
            select(User).where(User.username == "demo")
        ).scalar_one_or_none()

        if existing is not None:
            click.echo("Demo data already present.")
            return

        user = User(
            username="demo",
            password_hash=hash_password("correct-horse-battery-staple"),
            last_login_at=utcnow(),
        )
        db.session.add(user)
        db.session.flush()

        # Demonstrates all four tiers, including a shelf sitting directly in a
        # zone (no intervening building) and an item parked straight in a zone -
        # both legal, and both impossible under the old kind restrictions.
        tree = {
            "Elm Street Yard": {
                "kind": "site",
                "address": "12 Elm Street, Springfield",
                "children": {
                    "North Garage": {
                        "kind": "zone",
                        "children": {
                            "Rack A": {
                                "kind": "shelf",
                                "children": {
                                    "Tote A1": {"kind": "bin", "items": [
                                        ("Cordless drill", "18V, two batteries", 1),
                                        ("Drill bit set", "Titanium, 29 piece", 1),
                                    ]},
                                    "Tote A2": {"kind": "bin", "items": [
                                        ("Extension cords", "15m, outdoor rated", 4),
                                    ]},
                                },
                            },
                        },
                    },
                    "Back Yard": {
                        "kind": "zone",
                        # An item directly in a zone, and a shelf standing
                        # outdoors - flammables racked in the open.
                        "items": [("Ride-on mower", "Needs a service", 1)],
                        "children": {
                            "Flammables rack": {"kind": "shelf", "items": [
                                ("Petrol cans", "20L, full", 2),
                            ]},
                        },
                    },
                },
            },
            "Workshop Store": {
                "kind": "zone",
                "children": {
                    "Shelf 1": {"kind": "shelf", "items": [
                        ("Wood screws", "4x40mm, boxed", 800),
                        ("Safety goggles", "Impact rated", 6),
                    ]},
                },
            },
        }

        def build(name: str, spec: dict, parent: Location | None, depth: int) -> None:
            node = Location(
                owner_id=user.id,
                parent_id=parent.id if parent else None,
                kind=spec.get("kind", "bin"),
                name=name,
                address=spec.get("address"),
                depth=depth,
            )
            db.session.add(node)
            db.session.flush()

            for item_name, description, qty in spec.get("items", []):
                db.session.add(
                    Item(
                        owner_id=user.id,
                        location_id=node.id,
                        name=item_name,
                        description=description,
                        quantity=qty,
                    )
                )

            for child_name, child_spec in spec.get("children", {}).items():
                build(child_name, child_spec, node, depth + 1)

        for root_name, root_spec in tree.items():
            build(root_name, root_spec, None, 0)

        db.session.commit()
        click.echo("Seeded demo account.")
        click.echo("  username: demo")
        click.echo("  password: correct-horse-battery-staple")
