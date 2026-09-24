"""Second factor: TOTP enrolment and single-use recovery codes.

The first incremental revision since the squashed baseline, and deliberately
so. D-38 squashed seven migrations into one regenerated baseline and set the
condition for stopping: "start keeping real history at the first deployment
that holds data somebody would miss... practically, that is the first tagged
release". v0.1.0 is tagged and published, so this is written as a migration
rather than folded into the baseline.

It is additive only. Every column is nullable and the new table is new, so an
existing database moves forward without touching a row, and every account stays
exactly as single-factor as it was until somebody enrols.

Revision ID: 8f21c4a9de07
Revises: 372bba4db7ea
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from alembic import op

revision = "8f21c4a9de07"
down_revision = "372bba4db7ea"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.String(length=64), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))

    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_recovery_codes_user_id"), "recovery_codes", ["user_id"], unique=False
    )


def downgrade() -> None:
    """Reversible, and note what that means here.

    Dropping these columns disables the second factor for every account that
    had one, silently. That is the correct behaviour for a schema rollback -
    the alternative is an account whose login demands a code the database can
    no longer verify - but it is a security-relevant downgrade, so it is stated
    rather than left to be discovered.
    """
    op.drop_index(op.f("ix_recovery_codes_user_id"), table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_column("users", "totp_last_step")
    op.drop_column("users", "totp_confirmed_at")
    op.drop_column("users", "totp_secret")
