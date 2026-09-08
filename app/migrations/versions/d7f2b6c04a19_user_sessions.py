"""per-device sessions (ASVS 3.3.4)

Revision ID: d7f2b6c04a19
Revises: c3e9a1f45b82
"""
import sqlalchemy as sa
from alembic import op

revision = "d7f2b6c04a19"
down_revision = "c3e9a1f45b82"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(200), nullable=True),
        # Revoked rather than deleted: "this session was ended, and when" is
        # itself worth keeping.
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_user_sessions_user", "user_sessions", ["user_id", "revoked_at"]
    )


def downgrade():
    op.drop_index("ix_user_sessions_user", table_name="user_sessions")
    op.drop_table("user_sessions")
