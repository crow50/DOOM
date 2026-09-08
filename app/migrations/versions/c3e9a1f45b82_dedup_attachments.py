"""allow several attachment rows to share one stored blob

Revision ID: c3e9a1f45b82
Revises: b2d5f8c31e07
"""
import sqlalchemy as sa
from alembic import op

revision = "c3e9a1f45b82"
down_revision = "b2d5f8c31e07"
branch_labels = None
depends_on = None


def upgrade():
    # stored_name was unique when one row meant one file. Deduplication makes
    # that wrong: the same photo attached to two items should cost one blob.
    # Content uniqueness is what sha256 gives us; this column is a pointer.
    op.drop_constraint("attachments_stored_name_key", "attachments", type_="unique")
    op.create_index("ix_attachments_stored_name", "attachments", ["stored_name"])
    # Supports the dedup lookup: has this owner already stored these bytes?
    op.create_index(
        "ix_attachments_owner_sha", "attachments", ["owner_id", "sha256"]
    )


def downgrade():
    op.drop_index("ix_attachments_owner_sha", table_name="attachments")
    op.drop_index("ix_attachments_stored_name", table_name="attachments")
    op.create_unique_constraint(
        "attachments_stored_name_key", "attachments", ["stored_name"]
    )
