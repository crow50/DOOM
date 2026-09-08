"""nullable item name, barcode, search indexes

Revision ID: b2d5f8c31e07
Revises: a1c4e7b90d21
"""
import sqlalchemy as sa
from alembic import op

revision = "b2d5f8c31e07"
down_revision = "a1c4e7b90d21"
branch_labels = None
depends_on = None


def upgrade():
    # Name becomes optional: requiring one means requiring a decision before
    # anything can be recorded, which is the bottleneck the product exists to
    # remove. An item needs a name OR a photo, enforced in the view because no
    # single CHECK can see both tables.
    op.alter_column("items", "name", existing_type=sa.String(120), nullable=True)
    op.drop_constraint("ck_items_name_length", "items", type_="check")
    op.create_check_constraint(
        "ck_items_name_length", "items",
        "name IS NULL OR char_length(name) BETWEEN 1 AND 120",
    )

    op.add_column("items", sa.Column("barcode", sa.String(14), nullable=True))
    op.create_index("ix_items_barcode", "items", ["barcode"])
    # Digits only, at the database as well as at the form and the browser.
    # The GS1 GTIN shape is what makes a scanned value safe to handle (T-43).
    op.create_check_constraint(
        "ck_items_barcode_format", "items",
        "barcode IS NULL OR barcode ~ '^[0-9]{8,14}$'",
    )

    # Full-text indexes. Expression indexes rather than generated columns, so
    # no rewrite of existing rows is needed.
    # concat_ws() is not IMMUTABLE and so cannot appear in an index
    # expression; || and coalesce() are. The application builds the identical
    # expression in blueprints/search.py — an expression index is only used
    # when the query matches it exactly.
    op.execute(
        """
        CREATE INDEX ix_items_fts ON items USING GIN (
            to_tsvector('english',
                coalesce(name, '') || ' ' ||
                coalesce(description, '') || ' ' ||
                coalesce(barcode, ''))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_locations_fts ON locations USING GIN (
            to_tsvector('english',
                coalesce(name, '') || ' ' ||
                coalesce(notes, '') || ' ' ||
                coalesce(address, ''))
        )
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_locations_fts")
    op.execute("DROP INDEX IF EXISTS ix_items_fts")
    op.drop_constraint("ck_items_barcode_format", "items", type_="check")
    op.drop_index("ix_items_barcode", table_name="items")
    op.drop_column("items", "barcode")
    op.drop_constraint("ck_items_name_length", "items", type_="check")
    op.create_check_constraint(
        "ck_items_name_length", "items",
        "char_length(name) BETWEEN 1 AND 120",
    )
    op.execute("UPDATE items SET name = 'Unnamed' WHERE name IS NULL")
    op.alter_column("items", "name", existing_type=sa.String(120), nullable=False)
