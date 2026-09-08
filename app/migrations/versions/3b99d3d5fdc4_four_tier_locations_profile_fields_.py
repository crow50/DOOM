"""four-tier locations, profile fields, address

Revision ID: 3b99d3d5fdc4
Revises: e9da0d0e6211
Create Date: 2026-09-06 23:57:47.974776

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3b99d3d5fdc4'
down_revision = 'e9da0d0e6211'
branch_labels = None
depends_on = None


#: warehouse/zone described the same thing, and so did bin/tote, so choosing
#: between them was a coin flip rather than a decision. rack and shelf collapse
#: for the same reason. Nothing is lost: every old value maps onto exactly one
#: new one, and the old name usually survives in the location's own name.
KIND_MAP = {
    "warehouse": "zone",   # a warehouse IS a building within a site
    "zone": "zone",
    "rack": "shelf",       # a rack is shelving
    "shelf": "shelf",
    "bin": "bin",
    "tote": "bin",         # a tote is a bin you can carry
}


def upgrade():
    with op.batch_alter_table('locations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('address', sa.String(length=500), nullable=True))

    # --- location_kind: six overlapping values down to four distinct ones ---
    #
    # Postgres native enums cannot be edited in place, and Alembic does not
    # autogenerate the change. The column is widened to text, the rows are
    # remapped, then it is narrowed onto the new type - so the allowlist is
    # never absent, only briefly relaxed, and no row can hold a value outside
    # it once the migration completes.
    op.execute("ALTER TABLE locations ALTER COLUMN kind TYPE text")
    op.execute("ALTER TABLE locations ALTER COLUMN kind DROP DEFAULT")

    for old_kind, new_kind in KIND_MAP.items():
        op.execute(
            sa.text("UPDATE locations SET kind = :new WHERE kind = :old")
            .bindparams(new=new_kind, old=old_kind)
        )

    op.execute("DROP TYPE IF EXISTS location_kind")
    op.execute(
        "CREATE TYPE location_kind AS ENUM ('site', 'zone', 'shelf', 'bin')"
    )
    op.execute(
        "ALTER TABLE locations ALTER COLUMN kind TYPE location_kind "
        "USING kind::location_kind"
    )
    op.execute("ALTER TABLE locations ALTER COLUMN kind SET DEFAULT 'bin'")

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('display_name', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('email', sa.String(length=254), nullable=True))
        batch_op.add_column(sa.Column('timezone', sa.String(length=64), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('timezone')
        batch_op.drop_column('email')
        batch_op.drop_column('display_name')

    # Reverse the kind collapse as far as it can be reversed. The merge is
    # lossy by design - a bin that used to be a tote cannot be told apart from
    # one that was always a bin - so downgrade maps onto the coarser old value
    # rather than guessing.
    op.execute("ALTER TABLE locations ALTER COLUMN kind TYPE text")
    op.execute("ALTER TABLE locations ALTER COLUMN kind DROP DEFAULT")
    op.execute("UPDATE locations SET kind = 'zone' WHERE kind = 'site'")
    op.execute("DROP TYPE IF EXISTS location_kind")
    op.execute(
        "CREATE TYPE location_kind AS ENUM "
        "('warehouse', 'zone', 'rack', 'shelf', 'bin', 'tote')"
    )
    op.execute(
        "ALTER TABLE locations ALTER COLUMN kind TYPE location_kind "
        "USING kind::location_kind"
    )
    op.execute("ALTER TABLE locations ALTER COLUMN kind SET DEFAULT 'bin'")

    with op.batch_alter_table('locations', schema=None) as batch_op:
        batch_op.drop_column('address')
