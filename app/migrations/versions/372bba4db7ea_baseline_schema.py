"""baseline schema

Squashed from the seven incremental revisions that preceded it
(e9da0d0e6211 .. d7f2b6c04a19). Those revisions carried the schema's history:
an enum widening, a four-tier location rework that translated existing rows, a
checkouts table, the audit hash chain, barcode columns, attachment dedup and
per-device sessions. None of that history was protecting a database anybody
still had - the only deployments were development ones that get recreated - so
it was noise in every diff. See D-38 for the reasoning and for when to stop
regenerating this file and start keeping history again.

Generated from doom.models, so this file is the schema and nothing else. The
privilege rules that used to live in a1c4e7b90d21 - the audit_log REVOKE above
all - are deliberately NOT here: they now live in `flask db-grants`, because
anything durable cannot sit in a file that gets regenerated. `make upgrade`
runs both.

Revision ID: 372bba4db7ea
Revises:
Create Date: 2026-09-12 13:22:42.147926
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "372bba4db7ea"
down_revision = None
branch_labels = None
depends_on = None

#: Postgres enum types are created implicitly by the CREATE TABLE that first
#: references them, but they are not dropped implicitly - so downgrade has to
#: name them or a second upgrade fails with "type already exists".
ENUM_TYPES = ("location_kind", "visibility_level", "attachment_kind")


def upgrade():
    op.create_table('audit_log',
    sa.Column('actor_user_id', sa.UUID(), nullable=True),
    sa.Column('actor_username', sa.String(length=32), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('object_type', sa.String(length=32), nullable=True),
    sa.Column('object_id', sa.String(length=64), nullable=True),
    sa.Column('detail', sa.String(length=500), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('seq', sa.BigInteger(), nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('row_hash', sa.String(length=64), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('seq')
    )
    op.create_index('ix_audit_action_created', 'audit_log', ['action', 'created_at'], unique=False)
    op.create_index('ix_audit_actor_created', 'audit_log', ['actor_user_id', 'created_at'], unique=False)
    op.create_index('ix_audit_seq', 'audit_log', ['seq'], unique=False)
    op.create_table('users',
    sa.Column('username', postgresql.CITEXT(), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('session_version', sa.Integer(), nullable=False),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('display_name', sa.String(length=80), nullable=True),
    sa.Column('email', sa.String(length=254), nullable=True),
    sa.Column('timezone', sa.String(length=64), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('char_length(username) BETWEEN 3 AND 32', name='ck_users_username_length'),
    sa.CheckConstraint('failed_login_count >= 0', name='ck_users_failed_count'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('locations',
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('parent_id', sa.UUID(), nullable=True),
    sa.Column('kind', sa.Enum('site', 'zone', 'shelf', 'bin', name='location_kind'), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('address', sa.String(length=500), nullable=True),
    sa.Column('depth', sa.Integer(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('visibility', sa.Enum('private', 'shared', name='visibility_level'), nullable=False),
    sa.Column('share_token', sa.String(length=64), nullable=True),
    sa.Column('short_code', sa.String(length=16), nullable=True),
    sa.Column('share_pin_hash', sa.String(length=255), nullable=True),
    sa.CheckConstraint('char_length(name) BETWEEN 1 AND 120', name='ck_locations_name_length'),
    sa.CheckConstraint('depth BETWEEN 0 AND 12', name='ck_locations_depth'),
    sa.CheckConstraint('id <> parent_id', name='ck_locations_not_self_parent'),
    sa.CheckConstraint('notes IS NULL OR char_length(notes) <= 4000', name='ck_locations_notes_length'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_id'], ['locations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('share_token'),
    sa.UniqueConstraint('short_code')
    )
    op.create_index('ix_locations_owner_parent', 'locations', ['owner_id', 'parent_id'], unique=False)
    op.create_table('user_sessions',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=200), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_sessions_user', 'user_sessions', ['user_id', 'revoked_at'], unique=False)
    op.create_table('items',
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('location_id', sa.UUID(), nullable=True),
    sa.Column('name', sa.String(length=120), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('barcode', sa.String(length=14), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('visibility', sa.Enum('private', 'shared', name='visibility_level'), nullable=False),
    sa.Column('share_token', sa.String(length=64), nullable=True),
    sa.Column('short_code', sa.String(length=16), nullable=True),
    sa.Column('share_pin_hash', sa.String(length=255), nullable=True),
    sa.CheckConstraint("barcode IS NULL OR barcode ~ '^[0-9]{8,14}$'", name='ck_items_barcode_format'),
    sa.CheckConstraint('description IS NULL OR char_length(description) <= 4000', name='ck_items_description_length'),
    sa.CheckConstraint('name IS NULL OR char_length(name) BETWEEN 1 AND 120', name='ck_items_name_length'),
    sa.CheckConstraint('quantity BETWEEN 0 AND 1000000', name='ck_items_quantity_range'),
    sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('share_token'),
    sa.UniqueConstraint('short_code')
    )
    op.create_index(op.f('ix_items_barcode'), 'items', ['barcode'], unique=False)
    op.create_index('ix_items_owner_location', 'items', ['owner_id', 'location_id'], unique=False)
    op.create_table('attachments',
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('item_id', sa.UUID(), nullable=True),
    sa.Column('location_id', sa.UUID(), nullable=True),
    sa.Column('kind', sa.Enum('photo', 'document', name='attachment_kind'), nullable=False),
    sa.Column('stored_name', sa.String(length=80), nullable=False),
    sa.Column('thumbnail_name', sa.String(length=80), nullable=True),
    sa.Column('original_name', sa.String(length=255), nullable=False),
    sa.Column('content_type', sa.String(length=80), nullable=False),
    sa.Column('byte_size', sa.BigInteger(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint('byte_size > 0 AND byte_size <= 10485760', name='ck_attachments_size'),
    sa.CheckConstraint('num_nonnulls(item_id, location_id) = 1', name='ck_attachments_one_target'),
    sa.ForeignKeyConstraint(['item_id'], ['items.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attachments_item', 'attachments', ['item_id'], unique=False)
    op.create_index('ix_attachments_location', 'attachments', ['location_id'], unique=False)
    op.create_index('ix_attachments_owner_sha', 'attachments', ['owner_id', 'sha256'], unique=False)
    op.create_index(op.f('ix_attachments_stored_name'), 'attachments', ['stored_name'], unique=False)
    op.create_table('checkouts',
    sa.Column('item_id', sa.UUID(), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('holder_name', sa.String(length=120), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('from_location_id', sa.UUID(), nullable=True),
    sa.Column('checked_out_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('due_back_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('returned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('note', sa.String(length=300), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint('char_length(holder_name) BETWEEN 1 AND 120', name='ck_checkouts_holder_length'),
    sa.CheckConstraint('quantity BETWEEN 1 AND 1000000', name='ck_checkouts_quantity'),
    sa.CheckConstraint('returned_at IS NULL OR returned_at >= checked_out_at', name='ck_checkouts_return_after_issue'),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['from_location_id'], ['locations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['item_id'], ['items.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_checkouts_item_open', 'checkouts', ['item_id', 'returned_at'], unique=False)
    op.create_table('doc_links',
    sa.Column('item_id', sa.UUID(), nullable=True),
    sa.Column('location_id', sa.UUID(), nullable=True),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('url', sa.String(length=2000), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("url LIKE 'http://%%' OR url LIKE 'https://%%'", name='ck_doc_links_url_scheme'),
    sa.CheckConstraint('num_nonnulls(item_id, location_id) = 1', name='ck_doc_links_one_target'),
    sa.ForeignKeyConstraint(['item_id'], ['items.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('movements',
    sa.Column('item_id', sa.UUID(), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('from_location_id', sa.UUID(), nullable=True),
    sa.Column('to_location_id', sa.UUID(), nullable=True),
    sa.Column('delta_qty', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(length=200), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['from_location_id'], ['locations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['item_id'], ['items.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['to_location_id'], ['locations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_movements_item_created', 'movements', ['item_id', 'created_at'], unique=False)
    op.create_table('nfc_tags',
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('item_id', sa.UUID(), nullable=True),
    sa.Column('location_id', sa.UUID(), nullable=True),
    sa.Column('tag_uid', sa.String(length=64), nullable=False),
    sa.Column('written_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint('num_nonnulls(item_id, location_id) = 1', name='ck_nfc_tags_one_target'),
    sa.ForeignKeyConstraint(['item_id'], ['items.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('owner_id', 'tag_uid', name='uq_nfc_tags_owner_uid')
    )


def downgrade():
    op.drop_table('nfc_tags')
    op.drop_index('ix_movements_item_created', table_name='movements')
    op.drop_table('movements')
    op.drop_table('doc_links')
    op.drop_index('ix_checkouts_item_open', table_name='checkouts')
    op.drop_table('checkouts')
    op.drop_index('ix_attachments_item', table_name='attachments')
    op.drop_index('ix_attachments_location', table_name='attachments')
    op.drop_index('ix_attachments_owner_sha', table_name='attachments')
    op.drop_index(op.f('ix_attachments_stored_name'), table_name='attachments')
    op.drop_table('attachments')
    op.drop_index(op.f('ix_items_barcode'), table_name='items')
    op.drop_index('ix_items_owner_location', table_name='items')
    op.drop_table('items')
    op.drop_index('ix_user_sessions_user', table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_index('ix_locations_owner_parent', table_name='locations')
    op.drop_table('locations')
    op.drop_table('users')
    op.drop_index('ix_audit_action_created', table_name='audit_log')
    op.drop_index('ix_audit_actor_created', table_name='audit_log')
    op.drop_index('ix_audit_seq', table_name='audit_log')
    op.drop_table('audit_log')

    for enum_name in ENUM_TYPES:
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")
