"""Phase 2 normalization schema extensions

Revision ID: c3d82f91a014
Revises: 509239379941
Create Date: 2026-09-13 17:10:00.000000

Adds Phase 2 ECS-aligned columns to normalized_events:
  - normalization_version (VARCHAR(16), non-null, default '2.0.0')
  - decoder_name (VARCHAR(64), nullable, indexed)
  - wazuh_index_id (VARCHAR(128), nullable, indexed)
  - wazuh_index (VARCHAR(128), nullable)
  - agent_name (VARCHAR(128), nullable)
  - auth_action (VARCHAR(32), nullable)
  - auth_result (VARCHAR(16), nullable)
  - domain (VARCHAR(255), nullable)
  - url (TEXT, nullable)
  - event_category (VARCHAR(64), nullable, indexed)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3d82f91a014'
down_revision = '509239379941'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'normalized_events',
        sa.Column('normalization_version', sa.String(length=16), server_default='2.0.0', nullable=False),
    )
    op.add_column(
        'normalized_events',
        sa.Column('decoder_name', sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f('ix_normalized_events_decoder_name'),
        'normalized_events',
        ['decoder_name'],
        unique=False,
    )
    op.add_column(
        'normalized_events',
        sa.Column('wazuh_index_id', sa.String(length=128), nullable=True),
    )
    op.create_index(
        op.f('ix_normalized_events_wazuh_index_id'),
        'normalized_events',
        ['wazuh_index_id'],
        unique=False,
    )
    op.add_column(
        'normalized_events',
        sa.Column('wazuh_index', sa.String(length=128), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('agent_name', sa.String(length=128), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('auth_action', sa.String(length=32), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('auth_result', sa.String(length=16), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('domain', sa.String(length=255), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('url', sa.Text(), nullable=True),
    )
    op.add_column(
        'normalized_events',
        sa.Column('event_category', sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f('ix_normalized_events_event_category'),
        'normalized_events',
        ['event_category'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_normalized_events_event_category'), table_name='normalized_events')
    op.drop_column('normalized_events', 'event_category')
    op.drop_column('normalized_events', 'url')
    op.drop_column('normalized_events', 'domain')
    op.drop_column('normalized_events', 'auth_result')
    op.drop_column('normalized_events', 'auth_action')
    op.drop_column('normalized_events', 'agent_name')
    op.drop_column('normalized_events', 'wazuh_index')
    op.drop_index(op.f('ix_normalized_events_wazuh_index_id'), table_name='normalized_events')
    op.drop_column('normalized_events', 'wazuh_index_id')
    op.drop_index(op.f('ix_normalized_events_decoder_name'), table_name='normalized_events')
    op.drop_column('normalized_events', 'decoder_name')
    op.drop_column('normalized_events', 'normalization_version')
