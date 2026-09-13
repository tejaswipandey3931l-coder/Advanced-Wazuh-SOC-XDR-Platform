"""Phase 3 event correlation schema extensions

Revision ID: d4e5f6a1b2c3
Revises: c3d82f91a014
Create Date: 2026-09-14 10:00:00.000000

Adds Phase 3 Event Correlation structures:
  - incident_events junction table (linking NormalizedEvent to Incident with role and confidence)
  - incident correlation context: correlation_rule_id, confidence, dedup_key, and partial unique index uq_active_incident_dedup_key
  - correlation_rules metadata: version, severity, base_confidence, mitre_technique_id, mitre_tactic_id
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = 'd4e5f6a1b2c3'
down_revision = 'c3d82f91a014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. Create incident_events table ───────────────────────────────────────
    op.create_table(
        'incident_events',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('incident_id', UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('normalized_event_id', UUID(as_uuid=True), sa.ForeignKey('normalized_events.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('correlation_rule_id', UUID(as_uuid=True), sa.ForeignKey('correlation_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('match_role', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('incident_id', 'normalized_event_id', name='uq_incident_events_incident_event'),
    )
    op.create_index(
        op.f('ix_incident_events_incident_id'),
        'incident_events',
        ['incident_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_incident_events_event_id'),
        'incident_events',
        ['normalized_event_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_incident_events_correlation_rule_id'),
        'incident_events',
        ['correlation_rule_id'],
        unique=False,
    )

    # ── 2. Add columns and indexes to incidents ───────────────────────────────
    op.add_column(
        'incidents',
        sa.Column('correlation_rule_id', UUID(as_uuid=True), sa.ForeignKey('correlation_rules.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index(
        op.f('ix_incidents_correlation_rule_id'),
        'incidents',
        ['correlation_rule_id'],
        unique=False,
    )
    op.add_column(
        'incidents',
        sa.Column('confidence', sa.Float(), server_default='1.0', nullable=False),
    )
    op.add_column(
        'incidents',
        sa.Column('dedup_key', sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f('ix_incidents_dedup_key'),
        'incidents',
        ['dedup_key'],
        unique=False,
    )
    op.create_index(
        'uq_active_incident_dedup_key',
        'incidents',
        ['dedup_key'],
        unique=True,
        postgresql_where=sa.text("status IN ('open', 'investigating')"),
    )

    # ── 3. Add columns to correlation_rules ───────────────────────────────────
    op.add_column(
        'correlation_rules',
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
    )
    op.add_column(
        'correlation_rules',
        sa.Column('severity', sa.String(length=32), server_default='medium', nullable=False),
    )
    op.add_column(
        'correlation_rules',
        sa.Column('base_confidence', sa.Float(), server_default='0.7', nullable=False),
    )
    op.add_column(
        'correlation_rules',
        sa.Column('mitre_technique_id', sa.String(length=32), nullable=True),
    )
    op.add_column(
        'correlation_rules',
        sa.Column('mitre_tactic_id', sa.String(length=32), nullable=True),
    )


def downgrade() -> None:
    # ── 3. Revert correlation_rules columns ───────────────────────────────────
    op.drop_column('correlation_rules', 'mitre_tactic_id')
    op.drop_column('correlation_rules', 'mitre_technique_id')
    op.drop_column('correlation_rules', 'base_confidence')
    op.drop_column('correlation_rules', 'severity')
    op.drop_column('correlation_rules', 'version')

    # ── 2. Revert incidents indexes and columns ───────────────────────────────
    op.drop_index('uq_active_incident_dedup_key', table_name='incidents')
    op.drop_index(op.f('ix_incidents_dedup_key'), table_name='incidents')
    op.drop_column('incidents', 'dedup_key')
    op.drop_column('incidents', 'confidence')
    op.drop_index(op.f('ix_incidents_correlation_rule_id'), table_name='incidents')
    op.drop_column('incidents', 'correlation_rule_id')

    # ── 1. Revert incident_events table ───────────────────────────────────────
    op.drop_index(op.f('ix_incident_events_correlation_rule_id'), table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_event_id'), table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_incident_id'), table_name='incident_events')
    op.drop_table('incident_events')
