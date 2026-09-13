"""Phase 4 threat intelligence enrichment schema extensions

Revision ID: e5f6a1b2c3d4
Revises: d4e5f6a1b2c3
Create Date: 2026-09-14 15:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "e5f6a1b2c3d4"
down_revision = "d4e5f6a1b2c3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Extend cti_source enum with virustotal and alienvault_otx
    # Must be executed outside transactional DDL block in PostgreSQL if needed,
    # or using ALTER TYPE ADD VALUE IF NOT EXISTS.
    op.execute("ALTER TYPE cti_source ADD VALUE IF NOT EXISTS 'virustotal'")
    op.execute("ALTER TYPE cti_source ADD VALUE IF NOT EXISTS 'alienvault_otx'")

    # 2. Make normalized_event_id nullable (allows ad-hoc & incident-level lookups)
    op.alter_column(
        "threat_intel_results",
        "normalized_event_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )

    # 3. Add incident_id column
    op.add_column(
        "threat_intel_results",
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )

    # 4. Add verdict column
    op.add_column(
        "threat_intel_results",
        sa.Column(
            "verdict",
            sa.String(length=32),
            nullable=False,
            server_default="unknown",
        ),
    )

    # 5. Add severity column
    op.add_column(
        "threat_intel_results",
        sa.Column("severity", sa.String(length=32), nullable=True),
    )

    # 6. Add provider_confidence column
    op.add_column(
        "threat_intel_results",
        sa.Column("provider_confidence", sa.Float(), nullable=True),
    )

    # 7. Add derived_heuristic_confidence column
    op.add_column(
        "threat_intel_results",
        sa.Column("derived_heuristic_confidence", sa.Float(), nullable=True),
    )

    # 8. Add raw_response_text column
    op.add_column(
        "threat_intel_results",
        sa.Column("raw_response_text", sa.Text(), nullable=True),
    )

    # 9. Add source_reference column
    op.add_column(
        "threat_intel_results",
        sa.Column("source_reference", sa.String(length=256), nullable=True),
    )

    # 10. Create indexes
    op.create_index(
        "ix_threat_intel_results_incident_id",
        "threat_intel_results",
        ["incident_id"],
    )
    op.create_index(
        "ix_ti_ioc_source_queried",
        "threat_intel_results",
        ["ioc_value", "source", sa.text("queried_at DESC")],
    )


def downgrade() -> None:
    # 1. Drop indexes
    op.drop_index("ix_ti_ioc_source_queried", table_name="threat_intel_results")
    op.drop_index("ix_threat_intel_results_incident_id", table_name="threat_intel_results")

    # 2. Drop columns
    op.drop_column("threat_intel_results", "source_reference")
    op.drop_column("threat_intel_results", "raw_response_text")
    op.drop_column("threat_intel_results", "derived_heuristic_confidence")
    op.drop_column("threat_intel_results", "provider_confidence")
    op.drop_column("threat_intel_results", "severity")
    op.drop_column("threat_intel_results", "verdict")
    op.drop_column("threat_intel_results", "incident_id")

    # 3. Revert normalized_event_id nullability
    op.execute("DELETE FROM threat_intel_results WHERE normalized_event_id IS NULL")
    op.alter_column(
        "threat_intel_results",
        "normalized_event_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
