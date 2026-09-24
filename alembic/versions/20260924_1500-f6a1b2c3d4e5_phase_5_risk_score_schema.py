"""Phase 5 dynamic risk scoring schema extensions

Revision ID: f6a1b2c3d4e5
Revises: e5f6a1b2c3d4
Create Date: 2026-09-24 15:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "f6a1b2c3d4e5"
down_revision = "e5f6a1b2c3d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Create incident_risk_scores table (append-only audit trail)
    # ON DELETE RESTRICT on incident_id prevents destruction of risk audit history
    op.create_table(
        "incident_risk_scores",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "scoring_version",
            sa.String(length=32),
            nullable=False,
            server_default="risk-v1",
        ),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("priority_band", sa.String(length=32), nullable=False),
        sa.Column("base_score", sa.Float(), nullable=False),
        sa.Column("temporal_decay", sa.Float(), nullable=False),
        sa.Column("severity_score", sa.Float(), nullable=False),
        sa.Column("correlation_score", sa.Float(), nullable=False),
        sa.Column("cti_score", sa.Float(), nullable=False),
        sa.Column("volume_score", sa.Float(), nullable=False),
        sa.Column("mitre_score", sa.Float(), nullable=False),
        sa.Column("effective_weights", postgresql.JSONB(), nullable=False),
        sa.Column("factors", postgresql.JSONB(), nullable=False),
        sa.Column("explanation", postgresql.JSONB(), nullable=False),
        sa.Column("trigger_reason", sa.String(length=64), nullable=False),
        sa.Column("evidence_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_version", sa.BigInteger(), nullable=False),
        sa.Column("evaluation_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "calculated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )

    # 2. Create indexes on incident_risk_scores
    op.create_index(
        "ix_incident_risk_scores_incident_id",
        "incident_risk_scores",
        ["incident_id"],
    )
    op.create_index(
        "ix_incident_risk_scores_incident_calc",
        "incident_risk_scores",
        ["incident_id", sa.text("calculated_at DESC")],
    )
    op.create_index(
        "ix_incident_risk_scores_incident_ver",
        "incident_risk_scores",
        ["incident_id", sa.text("evidence_version DESC"), sa.text("evaluation_as_of DESC")],
    )
    op.create_index(
        "ix_incident_risk_scores_priority_calc",
        "incident_risk_scores",
        ["priority_band", sa.text("calculated_at DESC")],
    )

    # 3. Add materialized risk and evidence tracking columns to incidents table
    op.add_column(
        "incidents",
        sa.Column(
            "evidence_version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_priority_band", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "current_risk_score_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incident_risk_scores.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_evidence_version", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_evidence_as_of", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_evaluation_as_of", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_calculated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 4. Create composite index on incidents for risk prioritization
    op.create_index(
        "ix_incidents_risk_priority",
        "incidents",
        ["risk_score", "risk_priority_band"],
    )


def downgrade() -> None:
    # 1. Drop index on incidents
    op.drop_index("ix_incidents_risk_priority", table_name="incidents")

    # 2. Drop columns from incidents
    op.drop_column("incidents", "risk_calculated_at")
    op.drop_column("incidents", "risk_evaluation_as_of")
    op.drop_column("incidents", "risk_evidence_as_of")
    op.drop_column("incidents", "risk_evidence_version")
    op.drop_column("incidents", "current_risk_score_id")
    op.drop_column("incidents", "risk_priority_band")
    op.drop_column("incidents", "evidence_version")

    # 3. Drop indexes on incident_risk_scores
    op.drop_index("ix_incident_risk_scores_priority_calc", table_name="incident_risk_scores")
    op.drop_index("ix_incident_risk_scores_incident_ver", table_name="incident_risk_scores")
    op.drop_index("ix_incident_risk_scores_incident_calc", table_name="incident_risk_scores")
    op.drop_index("ix_incident_risk_scores_incident_id", table_name="incident_risk_scores")

    # 4. Drop table incident_risk_scores
    op.drop_table("incident_risk_scores")
