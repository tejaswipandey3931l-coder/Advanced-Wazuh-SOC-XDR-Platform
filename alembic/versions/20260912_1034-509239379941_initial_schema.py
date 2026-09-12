"""Initial schema — all Phase 0 tables.

Revision ID: 509239379941
Revises:
Create Date: 2026-09-12 10:34 UTC

Creates the following tables:
  - raw_alerts
  - normalized_events
  - incidents
  - correlation_rules
  - threat_intel_results
  - attack_chains
  - audit_logs

Along with all associated PostgreSQL enum types and indexes.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# ── Metadata ─────────────────────────────────────────────────────────────────
revision: str = "509239379941"
down_revision: str | None = None
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


# ── Named PostgreSQL ENUM types ──────────────────────────────────────────────
# Explicitly defined once using sa.Enum. These are created once in upgrade()
# and dropped in downgrade() after dependent tables are removed.
incident_status_enum = sa.Enum(
    "open", "investigating", "closed", "false_positive",
    name="incident_status",
)
incident_severity_enum = sa.Enum(
    "critical", "high", "medium", "low", "informational",
    name="incident_severity",
)
correlation_rule_type_enum = sa.Enum(
    "entity_group", "temporal", "sequence",
    name="correlation_rule_type",
)
ioc_type_enum = sa.Enum(
    "ip", "domain", "url", "file_hash", "email",
    name="ioc_type",
)
cti_source_enum = sa.Enum(
    "abuseipdb", "misp", "opencti", "local_feed",
    name="cti_source",
)

# ── Column ENUM references ───────────────────────────────────────────────────
# Reusable column definitions using postgresql.ENUM with create_type=False.
# This prevents SQLAlchemy/Alembic from attempting to emit CREATE TYPE again
# during op.create_table().
incident_status_col = postgresql.ENUM(
    "open", "investigating", "closed", "false_positive",
    name="incident_status",
    create_type=False,
)
incident_severity_col = postgresql.ENUM(
    "critical", "high", "medium", "low", "informational",
    name="incident_severity",
    create_type=False,
)
correlation_rule_type_col = postgresql.ENUM(
    "entity_group", "temporal", "sequence",
    name="correlation_rule_type",
    create_type=False,
)
ioc_type_col = postgresql.ENUM(
    "ip", "domain", "url", "file_hash", "email",
    name="ioc_type",
    create_type=False,
)
cti_source_col = postgresql.ENUM(
    "abuseipdb", "misp", "opencti", "local_feed",
    name="cti_source",
    create_type=False,
)


# ── Upgrade ───────────────────────────────────────────────────────────────────
def upgrade() -> None:
    # ── Create all PostgreSQL ENUM types explicitly once ──────────────────────
    incident_status_enum.create(op.get_bind(), checkfirst=True)
    incident_severity_enum.create(op.get_bind(), checkfirst=True)
    correlation_rule_type_enum.create(op.get_bind(), checkfirst=True)
    ioc_type_enum.create(op.get_bind(), checkfirst=True)
    cti_source_enum.create(op.get_bind(), checkfirst=True)

    # ── raw_alerts ────────────────────────────────────────────────────────────
    op.create_table(
        "raw_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("wazuh_index_id", sa.String(255), nullable=False,
                  comment="OpenSearch document _id for this alert"),
        sa.Column("agent_id", sa.String(64), nullable=True),
        sa.Column("agent_name", sa.String(255), nullable=True),
        sa.Column("rule_id", sa.Integer, nullable=True),
        sa.Column("rule_level", sa.Integer, nullable=True),
        sa.Column("rule_description", sa.Text, nullable=True),
        sa.Column("wazuh_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False,
                  comment="Complete alert JSON from wazuh-alerts-* index"),
        sa.Column("is_normalized", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_raw_alerts_wazuh_index_id", "raw_alerts", ["wazuh_index_id"], unique=True)
    op.create_index("ix_raw_alerts_agent_id", "raw_alerts", ["agent_id"])
    op.create_index("ix_raw_alerts_rule_id", "raw_alerts", ["rule_id"])
    op.create_index("ix_raw_alerts_wazuh_timestamp", "raw_alerts", ["wazuh_timestamp"])
    op.create_index("ix_raw_alerts_is_normalized", "raw_alerts", ["is_normalized"])
    op.create_index("ix_raw_alerts_agent_ts", "raw_alerts", ["agent_id", "wazuh_timestamp"])
    op.create_index("ix_raw_alerts_rule_level", "raw_alerts", ["rule_level"])

    # ── incidents ─────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", incident_status_col, nullable=False),
        sa.Column("severity", incident_severity_col, nullable=False),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("ml_priority_score", sa.Float, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer, nullable=False, default=1),
        sa.Column("mitre_techniques", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("mitre_tactics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ioc_matched", sa.Boolean, nullable=False, default=False),
        sa.Column("entity_context", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_first_seen", "incidents", ["first_seen"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])
    op.create_index("ix_incidents_status_severity", "incidents", ["status", "severity"])

    # ── normalized_events ─────────────────────────────────────────────────────
    op.create_table(
        "normalized_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("raw_alert_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("raw_alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False,
                  comment="e.g. wazuh_agent, zeek, suricata, syslog"),
        sa.Column("src_ip", sa.String(45), nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("src_port", sa.Integer, nullable=True),
        sa.Column("dst_port", sa.Integer, nullable=True),
        sa.Column("network_protocol", sa.String(16), nullable=True),
        sa.Column("user", sa.String(255), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("agent_id", sa.String(64), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("process_pid", sa.Integer, nullable=True),
        sa.Column("process_command_line", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_hash_md5", sa.String(32), nullable=True),
        sa.Column("file_hash_sha256", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("severity", sa.Integer, nullable=False,
                  comment="Wazuh rule level 1-16 or normalised equivalent"),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("rule_description", sa.Text, nullable=True),
        sa.Column("mitre_technique_ids", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("mitre_tactic_ids", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("ioc_matched", sa.Boolean, nullable=False, default=False),
        sa.Column("threat_score", sa.Float, nullable=True),
        sa.Column("ml_score", sa.Float, nullable=True),
        sa.Column("extra_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=True,
                  comment="Any source-specific fields not covered by schema columns"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_normalized_events_raw_alert_id", "normalized_events", ["raw_alert_id"], unique=True)
    op.create_index("ix_normalized_events_event_timestamp", "normalized_events", ["event_timestamp"])
    op.create_index("ix_normalized_events_source_type", "normalized_events", ["source_type"])
    op.create_index("ix_normalized_events_src_ip", "normalized_events", ["src_ip"])
    op.create_index("ix_normalized_events_dst_ip", "normalized_events", ["dst_ip"])
    op.create_index("ix_normalized_events_user", "normalized_events", ["user"])
    op.create_index("ix_normalized_events_hostname", "normalized_events", ["hostname"])
    op.create_index("ix_normalized_events_agent_id", "normalized_events", ["agent_id"])
    op.create_index("ix_normalized_events_event_type", "normalized_events", ["event_type"])
    op.create_index("ix_normalized_events_rule_id", "normalized_events", ["rule_id"])
    op.create_index("ix_ne_src_ip_ts", "normalized_events", ["src_ip", "event_timestamp"])
    op.create_index("ix_ne_user_host", "normalized_events", ["user", "hostname"])
    op.create_index("ix_ne_agent_ts", "normalized_events", ["agent_id", "event_timestamp"])

    # ── correlation_rules ─────────────────────────────────────────────────────
    op.create_table(
        "correlation_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("rule_type", correlation_rule_type_col, nullable=False),
        sa.Column("entity_field", sa.String(128), nullable=True),
        sa.Column("time_window_seconds", sa.Integer, nullable=False, default=300),
        sa.Column("min_event_count", sa.Integer, nullable=False, default=2),
        sa.Column("conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("priority", sa.Integer, nullable=False, default=100),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_correlation_rules_is_active", "correlation_rules", ["is_active"])
    op.create_index("ix_correlation_rules_rule_type", "correlation_rules", ["rule_type"])
    op.create_index("ix_corr_rules_active_priority", "correlation_rules", ["is_active", "priority"])

    # ── threat_intel_results ──────────────────────────────────────────────────
    op.create_table(
        "threat_intel_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("normalized_event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_type", ioc_type_col, nullable=False),
        sa.Column("ioc_value", sa.String(512), nullable=False),
        sa.Column("source", cti_source_col, nullable=False),
        sa.Column("matched", sa.Boolean, nullable=False, default=False),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("threat_type", sa.String(128), nullable=True),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("queried_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cache_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_threat_intel_results_normalized_event_id", "threat_intel_results", ["normalized_event_id"])
    op.create_index("ix_threat_intel_results_ioc_value", "threat_intel_results", ["ioc_value"])
    op.create_index("ix_threat_intel_results_cache_expires_at", "threat_intel_results", ["cache_expires_at"])
    op.create_index("ix_ti_ioc_source", "threat_intel_results", ["ioc_value", "source"])
    op.create_index("ix_ti_event_matched", "threat_intel_results", ["normalized_event_id", "matched"])

    # ── attack_chains ─────────────────────────────────────────────────────────
    op.create_table(
        "attack_chains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chain_steps", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, default=list),
        sa.Column("highest_tactic", sa.String(128), nullable=True),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("last_calculated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_attack_chains_incident_id", "attack_chains", ["incident_id"], unique=True)

    # ── audit_logs ────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(128), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, default=True),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_actor", "audit_logs", ["actor"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_actor_ts", "audit_logs", ["actor", "timestamp"])
    op.create_index("ix_audit_action_ts", "audit_logs", ["action", "timestamp"])
    op.create_index("ix_audit_resource", "audit_logs", ["resource_type", "resource_id"])


# ── Downgrade ─────────────────────────────────────────────────────────────────
def downgrade() -> None:
    # Drop tables (FK-dependent order: children first)
    op.drop_table("audit_logs")
    op.drop_table("attack_chains")
    op.drop_table("threat_intel_results")
    op.drop_table("correlation_rules")
    op.drop_table("normalized_events")
    op.drop_table("incidents")
    op.drop_table("raw_alerts")

    # Drop enum types only after dependent tables have been dropped
    cti_source_enum.drop(op.get_bind(), checkfirst=True)
    ioc_type_enum.drop(op.get_bind(), checkfirst=True)
    correlation_rule_type_enum.drop(op.get_bind(), checkfirst=True)
    incident_severity_enum.drop(op.get_bind(), checkfirst=True)
    incident_status_enum.drop(op.get_bind(), checkfirst=True)
