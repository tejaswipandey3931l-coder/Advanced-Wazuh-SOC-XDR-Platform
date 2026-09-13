"""
Tests for Phase 0 database models, metadata, and enum definitions.

Verifies:
  - All 7 Phase 0 models are registered with Base.metadata
  - All PostgreSQL enum types map to exact lowercase values
  - Foreign key and cascade relationships are properly configured
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import configure_mappers

from backend.app.models import (
    AttackChain,
    AuditLog,
    Base,
    CorrelationRule,
    Incident,
    NormalizedEvent,
    RawAlert,
    ThreatIntelResult,
)
from backend.app.models.correlation_rule import RuleType
from backend.app.models.incident import IncidentSeverity, IncidentStatus
from backend.app.models.threat_intel_result import CTISource, IOCType


def test_all_models_registered_in_metadata() -> None:
    """Verify all 7 Phase 0 tables are registered in Base.metadata."""
    table_names = set(Base.metadata.tables.keys())
    expected_tables = {
        "raw_alerts",
        "normalized_events",
        "incidents",
        "correlation_rules",
        "threat_intel_results",
        "attack_chains",
        "audit_logs",
    }
    assert expected_tables.issubset(table_names), (
        f"Missing tables: {expected_tables - table_names}"
    )


def test_mapper_configuration_succeeds() -> None:
    """Verify all SQLAlchemy mappers and relationships configure without error."""
    configure_mappers()


def test_incident_enum_values() -> None:
    """Verify Incident enums match the PostgreSQL enum definitions."""
    assert Incident.status.type.enums == [
        "open",
        "investigating",
        "closed",
        "false_positive",
    ]
    assert Incident.severity.type.enums == [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ]


def test_correlation_rule_enum_values() -> None:
    """Verify CorrelationRule enum matches the PostgreSQL enum definition."""
    assert CorrelationRule.rule_type.type.enums == [
        "entity_group",
        "temporal",
        "sequence",
    ]


def test_threat_intel_enum_values() -> None:
    """Verify ThreatIntelResult enums match the PostgreSQL enum definitions."""
    assert ThreatIntelResult.ioc_type.type.enums == [
        "ip",
        "domain",
        "url",
        "file_hash",
        "email",
    ]
    assert ThreatIntelResult.source.type.enums == [
        "abuseipdb",
        "misp",
        "opencti",
        "local_feed",
        "virustotal",
        "alienvault_otx",
    ]
