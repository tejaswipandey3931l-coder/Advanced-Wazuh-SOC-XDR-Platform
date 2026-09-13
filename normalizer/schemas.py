"""
Pydantic schemas and deterministic identifier generators for normalized events.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Project-specific stable namespace UUID for RFC 4122 Version 5 generation
SOC_EVENT_NAMESPACE = uuid.UUID("e4c19a82-3f7d-4b82-9a3d-1a8c4f2e5b90")


def generate_event_id(source_type: str, wazuh_index: str, wazuh_index_id: str) -> uuid.UUID:
    """Generate a deterministic UUIDv5 from stable source identity."""
    seed = f"{source_type}:{wazuh_index}:{wazuh_index_id}"
    return uuid.uuid5(SOC_EVENT_NAMESPACE, seed)


class NormalizedEventSchema(BaseModel):
    """Strongly-typed normalized representation of a security event.

    Follows an ECS-inspired flat relational structure, ensuring deterministic
    reproducibility while preserving all original forensic evidence.
    """

    model_config = ConfigDict(extra="ignore")

    # ── Identifiers & Provenance ─────────────────────────────────────────────
    event_id: uuid.UUID = Field(description="Deterministic UUIDv5 derived from source identity")
    raw_alert_id: uuid.UUID | None = Field(default=None, description="FK to raw_alerts.id in PostgreSQL")
    wazuh_index_id: str = Field(description="OpenSearch document _id")
    wazuh_index: str = Field(description="Source OpenSearch index name")
    normalization_version: str = Field(default="1.0.0", description="Normalizer schema version")
    normalized_at: datetime = Field(description="UTC timestamp of when normalization executed")

    # ── Timing (Strict 3-Way Semantics) ──────────────────────────────────────
    event_timestamp: datetime = Field(description="When the security event occurred according to Wazuh")
    ingestion_timestamp: datetime = Field(description="When our platform received/recorded the raw alert")

    # ── Classification & Source Distinction ──────────────────────────────────
    source_type: str = Field(default="wazuh", description="Originating telemetry system (wazuh, zeek, suricata)")
    decoder_name: str | None = Field(default=None, description="Wazuh decoder name (sca, sshd, syscheck, json)")
    event_category: str = Field(description="High-level category: authentication, network, process, file, configuration_assessment, system")
    event_type: str = Field(description="Specific event action: logon_failure, connection_opened, process_spawned, policy_check, service_started")
    severity: int = Field(ge=1, le=16, description="Wazuh rule severity level (1-16)")
    severity_label: str = Field(description="Mapped severity: low (1-4), medium (5-7), high (8-11), critical (12-16)")

    # ── Rule Context ─────────────────────────────────────────────────────────
    rule_id: str = Field(description="Originating detection rule ID")
    rule_description: str = Field(default="", description="Rule summary description")
    rule_groups: list[str] = Field(default_factory=list, description="Wazuh rule groups")

    # ── Host & Agent Context ─────────────────────────────────────────────────
    agent_id: str | None = Field(default=None, description="Wazuh agent ID")
    agent_name: str | None = Field(default=None, description="Wazuh agent name")
    hostname: str | None = Field(default=None, description="Target or source hostname")

    # ── Network Context ──────────────────────────────────────────────────────
    src_ip: str | None = Field(default=None, description="Canonical IPv4/IPv6 source address")
    dst_ip: str | None = Field(default=None, description="Canonical IPv4/IPv6 destination address")
    src_port: int | None = Field(default=None, ge=1, le=65535, description="Source port (1-65535)")
    dst_port: int | None = Field(default=None, ge=1, le=65535, description="Destination port (1-65535)")
    network_protocol: str | None = Field(default=None, description="Transport protocol: TCP, UDP, ICMP")

    # ── Identity Context ─────────────────────────────────────────────────────
    user: str | None = Field(default=None, description="Normalized username")
    auth_action: str | None = Field(default=None, description="Auth action: logon, logoff, privilege_elevation")
    auth_result: str | None = Field(default=None, description="Auth outcome: success, failure, not_applicable")

    # ── Process & Execution Context ──────────────────────────────────────────
    process_name: str | None = Field(default=None, description="Executing binary filename")
    process_pid: int | None = Field(default=None, description="Process ID")
    process_command_line: str | None = Field(default=None, description="Executed command line string")

    # ── File & Integrity Context ─────────────────────────────────────────────
    file_path: str | None = Field(default=None, description="Target filesystem path")
    file_hash_md5: str | None = Field(default=None, description="MD5 hash")
    file_hash_sha256: str | None = Field(default=None, description="SHA256 hash")

    # ── Web & Resource Context ───────────────────────────────────────────────
    domain: str | None = Field(default=None, description="FQDN or queried domain")
    url: str | None = Field(default=None, description="Resource URL")

    # ── Threat & Compliance Context ──────────────────────────────────────────
    mitre_technique_ids: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs (e.g. T1082)")
    mitre_tactic_ids: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactic IDs (e.g. TA0007)")
    compliance_frameworks: dict[str, list[str]] = Field(default_factory=dict, description="Regulatory frameworks (pci_dss, gdpr, hipaa)")

    # ── Unmapped Evidence Preservation ───────────────────────────────────────
    extra_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured fields lacking a first-class column (no redundant duplicates)",
    )
    raw_payload: dict[str, Any] = Field(description="Unaltered verbatim Wazuh raw alert payload")


@dataclass(frozen=True)
class NormalizationResult:
    """Outcome of single event normalization in batch pipelines."""

    success: bool
    event: NormalizedEventSchema | None = None
    error: str | None = None
    wazuh_index_id: str | None = None


class NormalizedEventListResponse(BaseModel):
    """Paginated collection of normalized events for API responses."""

    model_config = ConfigDict(extra="ignore")

    total: int = Field(ge=0, description="Total matching normalized events")
    count: int = Field(ge=0, description="Number of events returned in this page")
    limit: int = Field(ge=1, description="Page limit requested")
    offset: int = Field(ge=0, description="Page offset requested")
    events: list[NormalizedEventSchema] = Field(
        default_factory=list,
        description="List of normalized events",
    )
