"""
Pydantic schemas for Wazuh API metadata and OpenSearch raw alert payloads.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WazuhApiInfo(BaseModel):
    """Wazuh REST API top-level metadata."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(description="API service title")
    api_version: str = Field(description="Wazuh REST API version")
    revision: str | None = Field(default=None, description="API build revision")
    hostname: str | None = Field(default=None, description="Manager hostname")
    timestamp: str | None = Field(default=None, description="Server timestamp")


class WazuhManagerInfo(BaseModel):
    """Wazuh Manager node metadata."""

    model_config = ConfigDict(extra="ignore")

    version: str = Field(description="Wazuh Manager engine version")
    type: str | None = Field(default=None, description="Installation type (e.g. server)")
    path: str | None = Field(default=None, description="Installation path (e.g. /var/ossec)")
    uuid: str | None = Field(default=None, description="Unique manager instance UUID")
    tz_offset: str | None = Field(default=None, description="Timezone offset")
    tz_name: str | None = Field(default=None, description="Timezone name")


class WazuhManagerStatus(BaseModel):
    """Status of Wazuh core daemons."""

    model_config = ConfigDict(extra="ignore")

    daemons: dict[str, str] = Field(
        default_factory=dict,
        description="Status mapping of daemons (e.g. wazuh-analysisd: running)",
    )


class RawAlertItem(BaseModel):
    """Single raw alert retrieved from Wazuh Indexer.

    Contains extracted core routing keys for convenience, plus the full,
    unaltered ``raw`` dictionary for downstream Phase 2 normalization.
    """

    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="OpenSearch document _id")
    index: str = Field(description="Source OpenSearch index name")
    timestamp: str | None = Field(default=None, description="Alert event timestamp")
    rule_id: str | int | None = Field(default=None, description="Triggered rule ID")
    rule_level: int | None = Field(default=None, description="Wazuh rule severity level (1-16)")
    rule_description: str | None = Field(default=None, description="Rule description")
    agent_id: str | None = Field(default=None, description="Source Wazuh agent ID")
    agent_name: str | None = Field(default=None, description="Source Wazuh agent name")
    raw: dict[str, Any] = Field(
        description="Complete raw alert JSON payload as produced by Wazuh",
    )


class AlertListResponse(BaseModel):
    """Paginated collection of raw alerts.

    An empty alerts array with total=0 is a valid success response.
    """

    model_config = ConfigDict(extra="ignore")

    total: int = Field(ge=0, description="Total matching alerts in the query window")
    count: int = Field(ge=0, description="Number of alerts returned in this page")
    limit: int = Field(ge=1, description="Page limit requested")
    offset: int = Field(ge=0, description="Page offset requested")
    alerts: list[RawAlertItem] = Field(
        default_factory=list,
        description="List of raw alerts retrieved",
    )
