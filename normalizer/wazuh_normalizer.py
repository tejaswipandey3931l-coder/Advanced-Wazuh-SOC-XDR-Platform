"""
Wazuh event normalizer.

Performs pure, deterministic transformations of Wazuh raw alerts into ECS-aligned
NormalizedEventSchema instances with strict validation and typed normalization errors.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import ipaddress
from typing import Any
import uuid

import structlog

from backend.app.schemas.wazuh import RawAlertItem
from normalizer.categories import resolve_category_and_type
from normalizer.exceptions import (
    InvalidNetworkAddressError,
    InvalidTimestampError,
    MissingRequiredFieldError,
    NormalizationError,
)
from normalizer.schemas import (
    NormalizationResult,
    NormalizedEventSchema,
    generate_event_id,
)

logger = structlog.get_logger(__name__)

# Keys mapped to first-class columns from raw["data"] (to avoid redundant duplication in extra_fields)
MAPPED_DATA_KEYS = {
    "srcip",
    "src_ip",
    "dstip",
    "dst_ip",
    "srcport",
    "src_port",
    "dstport",
    "dst_port",
    "proto",
    "protocol",
    "srcuser",
    "dstuser",
    "user",
    "process_name",
    "process_id",
    "command",
    "cmd",
    "file",
    "domain",
    "vhost",
    "url",
    "uri",
}

# Keys mapped to first-class columns from raw["syscheck"]
MAPPED_SYSCHECK_KEYS = {
    "path",
    "md5_after",
    "md5_before",
    "sha256_after",
    "sha256_before",
    "uname_after",
    "uname_before",
}

SEVERITY_LEVEL_MAP = {
    range(1, 5): "low",
    range(5, 8): "medium",
    range(8, 12): "high",
    range(12, 17): "critical",
}


def _map_severity_label(level: int) -> str:
    for level_range, label in SEVERITY_LEVEL_MAP.items():
        if level in level_range:
            return label
    return "low"


class EventNormalizer:
    """Pure, deterministic event normalizer for Wazuh alerts.

    Does not perform database I/O or external network calls.
    """

    def __init__(self, normalization_version: str = "2.0.0") -> None:
        self.normalization_version = normalization_version

    def _parse_timestamp(self, ts_raw: Any) -> datetime:
        """Parse source event timestamp to UTC datetime.

        If timestamp lacks timezone offset, assumes UTC per documented limitation.
        Raises InvalidTimestampError on failure.
        """
        if not ts_raw:
            raise MissingRequiredFieldError("Event timestamp is required but was empty or missing")

        if isinstance(ts_raw, datetime):
            if ts_raw.tzinfo is None:
                return ts_raw.replace(tzinfo=timezone.utc)
            return ts_raw.astimezone(timezone.utc)

        if not isinstance(ts_raw, str):
            raise InvalidTimestampError(f"Timestamp must be ISO-8601 string or datetime, got {type(ts_raw).__name__}")

        ts_str = ts_raw.strip()
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                # Documented limitation/assumption: naive source timestamps assume UTC
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except Exception as exc:
            raise InvalidTimestampError(f"Failed to parse event timestamp '{ts_raw}': {exc}") from exc

    def _validate_ip(self, ip_str: str | None, field_name: str) -> str | None:
        """Validate canonical IPv4/IPv6 address.

        Raises InvalidNetworkAddressError if malformed.
        """
        if not ip_str:
            return None
        cleaned = ip_str.strip()
        if not cleaned:
            return None
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return str(ip_obj)
        except ValueError as exc:
            raise InvalidNetworkAddressError(f"Malformed {field_name} '{ip_str}': {exc}") from exc

    def _validate_port(self, port_val: Any, field_name: str) -> int | None:
        """Validate network port (1-65535).

        Raises InvalidNetworkAddressError if malformed or out of range.
        """
        if port_val is None or port_val == "":
            return None
        try:
            port_int = int(port_val)
        except (ValueError, TypeError) as exc:
            raise InvalidNetworkAddressError(f"Invalid {field_name} value '{port_val}': {exc}") from exc

        if not (1 <= port_int <= 65535):
            raise InvalidNetworkAddressError(f"{field_name} out of valid range (1-65535): {port_int}")
        return port_int

    def normalize_alert(
        self,
        item: RawAlertItem | dict[str, Any],
        ingestion_timestamp: datetime | None = None,
        raw_alert_id: uuid.UUID | None = None,
    ) -> NormalizedEventSchema:
        """Normalize a single Wazuh alert into NormalizedEventSchema.

        Args:
            item: RawAlertItem instance or dictionary matching its structure.
            ingestion_timestamp: Platform arrival timestamp (defaults to UTC now).
            raw_alert_id: Foreign key to raw_alerts.id in PostgreSQL if available.

        Returns:
            NormalizedEventSchema with all fields validated and mapped.

        Raises:
            MissingRequiredFieldError: If identity or mandatory fields are missing.
            InvalidTimestampError: If event timestamp is unparseable.
            InvalidNetworkAddressError: If IP or port is malformed.
            NormalizationError: For other normalization validation failures.
        """
        # Convert dictionary to RawAlertItem if needed
        if isinstance(item, dict):
            # Validate required top-level keys
            if "id" not in item:
                raise MissingRequiredFieldError("Alert item must contain 'id' field")
            if "index" not in item:
                raise MissingRequiredFieldError("Alert item must contain 'index' field")
            raw_dict = item.get("raw") or item
            item_obj = RawAlertItem(
                id=item["id"],
                index=item["index"],
                timestamp=item.get("timestamp"),
                rule_id=item.get("rule_id"),
                rule_level=item.get("rule_level"),
                rule_description=item.get("rule_description"),
                agent_id=item.get("agent_id"),
                agent_name=item.get("agent_name"),
                raw=raw_dict,
            )
        elif isinstance(item, RawAlertItem):
            item_obj = item
        else:
            raise NormalizationError(f"Unsupported item type: {type(item).__name__}")

        raw = item_obj.raw or {}
        wazuh_index_id = item_obj.id
        wazuh_index = item_obj.index

        if not wazuh_index_id:
            raise MissingRequiredFieldError("Missing required document ID (wazuh_index_id)")
        if not wazuh_index:
            raise MissingRequiredFieldError("Missing required index name (wazuh_index)")

        # 1. Deterministic event ID
        source_type = "wazuh"
        event_id = generate_event_id(source_type, wazuh_index, wazuh_index_id)

        # 2. Strict 3-way timestamps
        # event_timestamp: when the event occurred according to Wazuh
        raw_ts = raw.get("timestamp") or raw.get("@timestamp") or item_obj.timestamp
        event_timestamp = self._parse_timestamp(raw_ts)

        # ingestion_timestamp: when our platform ingested the alert
        if ingestion_timestamp is None:
            ingestion_timestamp = datetime.now(timezone.utc)
        elif ingestion_timestamp.tzinfo is None:
            ingestion_timestamp = ingestion_timestamp.replace(tzinfo=timezone.utc)
        else:
            ingestion_timestamp = ingestion_timestamp.astimezone(timezone.utc)

        # normalized_at: wall-clock execution time
        normalized_at = datetime.now(timezone.utc)

        # 3. Rule context & severity
        rule_block = raw.get("rule") or {}
        raw_rule_id = rule_block.get("id") or item_obj.rule_id
        if raw_rule_id is None:
            raise MissingRequiredFieldError("Missing required rule_id in alert")
        rule_id = str(raw_rule_id)

        rule_level_val = rule_block.get("level") or item_obj.rule_level or 1
        try:
            severity = int(rule_level_val)
        except (ValueError, TypeError) as exc:
            raise NormalizationError(f"Invalid rule level '{rule_level_val}': {exc}") from exc

        if not (1 <= severity <= 16):
            raise NormalizationError(f"Rule severity out of bounds (1-16): {severity}")

        severity_label = _map_severity_label(severity)
        rule_desc = rule_block.get("description") or item_obj.rule_description or ""
        rule_groups = rule_block.get("groups") or []
        if isinstance(rule_groups, str):
            rule_groups = [rule_groups]

        # 4. Source type vs decoder distinction
        decoder_block = raw.get("decoder") or {}
        decoder_name = decoder_block.get("name") if isinstance(decoder_block, dict) else None

        # 5. Category and event type resolution
        event_category, event_type, auth_action, auth_result = resolve_category_and_type(
            rule_id=rule_id,
            decoder_name=decoder_name,
            groups=rule_groups,
            rule_level=severity,
        )

        # 6. Host & Agent Context
        agent_block = raw.get("agent") or {}
        agent_id = str(agent_block.get("id") or item_obj.agent_id or "") or None
        agent_name = agent_block.get("name") or item_obj.agent_name or None

        # Hostname resolution
        hostname = (
            raw.get("hostname")
            or agent_name
            or agent_block.get("name")
            or (raw.get("syscheck", {}).get("uname") if isinstance(raw.get("syscheck"), dict) else None)
            or (raw.get("prefilter", {}).get("hostname") if isinstance(raw.get("prefilter"), dict) else None)
        )

        # 7. Network Context
        data_block = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        syscheck_block = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else {}

        raw_src_ip = data_block.get("srcip") or data_block.get("src_ip") or raw.get("srcip")
        raw_dst_ip = data_block.get("dstip") or data_block.get("dst_ip") or raw.get("dstip")
        raw_src_port = data_block.get("srcport") or data_block.get("src_port") or raw.get("srcport")
        raw_dst_port = data_block.get("dstport") or data_block.get("dst_port") or raw.get("dstport")

        src_ip = self._validate_ip(raw_src_ip, "src_ip")
        dst_ip = self._validate_ip(raw_dst_ip, "dst_ip")
        src_port = self._validate_port(raw_src_port, "src_port")
        dst_port = self._validate_port(raw_dst_port, "dst_port")

        network_protocol = (
            data_block.get("proto")
            or data_block.get("protocol")
            or raw.get("protocol")
        )
        if network_protocol:
            network_protocol = str(network_protocol).upper()

        # 8. Identity Context
        user = (
            data_block.get("dstuser")
            or data_block.get("srcuser")
            or data_block.get("user")
            or raw.get("dstuser")
            or raw.get("srcuser")
            or syscheck_block.get("uname_after")
            or syscheck_block.get("uname_before")
        )

        # 9. Process & Execution Context
        process_name = data_block.get("process_name") or raw.get("program_name")
        process_pid_raw = data_block.get("process_id")
        process_pid: int | None = None
        if process_pid_raw is not None:
            try:
                process_pid = int(process_pid_raw)
            except (ValueError, TypeError):
                process_pid = None

        process_command_line = data_block.get("command") or data_block.get("cmd")

        # 10. File & Integrity Context
        file_path = syscheck_block.get("path") or data_block.get("file")
        file_hash_md5 = syscheck_block.get("md5_after") or syscheck_block.get("md5_before")
        file_hash_sha256 = syscheck_block.get("sha256_after") or syscheck_block.get("sha256_before")

        # 11. Web & Resource Context
        domain = data_block.get("domain") or data_block.get("vhost")
        url = data_block.get("url") or data_block.get("uri")

        # 12. Threat & Compliance Context
        mitre_block = rule_block.get("mitre") or {}
        mitre_technique_ids: list[str] = []
        mitre_tactic_ids: list[str] = []

        raw_tech = mitre_block.get("id")
        if isinstance(raw_tech, list):
            mitre_technique_ids = [str(t) for t in raw_tech]
        elif raw_tech:
            mitre_technique_ids = [str(raw_tech)]

        raw_tactic = mitre_block.get("tactic")
        if isinstance(raw_tactic, list):
            mitre_tactic_ids = [str(t) for t in raw_tactic]
        elif raw_tactic:
            mitre_tactic_ids = [str(raw_tactic)]

        compliance_frameworks: dict[str, list[str]] = {}
        for framework_key in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"):
            if framework_key in rule_block:
                f_val = rule_block[framework_key]
                if isinstance(f_val, list):
                    compliance_frameworks[framework_key] = [str(v) for v in f_val]
                elif f_val:
                    compliance_frameworks[framework_key] = [str(f_val)]

        # 13. Extra Fields Extraction (Preserve unmapped structured data without duplicating first-class fields)
        extra_fields: dict[str, Any] = {}

        # Unmapped data.* fields
        if data_block:
            unmapped_data = {
                k: v for k, v in data_block.items() if k not in MAPPED_DATA_KEYS
            }
            if unmapped_data:
                extra_fields["data"] = unmapped_data

        # Unmapped syscheck.* fields
        if syscheck_block:
            unmapped_syscheck = {
                k: v for k, v in syscheck_block.items() if k not in MAPPED_SYSCHECK_KEYS
            }
            if unmapped_syscheck:
                extra_fields["syscheck"] = unmapped_syscheck

        # Other known unmapped blocks
        for block_name in ("audit", "sca", "rootcheck", "ciscat", "vulnerability"):
            if block_name in raw:
                extra_fields[block_name] = raw[block_name]

        return NormalizedEventSchema(
            event_id=event_id,
            raw_alert_id=raw_alert_id,
            wazuh_index_id=wazuh_index_id,
            wazuh_index=wazuh_index,
            normalization_version=self.normalization_version,
            normalized_at=normalized_at,
            event_timestamp=event_timestamp,
            ingestion_timestamp=ingestion_timestamp,
            source_type=source_type,
            decoder_name=decoder_name,
            event_category=event_category,
            event_type=event_type,
            severity=severity,
            severity_label=severity_label,
            rule_id=rule_id,
            rule_description=rule_desc,
            rule_groups=rule_groups,
            agent_id=agent_id,
            agent_name=agent_name,
            hostname=hostname,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            network_protocol=network_protocol,
            user=user,
            auth_action=auth_action,
            auth_result=auth_result,
            process_name=process_name,
            process_pid=process_pid,
            process_command_line=process_command_line,
            file_path=file_path,
            file_hash_md5=file_hash_md5,
            file_hash_sha256=file_hash_sha256,
            domain=domain,
            url=url,
            mitre_technique_ids=mitre_technique_ids,
            mitre_tactic_ids=mitre_tactic_ids,
            compliance_frameworks=compliance_frameworks,
            extra_fields=extra_fields,
            raw_payload=copy.deepcopy(raw),
        )

    def normalize_batch(
        self,
        items: list[RawAlertItem | dict[str, Any]],
        ingestion_timestamp: datetime | None = None,
    ) -> list[NormalizationResult]:
        """Normalize a batch of alerts, continuing on errors while collecting failures."""
        results: list[NormalizationResult] = []
        for item in items:
            doc_id: str | None = None
            if isinstance(item, dict):
                doc_id = item.get("id")
            elif isinstance(item, RawAlertItem):
                doc_id = item.id

            try:
                norm_event = self.normalize_alert(item, ingestion_timestamp=ingestion_timestamp)
                results.append(
                    NormalizationResult(
                        success=True,
                        event=norm_event,
                        error=None,
                        wazuh_index_id=doc_id,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "normalization_failed_for_alert",
                    wazuh_index_id=doc_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                results.append(
                    NormalizationResult(
                        success=False,
                        event=None,
                        error=f"{type(exc).__name__}: {exc}",
                        wazuh_index_id=doc_id,
                    )
                )
        return results
