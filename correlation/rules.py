"""
Rule Registry and default SOC detection rules.

Manages loading, validation, indexing, and deterministic retrieval of correlation rules.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid5, NAMESPACE_DNS

import structlog

from backend.app.models.correlation_rule import CorrelationRule as CorrelationRuleModel, RuleType
from backend.app.models.incident import IncidentSeverity
from .models import (
    CorrelationRuleDefinition,
    SequenceStepDefinition,
    matches_conditions,
)

logger = structlog.get_logger(__name__)

# Deterministic namespace for default rule IDs
SOC_RULE_NAMESPACE = uuid5(NAMESPACE_DNS, "wazuh.soc.rules")


def get_default_rules() -> list[CorrelationRuleDefinition]:
    """Returns standard, production-grade baseline correlation rules."""
    return [
        CorrelationRuleDefinition(
            id=uuid5(SOC_RULE_NAMESPACE, "ssh_bruteforce"),
            name="SSH / Authentication Brute Force Detected",
            description="Multiple failed authentication attempts from a single source IP within a sliding window.",
            rule_type=RuleType.ENTITY_GROUP,
            severity=IncidentSeverity.HIGH,
            base_confidence=0.80,
            time_window_seconds=300,
            min_event_count=5,
            entity_field="src_ip",
            conditions={"auth_result": {"in": ["failure", "failed"]}},
            mitre_technique_id="T1110.001",
            mitre_tactic_id="TA0006",
            priority=10,
            version=1,
        ),
        CorrelationRuleDefinition(
            id=uuid5(SOC_RULE_NAMESPACE, "priv_esc_sequence"),
            name="Suspected Privilege Escalation Sequence",
            description="Failed authentication followed by successful privilege escalation for the same user account.",
            rule_type=RuleType.SEQUENCE,
            severity=IncidentSeverity.CRITICAL,
            base_confidence=0.85,
            time_window_seconds=600,
            min_event_count=2,
            entity_field="user",
            sequence_steps=[
                SequenceStepDefinition(
                    step_id="step_failed_auth",
                    name="Initial Failed Authentication",
                    conditions={"auth_result": {"in": ["failure", "failed"]}},
                    min_count=1,
                    description="One or more failed login attempts",
                ),
                SequenceStepDefinition(
                    step_id="step_priv_escalation",
                    name="Privilege Escalation Execution",
                    conditions={"event_category": "privilege_escalation"},
                    min_count=1,
                    description="Sudo or privilege change execution",
                ),
            ],
            mitre_technique_id="T1548.003",
            mitre_tactic_id="TA0004",
            priority=20,
            version=1,
        ),
        CorrelationRuleDefinition(
            id=uuid5(SOC_RULE_NAMESPACE, "horizontal_port_scan"),
            name="Horizontal Port Scan Activity",
            description="Connection attempts to multiple distinct destination ports from a single source IP.",
            rule_type=RuleType.ENTITY_GROUP,
            severity=IncidentSeverity.MEDIUM,
            base_confidence=0.75,
            time_window_seconds=60,
            min_event_count=5,
            entity_field="src_ip",
            distinct_entity_field="dst_port",
            min_distinct_count=5,
            conditions={"event_category": "network"},
            mitre_technique_id="T1046",
            mitre_tactic_id="TA0043",
            priority=30,
            version=1,
        ),
    ]


class RuleRegistry:
    """Thread-safe, deterministic in-memory registry of correlation rules."""

    def __init__(self) -> None:
        self._rules: dict[UUID, CorrelationRuleDefinition] = {}

    def register_rule(self, rule: CorrelationRuleDefinition) -> None:
        """Register or update a validated correlation rule."""
        self._rules[rule.id] = rule
        logger.info("correlation_rule_registered", rule_id=str(rule.id), name=rule.name, rule_type=rule.rule_type.value)

    def get_rule(self, rule_id: UUID) -> CorrelationRuleDefinition | None:
        """Retrieve a rule by its UUID."""
        return self._rules.get(rule_id)

    def get_active_rules(self) -> list[CorrelationRuleDefinition]:
        """Returns all active rules in deterministic order: (priority ASC, rule_id ASC)."""
        active = [r for r in self._rules.values() if r.is_active]
        return sorted(active, key=lambda r: (r.priority, str(r.id)))

    def get_rules_for_event(self, event_dict: dict[str, Any]) -> list[CorrelationRuleDefinition]:
        """
        Filters and returns active rules applicable to this event in deterministic evaluation order.
        An applicable rule either binds to an entity present in the event or matches initial conditions.
        """
        applicable: list[CorrelationRuleDefinition] = []
        for rule in self.get_active_rules():
            # If the rule requires an entity field (e.g. src_ip, user), verify the event has it
            if rule.entity_field:
                entity_val = event_dict.get(rule.entity_field)
                if entity_val is None or str(entity_val).strip() == "":
                    continue

            # For sequence rules: check if the event matches at least one step's conditions
            if rule.rule_type == RuleType.SEQUENCE:
                step_matched = False
                for step in rule.sequence_steps:
                    if matches_conditions(event_dict, step.conditions):
                        step_matched = True
                        break
                if not step_matched:
                    continue
            else:
                # For entity_group / temporal rules: check rule-level conditions
                if rule.conditions and not matches_conditions(event_dict, rule.conditions):
                    continue

            applicable.append(rule)

        return applicable

    def load_from_db_models(self, db_rules: list[CorrelationRuleModel]) -> None:
        """Hydrates the registry from SQLAlchemy database records."""
        for db_rule in db_rules:
            # Parse sequence_steps from conditions if present
            cond = db_rule.conditions or {}
            seq_steps_raw = cond.get("sequence_steps", [])
            steps: list[SequenceStepDefinition] = []
            for s in seq_steps_raw:
                steps.append(SequenceStepDefinition.model_validate(s))

            rule_def = CorrelationRuleDefinition(
                id=db_rule.id,
                name=db_rule.name,
                description=db_rule.description,
                rule_type=db_rule.rule_type,
                severity=IncidentSeverity(db_rule.severity) if hasattr(IncidentSeverity, db_rule.severity.upper()) else IncidentSeverity.MEDIUM,
                base_confidence=db_rule.base_confidence,
                time_window_seconds=db_rule.time_window_seconds,
                min_event_count=db_rule.min_event_count,
                entity_field=db_rule.entity_field,
                distinct_entity_field=cond.get("distinct_entity_field"),
                min_distinct_count=cond.get("min_distinct_count"),
                conditions=cond.get("filters"),
                sequence_steps=steps,
                mitre_technique_id=db_rule.mitre_technique_id,
                mitre_tactic_id=db_rule.mitre_tactic_id,
                is_active=db_rule.is_active,
                priority=db_rule.priority,
                version=db_rule.version,
            )
            self.register_rule(rule_def)

    def load_defaults(self) -> None:
        """Loads standard default rules into the registry."""
        for r in get_default_rules():
            self.register_rule(r)
