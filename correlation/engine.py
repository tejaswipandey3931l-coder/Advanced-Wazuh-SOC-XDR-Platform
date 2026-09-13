"""
Pure Event Correlation Engine.

Evaluates normalized events against configured rules and sliding windows,
producing structured CorrelationMatch objects without direct database side-effects.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import structlog

from backend.app.models.correlation_rule import RuleType
from .models import (
    CorrelationMatch,
    CorrelationRuleDefinition,
    WindowItem,
    matches_conditions,
)
from .rules import RuleRegistry
from .state import WindowStateStore

logger = structlog.get_logger(__name__)

# Clock-skew tolerance threshold (seconds)
CLOCK_SKEW_TOLERANCE_SECONDS = 60.0


def calculate_confidence(
    rule: CorrelationRuleDefinition,
    matched_events_count: int,
    is_sequence_complete: bool = False,
) -> tuple[float, str]:
    """
    Computes a deterministic, explainable confidence score.
    Returns (confidence, rationale_string).
    """
    score = rule.base_confidence
    parts = [f"base({rule.base_confidence:.2f})"]

    # Boost for exceeding threshold
    excess = max(0, matched_events_count - rule.min_event_count)
    if excess > 0:
        count_boost = min(0.20, excess * 0.05)
        score += count_boost
        parts.append(f"+count_boost({matched_events_count} events: +{count_boost:.2f})")

    # Sequence completion boost
    if is_sequence_complete:
        score += 0.10
        parts.append("+sequence_completed(+0.10)")

    # MITRE mapping boost
    if rule.mitre_technique_id or rule.mitre_tactic_id:
        score += 0.05
        parts.append("+mitre_enrichment(+0.05)")

    final_score = round(max(0.0, min(1.0, score)), 4)
    rationale = " ".join(parts) + f" = {final_score:.2f}"
    return final_score, rationale


class CorrelationEngine:
    """
    Pure correlation engine evaluating normalized events against registered rules and state stores.
    """

    def __init__(self, registry: RuleRegistry, state_store: WindowStateStore) -> None:
        self.registry = registry
        self.state_store = state_store

    def _normalize_timestamps(
        self, event_timestamp: datetime, ingestion_timestamp: datetime
    ) -> tuple[datetime, datetime, dict[str, Any]]:
        """
        Preserves source timestamp while detecting and flagging clock skew / future timestamps.
        Never mutates the event_timestamp value.
        """
        flags: dict[str, Any] = {}

        if event_timestamp.tzinfo is None:
            event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
        else:
            event_timestamp = event_timestamp.astimezone(timezone.utc)

        if ingestion_timestamp.tzinfo is None:
            ingestion_timestamp = ingestion_timestamp.replace(tzinfo=timezone.utc)
        else:
            ingestion_timestamp = ingestion_timestamp.astimezone(timezone.utc)

        # Detect future timestamps exceeding tolerance
        if event_timestamp > ingestion_timestamp + timedelta(seconds=CLOCK_SKEW_TOLERANCE_SECONDS):
            flags["clock_skew_future"] = True
            logger.warning(
                "event_timestamp_in_future",
                event_timestamp=event_timestamp.isoformat(),
                ingestion_timestamp=ingestion_timestamp.isoformat(),
                skew_seconds=(event_timestamp - ingestion_timestamp).total_seconds(),
            )

        return event_timestamp, ingestion_timestamp, flags

    async def evaluate_event(
        self,
        event_id: UUID,
        event_dict: dict[str, Any],
        event_timestamp: datetime,
        ingestion_timestamp: datetime | None = None,
    ) -> list[CorrelationMatch]:
        """
        Evaluates a single normalized event against all applicable rules.
        Returns a list of CorrelationMatch objects (one per matched rule).
        """
        if ingestion_timestamp is None:
            ingestion_timestamp = datetime.now(timezone.utc)

        event_ts, ing_ts, skew_flags = self._normalize_timestamps(
            event_timestamp, ingestion_timestamp
        )

        applicable_rules = self.registry.get_rules_for_event(event_dict)
        if not applicable_rules:
            return []

        matches: list[CorrelationMatch] = []

        for rule in applicable_rules:
            entity_val = ""
            if rule.entity_field:
                raw_val = event_dict.get(rule.entity_field)
                if raw_val is not None:
                    entity_val = str(raw_val)
            else:
                # Temporal rule without entity_field: global window key
                entity_val = "global"

            # Create WindowItem
            window_item = WindowItem(
                event_id=event_id,
                event_timestamp=event_ts,
                ingestion_timestamp=ing_ts,
                entity_value=entity_val,
                data={**event_dict, **skew_flags},
            )

            # Store in sliding window
            await self.state_store.add_event(rule.id, entity_val, window_item)

            # Prune old state outside the sliding horizon
            prune_horizon = event_ts - timedelta(
                seconds=rule.time_window_seconds + CLOCK_SKEW_TOLERANCE_SECONDS
            )
            await self.state_store.prune_events(rule.id, entity_val, prune_horizon)

            # Evaluate matching logic for this rule
            match = await self._evaluate_rule_window(rule, entity_val, event_ts)
            if match:
                matches.append(match)

        return matches

    async def _evaluate_rule_window(
        self, rule: CorrelationRuleDefinition, entity_value: str, current_event_time: datetime
    ) -> CorrelationMatch | None:
        """Evaluates sliding window events for a specific rule and entity."""
        # Query window buffer around current_event_time to tolerate out-of-order delivery
        window_start = current_event_time - timedelta(seconds=rule.time_window_seconds)
        window_end = current_event_time + timedelta(seconds=rule.time_window_seconds)

        # Retrieve window events, sorted by event_timestamp ASC
        events = await self.state_store.get_events(
            rule.id, entity_value, window_start, window_end
        )

        if not events:
            return None

        if rule.rule_type == RuleType.SEQUENCE:
            return self._evaluate_sequence(rule, entity_value, events)
        else:
            return self._evaluate_threshold_or_distinct(rule, entity_value, events)

    def _evaluate_threshold_or_distinct(
        self,
        rule: CorrelationRuleDefinition,
        entity_value: str,
        events: list[WindowItem],
    ) -> CorrelationMatch | None:
        """Evaluates threshold and distinct-entity group rules."""
        # Filter events matching rule conditions
        matching_items: list[WindowItem] = []
        for item in events:
            if matches_conditions(item.data, rule.conditions):
                matching_items.append(item)

        if len(matching_items) < rule.min_event_count:
            return None

        # Distinct entity check if configured (e.g. distinct dst_port for port scan)
        if rule.distinct_entity_field and rule.min_distinct_count:
            distinct_vals = {
                item.data.get(rule.distinct_entity_field)
                for item in matching_items
                if item.data.get(rule.distinct_entity_field) is not None
            }
            if len(distinct_vals) < rule.min_distinct_count:
                return None

        # Threshold satisfied: Build CorrelationMatch
        matched_event_ids = [it.event_id for it in matching_items]
        event_roles = {it.event_id: "threshold_member" for it in matching_items}
        first_seen = matching_items[0].event_timestamp
        last_seen = matching_items[-1].event_timestamp

        confidence, rationale = calculate_confidence(rule, len(matching_items))

        mitre_tech = [rule.mitre_technique_id] if rule.mitre_technique_id else []
        mitre_tact = [rule.mitre_tactic_id] if rule.mitre_tactic_id else []

        return CorrelationMatch(
            rule=rule,
            entity_field=rule.entity_field or "global",
            entity_value=entity_value,
            matched_event_ids=matched_event_ids,
            matched_events=[it.data for it in matching_items],
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
            confidence_rationale=rationale,
            event_roles=event_roles,
            mitre_techniques=mitre_tech,
            mitre_tactics=mitre_tact,
        )

    def _evaluate_sequence(
        self,
        rule: CorrelationRuleDefinition,
        entity_value: str,
        events: list[WindowItem],
    ) -> CorrelationMatch | None:
        """
        Evaluates ordered sequence transitions (S_1 -> S_2 -> ... -> S_k).
        Enforces:
          - Ordered progression in time
          - Step min_count satisfaction
          - Reversed sequence does not fire
        """
        matched_items_by_step: list[list[WindowItem]] = []
        current_step_idx = 0
        current_step = rule.sequence_steps[0]
        current_step_matches: list[WindowItem] = []

        for item in events:
            if matches_conditions(item.data, current_step.conditions):
                current_step_matches.append(item)

                if len(current_step_matches) >= current_step.min_count:
                    # Satisfied current step!
                    matched_items_by_step.append(list(current_step_matches))
                    current_step_idx += 1
                    if current_step_idx < len(rule.sequence_steps):
                        current_step = rule.sequence_steps[current_step_idx]
                        current_step_matches = []
                    else:
                        # Completed all steps in the sequence!
                        break

        if len(matched_items_by_step) < len(rule.sequence_steps):
            return None

        # Build combined match evidence
        all_matched: list[WindowItem] = []
        event_roles: dict[UUID, str] = {}
        for step_idx, step_items in enumerate(matched_items_by_step):
            step_name = rule.sequence_steps[step_idx].step_id
            for it in step_items:
                all_matched.append(it)
                event_roles[it.event_id] = f"sequence_step_{step_idx + 1}:{step_name}"

        # Maintain sorted order
        all_matched.sort(key=lambda x: x.event_timestamp)
        first_seen = all_matched[0].event_timestamp
        last_seen = all_matched[-1].event_timestamp

        confidence, rationale = calculate_confidence(
            rule, len(all_matched), is_sequence_complete=True
        )

        mitre_tech = [rule.mitre_technique_id] if rule.mitre_technique_id else []
        mitre_tact = [rule.mitre_tactic_id] if rule.mitre_tactic_id else []

        return CorrelationMatch(
            rule=rule,
            entity_field=rule.entity_field or "global",
            entity_value=entity_value,
            matched_event_ids=[it.event_id for it in all_matched],
            matched_events=[it.data for it in all_matched],
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
            confidence_rationale=rationale,
            event_roles=event_roles,
            mitre_techniques=mitre_tech,
            mitre_tactics=mitre_tact,
        )
