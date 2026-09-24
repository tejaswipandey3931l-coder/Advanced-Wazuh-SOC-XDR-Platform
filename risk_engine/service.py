"""
Risk Service: Orchestrates evidentiary loading, deterministic CTI consensus resolution,
risk-v1 calculation, explanation building, and evidence-ordered concurrency persistence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from backend.app.database import async_session_factory
from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.incident_risk_score import IncidentRiskScore
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.threat_intel_result import ThreatIntelResult
from threat_intel.consensus import ConsensusEngine
from threat_intel.models import (
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatVerdict,
)

from .calculator import calculate_risk_v1
from .explainer import build_explanation
from .models import ComponentScores, FactorInputs, PriorityBand, RiskExplanation, RiskResult

logger = structlog.get_logger(__name__)


class RiskService:
    """
    Orchestrates the Phase 5 Risk Engine.
    Ensures that calculated scores strictly preserve the evidence-ordered concurrency invariant:
    (evidence_version, evaluation_as_of, deterministic_id).
    """

    async def evaluate_incident(
        self,
        db: AsyncSession,
        incident_id: uuid.UUID,
        evaluation_as_of: datetime | None = None,
        trigger_reason: str = "manual",
    ) -> RiskResult | None:
        """
        Loads incident evidentiary context, calculates risk-v1 priority score,
        records append-only audit history, and atomically updates the current incident state
        using the evidence-version concurrency guard.
        """
        # 1. Load Incident with related data
        stmt = (
            select(Incident)
            .where(Incident.id == incident_id)
            .options(
                selectinload(Incident.correlation_rule),
                selectinload(Incident.incident_events).selectinload(IncidentEvent.normalized_event),
                selectinload(Incident.threat_intel_results),
            )
        )
        res = await db.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            logger.warning("risk_evaluation_incident_not_found", incident_id=str(incident_id))
            return None

        # 2. Extract Event Evidence
        wazuh_levels: list[int] = []
        distinct_entities_set: set[str] = set()

        # Add incident entity context if present
        if incident.entity_context:
            for v in incident.entity_context.values():
                if v:
                    distinct_entities_set.add(str(v).strip().lower())

        member_events: list[NormalizedEvent] = []
        for ie in incident.incident_events:
            if ie.normalized_event:
                member_events.append(ie.normalized_event)
                wazuh_levels.append(ie.normalized_event.rule_level)
                if ie.normalized_event.agent_id:
                    distinct_entities_set.add(f"agent:{ie.normalized_event.agent_id}")
                if ie.normalized_event.host_hostname:
                    distinct_entities_set.add(f"host:{ie.normalized_event.host_hostname.lower()}")
                if ie.normalized_event.source_ip:
                    distinct_entities_set.add(f"ip:{ie.normalized_event.source_ip}")
                if ie.normalized_event.user_name:
                    distinct_entities_set.add(f"user:{ie.normalized_event.user_name.lower()}")

        alert_count = max(incident.alert_count, len(incident.incident_events), 1)
        distinct_entities = max(1, len(distinct_entities_set))

        # 3. Extract MITRE Tactics
        mitre_tactics = list(incident.mitre_tactics or [])

        # 4. Deterministic Latest-Valid CTI Resolution
        # Query all CTI records associated with this incident or its member events
        cti_stmt = (
            select(ThreatIntelResult)
            .where(
                (ThreatIntelResult.incident_id == incident_id)
                | (ThreatIntelResult.normalized_event_id.in_([e.id for e in member_events]))
                if member_events
                else (ThreatIntelResult.incident_id == incident_id)
            )
            .order_by(
                ThreatIntelResult.queried_at.desc(),
                ThreatIntelResult.created_at.desc(),
                ThreatIntelResult.id.desc(),
            )
        )
        cti_res = await db.execute(cti_stmt)
        all_cti_records = list(cti_res.scalars().all())

        # Partition by (ioc_type, canonical_ioc_value, source) and pick newest record
        latest_provider_map: dict[tuple[str, str, str], ThreatIntelResult] = {}
        for r in all_cti_records:
            key = (r.ioc_type.value, r.ioc_value.strip().lower(), r.source.value)
            if key not in latest_provider_map:
                latest_provider_map[key] = r

        # Group by distinct observable (ioc_type, canonical_ioc_value)
        obs_providers_map: dict[tuple[str, str], list[ThreatIntelResult]] = {}
        for (ioc_type, ioc_val, source), r in latest_provider_map.items():
            obs_key = (ioc_type, ioc_val)
            if obs_key not in obs_providers_map:
                obs_providers_map[obs_key] = []
            obs_providers_map[obs_key].append(r)

        observables_cti: list[dict[str, Any]] = []
        latest_cti_timestamps: list[datetime] = []

        for (ioc_type, ioc_val), p_records in obs_providers_map.items():
            norm_obs = NormalizedObservable(
                raw_ioc=ioc_val,
                canonical_ioc=ioc_val,
                ioc_type=ioc_type,
            )
            provider_results: list[ProviderResult] = []
            for pr in p_records:
                latest_cti_timestamps.append(pr.queried_at)
                # Map ThreatIntelResult to ProviderResult for consensus evaluation
                try:
                    verdict_enum = ThreatVerdict(pr.verdict.lower())
                except ValueError:
                    verdict_enum = ThreatVerdict.UNKNOWN

                status_enum = ProviderStatus.SUCCESS if pr.matched or pr.verdict != "unknown" else ProviderStatus.NOT_FOUND
                provider_results.append(
                    ProviderResult(
                        provider=pr.source.value,
                        status=status_enum,
                        verdict=verdict_enum,
                        severity=pr.severity,
                        confidence=pr.confidence,
                        provider_confidence=pr.provider_confidence,
                        derived_heuristic_confidence=pr.derived_heuristic_confidence,
                        threat_type=pr.threat_type,
                        queried_at=pr.queried_at,
                    )
                )

            consensus = ConsensusEngine.evaluate(norm_obs, provider_results)
            observables_cti.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_val,
                "verdict": consensus.verdict.value,
                "provider_confidence": consensus.provider_confidence,
                "derived_heuristic_confidence": consensus.derived_heuristic_confidence,
                "confidence": consensus.confidence,
            })

        # 5. Temporal Boundaries
        evidence_version = incident.evidence_version
        if latest_cti_timestamps:
            evidence_as_of = max(incident.last_seen, max(latest_cti_timestamps))
        else:
            evidence_as_of = incident.last_seen

        now_utc = datetime.now(timezone.utc)
        eval_as_of = evaluation_as_of or now_utc

        # 6. Build FactorInputs & Run Pure Calculator
        rule_conf = incident.correlation_rule.base_confidence if incident.correlation_rule else incident.confidence
        rule_type = incident.correlation_rule.rule_type.value if incident.correlation_rule else None
        rule_priority = incident.correlation_rule.priority if incident.correlation_rule else None
        is_corr = incident.correlation_rule_id is not None

        inputs = FactorInputs(
            wazuh_levels=wazuh_levels,
            incident_severity=incident.severity.value,
            rule_confidence=rule_conf,
            rule_type=rule_type,
            rule_priority=rule_priority,
            is_correlated=is_corr,
            alert_count=alert_count,
            distinct_entities=distinct_entities,
            mitre_tactics=mitre_tactics,
            observables_cti=observables_cti,
            last_seen=incident.last_seen,
            evidence_as_of=evidence_as_of,
            evidence_version=evidence_version,
            evaluation_as_of=eval_as_of,
        )

        calc_result = calculate_risk_v1(inputs)
        calc_time = datetime.now(timezone.utc)
        explanation = build_explanation(calc_result, incident_id=str(incident.id), calculated_at=calc_time)

        # 7. Persist to Append-Only History (incident_risk_scores)
        risk_score_id = uuid.uuid4()
        history_entry = IncidentRiskScore(
            id=risk_score_id,
            incident_id=incident.id,
            scoring_version="risk-v1",
            overall_score=calc_result["overall_score"],
            priority_band=calc_result["priority_band"].value,
            base_score=calc_result["base_score"],
            temporal_decay=calc_result["temporal_decay"],
            severity_score=calc_result["sub_scores"].severity,
            correlation_score=calc_result["sub_scores"].correlation,
            cti_score=calc_result["sub_scores"].cti,
            volume_score=calc_result["sub_scores"].volume,
            mitre_score=calc_result["sub_scores"].mitre_coverage,
            effective_weights=calc_result["effective_weights"],
            factors=calc_result["factors"],
            explanation=explanation.model_dump(mode="json"),
            trigger_reason=trigger_reason,
            evidence_as_of=evidence_as_of,
            evidence_version=evidence_version,
            evaluation_as_of=eval_as_of,
            calculated_at=calc_time,
        )
        db.add(history_entry)
        await db.flush()

        # 8. Atomic Concurrency Guard on incidents table
        # Primary: evidence_version
        # Secondary: evaluation_as_of (for decay re-evaluations on same evidence)
        # Tertiary: deterministic risk_score_id UUID string tie-break
        # calculated_at is AUDIT METADATA ONLY and does NOT participate in semantic freshness ordering
        from sqlalchemy import and_, cast, or_, String

        concurrency_condition = or_(
            Incident.risk_evidence_version.is_(None),
            Incident.risk_evidence_version < evidence_version,
            and_(
                Incident.risk_evidence_version == evidence_version,
                or_(
                    Incident.risk_evaluation_as_of.is_(None),
                    Incident.risk_evaluation_as_of < eval_as_of,
                    and_(
                        Incident.risk_evaluation_as_of == eval_as_of,
                        or_(
                            Incident.current_risk_score_id.is_(None),
                            cast(Incident.current_risk_score_id, String) < str(risk_score_id),
                        ),
                    ),
                ),
            ),
        )

        update_stmt = (
            update(Incident)
            .where(
                Incident.id == incident.id,
                concurrency_condition,
            )
            .values(
                risk_score=calc_result["overall_score"],
                risk_priority_band=calc_result["priority_band"].value,
                current_risk_score_id=risk_score_id,
                risk_evidence_version=evidence_version,
                risk_evidence_as_of=evidence_as_of,
                risk_evaluation_as_of=eval_as_of,
                risk_calculated_at=calc_time,
            )
        )
        await db.execute(update_stmt)
        await db.commit()

        logger.info(
            "incident_risk_evaluated",
            incident_id=str(incident.id),
            overall_score=calc_result["overall_score"],
            priority_band=calc_result["priority_band"].value,
            evidence_version=evidence_version,
            trigger_reason=trigger_reason,
        )

        return RiskResult(
            overall_score=calc_result["overall_score"],
            priority_band=calc_result["priority_band"],
            base_score=calc_result["base_score"],
            temporal_decay=calc_result["temporal_decay"],
            sub_scores=calc_result["sub_scores"],
            effective_weights=calc_result["effective_weights"],
            factors=calc_result["factors"],
            explanation=explanation,
            evidence_version=evidence_version,
            evidence_as_of=evidence_as_of,
            evaluation_as_of=eval_as_of,
            calculated_at=calc_time,
            clean_mitigation=calc_result["clean_mitigation"],
            risk_score_id=risk_score_id,
        )

    async def get_latest_risk(
        self,
        db: AsyncSession,
        incident_id: uuid.UUID,
    ) -> RiskResult | None:
        """Retrieves the latest persisted risk score calculation for an incident."""
        stmt = (
            select(IncidentRiskScore)
            .where(IncidentRiskScore.incident_id == incident_id)
            .order_by(
                IncidentRiskScore.evidence_version.desc(),
                IncidentRiskScore.evaluation_as_of.desc(),
                IncidentRiskScore.id.desc(),
            )
            .limit(1)
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            return None
        return self._record_to_result(record)

    async def get_risk_history(
        self,
        db: AsyncSession,
        incident_id: uuid.UUID,
        limit: int = 50,
    ) -> list[RiskResult]:
        """Retrieves append-only risk score history for an incident."""
        stmt = (
            select(IncidentRiskScore)
            .where(IncidentRiskScore.incident_id == incident_id)
            .order_by(IncidentRiskScore.calculated_at.desc())
            .limit(limit)
        )
        res = await db.execute(stmt)
        records = list(res.scalars().all())
        return [self._record_to_result(r) for r in records]

    @staticmethod
    def _record_to_result(record: IncidentRiskScore) -> RiskResult:
        """Converts an ORM IncidentRiskScore record to a RiskResult domain object."""
        exp_dict = record.explanation
        explanation = RiskExplanation(
            incident_id=str(record.incident_id),
            evidence_as_of=record.evidence_as_of,
            evidence_version=record.evidence_version,
            evaluation_as_of=record.evaluation_as_of,
            calculated_at=record.calculated_at,
            overall_score=record.overall_score,
            priority_band=PriorityBand(record.priority_band),
            base_score=record.base_score,
            temporal_decay=record.temporal_decay,
            contributions=exp_dict["contributions"],
            mitigations=exp_dict.get("mitigations", {}),
            weights_used=record.effective_weights,
            conservation_verified=exp_dict.get("conservation_verified", True),
            summary=exp_dict.get("summary", ""),
        )

        return RiskResult(
            overall_score=record.overall_score,
            priority_band=PriorityBand(record.priority_band),
            base_score=record.base_score,
            temporal_decay=record.temporal_decay,
            sub_scores=ComponentScores(
                severity=record.severity_score,
                correlation=record.correlation_score,
                cti=record.cti_score,
                volume=record.volume_score,
                mitre_coverage=record.mitre_score,
            ),
            effective_weights=record.effective_weights,
            factors=record.factors,
            explanation=explanation,
            evidence_version=record.evidence_version,
            evidence_as_of=record.evidence_as_of,
            evaluation_as_of=record.evaluation_as_of,
            calculated_at=record.calculated_at,
            risk_score_id=record.id,
        )

    @classmethod
    async def evaluate_incident_background(
        cls,
        incident_id: uuid.UUID,
        trigger_reason: str = "background_trigger",
    ) -> None:
        """
        Background task entrypoint with complete failure isolation.
        Errors are caught and logged at ERROR level, never crashing callers or rolling back alerts.
        """
        try:
            service = cls()
            async with async_session_factory() as db:
                await service.evaluate_incident(
                    db=db,
                    incident_id=incident_id,
                    trigger_reason=trigger_reason,
                )
        except Exception as e:
            logger.error(
                "risk_background_evaluation_failed",
                incident_id=str(incident_id),
                trigger_reason=trigger_reason,
                error=str(e),
                exc_info=True,
            )
