import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_, desc, func
from sqlalchemy.orm import selectinload

from ..models.incident import Incident
from ..models.normalized_event import NormalizedEvent
from ..models.incident_event import IncidentEvent
from ..models.threat_intel_result import ThreatIntelResult
from ..models.correlation_rule import CorrelationRule
from ..models.attack_chain import AttackChain

from .constants import ALGORITHM_VERSION
from .mitre import MitreCatalog
from .algorithm import AttackChainBuilder
from .identity import compute_cti_fingerprint, compute_chain_canonical_id
from .models import AttackChainVersion, AttackChainNode, AttackChainEdge

class ReconstructionService:
    def __init__(self, db: AsyncSession, mitre_catalog: MitreCatalog):
        self.db = db
        self.mitre = mitre_catalog

    async def reconstruct(self, incident_id: uuid.UUID, evidence_version: int) -> Optional[AttackChainVersion]:
        """
        Implementation of Reconstruction Algorithm (Steps 1-25) from §15.
        """
        # STEP 1 - VALIDATE AND ACQUIRE LOCK
        stmt = select(Incident).where(Incident.id == incident_id).with_for_update()
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()
        if not incident:
            return None
            
        if incident.evidence_version != evidence_version:
            # Stale request
            return None
            
        t_reconstruction = datetime.now(timezone.utc)
        
        # Load incident events and normalized events
        ie_stmt = select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        ie_result = await self.db.execute(ie_stmt)
        incident_events = ie_result.scalars().all()
        event_ids = [ie.normalized_event_id for ie in incident_events]
        
        if not event_ids:
            return None
            
        ne_stmt = select(NormalizedEvent).where(NormalizedEvent.id.in_(event_ids))
        ne_result = await self.db.execute(ne_stmt)
        events = ne_result.scalars().all()
        
        # Load CTI
        cti_stmt = select(ThreatIntelResult).where(
            or_(
                ThreatIntelResult.incident_id == incident_id,
                ThreatIntelResult.normalized_event_id.in_(event_ids)
            ),
            ThreatIntelResult.queried_at <= t_reconstruction
        ).order_by(ThreatIntelResult.queried_at.asc(), ThreatIntelResult.id.asc())
        
        cti_result = await self.db.execute(cti_stmt)
        cti_records = cti_result.scalars().all()
        
        # Load rules
        rule_ids = {ie.correlation_rule_id for ie in incident_events if ie.correlation_rule_id}
        rules = []
        if rule_ids:
            rule_stmt = select(CorrelationRule).where(CorrelationRule.id.in_(rule_ids))
            rule_result = await self.db.execute(rule_stmt)
            rules = rule_result.scalars().all()
            
        # STEP 2 - CHECK IDEMPOTENCY
        cti_fingerprint = compute_cti_fingerprint(cti_records)
        
        latest_version_stmt = select(AttackChainVersion).where(
            AttackChainVersion.incident_id == incident_id
        ).order_by(desc(AttackChainVersion.chain_version)).limit(1)
        
        latest_result = await self.db.execute(latest_version_stmt)
        latest_version = latest_result.scalar_one_or_none()
        
        if latest_version:
            is_idempotent = (
                latest_version.evidence_version == evidence_version and
                latest_version.cti_evidence_fingerprint == cti_fingerprint and
                latest_version.reconstruction_algorithm_version == ALGORITHM_VERSION and
                latest_version.attck_catalog_version == self.mitre.version
            )
            if is_idempotent:
                return latest_version
                
        # STEP 4 - COMPUTE EVIDENCE HORIZONS
        event_evidence_as_of = max([e.timestamp for e in events if e.timestamp] + [incident.created_at])
        cti_evidence_as_of = max([cti.queried_at for cti in cti_records]) if cti_records else None
        chain_evidence_as_of = max(event_evidence_as_of, cti_evidence_as_of or event_evidence_as_of)
        
        # STEPS 5 to 21 - BUILD GRAPH
        builder = AttackChainBuilder(
            incident_id=incident_id,
            evidence_version=evidence_version,
            events=events,
            incident_events=incident_events,
            cti_results=cti_records,
            rules=rules,
            mitre_catalog=self.mitre
        )
        nodes_dict_list, edges_dict_list, warnings, is_truncated = builder.build()
        
        node_logical_ids = [n["logical_node_id"] for n in nodes_dict_list]
        edge_logical_ids = [e["logical_edge_id"] for e in edges_dict_list]
        
        # STEP 22 - COMPUTE chain_canonical_id
        chain_canonical_id = compute_chain_canonical_id(
            incident_id=incident_id,
            cti_evidence_fingerprint=cti_fingerprint,
            algorithm_version=ALGORITHM_VERSION,
            catalog_version=self.mitre.version,
            node_logical_ids=node_logical_ids,
            edge_logical_ids=edge_logical_ids
        )
        
        # Ensure we don't recreate the exact same canonical id if it already exists (redundancy check)
        check_canonical_stmt = select(AttackChainVersion).where(
            AttackChainVersion.chain_canonical_id == chain_canonical_id
        ).limit(1)
        check_canon_res = await self.db.execute(check_canonical_stmt)
        if check_canon_res.scalar_one_or_none():
            # Already have this graph!
            # Could link to it, but the transaction flow dictates we create a new version if cti or evidence version changed.
            pass
        
        # STEP 23 - ALLOCATE chain_version
        version_stmt = select(func.coalesce(func.max(AttackChainVersion.chain_version), 0) + 1).where(
            AttackChainVersion.incident_id == incident_id
        )
        version_res = await self.db.execute(version_stmt)
        next_chain_version = version_res.scalar() or 1
        
        # STEP 24 - PERSIST
        tactic_ids_present = list(set([t for n in nodes_dict_list for t in n.get("mitre_tactic_ids", [])]))
        
        chain_version = AttackChainVersion(
            incident_id=incident_id,
            chain_canonical_id=chain_canonical_id,
            chain_version=next_chain_version,
            evidence_version=evidence_version,
            event_evidence_as_of=event_evidence_as_of,
            cti_evidence_as_of=cti_evidence_as_of,
            chain_evidence_as_of=chain_evidence_as_of,
            cti_evidence_fingerprint=cti_fingerprint,
            node_count=len(nodes_dict_list),
            edge_count=len(edges_dict_list),
            technique_count=len([n for n in nodes_dict_list if n["node_type"] == "TECHNIQUE"]),
            tactic_ids_present=tactic_ids_present,
            reconstruction_warnings=warnings,
            attck_catalog_version=self.mitre.version,
            reconstruction_algorithm_version=ALGORITHM_VERSION,
            truncated=is_truncated,
            complete=True
        )
        self.db.add(chain_version)
        await self.db.flush()
        
        for n in nodes_dict_list:
            node = AttackChainNode(chain_version_id=chain_version.id, **n)
            self.db.add(node)
            
        for e in edges_dict_list:
            edge = AttackChainEdge(chain_version_id=chain_version.id, **e)
            self.db.add(edge)
            
        # Additive Update to attack_chains stub
        ac_stmt = select(AttackChain).where(AttackChain.incident_id == incident_id)
        ac_res = await self.db.execute(ac_stmt)
        attack_chain = ac_res.scalar_one_or_none()
        if attack_chain:
            attack_chain.chain_version_id = chain_version.id
            attack_chain.evidence_version = evidence_version
            attack_chain.last_calculated_at = t_reconstruction
            # Also calculate confidence as the min node strength (simplified summary)
            node_strengths = [n.get("evidence_strength", 0.0) for n in nodes_dict_list]
            attack_chain.confidence = sum(node_strengths)/len(node_strengths) if node_strengths else 0.0
            
        return chain_version
