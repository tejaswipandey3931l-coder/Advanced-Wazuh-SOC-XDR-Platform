import uuid
import pytest
from datetime import datetime, timezone
from app.attack_chain.algorithm import AttackChainBuilder
from app.attack_chain.mitre import MitreCatalog
from app.models.normalized_event import NormalizedEvent
from app.models.incident_event import IncidentEvent
from app.models.threat_intel_result import ThreatIntelResult

def test_builder_steps():
    mitre = MitreCatalog()
    
    e1 = NormalizedEvent(id=uuid.uuid4(), src_ip="10.0.0.1", dst_ip="192.168.1.1", event_timestamp=datetime.now(timezone.utc), agent_id="agent1")
    e2 = NormalizedEvent(id=uuid.uuid4(), src_ip="192.168.1.1", event_timestamp=datetime.now(timezone.utc), agent_id="agent1")
    
    ie1 = IncidentEvent(id=uuid.uuid4(), incident_id=uuid.uuid4(), normalized_event_id=e1.id)
    ie2 = IncidentEvent(id=uuid.uuid4(), incident_id=ie1.incident_id, normalized_event_id=e2.id)
    
    builder = AttackChainBuilder(
        incident_id=ie1.incident_id,
        evidence_version=1,
        events=[e1, e2],
        incident_events=[ie1, ie2],
        cti_results=[],
        rules=[],
        mitre_catalog=mitre
    )
    
    nodes, edges, warnings, truncated = builder.build()
    
    # Check that events produced nodes
    assert len([n for n in nodes if n["node_type"] == "EVENT"]) == 2
    
    # Check that IPs and Agent produced ENTITY nodes
    assert len([n for n in nodes if n["node_type"] == "ENTITY"]) == 3
    
    # Check chronological edge
    chron_edges = [e for e in edges if e["edge_type"] == "CHRONOLOGICAL_NEXT"]
    assert len(chron_edges) == 1
    
    # Check network relation
    net_edges = [e for e in edges if e["edge_type"] == "NETWORK_RELATION"]
    assert len(net_edges) == 1
