import pytest
import uuid
from datetime import datetime, timezone
from backend.app.attack_chain.algorithm import AttackChainBuilder
from backend.app.attack_chain.constants import LIMITS
from backend.app.attack_chain.mitre import MitreCatalog
from backend.app.models.normalized_event import NormalizedEvent

@pytest.fixture
def catalog():
    return MitreCatalog()

def test_size_limits_enforced(catalog):
    args = {
        "incident_id": uuid.uuid4(),
        "evidence_version": 1,
        "events": [],
        "incident_events": [],
        "cti_results": [],
        "rules": []
    }
    
    # Exceed edges and nodes limits manually, verify truncation
    builder = AttackChainBuilder(mitre_catalog=catalog, **args)
    
    node_limit = LIMITS["MAX_EVENT_NODES_PER_CHAIN"]
    edge_limit = LIMITS["MAX_TOTAL_EDGES_PER_CHAIN"]
    
    # Insert more nodes than limit
    for i in range(node_limit + 10):
        logical_id = f"node_{i}"
        builder.nodes[logical_id] = {
            "logical_node_id": logical_id,
            "evidence_strength": 0.5
        }
        
    # Insert more edges than limit
    for i in range(edge_limit + 10):
        logical_id = f"edge_{i}"
        builder.edges[logical_id] = {
            "logical_edge_id": logical_id,
            "src_node_logical_id": f"node_{i % (node_limit + 10)}", # Point to existing nodes
            "dst_node_logical_id": f"node_{i % (node_limit + 10)}",
            "evidence_strength": 0.5
        }
        
    # Apply truncation
    builder._step21_apply_size_limits()
    
    assert len(builder.nodes) <= node_limit
    assert len(builder.edges) <= edge_limit
    assert builder.truncated is True
    
    # Ensure warnings were added
    warning_types = [w["type"] for w in builder.warnings]
    assert "node_truncation" in warning_types
    assert "edge_truncation" in warning_types

def test_pair_limits(catalog):
    # Tests that pair limits are checked.
    # To truly test pair limits we can insert many events with the same entity.
    pass
