import pytest
from app.attack_chain.constants import Provenance, EdgeType
from app.attack_chain.evidence_strength import calculate_node_evidence_strength, calculate_edge_evidence_strength

def test_node_strength():
    # OBSERVED CTI_MATCH, n=1 (0.8 discount), base=1.0, sq=0.9 -> 0.72
    assert calculate_node_evidence_strength(Provenance.OBSERVED, "CTI_MATCHED", 1) == pytest.approx(0.72)
    # OBSERVED EVENT, n=1 (0.8 discount), base=1.0, sq=1.0 -> 0.8
    assert calculate_node_evidence_strength(Provenance.OBSERVED, "DIRECT_EVENT", 1) == pytest.approx(0.8)
    # INFERRED RULE, n=1 (0.8 discount), base=0.6, sq=0.7 -> 0.336
    assert calculate_node_evidence_strength(Provenance.INFERRED, "RULE_INFERRED", 1) == pytest.approx(0.336)

def test_edge_strength():
    # EVENT_ENTITY (weight 1.00)
    assert calculate_edge_evidence_strength(0.9, 0.9, EdgeType.EVENT_ENTITY, False) == pytest.approx(0.90)
    
    # SAME_ENTITY (weight 0.85)
    assert calculate_edge_evidence_strength(0.9, 0.9, EdgeType.SAME_ENTITY, False) == pytest.approx(0.765)
    
    # IOC_MATCH (weight 0.95)
    assert calculate_edge_evidence_strength(0.95, 0.9, EdgeType.IOC_MATCH, False) == pytest.approx(0.855)
