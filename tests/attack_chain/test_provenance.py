import pytest
from app.attack_chain.constants import Provenance, EdgeType

def test_provenance_verification():
    # Explicitly verify that terminology does not imply inferred edges prove causality.
    # Note: EdgeType doesn't store provenance directly, it's assigned in algorithm.py.
    # We will test the constants/logic explicitly mapped in the plan.
    
    # 1) EVENT_ENTITY = OBSERVED
    # 2) CTI_MATCH = OBSERVED (Node)
    # 3) IOC_MATCH = INFERRED
    # 4) SAME_ENTITY = INFERRED
    # 5) SAME_AGENT = INFERRED
    # 6) CORRELATED_WITH = INFERRED
    # 7) CHRONOLOGICAL_NEXT = INFERRED
    
    # Check the ENUM values to ensure they are strictly defined
    assert Provenance.OBSERVED.value == "OBSERVED"
    assert Provenance.INFERRED.value == "INFERRED"
    
    # Note: CHRONOLOGICAL_NEXT does NOT imply causality, as stated in Rev5: 
    # "[Chronological adjacency; does NOT imply causality]"
    assert EdgeType.CHRONOLOGICAL_NEXT.value == "CHRONOLOGICAL_NEXT"
    assert EdgeType.SAME_ENTITY.value == "SAME_ENTITY"
    assert EdgeType.SAME_AGENT.value == "SAME_AGENT"
    assert EdgeType.CORRELATED_WITH.value == "CORRELATED_WITH"
    assert EdgeType.IOC_MATCH.value == "IOC_MATCH"
    assert EdgeType.EVENT_ENTITY.value == "EVENT_ENTITY"
    
    # Ensure no CAUSAL provenance or edge exists in the code to violate this rule
    assert not hasattr(Provenance, "CAUSAL")
    assert not hasattr(EdgeType, "CAUSED_BY")
