from typing import Optional
from .constants import (
    Provenance,
    EdgeType,
    PROVENANCE_BASE_TIER,
    SOURCE_QUALITY,
    EDGE_TYPE_WEIGHTS,
    support_discount
)

def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

def calculate_node_evidence_strength(
    provenance: Provenance,
    source_type: str,
    n_corroborating_events: int
) -> float:
    """
    Calculates the evidence strength for a node based on:
    - Provenance (OBSERVED, INFERRED, UNKNOWN)
    - Source Quality (DIRECT_EVENT, CTI_MATCHED, RULE_INFERRED)
    - Number of corroborating events
    """
    base = PROVENANCE_BASE_TIER.get(provenance, 0.0)
    sq = SOURCE_QUALITY.get(source_type, 0.0)
    sd = support_discount(n_corroborating_events)
    
    return clamp(base * sq * sd)

def calculate_edge_evidence_strength(
    src_node_strength: float,
    dst_node_strength: float,
    edge_type: EdgeType,
    is_inferred_mapping: bool = False
) -> float:
    """
    Calculates the evidence strength for an edge.
    Note: TECHNIQUE_SUPPORT has two weights based on direct vs inferred mapping.
    """
    weight_key = edge_type
    
    # Handle the technique support split
    if edge_type == EdgeType.TECHNIQUE_SUPPORT:
        if is_inferred_mapping:
            weight_key = "TECHNIQUE_SUPPORT_INFERRED"
        else:
            weight_key = "TECHNIQUE_SUPPORT_DIRECT"
            
    weight = EDGE_TYPE_WEIGHTS.get(weight_key, 0.0)
    
    return clamp(min(src_node_strength, dst_node_strength) * weight)
