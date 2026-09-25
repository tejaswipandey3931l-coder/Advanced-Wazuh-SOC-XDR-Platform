import enum

# Current algorithm version
ALGORITHM_VERSION = "1.0.0"

class NodeType(str, enum.Enum):
    EVENT = "EVENT"
    ENTITY = "ENTITY"
    CTI_MATCH = "CTI_MATCH"
    TECHNIQUE = "TECHNIQUE"

class EdgeType(str, enum.Enum):
    CHRONOLOGICAL_NEXT = "CHRONOLOGICAL_NEXT"
    SAME_ENTITY = "SAME_ENTITY"
    SAME_AGENT = "SAME_AGENT"
    CORRELATED_WITH = "CORRELATED_WITH"
    NETWORK_RELATION = "NETWORK_RELATION"
    IOC_MATCH = "IOC_MATCH"
    EVENT_ENTITY = "EVENT_ENTITY"
    TECHNIQUE_SUPPORT = "TECHNIQUE_SUPPORT"

class Provenance(str, enum.Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"

class VerificationStatus(str, enum.Enum):
    VERIFIABLE = "VERIFIABLE"
    UNVERIFIABLE = "UNVERIFIABLE"

class MitreMappingType(str, enum.Enum):
    DIRECT_MAPPING = "DIRECT_MAPPING"
    INFERRED_MAPPING = "INFERRED_MAPPING"
    UNKNOWN = "UNKNOWN"

# Size Limits
LIMITS = {
    "MAX_EVENT_NODES_PER_CHAIN": 500,
    "MAX_SAME_ENTITY_EDGE_PAIRS_PER_ENTITY": 50,
    "MAX_CORRELATED_WITH_PAIRS_PER_RULE_GROUP": 100,
    "MAX_NETWORK_RELATION_EDGES_PER_CHAIN": 200,
    "MAX_SAME_AGENT_EDGE_PAIRS": 50,
    "MAX_TOTAL_EDGES_PER_CHAIN": 2000,
    "RECONSTRUCTION_TIMEOUT_SECONDS": 30,
}

# Base Tier (Provenance)
PROVENANCE_BASE_TIER = {
    Provenance.OBSERVED: 1.0,
    Provenance.INFERRED: 0.6,
    Provenance.UNKNOWN: 0.0,
}

# Source Quality
SOURCE_QUALITY = {
    "DIRECT_EVENT": 1.0,
    "CTI_MATCHED": 0.9,
    "RULE_INFERRED": 0.7,
}

# Support Discount
def support_discount(n: int) -> float:
    if n >= 3:
        return 1.0
    elif n == 2:
        return 0.9
    elif n == 1:
        return 0.8
    return 0.0

# Edge Type Weights
EDGE_TYPE_WEIGHTS = {
    EdgeType.EVENT_ENTITY: 1.00,
    EdgeType.IOC_MATCH: 0.95,
    "TECHNIQUE_SUPPORT_DIRECT": 0.90,
    EdgeType.SAME_AGENT: 0.90,
    "TECHNIQUE_SUPPORT_INFERRED": 0.70,
    EdgeType.CORRELATED_WITH: 0.85,
    EdgeType.SAME_ENTITY: 0.85,
    EdgeType.NETWORK_RELATION: 0.75,
    EdgeType.CHRONOLOGICAL_NEXT: 0.70,
}
