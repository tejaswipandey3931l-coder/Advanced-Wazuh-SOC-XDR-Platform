import hashlib
import uuid
from typing import List, Iterable
from ..models.threat_intel_result import ThreatIntelResult

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def compute_cti_fingerprint(cti_records: Iterable[ThreatIntelResult]) -> str:
    """
    Computes the CTI evidence fingerprint for idempotency checking.
    Records must be sorted by queried_at ASC, id ASC before passing here.
    """
    # Assuming they are already ordered correctly per C10 correction.
    cti_ids = [str(r.id) for r in cti_records]
    if not cti_ids:
        return sha256_hash("EMPTY_CTI_SET")
    
    # We still sort them here to be absolutely safe
    sorted_ids = sorted(cti_ids)
    return sha256_hash(",".join(sorted_ids))

def compute_chain_canonical_id(
    incident_id: uuid.UUID,
    cti_evidence_fingerprint: str,
    algorithm_version: str,
    catalog_version: str,
    node_logical_ids: List[str],
    edge_logical_ids: List[str]
) -> str:
    """
    Computes the canonical identity of the chain (Correction C7).
    """
    sorted_nodes = sorted(node_logical_ids)
    sorted_edges = sorted(edge_logical_ids)
    
    nodes_hash = sha256_hash(",".join(sorted_nodes))
    edges_hash = sha256_hash(",".join(sorted_edges))
    
    components = [
        str(incident_id),
        cti_evidence_fingerprint,
        algorithm_version,
        catalog_version,
        nodes_hash,
        edges_hash
    ]
    
    return sha256_hash("|".join(components))
