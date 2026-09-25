import pytest
from backend.app.attack_chain.identity import compute_chain_canonical_id

def test_chain_idempotency():
    args = {
        "incident_id": "12345678-1234-5678-1234-567812345678",
        "cti_evidence_fingerprint": "mock_cti_fingerprint",
        "algorithm_version": "1.0",
        "catalog_version": "1.0",
        "node_logical_ids": ["n1", "n2"],
        "edge_logical_ids": ["e1"]
    }
    
    # 1) Base canonical identity
    id1 = compute_chain_canonical_id(**args)
    
    # 2) Same evidence -> same canonical chain identity
    id2 = compute_chain_canonical_id(**args)
    assert id1 == id2
    
    # 3) Changed edge set -> different canonical identity
    args3 = dict(args)
    args3["edge_logical_ids"] = ["e1", "e2"]
    id3 = compute_chain_canonical_id(**args3)
    assert id1 != id3
    
    # 4) Changed CTI fingerprint -> different canonical identity
    args4 = dict(args)
    args4["cti_evidence_fingerprint"] = "new_cti_fingerprint"
    id4 = compute_chain_canonical_id(**args4)
    assert id1 != id4
    
    # 5) Changed algorithm version -> different canonical identity
    args5 = dict(args)
    args5["algorithm_version"] = "1.1"
    id5 = compute_chain_canonical_id(**args5)
    assert id1 != id5
    
    # 6) Changed catalog version -> different canonical identity
    args6 = dict(args)
    args6["catalog_version"] = "1.1"
    id6 = compute_chain_canonical_id(**args6)
    assert id1 != id6
