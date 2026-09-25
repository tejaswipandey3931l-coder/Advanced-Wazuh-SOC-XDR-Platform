import pytest
from app.attack_chain.entity import extract_entities_from_event, EntityInfo
from app.attack_chain.constants import NodeType
from app.models.normalized_event import NormalizedEvent

def test_extract_ip():
    event = NormalizedEvent(src_ip="192.168.1.1", dst_ip="10.0.0.1")
    warnings = []
    entities = extract_entities_from_event(event, warnings.append)
    canonical_ids = {e.canonical_id for e in entities}
    assert "ip:192.168.1.1" in canonical_ids
    assert "ip:10.0.0.1" in canonical_ids

def test_extract_invalid_ip():
    event = NormalizedEvent(src_ip="010.0.0.1") # leading zero
    warnings = []
    entities = extract_entities_from_event(event, warnings.append)
    canonical_ids = {e.canonical_id for e in entities}
    assert "ip:010.0.0.1" not in canonical_ids # Rejected
    assert len(warnings) == 1

def test_extract_user():
    event = NormalizedEvent(user="Admin")
    warnings = []
    entities = extract_entities_from_event(event, warnings.append)
    assert len(entities) == 1
    assert entities[0].canonical_id == "user:admin"

def test_extract_file():
    event = NormalizedEvent(file_hash_sha256="A"*64)
    warnings = []
    entities = extract_entities_from_event(event, warnings.append)
    assert len(entities) == 1
    assert entities[0].canonical_id == f"file_sha256:{'a'*64}"
