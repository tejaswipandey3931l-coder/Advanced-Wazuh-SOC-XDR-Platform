import pytest
from datetime import datetime, timezone
import hashlib

from backend.app.attack_chain.identity import compute_cti_fingerprint
from backend.app.models.threat_intel_result import ThreatIntelResult

def mock_cti(id_val, queried_at_iso, ioc, matched=True):
    cti = ThreatIntelResult(
        id=id_val,
        ioc_value=ioc,
        matched=matched,
        queried_at=datetime.fromisoformat(queried_at_iso)
    )
    return cti

def test_cti_fingerprint_behavior():
    cti1 = mock_cti(1, "2026-01-01T10:00:00+00:00", "10.0.0.1")
    cti2 = mock_cti(2, "2026-01-01T11:00:00+00:00", "192.168.1.1")
    
    # 1) Base fingerprint
    f1 = compute_cti_fingerprint([cti1, cti2])
    
    # 2) MAX(queried_at) unchanged, but eligible evidence changed
    cti3 = mock_cti(3, "2026-01-01T10:30:00+00:00", "10.0.0.2")
    f2 = compute_cti_fingerprint([cti1, cti3, cti2])
    assert f1 != f2, "Fingerprint should change when evidence set changes"
    
    # 3) Same evidence -> same fingerprint
    f3 = compute_cti_fingerprint([cti1, cti3, cti2])
    assert f2 == f3, "Identical evidence set should yield identical fingerprint"
    
    # 4) Empty evidence set -> deterministic fingerprint
    f_empty = compute_cti_fingerprint([])
    expected_empty = hashlib.sha256(b"EMPTY_CTI_SET").hexdigest()
    assert f_empty == expected_empty, "Empty set should yield deterministic fallback fingerprint"
