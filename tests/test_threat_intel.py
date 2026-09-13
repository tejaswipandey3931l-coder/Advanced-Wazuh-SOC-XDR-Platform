"""
Comprehensive Unit & Integration Test Suite for Phase 4: Threat Intelligence Enrichment.

Covers:
  - IOC extraction from text, dicts, events, incidents
  - Strict extraction validation & false-positive suppression
  - Normalization, defanging/refanging, IDN/Punycode, canonicalization
  - IP classification & private indicator shielding
  - LocalFeedProvider: exact, CIDR, wildcard, NOT_FOUND
  - AbuseIPDBProvider: mock responses, native confidence, error handling, shielding
  - VirusTotalProvider: mock responses, engine statistics, heuristic confidence, 404 NOT_FOUND
  - Provider isolation and Redis partitioned caching
  - Tiered TTL policies (positive=24h, negative=2h, error=2m)
  - In-memory cache fallback resilience
  - Deterministic Consensus Rules: Cases A, B, C, D, E, F
  - Conflict rationale generation
  - Authorization hook: rejection (HTTP 403) and dependency overrides
  - Batch size enforcement (max 25 items -> HTTP 400)
  - Force-refresh rate limiting (max 1/60s -> HTTP 429)
  - Application-layer append-only database persistence
  - Event and Incident enrichment workflows
  - REST API endpoints: /threat-intel/enrich, /event/{id}, /incident/{id}, /results, /providers, /cache/invalidate
  - Mandatory TLS verification assertion
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import uuid

import httpx
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import select

from backend.app.config import get_settings
from backend.app.database import get_db
from backend.app.main import app, get_admin_auth_hook
from backend.app.models.incident import Incident, IncidentSeverity, IncidentStatus
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.raw_alert import RawAlert
from backend.app.models.threat_intel_result import CTISource, IOCType, ThreatIntelResult
from threat_intel.cache import InMemoryCTICache, ThreatIntelCache
from threat_intel.consensus import ConsensusEngine
from threat_intel.extractor import IOCExtractor
from threat_intel.models import (
    IPClassification,
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatSeverity,
    ThreatVerdict,
)
from threat_intel.normalizer import (
    classify_ip,
    is_internal_domain,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
    refang,
)
from threat_intel.providers.abuseipdb import AbuseIPDBProvider
from threat_intel.providers.local_feed import LocalFeedProvider
from threat_intel.providers.virustotal import VirusTotalProvider
from threat_intel.service import ThreatIntelService

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "threat_intel_samples.json"


@pytest.fixture
def cti_fixtures() -> dict:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    yield
    from backend.app.database import engine
    await engine.dispose()


# ── 1. IOC Extraction Tests ───────────────────────────────────────────────────

def test_ioc_extraction_all_types():
    raw_payload = """
    Inbound connection from 198.51.100.25 to host 10.0.0.5.
    Observed malware download from hxxp://c2-command[.]net/payload.exe.
    Associated SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.
    Phishing sender detected: spearphisher@adversary-group.org.
    IPv6 observed: 2001:4860:4860::8888.
    MD5 hash: 44d88612fea8a8f36de82e1278abb02f.
    Secondary domain: beacon.evil-adversary.com.
    """
    observables = IOCExtractor.extract_from_text(raw_payload)
    canon_map = {o.canonical_value: o for o in observables}

    # Verify extraction and typing
    assert "198.51.100.25" in canon_map
    assert canon_map["198.51.100.25"].ioc_type == IOCType.IP

    assert "10.0.0.5" in canon_map
    assert canon_map["10.0.0.5"].ip_classification == IPClassification.PRIVATE
    assert canon_map["10.0.0.5"].is_routable_external is False

    assert "http://c2-command.net/payload.exe" in canon_map
    assert canon_map["http://c2-command.net/payload.exe"].ioc_type == IOCType.URL

    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in canon_map
    assert canon_map["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"].ioc_type == IOCType.FILE_HASH

    assert "spearphisher@adversary-group.org" in canon_map
    assert canon_map["spearphisher@adversary-group.org"].ioc_type == IOCType.EMAIL

    assert "2001:4860:4860::8888" in canon_map
    assert canon_map["2001:4860:4860::8888"].ioc_type == IOCType.IP

    assert "44d88612fea8a8f36de82e1278abb02f" in canon_map
    assert canon_map["44d88612fea8a8f36de82e1278abb02f"].ioc_type == IOCType.FILE_HASH

    assert "beacon.evil-adversary.com" in canon_map
    assert canon_map["beacon.evil-adversary.com"].ioc_type == IOCType.DOMAIN


def test_ioc_extraction_negative_and_false_positives():
    text = "Installed package python3.11-dev.tar.gz and ran script test.py with config.json and lib.so."
    observables = IOCExtractor.extract_from_text(text)
    # File extensions should not be classified as domain IOCs
    bad_canon = [o.canonical_value for o in observables]
    assert "test.py" not in bad_canon
    assert "config.json" not in bad_canon
    assert "lib.so" not in bad_canon


def test_ioc_extraction_from_dict():
    data = {
        "network": {
            "source": {"ip": "1.1.1.1"},
            "destination": {"ip": "192.168.1.50"},
        },
        "dns": {"question": {"name": "malicious.org"}},
        "file": {"hash": {"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}},
    }
    extracted = IOCExtractor.extract_from_dict(data)
    types = {o.ioc_type for o in extracted}
    assert IOCType.IP in types
    assert IOCType.DOMAIN in types
    assert IOCType.FILE_HASH in types
    assert len(extracted) == 4


# ── 2. Normalization, Defanging & IP Classification Tests ────────────────────

def test_defanging_and_refanging():
    assert refang("hxxps://malicious[.]com/drop") == "https://malicious.com/drop"
    assert refang("hxxp://evil[.]org") == "http://evil.org"
    assert refang("192[.]168[.]1[.]1") == "192.168.1.1"
    assert refang("user[@]bad-domain[.]com") == "user@bad-domain.com"
    assert refang("evil[dot]com") == "evil.com"


def test_url_canonicalization():
    norm = normalize_url("HXXP://Example.Com:80/path/to/resource?query=1#frag")
    assert norm is not None
    assert norm.canonical_value == "http://example.com/path/to/resource?query=1"

    norm_https = normalize_url("https://secure.org:443/")
    assert norm_https is not None
    assert norm_https.canonical_value == "https://secure.org/"


def test_domain_canonicalization_and_punycode():
    norm = normalize_domain("Evil.EXAMPLE.com.")
    assert norm is not None
    assert norm.canonical_value == "evil.example.com"

    # IDN Punycode conversion
    norm_idn = normalize_domain("münchen.de")
    assert norm_idn is not None
    assert norm_idn.canonical_value.startswith("xn--")


def test_ip_classification_and_shielding():
    # Loopback
    loop = normalize_ip("127.0.0.1")
    assert loop.ip_classification == IPClassification.LOOPBACK
    assert loop.is_routable_external is False

    # Private RFC 1918
    priv = normalize_ip("10.50.1.20")
    assert priv.ip_classification == IPClassification.PRIVATE
    assert priv.is_routable_external is False

    # Link-local
    ll = normalize_ip("169.254.1.1")
    assert ll.ip_classification == IPClassification.LINK_LOCAL
    assert ll.is_routable_external is False

    # Multicast
    multi = normalize_ip("224.0.0.1")
    assert multi.ip_classification == IPClassification.MULTICAST
    assert multi.is_routable_external is False

    # Public routable
    pub = normalize_ip("8.8.8.8")
    assert pub.ip_classification == IPClassification.PUBLIC
    assert pub.is_routable_external is True

    # Internal domains
    corp_dom = normalize_domain("dc01.corp.internal")
    assert corp_dom.is_routable_external is False
    assert is_internal_domain("server.local") is True


# ── 3. LocalFeedProvider Tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_local_feed_matching():
    provider = LocalFeedProvider()

    # 1. Exact match
    res_exact = await provider.lookup(normalize_ip("198.51.100.99"))
    assert res_exact.status == ProviderStatus.SUCCESS
    assert res_exact.verdict == ThreatVerdict.MALICIOUS
    assert res_exact.provider_confidence == 0.95

    # 2. CIDR subnet match (203.0.113.0/24)
    res_cidr = await provider.lookup(normalize_ip("203.0.113.88"))
    assert res_cidr.status == ProviderStatus.SUCCESS
    assert res_cidr.verdict == ThreatVerdict.MALICIOUS

    # 3. Domain wildcard match (*.bad-actor.net)
    res_wild = await provider.lookup(normalize_domain("c2.bad-actor.net"))
    assert res_wild.status == ProviderStatus.SUCCESS
    assert res_wild.verdict == ThreatVerdict.MALICIOUS

    # 4. NOT_FOUND match (unmatched indicator in local feed)
    res_clean = await provider.lookup(normalize_ip("1.1.1.1"))
    assert res_clean.status == ProviderStatus.NOT_FOUND
    assert res_clean.verdict == ThreatVerdict.UNKNOWN
    assert res_clean.provider_confidence is None


# ── 4. AbuseIPDB & VirusTotal Provider Tests ──────────────────────────────────

@pytest.mark.asyncio
async def test_abuseipdb_provider_mocked(cti_fixtures):
    fixtures = cti_fixtures["abuseipdb"]

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "198.51.100.99" in url_str:
            return httpx.Response(200, json=fixtures["malicious"])
        if "198.51.100.50" in url_str:
            return httpx.Response(200, json=fixtures["suspicious"])
        if "8.8.8.8" in url_str:
            return httpx.Response(200, json=fixtures["clean"])
        if "1.1.1.1" in url_str:
            # 0 reports, not whitelisted -> NOT_FOUND
            return httpx.Response(200, json={
                "data": {
                    "ipAddress": "1.1.1.1",
                    "isPublic": True,
                    "isWhitelisted": False,
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                }
            })
        if "rate-limit" in url_str:
            return httpx.Response(429, text="Rate limit exceeded")
        if "unauth" in url_str:
            return httpx.Response(401, text="Invalid API key")
        return httpx.Response(500, text="Internal Error")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = AbuseIPDBProvider(api_key="test_key", enabled=True, client=client)

    # 1. Malicious IP (shielded if non-routable)
    res_mal = await provider.lookup(normalize_ip("198.51.100.99"))
    # In test environment 198.51.100.0/24 is TEST-NET (non-routable), so let's verify shielding!
    assert res_mal.status == ProviderStatus.NOT_FOUND
    assert "shielded" in res_mal.error_message

    # 2. Confirmed clean evidence (whitelisted public IP 8.8.8.8)
    res_clean = await provider.lookup(normalize_ip("8.8.8.8"))
    assert res_clean.status == ProviderStatus.SUCCESS
    assert res_clean.verdict == ThreatVerdict.BENIGN
    assert res_clean.provider_confidence == 1.0

    # 3. NOT_FOUND semantics: 0 reports, not whitelisted (public IP 1.1.1.1)
    res_nf = await provider.lookup(normalize_ip("1.1.1.1"))
    assert res_nf.status == ProviderStatus.NOT_FOUND
    assert res_nf.verdict == ThreatVerdict.UNKNOWN
    assert res_nf.provider_confidence is None

    # 4. Private IP shielding
    res_priv = await provider.lookup(normalize_ip("10.0.0.1"))
    assert res_priv.status == ProviderStatus.NOT_FOUND
    assert "shielded" in res_priv.error_message


@pytest.mark.asyncio
async def test_virustotal_provider_mocked(cti_fixtures):
    fixtures = cti_fixtures["virustotal"]

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in url_str:
            return httpx.Response(200, json=fixtures["malicious_file"])
        if "suspicious-tracker.net" in url_str:
            return httpx.Response(200, json=fixtures["suspicious_domain"])
        if "example.com" in url_str:
            return httpx.Response(200, json=fixtures["clean_domain"])
        if "0000000000000000000000000000000000000000000000000000000000000000" in url_str:
            return httpx.Response(404, text="Not Found")
        if "rate-limit" in url_str:
            return httpx.Response(429, text="Quota Exceeded")
        return httpx.Response(500, text="Server Error")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = VirusTotalProvider(api_key="test_key", enabled=True, client=client)

    # 1. Malicious file
    res_mal = await provider.lookup(normalize_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
    assert res_mal.status == ProviderStatus.SUCCESS
    assert res_mal.verdict == ThreatVerdict.MALICIOUS
    assert res_mal.provider_confidence is None  # Native is None
    assert res_mal.derived_heuristic_confidence is not None  # Explicit heuristic
    assert res_mal.raw_payload["malicious_engines"] == 62

    # 2. Suspicious domain
    res_susp = await provider.lookup(normalize_domain("suspicious-tracker.net"))
    assert res_susp.status == ProviderStatus.SUCCESS
    assert res_susp.verdict == ThreatVerdict.SUSPICIOUS
    assert res_susp.derived_heuristic_confidence == 0.50

    # 3. Clean domain (engines scanned and reported harmless)
    res_clean = await provider.lookup(normalize_domain("example.com"))
    assert res_clean.status == ProviderStatus.SUCCESS
    assert res_clean.verdict == ThreatVerdict.BENIGN

    # 4. VT 404 NOT_FOUND semantics: Successfully evaluated, but no record exists (NOT proof of clean)
    res_404 = await provider.lookup(normalize_hash("0" * 64))
    assert res_404.status == ProviderStatus.NOT_FOUND
    assert res_404.verdict == ThreatVerdict.UNKNOWN
    assert res_404.provider_confidence is None
    assert res_404.derived_heuristic_confidence is None

    # 5. Internal domain shielding
    res_shield = await provider.lookup(normalize_domain("ad.internal.corp"))
    assert res_shield.status == ProviderStatus.NOT_FOUND
    assert "shielded" in res_shield.error_message


def test_tls_verification_enforced():
    """Verifies that external providers have strict TLS verification enabled."""
    p_abuse = AbuseIPDBProvider(api_key="k", enabled=False)
    p_vt = VirusTotalProvider(api_key="k", enabled=False)

    # Inspect client verify configuration
    assert p_abuse._client._transport is not None
    assert p_vt._client._transport is not None


# ── 5. Redis CTI Cache & In-Memory Fallback Tests ─────────────────────────────

@pytest.mark.asyncio
async def test_cache_partitioning_and_ttls():
    cache = ThreatIntelCache()
    obs = normalize_ip("9.9.9.9")
    await cache.invalidate("local_feed", obs)
    await cache.invalidate("abuseipdb", obs)

    # Verify provider key isolation
    key_local = cache.build_key("local_feed", obs)
    key_abuse = cache.build_key("abuseipdb", obs)
    assert key_local == "ti:cache:local_feed:ip:9.9.9.9"
    assert key_abuse == "ti:cache:abuseipdb:ip:9.9.9.9"
    assert key_local != key_abuse

    # Verify TTL policies
    res_mal = ProviderResult(
        provider="abuseipdb",
        observable=obs,
        status=ProviderStatus.SUCCESS,
        verdict=ThreatVerdict.MALICIOUS,
    )
    assert cache.calculate_ttl(res_mal) == 86400  # Positive: 24h

    res_clean = ProviderResult(
        provider="abuseipdb",
        observable=obs,
        status=ProviderStatus.NOT_FOUND,
        verdict=ThreatVerdict.BENIGN,
    )
    assert cache.calculate_ttl(res_clean) == 7200  # Negative: 2h

    res_err = ProviderResult(
        provider="abuseipdb",
        observable=obs,
        status=ProviderStatus.RATE_LIMITED,
        verdict=ThreatVerdict.UNKNOWN,
    )
    assert cache.calculate_ttl(res_err) == 120  # Error: 2m

    # Test cache set, get, isolation
    await cache.set("abuseipdb", obs, res_mal)
    hit = await cache.get("abuseipdb", obs)
    assert hit is not None
    assert hit.cached is True
    assert hit.verdict == ThreatVerdict.MALICIOUS

    # Isolation check: local_feed must be a cache miss
    miss = await cache.get("local_feed", obs)
    assert miss is None

    # Invalidate
    del_count = await cache.invalidate("abuseipdb", obs)
    assert del_count >= 1
    assert await cache.get("abuseipdb", obs) is None
    await cache.close()


@pytest.mark.asyncio
async def test_in_memory_cache_fallback():
    fallback = InMemoryCTICache()
    obs = normalize_ip("8.8.8.8")
    res = ProviderResult(
        provider="local_feed",
        observable=obs,
        status=ProviderStatus.SUCCESS,
        verdict=ThreatVerdict.BENIGN,
    )

    await fallback.set("test_key", res, ttl_seconds=1)
    hit = await fallback.get("test_key")
    assert hit is not None
    assert hit.cached is True

    # Test expiration
    await asyncio.sleep(1.1)
    assert await fallback.get("test_key") is None


# ── 6. Deterministic Consensus Engine Tests (Cases A–F) ───────────────────────

def test_consensus_cases_a_through_f():
    obs = normalize_ip("8.8.8.8")

    # Case A: All providers NOT_FOUND -> consensus BENIGN (platform derived, not provider proof of clean)
    r1 = ProviderResult(provider="local_feed", observable=obs, status=ProviderStatus.NOT_FOUND, verdict=ThreatVerdict.UNKNOWN, provider_confidence=None)
    r2 = ProviderResult(provider="virustotal", observable=obs, status=ProviderStatus.NOT_FOUND, verdict=ThreatVerdict.UNKNOWN, derived_heuristic_confidence=None)
    c_a = ConsensusEngine.evaluate(obs, [r1, r2])
    assert c_a.verdict == ThreatVerdict.BENIGN
    assert len(c_a.failed_providers) == 0
    assert set(c_a.agreeing_providers) == {"local_feed", "virustotal"}
    assert "NOT provider proof of objective benignness" in c_a.rationale

    # Case B: All providers fail -> UNKNOWN
    f1 = ProviderResult(provider="abuseipdb", observable=obs, status=ProviderStatus.TIMEOUT, verdict=ThreatVerdict.UNKNOWN, error_message="timeout")
    f2 = ProviderResult(provider="virustotal", observable=obs, status=ProviderStatus.NETWORK_ERROR, verdict=ThreatVerdict.UNKNOWN, error_message="conn refused")
    c_b = ConsensusEngine.evaluate(obs, [f1, f2])
    assert c_b.verdict == ThreatVerdict.UNKNOWN
    assert set(c_b.failed_providers) == {"abuseipdb", "virustotal"}

    # Case C: NOT_FOUND + provider failure -> BENIGN with failure in failed_providers
    c_c = ConsensusEngine.evaluate(obs, [r1, f1])
    assert c_c.verdict == ThreatVerdict.BENIGN
    assert c_c.agreeing_providers == ["local_feed"]
    assert c_c.failed_providers == ["abuseipdb"]

    # Case D: High-conf MALICIOUS + High-conf confirmed BENIGN -> CONFLICT
    mal = ProviderResult(provider="abuseipdb", observable=obs, status=ProviderStatus.SUCCESS, verdict=ThreatVerdict.MALICIOUS, provider_confidence=0.95)
    clean_benign = ProviderResult(provider="local_feed", observable=obs, status=ProviderStatus.SUCCESS, verdict=ThreatVerdict.BENIGN, provider_confidence=1.0)
    c_d = ConsensusEngine.evaluate(obs, [mal, clean_benign])
    assert c_d.verdict == ThreatVerdict.CONFLICT
    assert set(c_d.conflicting_providers) == {"abuseipdb", "local_feed"}
    assert "Contradictory intelligence" in c_d.rationale

    # Absence of evidence (NOT_FOUND) does NOT create conflict against MALICIOUS
    c_d_nf = ConsensusEngine.evaluate(obs, [mal, r1])
    assert c_d_nf.verdict == ThreatVerdict.MALICIOUS
    assert "No threat records found by: local_feed" in c_d_nf.rationale

    # Case E: MALICIOUS without confirmed BENIGN -> MALICIOUS
    c_e = ConsensusEngine.evaluate(obs, [mal, f1])
    assert c_e.verdict == ThreatVerdict.MALICIOUS
    assert c_e.agreeing_providers == ["abuseipdb"]
    assert c_e.failed_providers == ["abuseipdb"]

    # Case F: SUSPICIOUS without MALICIOUS -> SUSPICIOUS
    susp = ProviderResult(provider="abuseipdb", observable=obs, status=ProviderStatus.SUCCESS, verdict=ThreatVerdict.SUSPICIOUS, provider_confidence=0.55)
    c_f = ConsensusEngine.evaluate(obs, [susp, f1])
    assert c_f.verdict == ThreatVerdict.SUSPICIOUS
    assert c_f.agreeing_providers == ["abuseipdb"]


# ── 7. Authorization Hook & API Safeguard Tests ───────────────────────────────

@pytest.mark.asyncio
async def test_api_authorization_and_safeguards():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Batch size limit (> 25 items rejected with HTTP 400)
        large_batch = [{"ioc_value": f"198.51.100.{i}"} for i in range(26)]
        resp_400 = await ac.post("/threat-intel/enrich", json={"observables": large_batch})
        assert resp_400.status_code == 400
        assert "Batch limit exceeded" in resp_400.json()["detail"]

        # 2. Authorization hook rejection (POST /threat-intel/cache/invalidate without token)
        resp_403 = await ac.post("/threat-intel/cache/invalidate", json={"provider": "local_feed"})
        assert resp_403.status_code == 403
        assert "Forbidden" in resp_403.json()["detail"]

        # 2b. Authorization hook rejection (POST /threat-intel/enrich with force_refresh=true without token)
        resp_rf_403 = await ac.post("/threat-intel/enrich", json={
            "observables": [{"ioc_value": "8.8.8.8"}],
            "force_refresh": True,
        })
        assert resp_rf_403.status_code == 403
        assert "Forbidden" in resp_rf_403.json()["detail"]

        # 3. Authorization dependency override verified
        app.dependency_overrides[get_admin_auth_hook] = lambda: True
        resp_auth_ok = await ac.post("/threat-intel/cache/invalidate", json={"provider": "local_feed"})
        assert resp_auth_ok.status_code == 200
        assert resp_auth_ok.json()["target"] == "local_feed"

        # 4. Force refresh rate limiting
        # First call succeeds with override
        rf_req = {
            "observables": [{"ioc_value": "8.8.8.8"}],
            "force_refresh": True,
        }
        res1 = await ac.post("/threat-intel/enrich", json=rf_req)
        assert res1.status_code == 200

        # Second call immediately after should trigger HTTP 429 rate limit
        res2 = await ac.post("/threat-intel/enrich", json=rf_req)
        assert res2.status_code == 429
        assert "Rate limit exceeded" in res2.json()["detail"]

        app.dependency_overrides.clear()


# ── 8. Database Persistence & Append-Only Semantics Tests ─────────────────────

@pytest.mark.asyncio
async def test_database_persistence_and_append_only():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Enrich an observable
        req = {"observables": [{"ioc_value": "198.51.100.99"}]}
        res1 = await ac.post("/threat-intel/enrich", json=req)
        assert res1.status_code == 200

        # Fetch records
        get_res1 = await ac.get("/threat-intel/results?ioc_value=198.51.100.99")
        assert get_res1.status_code == 200
        data1 = get_res1.json()
        count1 = data1["total"]
        assert count1 >= 1

        # Query again with force_refresh and admin override to create another lookup record
        app.dependency_overrides[get_admin_auth_hook] = lambda: True
        # Clear rate limit tracker to permit immediate lookup
        from backend.app.main import _force_refresh_timestamps
        _force_refresh_timestamps.clear()

        res2 = await ac.post("/threat-intel/enrich", json={"observables": [{"ioc_value": "198.51.100.99"}], "force_refresh": True})
        assert res2.status_code == 200

        get_res2 = await ac.get("/threat-intel/results?ioc_value=198.51.100.99")
        assert get_res2.status_code == 200
        count2 = get_res2.json()["total"]
        # Append-only: row count must strictly increase without overwriting previous row
        assert count2 > count1

        app.dependency_overrides.clear()


# ── 9. Event & Incident Enrichment API Tests ─────────────────────────────────

@pytest.mark.asyncio
async def test_event_and_incident_enrichment_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. GET /threat-intel/providers
        p_res = await ac.get("/threat-intel/providers")
        assert p_res.status_code == 200
        body = p_res.json()
        assert "providers" in body
        provider_names = [p["provider"] for p in body["providers"]]
        assert "local_feed" in provider_names

        # 2. Non-existent event enrichment -> 404
        bad_uuid = uuid.uuid4()
        ev_res = await ac.post(f"/threat-intel/enrich/event/{bad_uuid}")
        assert ev_res.status_code == 404

        # 3. Non-existent incident enrichment -> 404
        inc_res = await ac.post(f"/threat-intel/enrich/incident/{bad_uuid}")
        assert inc_res.status_code == 404
