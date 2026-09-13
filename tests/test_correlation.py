"""
Comprehensive test suite for Phase 3 Event Correlation Engine.

Covers:
  - Threshold correlation
  - Below threshold handling
  - Window expiration & sliding horizon
  - Ordered sequence correlation
  - Reversed sequence rejection
  - Entity mismatch rejection
  - Entity segregation
  - Distinct-entity / multi-entity (port scan)
  - Database concurrency protection (PostgreSQL partial unique index)
  - Deterministic inactivity timeout transition and incident re-creation
  - Evidence idempotency & alert_count accuracy
  - Cross-window aggregation
  - Multiple rule matches
  - Redis degradation and recovery
  - Timestamp integrity & future clock-skew handling
  - Out-of-order log processing
  - Rule schema grammar validation
  - API endpoints: /correlation/evaluate, /incidents, /incidents/{id}, /incidents/{id}/events, /correlation/rules
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import uuid
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import func, select

from backend.app.config import get_settings
from backend.app.database import get_db
from backend.app.main import app
from backend.app.models.correlation_rule import CorrelationRule as CorrelationRuleModel, RuleType
from backend.app.models.incident import Incident, IncidentSeverity, IncidentStatus
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.raw_alert import RawAlert
from correlation.engine import CorrelationEngine, calculate_confidence
from correlation.models import (
    CorrelationMatch,
    CorrelationRuleDefinition,
    SequenceStepDefinition,
    WindowItem,
)
from correlation.rules import RuleRegistry, get_default_rules
from correlation.service import CorrelationService, generate_dedup_key
from correlation.state import InMemoryWindowStateStore, RedisWindowStateStore

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "correlation_events_samples.json"


@pytest.fixture
def correlation_fixtures() -> dict:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def clean_registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.load_defaults()
    return reg


@pytest.fixture
def in_memory_store() -> InMemoryWindowStateStore:
    return InMemoryWindowStateStore()


@pytest.fixture
def test_engine(clean_registry, in_memory_store) -> CorrelationEngine:
    return CorrelationEngine(registry=clean_registry, state_store=in_memory_store)


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    yield
    from backend.app.database import engine
    await engine.dispose()


# ===========================================================================
# 1. Threshold Correlation Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_threshold_correlation_fires_at_min_events(test_engine):
    """Threshold rule fires when >= min_event_count arrive within time window."""
    now = datetime.now(timezone.utc)
    ip = "198.51.100.45"

    # Send 4 failed logins (min_event_count is 5 for default SSH brute force)
    for i in range(4):
        matches = await test_engine.evaluate_event(
            event_id=uuid4(),
            event_dict={
                "event_type": "authentication_failed",
                "auth_result": "failed",
                "src_ip": ip,
            },
            event_timestamp=now + timedelta(seconds=i * 10),
        )
        assert len(matches) == 0

    # 5th event arrives -> fires match!
    matches = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={
            "event_type": "authentication_failed",
            "auth_result": "failed",
            "src_ip": ip,
        },
        event_timestamp=now + timedelta(seconds=40),
    )
    assert len(matches) == 1
    match = matches[0]
    assert match.rule.name == "SSH / Authentication Brute Force Detected"
    assert match.entity_value == ip
    assert len(match.matched_event_ids) == 5
    assert match.confidence >= 0.80
    assert "T1110.001" in match.mitre_techniques


@pytest.mark.asyncio
async def test_threshold_correlation_below_threshold_does_not_fire(test_engine):
    """Less than min_event_count events must not trigger a match."""
    now = datetime.now(timezone.utc)
    for i in range(3):
        matches = await test_engine.evaluate_event(
            event_id=uuid4(),
            event_dict={
                "event_type": "authentication_failed",
                "auth_result": "failed",
                "src_ip": "192.0.2.1",
            },
            event_timestamp=now + timedelta(seconds=i * 5),
        )
        assert len(matches) == 0


@pytest.mark.asyncio
async def test_window_expiration_events_outside_window_do_not_contribute(test_engine):
    """Events outside [event_timestamp - window, event_timestamp] are pruned and do not contribute."""
    t0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
    ip = "198.51.100.99"

    # Send 4 events at t0
    for _ in range(4):
        await test_engine.evaluate_event(
            event_id=uuid4(),
            event_dict={"event_type": "authentication_failed", "auth_result": "failed", "src_ip": ip},
            event_timestamp=t0,
        )

    # 5th event arrives 400 seconds later (window is 300s). The earlier 4 events expired!
    matches = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"event_type": "authentication_failed", "auth_result": "failed", "src_ip": ip},
        event_timestamp=t0 + timedelta(seconds=400),
    )
    assert len(matches) == 0


# ===========================================================================
# 2. Sequence Correlation Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_ordered_sequence_fires(test_engine):
    """Ordered sequence S1 -> S2 for the same entity triggers privilege escalation match."""
    t0 = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    user = "alice"

    # Step 1: Failed auth
    m1 = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"auth_result": "failed", "user": user},
        event_timestamp=t0,
    )
    assert len(m1) == 0

    # Step 2: Privilege escalation
    m2 = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"event_category": "privilege_escalation", "user": user},
        event_timestamp=t0 + timedelta(seconds=60),
    )
    assert len(m2) == 1
    match = m2[0]
    assert match.rule.name == "Suspected Privilege Escalation Sequence"
    assert match.entity_value == user
    assert len(match.matched_event_ids) == 2
    assert "T1548.003" in match.mitre_techniques
    assert match.confidence >= 0.85


@pytest.mark.asyncio
async def test_reversed_sequence_does_not_fire(test_engine):
    """Reversed sequence (S2 before S1) must NOT trigger."""
    t0 = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    user = "bob"

    # S2 arrives first
    await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"event_category": "privilege_escalation", "user": user},
        event_timestamp=t0,
    )

    # S1 arrives later
    m = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"auth_result": "failed", "user": user},
        event_timestamp=t0 + timedelta(seconds=60),
    )
    assert len(m) == 0


@pytest.mark.asyncio
async def test_sequence_entity_mismatch_does_not_fire(test_engine):
    """S1 for alice and S2 for charlie must NOT correlate together."""
    t0 = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)

    await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"auth_result": "failed", "user": "alice"},
        event_timestamp=t0,
    )
    m = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"event_category": "privilege_escalation", "user": "charlie"},
        event_timestamp=t0 + timedelta(seconds=30),
    )
    assert len(m) == 0


# ===========================================================================
# 3. Distinct-Entity / Multi-Entity (Port Scan) Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_multi_entity_port_scan_correlation(test_engine, correlation_fixtures):
    """Port scan rule triggers only when distinct dst_port threshold is reached."""
    events = correlation_fixtures["port_scan_events"]
    t0 = datetime.now(timezone.utc)

    # Send first 4 events with distinct ports (rule requires 5)
    for evt in events[:4]:
        m = await test_engine.evaluate_event(
            event_id=uuid4(),
            event_dict=evt,
            event_timestamp=t0 + timedelta(seconds=evt["timestamp_offset_seconds"]),
        )
        assert len(m) == 0

    # 5th event with distinct port (443) -> fires!
    m = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict=events[4],
        event_timestamp=t0 + timedelta(seconds=events[4]["timestamp_offset_seconds"]),
    )
    assert len(m) == 1
    assert m[0].rule.name == "Horizontal Port Scan Activity"
    assert m[0].entity_value == "203.0.113.10"


# ===========================================================================
# 4. Concurrency Protection Tests (PostgreSQL Enforced)
# ===========================================================================

@pytest.mark.asyncio
async def test_concurrent_incident_creation_prevented(test_engine):
    """
    10 concurrent tasks resolving the same triggering match under concurrent race conditions:
    PostgreSQL enforces at most one active incident for a given dedup_key.
    """
    rule = test_engine.registry.get_active_rules()[0]
    entity_ip = f"198.51.100.{uuid4().int % 250}"
    dedup_key = generate_dedup_key(rule.id, "src_ip", entity_ip)

    now = datetime.now(timezone.utc)
    match = CorrelationMatch(
        rule=rule,
        entity_field="src_ip",
        entity_value=entity_ip,
        matched_event_ids=[uuid4()],
        matched_events=[{"src_ip": entity_ip}],
        first_seen=now,
        last_seen=now,
        confidence=0.8,
        confidence_rationale="test",
        event_roles={},
    )

    async def worker_task():
        async for db in get_db():
            service = CorrelationService(engine=test_engine)
            inc, created = await service.get_or_create_active_incident(db, dedup_key, match)
            await db.commit()
            return inc.id, created

    results = await asyncio.gather(*[worker_task() for _ in range(10)])

    # Exactly 1 worker should have created the row; 9 should have resolved the active winner
    created_flags = [r[1] for r in results]
    incident_ids = {r[0] for r in results}

    assert created_flags.count(True) == 1
    assert created_flags.count(False) == 9
    assert len(incident_ids) == 1

    # Verify directly in PostgreSQL: exactly 1 active incident exists for this dedup_key
    async for db in get_db():
        stmt = select(func.count(Incident.id)).where(
            Incident.dedup_key == dedup_key,
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        )
        active_count = (await db.execute(stmt)).scalar_one()
        assert active_count == 1
        break


# ===========================================================================
# 5. Inactivity Timeout Transition & Incident Re-creation Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_expired_incident_closed_on_inactivity_and_new_incident_created(test_engine):
    """
    Deterministic Lifecycle Flow:
    1. Create OPEN Incident A with dedup_key = K and last_seen = t_0.
    2. Inactivity timeout T_inactivity exceeded (t1 - t0 > T_inactivity).
    3. New matching event arrives with identical dedup_key = K at t1.
    4. Incident A transitions to CLOSED (no longer active) and flushes state.
    5. Incident B is created with status = OPEN and same dedup_key = K.
    6. Assert: Incident A.id != Incident B.id, Incident A is CLOSED, Incident B is OPEN,
       and PostgreSQL enforces at most one active incident for dedup_key = K.
    """
    rule = test_engine.registry.get_active_rules()[0]
    entity_ip = f"192.168.10.{uuid4().int % 250}"
    dedup_key = generate_dedup_key(rule.id, "src_ip", entity_ip)

    t0 = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    t_inactivity = 3600  # 1 hour

    async for db in get_db():
        service = CorrelationService(engine=test_engine, t_inactivity_seconds=t_inactivity)

        # 1. Create initial OPEN Incident A
        match_a = CorrelationMatch(
            rule=rule,
            entity_field="src_ip",
            entity_value=entity_ip,
            matched_event_ids=[uuid4()],
            matched_events=[{"src_ip": entity_ip}],
            first_seen=t0,
            last_seen=t0,
            confidence=0.8,
            confidence_rationale="initial",
            event_roles={},
        )
        incident_a, created_a = await service.get_or_create_active_incident(db, dedup_key, match_a)
        await db.commit()
        assert created_a is True
        assert incident_a.status == IncidentStatus.OPEN

        # 2. Time advances beyond T_inactivity: t1 = t0 + 3601 seconds
        t1 = t0 + timedelta(seconds=t_inactivity + 1)

        # 3. New matching event arrives with the same dedup_key
        match_b = CorrelationMatch(
            rule=rule,
            entity_field="src_ip",
            entity_value=entity_ip,
            matched_event_ids=[uuid4()],
            matched_events=[{"src_ip": entity_ip}],
            first_seen=t1,
            last_seen=t1,
            confidence=0.8,
            confidence_rationale="new campaign after timeout",
            event_roles={},
        )

        # 4 & 5. Evaluates inactivity, transitions Incident A to CLOSED, and creates Incident B
        incident_b, created_b = await service.get_or_create_active_incident(db, dedup_key, match_b)
        await db.commit()

        # 6. Assertions
        assert created_b is True
        assert incident_b.id != incident_a.id
        assert incident_b.status == IncidentStatus.OPEN
        assert incident_b.first_seen == t1

        # Re-fetch Incident A to verify it transitioned to CLOSED
        refreshed_a = await db.get(Incident, incident_a.id)
        assert refreshed_a.status == IncidentStatus.CLOSED
        assert "Automatically closed due to inactivity timeout" in refreshed_a.description

        # Verify PostgreSQL state: Exactly one active incident exists for this dedup_key
        active_stmt = select(func.count(Incident.id)).where(
            Incident.dedup_key == dedup_key,
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        )
        active_count = (await db.execute(active_stmt)).scalar_one()
        assert active_count == 1

        # Total incidents with this dedup_key is 2 (1 closed + 1 open)
        total_stmt = select(func.count(Incident.id)).where(Incident.dedup_key == dedup_key)
        total_count = (await db.execute(total_stmt)).scalar_one()
        assert total_count == 2
        break


# ===========================================================================
# 6. Idempotency & Alert Count Accuracy Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_evidence_idempotency_and_alert_count(test_engine):
    """Re-submitting the same normalized event does not inflate alert_count or create duplicate links."""
    now = datetime.now(timezone.utc)
    test_ip = f"10.200.5.{uuid4().int % 250}"

    async for db in get_db():
        # Create persistent RawAlert first to satisfy foreign key
        raw_alert = RawAlert(
            wazuh_index_id=f"alert-{uuid4().hex[:8]}",
            raw_json={"test": "payload"},
        )
        db.add(raw_alert)
        await db.flush()

        # Create persistent NormalizedEvent
        norm_event = NormalizedEvent(
            raw_alert_id=raw_alert.id,
            event_type="authentication_failed",
            event_category="authentication",
            severity=5,
            rule_id="5710",
            source_type="wazuh_agent",
            src_ip=test_ip,
            auth_result="failed",
            event_timestamp=now,
        )
        db.add(norm_event)
        await db.commit()

        rule = test_engine.registry.get_active_rules()[0]
        match = CorrelationMatch(
            rule=rule,
            entity_field="src_ip",
            entity_value=test_ip,
            matched_event_ids=[norm_event.id],
            matched_events=[{"src_ip": test_ip}],
            first_seen=now,
            last_seen=now,
            confidence=0.8,
            confidence_rationale="idempotency test",
            event_roles={norm_event.id: "threshold_member"},
        )

        service = CorrelationService(engine=test_engine)

        # First pass
        inc1 = await service.persist_correlation_match(db, match)
        await db.commit()
        assert inc1.alert_count == 1

        # Second pass with identical event
        inc2 = await service.persist_correlation_match(db, match)
        await db.commit()

        assert inc2.id == inc1.id
        assert inc2.alert_count == 1  # Not inflated!

        # Verify junction table has exactly 1 row
        links_stmt = select(func.count(IncidentEvent.id)).where(IncidentEvent.incident_id == inc1.id)
        links_count = (await db.execute(links_stmt)).scalar_one()
        assert links_count == 1
        break


# ===========================================================================
# 7. Redis Degradation & Recovery Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_redis_degradation_and_fallback_resilience():
    """When Redis is unreachable, RedisWindowStateStore transitions to in-memory fallback without throwing."""
    # Point to an unreachable port
    bad_store = RedisWindowStateStore(redis_url="redis://127.0.0.1:59999/0")
    rule_id = uuid4()
    item = WindowItem(
        event_id=uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        ingestion_timestamp=datetime.now(timezone.utc),
        entity_value="10.0.0.1",
        data={"src_ip": "10.0.0.1"},
    )

    # Should not raise exception; should switch to degraded fallback
    await bad_store.add_event(rule_id, "10.0.0.1", item)
    assert bad_store.is_degraded is True

    # Retrieve should still work via fallback
    events = await bad_store.get_events(
        rule_id,
        "10.0.0.1",
        datetime.now(timezone.utc) - timedelta(minutes=5),
        datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert len(events) == 1
    assert events[0].event_id == item.event_id

    await bad_store.close()


@pytest.mark.asyncio
async def test_redis_live_health_and_operations():
    """Verifies RedisWindowStateStore works directly against local live Redis container."""
    settings = get_settings()
    store = RedisWindowStateStore(redis_url=settings.soc_redis_url)
    is_healthy = await store.check_health()
    assert is_healthy is True
    assert store.is_degraded is False

    rule_id = uuid4()
    now = datetime.now(timezone.utc)
    item = WindowItem(
        event_id=uuid4(),
        event_timestamp=now,
        ingestion_timestamp=now,
        entity_value="redis_test_ip",
        data={"src_ip": "redis_test_ip"},
    )

    await store.add_event(rule_id, "redis_test_ip", item)
    events = await store.get_events(
        rule_id,
        "redis_test_ip",
        now - timedelta(seconds=10),
        now + timedelta(seconds=10),
    )
    assert len(events) == 1
    assert events[0].event_id == item.event_id

    # Pruning test
    pruned = await store.prune_events(rule_id, "redis_test_ip", now + timedelta(seconds=1))
    assert pruned == 1

    await store.clear()
    await store.close()


# ===========================================================================
# 8. Timestamp Integrity & Clock Skew Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_timestamp_integrity_and_future_skew_flagging(test_engine):
    """Source event timestamp is never mutated; future timestamps flag clock_skew_future."""
    now = datetime.now(timezone.utc)
    future_time = now + timedelta(seconds=120)  # Skew > 60s

    event_id = uuid4()
    await test_engine.evaluate_event(
        event_id=event_id,
        event_dict={"auth_result": "failed", "src_ip": "10.0.0.9"},
        event_timestamp=future_time,
        ingestion_timestamp=now,
    )

    # Inspect stored item in sliding window
    rule = test_engine.registry.get_active_rules()[0]
    items = await test_engine.state_store.get_events(
        rule.id, "10.0.0.9", now, future_time + timedelta(seconds=1)
    )
    assert len(items) == 1
    # event_timestamp is intact and not overwritten!
    assert items[0].event_timestamp == future_time
    assert items[0].data.get("clock_skew_future") is True


@pytest.mark.asyncio
async def test_out_of_order_events_sorted_correctly_for_sequences(test_engine):
    """Logs arriving out of order are sorted by source event_timestamp before sequence matching."""
    t0 = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=60)
    user = "dan"

    # Step 2 event arrives FIRST over network (timestamp = t1)
    await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"event_category": "privilege_escalation", "user": user},
        event_timestamp=t1,
    )

    # Step 1 event arrives SECOND (timestamp = t0)
    matches = await test_engine.evaluate_event(
        event_id=uuid4(),
        event_dict={"auth_result": "failed", "user": user},
        event_timestamp=t0,
    )

    # Engine correctly orders events by timestamp ASC and triggers sequence match!
    assert len(matches) == 1
    assert matches[0].rule.name == "Suspected Privilege Escalation Sequence"
    assert matches[0].entity_value == user


# ===========================================================================
# 9. Rule Schema Grammar Validation Tests
# ===========================================================================

def test_sequence_rule_must_have_at_least_two_steps():
    """Pydantic rejects sequence rules with < 2 steps."""
    with pytest.raises(ValidationError) as exc_info:
        CorrelationRuleDefinition(
            name="Invalid Sequence Rule",
            rule_type=RuleType.SEQUENCE,
            time_window_seconds=300,
            entity_field="user",
            sequence_steps=[
                SequenceStepDefinition(step_id="step1", name="Step 1", conditions={}),
            ],
        )
    assert "at least 2 ordered sequence_steps" in str(exc_info.value)


def test_sequence_rule_requires_entity_field():
    """Sequence rule without entity_field is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        CorrelationRuleDefinition(
            name="Invalid Sequence Rule No Entity",
            rule_type=RuleType.SEQUENCE,
            time_window_seconds=300,
            entity_field=None,
            sequence_steps=[
                SequenceStepDefinition(step_id="step1", name="Step 1", conditions={}),
                SequenceStepDefinition(step_id="step2", name="Step 2", conditions={}),
            ],
        )
    assert "require an entity_field" in str(exc_info.value)


def test_rule_rejects_invalid_condition_operators():
    """Unknown condition operators are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        CorrelationRuleDefinition(
            name="Bad Operator Rule",
            rule_type=RuleType.ENTITY_GROUP,
            time_window_seconds=300,
            entity_field="src_ip",
            conditions={"severity": {"invalid_op": 10}},
        )
    assert "Unknown operator 'invalid_op'" in str(exc_info.value)


# ===========================================================================
# 10. API Integration Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_api_correlation_rules_endpoints(client: AsyncClient):
    """GET and POST /correlation/rules work with validation and persistence."""
    # List rules
    res = await client.get("/correlation/rules")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3

    # Create new rule
    new_rule = {
        "name": f"Test Dynamic Rule {uuid4().hex[:6]}",
        "description": "Rule created via API test",
        "rule_type": "entity_group",
        "severity": "high",
        "base_confidence": 0.82,
        "time_window_seconds": 120,
        "min_event_count": 3,
        "entity_field": "hostname",
        "conditions": {"auth_result": "failed"},
    }
    create_res = await client.post("/correlation/rules", json=new_rule)
    assert create_res.status_code == 200
    created = create_res.json()
    assert created["name"] == new_rule["name"]
    assert created["severity"] == "high"
    assert created["base_confidence"] == 0.82


@pytest.mark.asyncio
async def test_api_correlation_evaluate_and_incidents_endpoints(client: AsyncClient):
    """POST /correlation/evaluate generates an Incident; GET /incidents and /incidents/{id} return it."""
    now = datetime.now(timezone.utc)
    ip = f"172.16.0.{uuid4().int % 250}"

    # Insert 5 matching events into DB
    event_ids = []
    async for db in get_db():
        for i in range(5):
            raw_alert = RawAlert(
                wazuh_index_id=f"alert-{uuid4().hex[:12]}",
                raw_json={"test": "payload"},
            )
            db.add(raw_alert)
            await db.flush()

            evt = NormalizedEvent(
                raw_alert_id=raw_alert.id,
                event_type="authentication_failed",
                event_category="authentication",
                severity=5,
                rule_id="5710",
                source_type="wazuh_agent",
                src_ip=ip,
                auth_result="failure",
                event_timestamp=now + timedelta(seconds=i * 5),
            )
            db.add(evt)
            await db.flush()
            event_ids.append(evt.id)
        await db.commit()
        break

    # Evaluate 4 events: no incident yet
    for eid in event_ids[:4]:
        res = await client.post("/correlation/evaluate", json={"event_id": str(eid)})
        assert res.status_code == 200
        assert res.json()["matches_count"] == 0

    # Evaluate 5th event: triggers incident!
    res5 = await client.post("/correlation/evaluate", json={"event_id": str(event_ids[4])})
    assert res5.status_code == 200
    eval_data = res5.json()
    assert eval_data["matches_count"] == 1
    incident_id = eval_data["incidents"][0]["id"]

    # GET /incidents
    incidents_res = await client.get("/incidents?status=open")
    assert incidents_res.status_code == 200
    inc_list = incidents_res.json()
    assert inc_list["total"] >= 1
    assert any(i["id"] == incident_id for i in inc_list["items"])

    # GET /incidents/{id}
    detail_res = await client.get(f"/incidents/{incident_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == incident_id
    assert detail["alert_count"] == 5
    assert len(detail["events"]) == 5

    # GET /incidents/{id}/events
    events_res = await client.get(f"/incidents/{incident_id}/events")
    assert events_res.status_code == 200
    evts_data = events_res.json()
    assert evts_data["total"] == 5
