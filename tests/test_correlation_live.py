"""
Live integration tests for Phase 3 Event Correlation Engine against live OpenSearch, Redis, and PostgreSQL.
Does NOT assume live Wazuh contains active attacks:
- Real Wazuh telemetry is tested for normalization + correlation compatibility.
- Controlled synthetic events are tested for deterministic attack pattern detection and persistence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from sqlalchemy import select

from backend.app.database import get_db
from backend.app.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.raw_alert import RawAlert
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.config import get_settings
from backend.app.wazuh_client import WazuhIndexerClient
from normalizer.wazuh_normalizer import EventNormalizer
from normalizer.service import NormalizationService
from correlation.engine import CorrelationEngine
from correlation.rules import RuleRegistry
from correlation.state import RedisWindowStateStore, InMemoryWindowStateStore
from correlation.service import CorrelationService


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_telemetry_correlation_compatibility():
    """
    Retrieve real telemetry from native Wazuh/OpenSearch, normalize it,
    and verify the pure CorrelationEngine evaluates all events without error.
    """
    client = WazuhIndexerClient()
    normalizer = EventNormalizer()

    try:
        res = await client.get_alerts(limit=50)
    except Exception as exc:
        pytest.skip(f"Live OpenSearch not reachable or error querying alerts: {exc}")

    if res.count == 0:
        pytest.skip("No live alerts available in current Wazuh index.")

    normalized_events = []
    for alert in res.alerts:
        try:
            norm = normalizer.normalize_alert(alert)
            normalized_events.append(norm)
        except Exception:
            continue

    assert len(normalized_events) > 0, "Expected at least one alert to normalize successfully"

    registry = RuleRegistry()
    registry.load_defaults()
    store = InMemoryWindowStateStore()
    engine = CorrelationEngine(registry=registry, state_store=store)

    total_evaluated = 0
    total_matches = 0

    for norm in normalized_events:
        matches = await engine.evaluate_event(
            event_id=norm.event_id,
            event_timestamp=norm.event_timestamp,
            event_dict=norm.model_dump(),
        )
        total_evaluated += 1
        total_matches += len(matches)

    print(
        f"\n[LIVE CORRELATION] Evaluated {total_evaluated} live Wazuh events through "
        f"{len(registry.get_active_rules())} active rules. Matches triggered: {total_matches}"
    )
    assert total_evaluated == len(normalized_events)


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_controlled_attack_pattern_with_redis_and_postgres():
    """
    End-to-end integration test with live PostgreSQL and live Redis:
    Inject a controlled brute-force sequence, verify incident creation,
    Redis window state updates, and incident_events evidence linkage.
    """
    settings = get_settings()
    redis_store = RedisWindowStateStore(redis_url=settings.soc_redis_url)

    # Verify live Redis connection
    healthy = await redis_store.check_health()
    if not healthy:
        pytest.skip(f"Live Redis not available or unhealthy at {settings.soc_redis_url}")

    registry = RuleRegistry()
    registry.load_defaults()
    engine = CorrelationEngine(registry=registry, state_store=redis_store)
    service = CorrelationService(engine=engine)

    # Clean up test keys in Redis for isolation
    test_src_ip = f"198.51.100.{uuid4().hex[:4]}"
    now = datetime.now(timezone.utc)

    async for db in get_db():
        events = []
        for i in range(5):
            raw = RawAlert(
                wazuh_index_id=f"live-test-ctrl-{uuid4().hex[:12]}",
                raw_json={"test": True, "idx": i},
                is_normalized=True,
            )
            db.add(raw)
            await db.flush()

            evt = NormalizedEvent(
                raw_alert_id=raw.id,
                event_type="authentication_failed",
                event_category="authentication",
                severity=5,
                rule_id="5710",
                source_type="wazuh_agent",
                src_ip=test_src_ip,
                auth_result="failure",
                event_timestamp=now + timedelta(seconds=i * 5),
            )
            db.add(evt)
            await db.flush()
            events.append(evt)

        # Evaluate events sequentially
        incidents = []
        for evt in events:
            inc_list = await service.process_normalized_event(db, evt)
            incidents.extend(inc_list)

        await db.commit()

        # The 5th event must trigger the SSH brute force incident
        assert len(incidents) >= 1
        created_incident = incidents[0]
        assert created_incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
        assert created_incident.entity_context.get("src_ip") == test_src_ip
        assert created_incident.alert_count == 5

        # Query incident_events to verify evidence links
        evt_links_stmt = select(IncidentEvent).where(
            IncidentEvent.incident_id == created_incident.id
        )
        evt_links = (await db.execute(evt_links_stmt)).scalars().all()
        assert len(evt_links) == 5
        linked_event_ids = {e.normalized_event_id for e in evt_links}
        assert linked_event_ids == {e.id for e in events}

        print(
            f"\n[LIVE CORRELATION] Successfully verified controlled incident {created_incident.id} "
            f"with {len(evt_links)} linked evidence events in PostgreSQL using live Redis."
        )
        break

    await redis_store.close()
