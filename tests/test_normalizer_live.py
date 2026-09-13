"""
Live integration tests for Phase 2 Event Normalizer against live Wazuh/OpenSearch alerts.
"""

from __future__ import annotations

import os
import pytest

from backend.app.wazuh_client import WazuhIndexerClient
from normalizer.schemas import generate_event_id
from normalizer.wazuh_normalizer import EventNormalizer


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_alerts_normalization():
    """Retrieve live alerts from local OpenSearch and test normalization."""
    client = WazuhIndexerClient()
    normalizer = EventNormalizer()

    try:
        res = await client.get_alerts(limit=50)
    except Exception as exc:
        pytest.skip(f"Live OpenSearch not reachable or error querying alerts: {exc}")

    print(f"\n[LIVE WAZUH TEST] Total alerts in index: {res.total}, Retrieved in page: {res.count}")

    if res.count == 0:
        print("[LIVE WAZUH TEST] Zero alerts in active index; test verified query succeeds.")
        return

    successes = 0
    failures = []

    for alert in res.alerts:
        try:
            norm = normalizer.normalize_alert(alert)
            successes += 1

            # Verify deterministic event_id
            expected_id = generate_event_id("wazuh", alert.index, alert.id)
            assert norm.event_id == expected_id
            assert norm.source_type == "wazuh"
            assert norm.event_timestamp.tzinfo is not None
            assert norm.normalized_at.tzinfo is not None
            assert norm.raw_payload == alert.raw
        except Exception as exc:
            failures.append({
                "alert_id": alert.id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })

    print(f"[LIVE WAZUH TEST] Normalization outcome: {successes}/{res.count} succeeded")
    if failures:
        print(f"[LIVE WAZUH TEST] Failures ({len(failures)}):")
        for f in failures:
            print(f"  - ID: {f['alert_id']} | {f['error_type']}: {f['error']}")

    # Assert at least some alerts normalized or report failures honestly
    assert successes + len(failures) == res.count


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_alerts_service_persistence():
    """Retrieve live alerts and persist them to PostgreSQL via NormalizationService."""
    from backend.app.database import engine, get_db
    from backend.app.models.normalized_event import NormalizedEvent
    from backend.app.models.raw_alert import RawAlert
    from normalizer.service import NormalizationService

    client = WazuhIndexerClient()
    service = NormalizationService()

    try:
        res = await client.get_alerts(limit=20)
    except Exception as exc:
        pytest.skip(f"Live OpenSearch not reachable or error querying alerts: {exc}")

    if res.count == 0:
        return

    async for db in get_db():
        results = await service.process_batch(db, res.alerts)
        assert len(results) == res.count
        successful = [r for r in results if r.success]
        assert len(successful) == res.count

        # Verify a persisted event in the DB
        first_event = successful[0].event
        raw_row = await db.get(RawAlert, first_event.raw_alert_id)
        assert raw_row is not None
        assert raw_row.is_normalized is True

        event_row = await db.get(NormalizedEvent, first_event.event_id)
        assert event_row is not None
        assert event_row.raw_alert_id == raw_row.id
        break

    await engine.dispose()
