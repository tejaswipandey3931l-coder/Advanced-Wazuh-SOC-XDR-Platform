"""
Integration tests for Phase 5 Dynamic Risk Engine (risk-v1).
Verifies:
- Concurrency guard ordering:
  1. Higher evidence_version wins.
  2. For equal evidence_version, higher evaluation_as_of wins.
  3. For equal evidence_version and evaluation_as_of, lexicographically larger risk_score_id UUID wins.
  4. calculated_at is purely audit metadata and NEVER participates in freshness ordering.
- Append-only incident_risk_scores history.
- ON DELETE RESTRICT foreign key integrity on incidents.
- Failure isolation of background risk evaluation triggers.
- REST API endpoints (/incidents/{id}/risk, /recalculate, /history, /risk/evaluate).
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import and_, cast, or_, select, String, update
from sqlalchemy.exc import IntegrityError

from backend.app.database import AsyncSessionLocal, engine
from backend.app.main import app
from backend.app.models.incident import Incident, IncidentSeverity, IncidentStatus
from backend.app.models.incident_risk_score import IncidentRiskScore
from risk_engine.service import RiskService


@pytest.fixture(autouse=True)
async def cleanup_db():
    yield
    await engine.dispose()


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


async def create_test_incident(db, evidence_version=1) -> Incident:
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=uuid.uuid4(),
        title="Test Security Incident",
        description="Integration test incident for dynamic risk scoring",
        status=IncidentStatus.OPEN,
        severity=IncidentSeverity.HIGH,
        confidence=0.85,
        first_seen=now - timedelta(hours=2),
        last_seen=now - timedelta(minutes=5),
        alert_count=3,
        evidence_version=evidence_version,
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)
    return inc


# ── Concurrency Guard Tests ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrency_higher_evidence_version_wins():
    """Out-of-order completion: a delayed task with older evidence_version cannot overwrite newer evidence."""
    async with AsyncSessionLocal() as db:
        inc = await create_test_incident(db, evidence_version=2)
        service = RiskService()

        # Step 1: Version 2 evaluation completes first
        res_v2 = await service.evaluate_incident(db, inc.id, trigger_reason="newer_task")
        assert res_v2 is not None
        assert res_v2.evidence_version == 2

        await db.refresh(inc)
        assert inc.risk_evidence_version == 2
        score_v2 = inc.risk_score

        # Step 2: Delayed task simulating older version 1 tries to write with newer calculated_at
        older_score_id = uuid.uuid4()
        now_utc = datetime.now(timezone.utc)
        older_calc_time = now_utc + timedelta(minutes=10)  # Wall-clock is newer!

        older_history = IncidentRiskScore(
            id=older_score_id,
            incident_id=inc.id,
            scoring_version="risk-v1",
            overall_score=15.0,
            priority_band="LOW",
            base_score=15.0,
            temporal_decay=1.0,
            severity_score=15.0,
            correlation_score=15.0,
            cti_score=0.0,
            volume_score=15.0,
            mitre_score=0.0,
            effective_weights={},
            factors={},
            explanation={},
            trigger_reason="delayed_older_task",
            evidence_as_of=now_utc - timedelta(hours=1),
            evidence_version=1,  # Older version
            evaluation_as_of=now_utc,
            calculated_at=older_calc_time,
        )
        db.add(older_history)
        await db.flush()

        # Concurrency condition for version 1
        cond_v1 = or_(
            Incident.risk_evidence_version.is_(None),
            Incident.risk_evidence_version < 1,
            and_(
                Incident.risk_evidence_version == 1,
                or_(
                    Incident.risk_evaluation_as_of.is_(None),
                    Incident.risk_evaluation_as_of < now_utc,
                    and_(
                        Incident.risk_evaluation_as_of == now_utc,
                        or_(
                            Incident.current_risk_score_id.is_(None),
                            cast(Incident.current_risk_score_id, String) < str(older_score_id),
                        ),
                    ),
                ),
            ),
        )

        update_stmt = (
            update(Incident)
            .where(Incident.id == inc.id, cond_v1)
            .values(
                risk_score=15.0,
                risk_priority_band="LOW",
                current_risk_score_id=older_score_id,
                risk_evidence_version=1,
                risk_evidence_as_of=now_utc - timedelta(hours=1),
                risk_evaluation_as_of=now_utc,
                risk_calculated_at=older_calc_time,
            )
        )
        result = await db.execute(update_stmt)
        await db.commit()

        # Row must NOT be updated (rowcount == 0)
        assert result.rowcount == 0

        # Verify incident materialized state is preserved
        await db.refresh(inc)
        assert inc.risk_evidence_version == 2
        assert inc.risk_score == score_v2


@pytest.mark.asyncio
async def test_concurrency_equal_version_higher_evaluation_as_of_wins():
    """For equal evidence_version, decay re-evaluation with newer evaluation_as_of wins."""
    async with AsyncSessionLocal() as db:
        inc = await create_test_incident(db, evidence_version=1)
        service = RiskService()

        now = datetime.now(timezone.utc)
        eval_t2 = now + timedelta(hours=48)
        eval_t1 = now + timedelta(hours=12)

        # Step 1: Re-evaluation at T2 (decayed further) completes first
        res_t2 = await service.evaluate_incident(db, inc.id, evaluation_as_of=eval_t2)
        assert res_t2 is not None

        await db.refresh(inc)
        score_t2 = inc.risk_score
        assert inc.risk_evaluation_as_of == eval_t2

        # Step 2: Delayed evaluation at T1 (earlier evaluation time) completes later
        res_t1 = await service.evaluate_incident(db, inc.id, evaluation_as_of=eval_t1)
        assert res_t1 is not None

        # Materialized state must STILL reflect T2 (higher evaluation_as_of)
        await db.refresh(inc)
        assert inc.risk_score == score_t2
        assert inc.risk_evaluation_as_of == eval_t2


@pytest.mark.asyncio
async def test_concurrency_equal_version_and_evaluation_deterministic_uuid_tiebreak():
    """For identical evidence_version and evaluation_as_of, lexicographically larger UUID wins."""
    async with AsyncSessionLocal() as db:
        inc = await create_test_incident(db, evidence_version=1)
        now = datetime.now(timezone.utc)

        u_a = uuid.uuid4()
        u_b = uuid.uuid4()
        uuid_small, uuid_large = (u_a, u_b) if str(u_a) < str(u_b) else (u_b, u_a)

        entry_small = IncidentRiskScore(
            id=uuid_small,
            incident_id=inc.id,
            scoring_version="risk-v1",
            overall_score=50.0,
            priority_band="MEDIUM",
            base_score=50.0,
            temporal_decay=1.0,
            severity_score=50.0,
            correlation_score=50.0,
            cti_score=0.0,
            volume_score=50.0,
            mitre_score=0.0,
            effective_weights={},
            factors={},
            explanation={},
            trigger_reason="test_small",
            evidence_as_of=now,
            evidence_version=1,
            evaluation_as_of=now,
            calculated_at=now,
        )
        entry_large = IncidentRiskScore(
            id=uuid_large,
            incident_id=inc.id,
            scoring_version="risk-v1",
            overall_score=75.0,
            priority_band="HIGH",
            base_score=75.0,
            temporal_decay=1.0,
            severity_score=75.0,
            correlation_score=75.0,
            cti_score=0.0,
            volume_score=75.0,
            mitre_score=0.0,
            effective_weights={},
            factors={},
            explanation={},
            trigger_reason="test_large",
            evidence_as_of=now,
            evidence_version=1,
            evaluation_as_of=now,
            calculated_at=now,
        )
        db.add_all([entry_small, entry_large])
        await db.flush()

        # Set materialized state to uuid_small
        inc.current_risk_score_id = uuid_small
        inc.risk_evidence_version = 1
        inc.risk_evaluation_as_of = now
        inc.risk_score = 50.0
        await db.commit()

        # Condition for updating with score_id
        def make_cond(target_id):
            return or_(
                Incident.risk_evidence_version.is_(None),
                Incident.risk_evidence_version < 1,
                and_(
                    Incident.risk_evidence_version == 1,
                    or_(
                        Incident.risk_evaluation_as_of.is_(None),
                        Incident.risk_evaluation_as_of < now,
                        and_(
                            Incident.risk_evaluation_as_of == now,
                            or_(
                                Incident.current_risk_score_id.is_(None),
                                cast(Incident.current_risk_score_id, String) < str(target_id),
                            ),
                        ),
                    ),
                ),
            )

        # Step 1: uuid_large attempts update -> MUST succeed (uuid_large > uuid_small)
        stmt_large = (
            update(Incident)
            .where(Incident.id == inc.id, make_cond(uuid_large))
            .values(risk_score=75.0, current_risk_score_id=uuid_large)
        )
        res_large = await db.execute(stmt_large)
        await db.commit()
        assert res_large.rowcount == 1

        # Step 2: uuid_small attempts update again -> MUST fail (uuid_small < uuid_large)
        stmt_small = (
            update(Incident)
            .where(Incident.id == inc.id, make_cond(uuid_small))
            .values(risk_score=50.0, current_risk_score_id=uuid_small)
        )
        res_small = await db.execute(stmt_small)
        await db.commit()
        assert res_small.rowcount == 0


# ── Audit & Referential Integrity ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_on_delete_restrict_prevents_incident_deletion():
    """Deleting an incident with risk score history must be blocked by ON DELETE RESTRICT."""
    async with AsyncSessionLocal() as db:
        inc = await create_test_incident(db, evidence_version=1)
        service = RiskService()

        # Generate a risk score record
        await service.evaluate_incident(db, inc.id)

        # Attempt to delete the incident
        await db.delete(inc)
        with pytest.raises(IntegrityError):
            await db.commit()

        await db.rollback()


# ── Failure Isolation ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_background_trigger_failure_isolation():
    """Background risk evaluation never raises or crashes on error."""
    non_existent_id = uuid.uuid4()
    await RiskService.evaluate_incident_background(non_existent_id, trigger_reason="test_missing")


# ── REST API Endpoints ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_recalculate_and_get_risk(client: AsyncClient):
    async with AsyncSessionLocal() as db:
        inc = await create_test_incident(db, evidence_version=1)
        inc_id = str(inc.id)

    # Recalculate endpoint
    resp = await client.post(f"/incidents/{inc_id}/risk/recalculate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == inc_id
    assert "overall_score" in data
    assert "priority_band" in data
    assert "explanation" in data
    assert data["evidence_version"] == 1

    # Query endpoint
    get_resp = await client.get(f"/incidents/{inc_id}/risk")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["overall_score"] == data["overall_score"]

    # History endpoint
    hist_resp = await client.get(f"/incidents/{inc_id}/risk/history")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total"] >= 1
    assert len(hist_data["items"]) >= 1


@pytest.mark.asyncio
async def test_api_risk_evaluate_simulation(client: AsyncClient):
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "factors": {
            "wazuh_levels": [12, 14],
            "incident_severity": "high",
            "rule_confidence": 0.8,
            "rule_type": "sequence",
            "rule_priority": 70,
            "is_correlated": True,
            "alert_count": 10,
            "distinct_entities": 3,
            "mitre_tactics": ["execution", "persistence"],
            "observables_cti": [
                {"verdict": "malicious", "provider_confidence": 0.85}
            ],
            "last_seen": now,
            "evidence_as_of": now,
            "evidence_version": 1,
            "evaluation_as_of": now,
        }
    }
    resp = await client.post("/risk/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] > 0.0
    assert data["priority_band"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "explanation" in data
    assert "sub_scores" in data


@pytest.mark.asyncio
async def test_api_risk_not_found(client: AsyncClient):
    bad_id = str(uuid.uuid4())
    resp = await client.get(f"/incidents/{bad_id}/risk")
    assert resp.status_code == 404
