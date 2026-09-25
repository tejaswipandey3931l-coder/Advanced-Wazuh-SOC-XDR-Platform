import pytest
from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from app.models.incident import Incident
from app.attack_chain.models import AttackChainVersion, AttackChainNode
from app.database import AsyncSessionLocal

@pytest.mark.asyncio
async def test_historical_retention_and_restrict():
    incident_id = uuid4()
    version_id = uuid4()
    
    async with AsyncSessionLocal() as session:
        inc = Incident(
            id=incident_id,
            title="Retention Test",
            evidence_version=1,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        session.add(inc)
        await session.flush()
        
        acv = AttackChainVersion(
            id=version_id,
            incident_id=incident_id,
            evidence_version=1,
            chain_version=1,
            chain_canonical_id="test_canonical",
            cti_evidence_fingerprint="test_fingerprint",
            reconstruction_algorithm_version="1.0",
            attck_catalog_version="1.0"
        )
        session.add(acv)
        
        acn = AttackChainNode(
            chain_version_id=version_id,
            logical_node_id="n1",
            node_type="EVENT",
            provenance="OBSERVED",
            evidence_strength=1.0
        )
        session.add(acn)
        await session.commit()
        
        # Verify queryable
        res = await session.execute(select(AttackChainVersion).where(AttackChainVersion.incident_id == incident_id))
        versions = res.scalars().all()
        assert len(versions) == 1
        
        # Verify deletion RESTRICT (Foreign Key constraint from AttackChainVersion on Incident)
        try:
            await session.execute(delete(Incident).where(Incident.id == incident_id))
            await session.commit()
            assert False, "Should have raised IntegrityError due to RESTRICT on incident deletion"
        except IntegrityError:
            await session.rollback()
            assert True
