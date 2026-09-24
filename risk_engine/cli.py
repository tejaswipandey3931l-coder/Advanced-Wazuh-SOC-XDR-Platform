"""
Standalone CLI for Risk Engine backfill and recalculation operations.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
import structlog

from backend.app.database import async_session_factory
from backend.app.models.incident import Incident, IncidentStatus
from risk_engine.service import RiskService

logger = structlog.get_logger(__name__)


async def backfill_incidents(
    status_filter: str | None = None,
    batch_size: int = 100,
    limit: int | None = None,
) -> int:
    """Backfills risk scores for existing open/specified incidents."""
    print(f"Starting risk score backfill (status={status_filter or 'ALL'}, batch_size={batch_size})...")
    service = RiskService()
    processed = 0

    async with async_session_factory() as db:
        query = select(Incident.id)
        if status_filter:
            try:
                st = IncidentStatus(status_filter.lower())
                query = query.where(Incident.status == st)
            except ValueError:
                print(f"Invalid status filter '{status_filter}'", file=sys.stderr)
                return 0

        query = query.order_by(Incident.created_at.desc())
        if limit:
            query = query.limit(limit)

        result = await db.execute(query)
        incident_ids = list(result.scalars().all())

    print(f"Found {len(incident_ids)} incidents to process.")
    for idx, inc_id in enumerate(incident_ids, start=1):
        async with async_session_factory() as db:
            try:
                res = await service.evaluate_incident(
                    db=db,
                    incident_id=inc_id,
                    trigger_reason="cli_backfill",
                )
                if res:
                    processed += 1
                    print(f"[{idx}/{len(incident_ids)}] Incident {inc_id}: Score {res.overall_score:.2f} ({res.priority_band.value})")
            except Exception as e:
                print(f"[{idx}/{len(incident_ids)}] Incident {inc_id} FAILED: {e}", file=sys.stderr)

    print(f"Backfill complete. Processed {processed}/{len(incident_ids)} incidents successfully.")
    return processed


async def recalculate_single_incident(incident_id_str: str) -> None:
    """Recalculates a single incident by ID."""
    try:
        inc_id = uuid.UUID(incident_id_str)
    except ValueError:
        print(f"Invalid UUID: {incident_id_str}", file=sys.stderr)
        sys.exit(1)

    service = RiskService()
    async with async_session_factory() as db:
        res = await service.evaluate_incident(
            db=db,
            incident_id=inc_id,
            trigger_reason="cli_recalculate",
        )
        if res:
            print(f"Incident {inc_id} recalculated successfully:")
            print(f"  Overall Score:   {res.overall_score:.2f}")
            print(f"  Priority Band:   {res.priority_band.value}")
            print(f"  Base Score:      {res.base_score:.2f}")
            print(f"  Temporal Decay:  {res.temporal_decay:.4f}")
            print(f"  Evidence Version:{res.evidence_version}")
            print(f"  Summary:         {res.explanation.summary}")
        else:
            print(f"Incident {inc_id} not found.", file=sys.stderr)
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 5 Risk Engine Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Backfill command
    bf_parser = subparsers.add_parser("backfill", help="Backfill risk scores for incidents")
    bf_parser.add_argument("--status", choices=["open", "investigating", "closed", "false_positive"], default="open")
    bf_parser.add_argument("--batch-size", type=int, default=100)
    bf_parser.add_argument("--limit", type=int, default=None)

    # Recalculate command
    rc_parser = subparsers.add_parser("recalculate", help="Recalculate risk score for a single incident")
    rc_parser.add_argument("--incident-id", required=True, help="UUID of the incident to recalculate")

    args = parser.parse_args()

    if args.command == "backfill":
        asyncio.run(backfill_incidents(status_filter=args.status, batch_size=args.batch_size, limit=args.limit))
    elif args.command == "recalculate":
        asyncio.run(recalculate_single_incident(args.incident_id))


if __name__ == "__main__":
    main()
