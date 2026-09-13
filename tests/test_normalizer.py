"""
Unit tests for Phase 2 Event Normalization & ECS Mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.database import get_db
from backend.app.main import app
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.raw_alert import RawAlert
from backend.app.schemas.wazuh import RawAlertItem
from normalizer.categories import resolve_category_and_type
from normalizer.exceptions import (
    InvalidNetworkAddressError,
    InvalidTimestampError,
    MissingRequiredFieldError,
    NormalizationError,
)
from normalizer.schemas import (
    SOC_EVENT_NAMESPACE,
    NormalizedEventSchema,
    generate_event_id,
)
from normalizer.service import NormalizationService
from normalizer.wazuh_normalizer import EventNormalizer

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "wazuh_alerts_samples.json"


@pytest.fixture
def sample_alerts() -> dict[str, dict]:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    yield
    from backend.app.database import engine
    await engine.dispose()


# ===========================================================================
# 1. Deterministic Event ID Tests
# ===========================================================================

def test_deterministic_event_id_reproducibility():
    """Identical source identity must always produce the identical UUIDv5."""
    source_type = "wazuh"
    wazuh_index = "wazuh-alerts-4.x-2026.09.12"
    doc_id = "alert-abc-12345"

    id1 = generate_event_id(source_type, wazuh_index, doc_id)
    id2 = generate_event_id(source_type, wazuh_index, doc_id)

    assert id1 == id2
    assert isinstance(id1, uuid.UUID)
    assert id1.version == 5
    # Expected seed format verification
    expected_seed = f"{source_type}:{wazuh_index}:{doc_id}"
    assert id1 == uuid.uuid5(SOC_EVENT_NAMESPACE, expected_seed)


def test_changed_source_identity_changes_event_id():
    """Different index or document ID must generate a different event_id."""
    id_base = generate_event_id("wazuh", "index-a", "doc-1")
    id_diff_doc = generate_event_id("wazuh", "index-a", "doc-2")
    id_diff_idx = generate_event_id("wazuh", "index-b", "doc-1")
    id_diff_src = generate_event_id("suricata", "index-a", "doc-1")

    assert id_base != id_diff_doc
    assert id_base != id_diff_idx
    assert id_base != id_diff_src


# ===========================================================================
# 2. Timestamp Semantics Tests
# ===========================================================================

def test_timestamp_semantics_three_distinct_times(sample_alerts):
    """event_timestamp, ingestion_timestamp, normalized_at must be distinct and UTC."""
    normalizer = EventNormalizer()
    alert_raw = sample_alerts["rule_5710_sshd_failed_login"]
    item = RawAlertItem(**alert_raw)

    ingest_time = datetime(2026, 9, 12, 8, 16, 0, tzinfo=timezone.utc)
    norm = normalizer.normalize_alert(item, ingestion_timestamp=ingest_time)

    # 1. event_timestamp from Wazuh (2026-09-12T08:15:30.123000+00:00)
    assert norm.event_timestamp == datetime(2026, 9, 12, 8, 15, 30, 123000, tzinfo=timezone.utc)
    assert norm.event_timestamp.tzinfo is not None

    # 2. ingestion_timestamp from platform ingestion
    assert norm.ingestion_timestamp == ingest_time
    assert norm.ingestion_timestamp.tzinfo is not None

    # 3. normalized_at from execution time
    assert norm.normalized_at.tzinfo is not None
    assert norm.normalized_at > ingest_time
    assert norm.normalized_at != norm.event_timestamp
    assert norm.ingestion_timestamp != norm.event_timestamp


def test_naive_timestamp_assumes_utc():
    """Documented limitation: source timestamps without timezone assume UTC."""
    normalizer = EventNormalizer()
    naive_item = RawAlertItem(
        id="doc-naive-001",
        index="wazuh-alerts-2026",
        timestamp="2026-09-12T12:00:00",
        rule_id="100",
        rule_level=3,
        raw={"timestamp": "2026-09-12T12:00:00", "rule": {"id": "100", "level": 3}},
    )
    norm = normalizer.normalize_alert(naive_item)
    assert norm.event_timestamp == datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)


# ===========================================================================
# 3. Classification & Categorization Tests
# ===========================================================================

def test_source_type_vs_decoder_name(sample_alerts):
    """source_type is platform-level 'wazuh'; decoder_name preserves Wazuh decoder."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["rule_5710_sshd_failed_login"])
    norm = normalizer.normalize_alert(item)

    assert norm.source_type == "wazuh"
    assert norm.decoder_name == "sshd"


def test_server_startup_rule_502(sample_alerts):
    """Rule 502 must map to category 'system' and event_type 'os_service_event'."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["rule_502_server_started"])
    norm = normalizer.normalize_alert(item)

    assert norm.rule_id == "502"
    assert norm.event_category == "system"
    assert norm.event_type == "os_service_event"
    assert norm.severity == 3
    assert norm.severity_label == "low"
    assert norm.agent_name == "wazuh.manager"


def test_sshd_rules_5710_and_5715(sample_alerts):
    """Rule 5710 (failure) and 5715 (success) authentication mapping."""
    normalizer = EventNormalizer()

    # 5710: Failed login
    item_5710 = RawAlertItem(**sample_alerts["rule_5710_sshd_failed_login"])
    norm_5710 = normalizer.normalize_alert(item_5710)
    assert norm_5710.event_category == "authentication"
    assert norm_5710.event_type == "user_login_failed"
    assert norm_5710.auth_action == "logon"
    assert norm_5710.auth_result == "failure"
    assert norm_5710.src_ip == "198.51.100.45"
    assert norm_5710.src_port == 44120
    assert norm_5710.user == "invalid_user"
    assert norm_5710.severity == 5
    assert norm_5710.severity_label == "medium"
    assert "T1110.001" in norm_5710.mitre_technique_ids

    # 5715: Succeeded login
    item_5715 = RawAlertItem(**sample_alerts["rule_5715_sshd_success_login"])
    norm_5715 = normalizer.normalize_alert(item_5715)
    assert norm_5715.event_category == "authentication"
    assert norm_5715.event_type == "user_login"
    assert norm_5715.auth_action == "logon"
    assert norm_5715.auth_result == "success"
    assert norm_5715.src_ip == "192.168.1.50"
    assert norm_5715.src_port == 51234
    assert norm_5715.user == "admin"
    assert norm_5715.severity == 3
    assert norm_5715.severity_label == "low"


def test_syscheck_rules_550_and_554(sample_alerts):
    """Syscheck FIM rules 550 (modified) and 554 (added)."""
    normalizer = EventNormalizer()

    # 550: Checksum modified
    item_550 = RawAlertItem(**sample_alerts["rule_550_syscheck_modified"])
    norm_550 = normalizer.normalize_alert(item_550)
    assert norm_550.event_category == "file"
    assert norm_550.event_type == "file_modification"
    assert norm_550.file_path == "/etc/shadow"
    assert norm_550.file_hash_md5 == "e4d909c290d0fb1ca068ffaddf22cbd0"
    assert norm_550.file_hash_sha256 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2134f1ec2d6a71d78292"
    assert norm_550.user == "root"
    assert norm_550.severity == 7
    assert norm_550.severity_label == "medium"

    # 554: File added
    item_554 = RawAlertItem(**sample_alerts["rule_554_syscheck_added"])
    norm_554 = normalizer.normalize_alert(item_554)
    assert norm_554.event_category == "file"
    assert norm_554.event_type == "file_creation"
    assert norm_554.file_path == "/tmp/malicious.sh"
    assert norm_554.file_hash_md5 == "c4ca4238a0b923820dcc509a6f75849b"


def test_sca_categorization(sample_alerts):
    """SCA alert must map to category configuration_assessment and compliance_check."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["sca_policy_check"])
    norm = normalizer.normalize_alert(item)

    assert norm.event_category == "configuration_assessment"
    assert norm.event_type == "compliance_check"
    assert norm.decoder_name == "sca"
    # Verify unmapped sca details are captured in extra_fields
    assert "sca" in norm.extra_fields.get("data", {})
    assert norm.extra_fields["data"]["sca"]["check"]["id"] == 5001


# ===========================================================================
# 4. Strict Validation & Typed Error Tests
# ===========================================================================

def test_validation_invalid_ip(sample_alerts):
    """Invalid IP address must raise InvalidNetworkAddressError (no silent coercion)."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["malformed_invalid_ip"])
    with pytest.raises(InvalidNetworkAddressError) as exc_info:
        normalizer.normalize_alert(item)
    assert "999.999.999.999" in str(exc_info.value)


def test_validation_invalid_port(sample_alerts):
    """Out-of-range port must raise InvalidNetworkAddressError."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["malformed_invalid_port"])
    with pytest.raises(InvalidNetworkAddressError) as exc_info:
        normalizer.normalize_alert(item)
    assert "99999" in str(exc_info.value)


def test_validation_invalid_timestamp(sample_alerts):
    """Unparseable timestamp must raise InvalidTimestampError."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["malformed_invalid_timestamp"])
    with pytest.raises(InvalidTimestampError) as exc_info:
        normalizer.normalize_alert(item)
    assert "not-a-valid-timestamp" in str(exc_info.value)


def test_validation_missing_rule_id(sample_alerts):
    """Alert missing rule_id must raise MissingRequiredFieldError."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["malformed_missing_rule_id"])
    with pytest.raises(MissingRequiredFieldError) as exc_info:
        normalizer.normalize_alert(item)
    assert "rule_id" in str(exc_info.value)


# ===========================================================================
# 5. Evidence & Payload Preservation Tests
# ===========================================================================

def test_extra_fields_preservation_and_no_redundant_duplication(sample_alerts):
    """Unmapped fields go to extra_fields; mapped columns must NOT be duplicated."""
    normalizer = EventNormalizer()
    item = RawAlertItem(**sample_alerts["rule_5710_sshd_failed_login"])
    norm = normalizer.normalize_alert(item)

    # First-class mapped columns
    assert norm.src_ip == "198.51.100.45"
    assert norm.src_port == 44120
    assert norm.user == "invalid_user"

    # Mapped keys must NOT be present in extra_fields["data"]
    data_extra = norm.extra_fields.get("data", {})
    assert "srcip" not in data_extra
    assert "srcport" not in data_extra
    assert "dstuser" not in data_extra


def test_raw_payload_preservation(sample_alerts):
    """Original Wazuh raw alert dictionary must be preserved verbatim in raw_payload."""
    normalizer = EventNormalizer()
    alert_raw = sample_alerts["rule_550_syscheck_modified"]
    item = RawAlertItem(**alert_raw)
    norm = normalizer.normalize_alert(item)

    assert norm.raw_payload == alert_raw["raw"]


def test_batch_normalization_fault_tolerance(sample_alerts):
    """Batch normalization must continue processing valid alerts while reporting errors."""
    normalizer = EventNormalizer()
    batch = [
        RawAlertItem(**sample_alerts["rule_502_server_started"]),
        RawAlertItem(**sample_alerts["malformed_invalid_ip"]),
        RawAlertItem(**sample_alerts["rule_5715_sshd_success_login"]),
        RawAlertItem(**sample_alerts["malformed_invalid_port"]),
    ]

    results = normalizer.normalize_batch(batch)
    assert len(results) == 4

    assert results[0].success is True
    assert results[0].event.rule_id == "502"

    assert results[1].success is False
    assert "InvalidNetworkAddressError" in results[1].error

    assert results[2].success is True
    assert results[2].event.rule_id == "5715"

    assert results[3].success is False
    assert "InvalidNetworkAddressError" in results[3].error


# ===========================================================================
# 6. Database Persistence & Idempotency Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_normalization_service_db_linkage_and_idempotency(sample_alerts):
    """Service persists RawAlert, creates NormalizedEvent with raw_alert_id, and is idempotent."""
    service = NormalizationService()
    alert_data = sample_alerts["rule_5715_sshd_success_login"]
    item = RawAlertItem(**alert_data)

    async for db in get_db():
        # First pass: creates RawAlert and NormalizedEvent
        norm1 = await service.process_and_store(db, item)
        assert norm1.raw_alert_id is not None

        # Verify RawAlert row
        raw_row = await db.get(RawAlert, norm1.raw_alert_id)
        assert raw_row is not None
        assert raw_row.is_normalized is True
        assert raw_row.wazuh_index_id == item.id

        # Verify NormalizedEvent row
        event_row = await db.get(NormalizedEvent, norm1.event_id)
        assert event_row is not None
        assert event_row.raw_alert_id == raw_row.id
        assert event_row.decoder_name == "sshd"
        assert event_row.event_category == "authentication"

        # Second pass: repeated normalization must be idempotent
        norm2 = await service.process_and_store(db, item)
        assert norm2.event_id == norm1.event_id
        assert norm2.raw_alert_id == norm1.raw_alert_id
        break


# ===========================================================================
# 7. API Endpoint Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_api_post_normalize_success(sample_alerts):
    """POST /normalizer/normalize returns 200 with NormalizedEventSchema."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = sample_alerts["rule_502_server_started"]
        resp = await client.post("/normalizer/normalize?persist=false", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == "502"
        assert data["event_category"] == "system"
        assert data["event_type"] == "os_service_event"
        assert data["event_id"] is not None


@pytest.mark.asyncio
async def test_api_post_normalize_validation_error(sample_alerts):
    """POST /normalizer/normalize with malformed IP returns 422 with error detail."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = sample_alerts["malformed_invalid_ip"]
        resp = await client.post("/normalizer/normalize?persist=false", json=payload)
        assert resp.status_code == 422
        data = resp.json()
        assert "InvalidNetworkAddressError" in data.get("error_type", "")


@pytest.mark.asyncio
async def test_api_get_normalized_events(sample_alerts):
    """GET /events/normalized returns paginated list of normalized events."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First persist an alert
        payload = sample_alerts["rule_5710_sshd_failed_login"]
        post_resp = await client.post("/normalizer/normalize?persist=true", json=payload)
        assert post_resp.status_code == 200

        # Now query list with rule_id filter
        get_resp = await client.get("/events/normalized?category=authentication&rule_id=5710")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["total"] >= 1
        assert len(data["events"]) >= 1
        event = data["events"][0]
        assert event["event_category"] == "authentication"
        assert event["rule_id"] == "5710"
        assert event["auth_result"] == "failure"
