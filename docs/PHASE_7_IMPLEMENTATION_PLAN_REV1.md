# PHASE 7 IMPLEMENTATION PLAN — REVISION 1
## Attack Chain / Incident Reconstruction Engine

**Document status:** PLAN REVISION 1 — AWAITING MANUAL REVIEW
**Created:** 2026-09-25
**Preceding checkpoints:**
- `phase-5-complete` → `a51c369d7e5d8363a8a3a7891faea0e804f33b1`
- `phase-6-complete` → `9b447c5b20c9182844d0ba5ae585f97f6fdd4e7d`

---

## 1. Executive Summary

Phase 7 delivers a deterministic, evidence-backed **Attack Chain Reconstruction Engine**
that maps the temporal and causal structure of security incidents onto a directed graph
anchored to MITRE ATT&CK. It consumes evidence produced by Phases 1–6 without modifying
any upstream contract.

Every reconstructed chain element carries explicit **provenance** (OBSERVED / INFERRED /
UNKNOWN) and a transparent **evidence-based confidence** score. The system answers:

- *What happened?* — ordered timeline of correlated events
- *In what order?* — deterministic chronological graph
- *Which entities?* — canonicalized host/user/IP/file/process actors
- *Which ATT&CK techniques?* — only those directly supported by evidence
- *Which relationships are observed vs. inferred?* — explicit provenance on every edge
- *How does the chain change with late evidence?* — versioned reconstruction keyed on `evidence_version`

The engine does **not** claim attacker intent or certainty beyond what the evidence supports.
It does **not** perform automated containment, SOAR integration, LLM reasoning, or any
action — those are out of scope (Phase 8+).

---

## 2. Research Objective

Produce a reproducible, deterministic reconstruction of incident attack chains from
heterogeneous Wazuh/CTI/correlation evidence, suitable for:

1. Analyst review during incident investigation
2. Research evaluation of evidence coverage and chain completeness
3. Academic reporting in the capstone paper

---

## 3. Research Questions

| ID  | Question |
|-----|----------|
| RQ1 | Can deterministic evidence reconstruction produce reproducible attack chains from heterogeneous Wazuh/CTI/correlation evidence? |
| RQ2 | How accurately does the reconstructed timeline preserve the temporal ordering of known attack scenario event sequences? |
| RQ3 | How does late-arriving evidence (measured by `evidence_version` increment) affect chain completeness and node/edge counts? |
| RQ4 | What proportion of reconstructed relationships are directly observed (OBSERVED provenance) versus inferred (INFERRED provenance)? |
| RQ5 | Which MITRE ATT&CK techniques are recoverable from the current Wazuh/CTI evidence schema, and which require future telemetry enrichment? |

---

## 4. Existing Architecture Integration

Phase 7 is **additive only**. The following Phase 0–6 contracts are frozen:

| Component | Status |
|-----------|--------|
| RawAlert ingestion | Frozen — Phase 1 |
| NormalizedEvent schema | Frozen — Phase 2 |
| Correlation engine, IncidentEvent, CorrelationRule | Frozen — Phase 3 |
| ThreatIntelResult, CTI providers, cache | Frozen — Phase 4 |
| risk-v1 formula, weights, decay, concurrency, PriorityBand | Frozen — Phase 5 |
| IncidentRiskScore temporal concepts | Frozen — Phase 5 |
| ML pipeline, DATASET_STATUS, inference disabled-by-default | Frozen — Phase 6 |

Phase 7 **reads** from existing tables. It **writes** only to Phase 7-specific tables
(`attack_chain_versions`, `attack_chain_nodes`, `attack_chain_edges`) plus updating
the existing `attack_chains` stub summary.

---

## 5. Repository Inspection Findings

### 5.1 Existing `AttackChain` Model

File: `backend/app/models/attack_chain.py`

An `AttackChain` stub model exists from the Phase 0 initial schema. Registered in
`models/__init__.py` and migrated by `20260912_1034-509239379941_initial_schema.py`.

**Current columns:**

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | via `UUIDPrimaryKeyMixin` |
| `incident_id` | UUID FK → `incidents.id` | `unique=True` — one chain per incident |
| `chain_steps` | JSONB | Flat ordered list of `ChainStep` dicts |
| `highest_tactic` | String(128) | nullable |
| `confidence` | Float | nullable, 0.0–1.0, no formula defined |
| `summary` | Text | nullable |
| `last_calculated_at` | DateTime(tz) | nullable — wall-clock only |
| `created_at`, `updated_at` | DateTime(tz) | via `TimestampMixin` |

**Assessment:** The stub is semantically insufficient for Phase 7:
- `chain_steps` is a flat JSONB array, not a graph structure
- No `evidence_version`, `evidence_as_of`, or `chain_version` fields
- No node/edge identity — steps are not independently addressable
- No provenance (OBSERVED/INFERRED/UNKNOWN) on individual steps
- `confidence` is an undocumented scalar with no formula
- `last_calculated_at` is wall-clock time, not a semantic evidence timestamp
- The docstring labels it "Phase 8" but the table is available now

**Decision:** The existing stub is preserved as a **materialized summary row**
(one-liner per incident for backward-compatible API consumers). Phase 7 introduces
three richer tables for the full graph model. The stub's `chain_steps` JSONB is
back-filled from the Phase 7 graph as a read-optimized summary.

### 5.2 `attack_chain/` Package

The directory `/attack_chain/` exists at project root but is **completely empty**.
No implementation exists.

### 5.3 No Attack-Chain API Routes

`backend/app/main.py` (1,302 lines) contains no `/attack-chain*` routes.
Attack-chain endpoints are entirely unimplemented.

Confirmed routes ending at `simulate_risk_evaluation` (line 1,302).

### 5.4 `Incident` Model — Available Fields

| Field | Type | Phase | Notes |
|-------|------|-------|-------|
| `id` | UUID | 0 | PK |
| `title` | String(512) | 0 | |
| `status` | Enum | 0 | open/investigating/closed/false_positive |
| `severity` | Enum | 0 | critical/high/medium/low/informational |
| `evidence_version` | BigInteger | 5 | monotonic evidence snapshot counter |
| `risk_score` | Float | 5 | materialized from risk-v1 |
| `risk_priority_band` | String(32) | 5 | INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL |
| `risk_evidence_version` | BigInteger | 5 | evidence_version at last risk calc |
| `risk_evidence_as_of` | DateTime | 5 | chronological horizon of evidence |
| `risk_evaluation_as_of` | DateTime | 5 | logical temporal decay reference |
| `risk_calculated_at` | DateTime | 5 | wall-clock of last risk calc |
| `ml_priority_score` | Float | 6 | optional ML signal |
| `first_seen` | DateTime | 0 | first event occurrence time |
| `last_seen` | DateTime | 0 | most recent event occurrence time |
| `alert_count` | Integer | 0 | |
| `correlation_rule_id` | UUID FK | 3 | |
| `confidence` | Float | 3 | correlation confidence |
| `dedup_key` | String(64) | 3 | |
| `mitre_techniques` | JSONB list | 0 | aggregated from events |
| `mitre_tactics` | JSONB list | 0 | aggregated from events |
| `ioc_matched` | Boolean | 4 | |
| `entity_context` | JSONB dict | 3 | e.g. `{"src_ip": "…", "user": "…"}` |

### 5.5 `NormalizedEvent` — Available Fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | PK |
| `raw_alert_id` | UUID FK | → `raw_alerts.id` |
| `event_timestamp` | DateTime(tz) | **primary event occurrence time** |
| `source_type` | String(64) | wazuh_agent/zeek/suricata/syslog |
| `normalization_version` | String(16) | 2.0.0 |
| `decoder_name` | String(64) | Wazuh decoder name |
| `src_ip` | String(45) | nullable |
| `dst_ip` | String(45) | nullable |
| `src_port` | Integer | nullable |
| `dst_port` | Integer | nullable |
| `network_protocol` | String(16) | nullable |
| `user` | String(255) | nullable |
| `hostname` | String(255) | nullable |
| `agent_id` | String(64) | Wazuh agent identifier |
| `agent_name` | String(128) | nullable |
| `auth_action` | String(32) | nullable |
| `auth_result` | String(16) | nullable |
| `domain` | String(255) | nullable |
| `url` | Text | nullable |
| `process_name` | String(255) | nullable |
| `process_pid` | Integer | nullable |
| `process_command_line` | Text | nullable |
| `file_path` | Text | nullable |
| `file_hash_md5` | String(32) | nullable |
| `file_hash_sha256` | String(64) | nullable |
| `event_category` | String(64) | nullable |
| `event_type` | String(128) | non-null |
| `severity` | Integer | Wazuh rule level 1–16 |
| `rule_id` | String(64) | nullable |
| `rule_description` | Text | nullable |
| `mitre_technique_ids` | ARRAY(String) | nullable — e.g. `["T1059", "T1059.003"]` |
| `mitre_tactic_ids` | ARRAY(String) | nullable — e.g. `["TA0002"]` |
| `ioc_matched` | Boolean | |
| `threat_score` | Float | nullable |
| `ml_score` | Float | nullable |
| `extra_fields` | JSONB | overflow fields |

### 5.6 `ThreatIntelResult` — Available Fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | PK |
| `normalized_event_id` | UUID FK | nullable |
| `incident_id` | UUID FK | nullable |
| `ioc_type` | Enum | ip/domain/url/file_hash/email |
| `ioc_value` | String(512) | canonical IOC value |
| `source` | Enum | abuseipdb/misp/opencti/local_feed/virustotal/alienvault_otx |
| `matched` | Boolean | |
| `verdict` | String(32) | malicious/suspicious/clean/unknown |
| `severity` | String(32) | nullable |
| `confidence` | Float | general confidence |
| `provider_confidence` | Float | provider-reported |
| `derived_heuristic_confidence` | Float | uncalibrated heuristic |
| `threat_type` | String(128) | e.g. malware/phishing/scanner |
| `context` | JSONB | semantically preserved payload |
| `source_reference` | String(256) | external URL/ID |
| `queried_at` | DateTime | **when CTI was queried** |
| `cache_expires_at` | DateTime | |

### 5.7 `IncidentEvent` (Junction) — Available Fields

| Field | Type | Notes |
|-------|------|-------|
| `incident_id` | UUID FK | |
| `normalized_event_id` | UUID FK | |
| `correlation_rule_id` | UUID FK | nullable |
| `match_role` | String(64) | e.g. threshold_member, sequence_step_1 |
| `confidence` | Float | |
| `added_at` | DateTime | when event was associated to incident |

### 5.8 `CorrelationRule` — Available Fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | |
| `name` | String(255) | |
| `rule_type` | Enum | entity_group/temporal/sequence |
| `entity_field` | String(128) | field used for grouping |
| `time_window_seconds` | Integer | |
| `min_event_count` | Integer | |
| `conditions` | JSONB | filter predicates |
| `mitre_technique_id` | String(32) | single technique — may be null |
| `mitre_tactic_id` | String(32) | single tactic — may be null |
| `base_confidence` | Float | |
| `severity` | String(32) | |

### 5.9 `IncidentRiskScore` — Four Temporal Concepts

| Concept | Column | Meaning |
|---------|--------|---------|
| Evidence version | `evidence_version` | monotonic snapshot counter |
| Evidence chronological horizon | `evidence_as_of` | newest evidence timestamp |
| Logical evaluation time | `evaluation_as_of` | temporal decay reference |
| Wall-clock calculation | `calculated_at` | audit metadata only |

### 5.10 `RawAlert`

Full original Wazuh JSON in `raw_json` (JSONB). Available for forensic verification.
Key promoted columns: `wazuh_index_id`, `agent_id`, `agent_name`, `rule_id`,
`rule_level`, `rule_description`, `wazuh_timestamp`.

### 5.11 Existing Alembic Migrations

```
20260912 — initial schema (includes attack_chains stub)
20260913 — Phase 2 normalization
20260914 — Phase 3 correlation
20260914 — Phase 4 threat intel
20260924 — Phase 5 risk score (incident_risk_scores, temporal columns)
```

No Phase 6 or Phase 7 migrations exist.

### 5.12 MITRE Data Summary

MITRE data is stored as plain string IDs. There is no ATT&CK name-resolution table.

- `NormalizedEvent.mitre_technique_ids` — ARRAY(String), nullable
- `NormalizedEvent.mitre_tactic_ids` — ARRAY(String), nullable
- `Incident.mitre_techniques` — JSONB list (aggregated by correlation engine)
- `Incident.mitre_tactics` — JSONB list (aggregated by correlation engine)
- `CorrelationRule.mitre_technique_id` — single String, nullable
- `CorrelationRule.mitre_tactic_id` — single String, nullable

Phase 7 must resolve IDs to human-readable names at display time via a bundled
ATT&CK catalog JSON file. Unknown IDs are stored as-is with `name=null`.

---

## 6. Input Evidence Model

Phase 7 reads from the following tables (read-only):

```
incidents
  ├── incident_events          — junction: incident ↔ normalized_event
  │     └── normalized_events  — event occurrence, entity fields, MITRE
  │           └── raw_alerts   — original Wazuh JSON (forensic only)
  ├── threat_intel_results      — CTI verdicts linked to event or incident
  ├── correlation_rules         — rule type, technique/tactic mappings
  └── incident_risk_scores      — Phase 5 risk context (contextual metadata only)
```

`Incident.ml_priority_score` (Phase 6) is available as optional contextual metadata
only. It is **never used** as evidence for chain provenance or confidence.

---

## 7. Timestamp Semantics

Phase 7 uses seven distinct timestamp concepts. These must never be conflated:

| Concept | Source Field | Meaning | Use in Chain |
|---------|-------------|---------|-------------|
| **Event occurrence** | `NormalizedEvent.event_timestamp` | When the security event occurred on the host/network | Primary temporal ordering |
| **Wazuh alert time** | `RawAlert.wazuh_timestamp` | When Wazuh generated the alert | Fallback if `event_timestamp` unavailable |
| **Event ingestion** | `NormalizedEvent.created_at` | When the event entered the pipeline | Not used for ordering; available for lag analysis |
| **CTI queried** | `ThreatIntelResult.queried_at` | When the IOC was looked up | Determines CTI temporal eligibility |
| **Incident span** | `Incident.first_seen` / `Incident.last_seen` | Chronological bounds of the incident | Chain timeline boundaries |
| **Evidence snapshot** | `Incident.evidence_version` | Monotonic counter — incremented when new evidence is correlated | Primary concurrency key for chain versioning |
| **Chain generated at** | `chain_version.generated_at` | Wall-clock time when reconstruction ran | Audit metadata only — NOT used for evidence ordering |

### 7.1 Primary Ordering Rule

Events are ordered by `(event_timestamp ASC, normalized_event_id ASC)`.

`normalized_event_id` (UUID) is the deterministic tiebreaker for equal
`event_timestamp`. UUIDs are compared as byte sequences to ensure determinism.

### 7.2 Missing Timestamps

If `NormalizedEvent.event_timestamp` is NULL (schema says `nullable=False`; handled
defensively):
1. Fall back to `RawAlert.wazuh_timestamp`
2. If still NULL: use `NormalizedEvent.created_at`
3. Mark the node with `timestamp_source = "ingestion_fallback"`

### 7.3 Late Evidence

Late evidence is identified by:

```
is_stale = (incident.evidence_version > latest_chain_version.evidence_version)
```

When stale, the chain must be reconstructed from the full current evidence snapshot.

### 7.4 CTI Temporal Eligibility

A `ThreatIntelResult` is eligible if `queried_at <= T_chain`, where `T_chain` is
the `evidence_as_of` timestamp passed to the reconstruction. This prevents future
CTI lookups from influencing retrospective ordering.

---

## 8. Entity Model

Entities are **canonicalized actors** extracted from normalized events. Only entities
extractable from existing schema columns are defined.

### 8.1 Supported Entity Types

| Type | Source Field(s) | Canonical ID Formula |
|------|----------------|---------------------|
| `HOST` | `NormalizedEvent.hostname` | `host:<lowercase(hostname)>` |
| `USER` | `NormalizedEvent.user` | `user:<lowercase(user)>` |
| `AGENT` | `NormalizedEvent.agent_id` | `agent:<agent_id>` |
| `SRC_IP` | `NormalizedEvent.src_ip` | `ip:<src_ip>` |
| `DST_IP` | `NormalizedEvent.dst_ip` | `ip:<dst_ip>` |
| `DOMAIN` | `NormalizedEvent.domain` | `domain:<lowercase(domain)>` |
| `URL` | `NormalizedEvent.url` | `url:<sha256_of_normalized_url>` |
| `PROCESS` | `NormalizedEvent.process_name` + `process_pid` | `process:<hostname>:<pid>:<process_name>` |
| `FILE` | `NormalizedEvent.file_path` / `file_hash_sha256` | `file:<sha256>` if hash present, else `file:<sha256_of_path>` |
| `FILE_HASH_MD5` | `NormalizedEvent.file_hash_md5` | `hash_md5:<md5>` |
| `FILE_HASH_SHA256` | `NormalizedEvent.file_hash_sha256` | `hash_sha256:<sha256>` |
| `IOC` | `ThreatIntelResult.ioc_value` | `ioc:<ioc_type>:<ioc_value>` |

**Not supported (no schema columns):** email, ASN, geolocation, certificate,
registry key, named pipe, mutex. These require future telemetry enrichment.

### 8.2 Canonicalization Rules

1. Strip leading/trailing whitespace from all string fields.
2. Lowercase hostnames and domains.
3. IP addresses: stored as-is (IPv4 dotted-decimal / IPv6 compressed).
4. URLs: strip fragment, lowercase scheme, sort query params by key, compute
   SHA-256 of the resulting normalized URL string.
5. Processes without a PID: use `pid=0` in the canonical ID.
6. Files: prefer `file_hash_sha256` over `file_path` for canonical ID.
7. NULL or empty string → entity is **not extracted** for that field.

### 8.3 Missing / Ambiguous Entities

- If any component of the canonical ID is NULL, that entity type is skipped.
- If `hostname` is NULL but `agent_id` is not NULL, extract only an `AGENT` entity.
- Conflicting hostnames for the same `agent_id` across events: both HOST entities
  are created; a `SAME_AGENT` edge links them.

---

## 9. Node Model

An `AttackChainNode` represents a discrete, evidence-backed element in the chain.

### 9.1 Node Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Stable surrogate PK |
| `chain_version_id` | UUID FK | Parent chain version |
| `node_canonical_id` | String(128) | Deterministic ID (see §9.2) |
| `node_type` | Enum | `EVENT` / `CTI_MATCH` / `ENTITY` / `TECHNIQUE` |
| `normalized_event_id` | UUID FK | nullable — source event |
| `threat_intel_result_id` | UUID FK | nullable — source CTI record |
| `entity_canonical_id` | String(256) | nullable — canonical entity |
| `mitre_technique_id` | String(32) | nullable |
| `mitre_tactic_id` | String(32) | nullable |
| `mitre_mapping_type` | Enum | `DIRECT_MAPPING` / `INFERRED_MAPPING` / `UNKNOWN` |
| `event_timestamp` | DateTime | canonical occurrence time |
| `timestamp_source` | String(32) | `event_timestamp` / `wazuh_timestamp` / `ingestion_fallback` |
| `provenance` | Enum | `OBSERVED` / `INFERRED` / `UNKNOWN` |
| `confidence` | Float | evidence-based, [0.0, 1.0] |
| `sequence_index` | Integer | 0-based temporal position within chain |
| `evidence_refs` | JSONB | list of `{table, id}` references |
| `evidence_snapshot` | JSONB | denormalized evidence for auditability |
| `evidence_deleted` | Boolean | True if a referenced evidence row was deleted |
| `created_at` | DateTime | wall-clock generation time |

### 9.2 Deterministic `node_canonical_id`

```
node_canonical_id = sha256(
    "<chain_evidence_version>|<node_type>|<primary_evidence_id>"
)[:64]
```

Where `primary_evidence_id` is:
- `EVENT` nodes → `normalized_event_id`
- `CTI_MATCH` nodes → `threat_intel_result_id`
- `ENTITY` nodes → `entity_canonical_id`
- `TECHNIQUE` nodes → `<mitre_technique_id>:<incident_id>`

### 9.3 Node Types and Provenance

| Type | Created When | Provenance |
|------|-------------|-----------|
| `EVENT` | One per `NormalizedEvent` in the incident | `OBSERVED` |
| `CTI_MATCH` | One per `ThreatIntelResult` with `matched=True` | `OBSERVED` |
| `ENTITY` | One per unique `entity_canonical_id` | `OBSERVED` if field non-null |
| `TECHNIQUE` | One per unique `(mitre_technique_id, incident_id)` | `DIRECT_MAPPING` if from event; `INFERRED_MAPPING` if from rule only |

---

## 10. Edge Model

An `AttackChainEdge` is a directed relationship between two nodes.

### 10.1 Edge Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Stable surrogate PK |
| `chain_version_id` | UUID FK | Parent chain version |
| `edge_canonical_id` | String(128) | Deterministic ID (see §10.3) |
| `src_node_id` | UUID FK | Source node |
| `dst_node_id` | UUID FK | Destination node |
| `edge_type` | Enum | See §10.2 |
| `provenance` | Enum | `OBSERVED` / `INFERRED` / `UNKNOWN` |
| `confidence` | Float | evidence-based, [0.0, 1.0] |
| `evidence_refs` | JSONB | list of `{table, id}` references |
| `created_at` | DateTime | wall-clock |

### 10.2 Edge Types

| Edge Type | Creation Condition | Required Evidence | Provenance |
|-----------|-------------------|------------------|-----------|
| `TEMPORAL_NEXT` | Consecutive events E_i, E_{i+1} in the incident | `incident_events` membership + `event_timestamp` | `OBSERVED` |
| `SAME_ENTITY` | Two EVENT nodes share the same `entity_canonical_id` | Entity extraction from both events | `OBSERVED` |
| `CORRELATED_WITH` | Two events joined by the same correlation rule | `incident_events.correlation_rule_id` both equal and non-null | `OBSERVED` |
| `IOC_MATCH` | EVENT node entity matches a CTI_MATCH node's `ioc_value` | `ThreatIntelResult.matched=True` | `OBSERVED` |
| `TECHNIQUE_SUPPORT` | EVENT node carries a `mitre_technique_id` | `NormalizedEvent.mitre_technique_ids` non-empty | `OBSERVED` (direct) or `INFERRED` (rule-inherited) |
| `TACTIC_PROGRESSION` | Two TECHNIQUE nodes belong to consecutive ATT&CK tactics | Both TECHNIQUE nodes exist with valid tactic IDs | `INFERRED` |
| `SAME_AGENT` | Two entities share the same `agent_id` | `NormalizedEvent.agent_id` equality | `OBSERVED` |
| `NETWORK_RELATION` | E_i.`dst_ip` = E_j.`src_ip` | Field equality within incident | `INFERRED` |
| `PROCESS_RELATION` | Two PROCESS entities share `hostname` and one `process_name` appears in the other's `process_command_line` | String containment match | `INFERRED` |

**Excluded from Phase 7** (insufficient schema evidence):
- Parent-child process relationships (no PID lineage columns)
- Registry key modifications (not in NormalizedEvent schema)
- Lateral movement without shared `src_ip`/`dst_ip` evidence
- Time-proximity-only edges (events close in time but sharing no entity)

### 10.3 Deterministic `edge_canonical_id`

```
edge_canonical_id = sha256(
    "<chain_evidence_version>|<edge_type>|<src_node_canonical_id>|<dst_node_canonical_id>"
)[:64]
```

---

## 11. MITRE ATT&CK Representation

### 11.1 Mapping Types

| Type | Source | Semantics |
|------|--------|-----------|
| `DIRECT_MAPPING` | `NormalizedEvent.mitre_technique_ids` non-empty | Rule or normalizer explicitly mapped this event |
| `INFERRED_MAPPING` | `CorrelationRule.mitre_technique_id` and event has no technique IDs | Technique inherited from correlation rule |
| `UNKNOWN` | No technique data available | Technique node is not generated |

### 11.2 Technique Deduplication

Multiple events supporting the same `mitre_technique_id` produce **one** TECHNIQUE
node per technique per incident. All supporting EVENT nodes emit `TECHNIQUE_SUPPORT`
edges to that node.

### 11.3 ATT&CK Name Resolution

A static ATT&CK technique/tactic name lookup table (JSON file bundled in
`attack_chain/data/attck_catalog.json`) is used to resolve IDs to human-readable
names at reconstruction time. This is not a live internet query.
The catalog version is recorded in the `chain_version` record.
Unknown IDs are stored with `name=null`.

### 11.4 Kill-Chain Tactic Ordering (static list)

```
TA0001 Reconnaissance
TA0002 Resource Development
TA0003 Initial Access
TA0004 Execution
TA0005 Persistence
TA0006 Privilege Escalation
TA0007 Defense Evasion
TA0008 Credential Access
TA0009 Discovery
TA0010 Lateral Movement
TA0011 Collection
TA0040 Impact
TA0042 Resource Hijacking
TA0043 Exfiltration
TA0011 Command and Control
```

`TACTIC_PROGRESSION` edges are INFERRED. They connect technique nodes whose tactic
IDs are consecutive in the above ordering, but only where both tactics are observed.

---

## 12. Reconstruction Algorithm

Deterministic for a fixed `(incident_id, evidence_version)`. Re-running with the
same evidence snapshot produces an identical graph.

```
function reconstruct(incident_id, evidence_version, evidence_as_of):

  STEP 1 — LOAD EVIDENCE SNAPSHOT
    a. Load Incident; verify evidence_version matches input
    b. Load all IncidentEvent records for incident_id
    c. Load all NormalizedEvent records via IncidentEvent join
    d. Load ThreatIntelResult records where
       (incident_id = X OR normalized_event_id IN event_ids)
       AND queried_at <= evidence_as_of
    e. Load CorrelationRule records referenced by IncidentEvent records

  STEP 2 — DEDUPLICATION
    - NormalizedEvents: deduplicate by id (schema guarantees uniqueness)
    - ThreatIntelResult: deduplicate by (ioc_value, source, normalized_event_id)
      keeping the most recent queried_at

  STEP 3 — ORDER EVENTS
    - Sort by (event_timestamp ASC, id ASC)
    - Assign sequence_index 0, 1, 2, …, N-1

  STEP 4 — CANONICALIZE ENTITIES
    - For each NormalizedEvent: extract non-null entity fields
    - Apply canonicalization rules (§8.2)
    - Build index: entity_canonical_id → set of normalized_event_ids

  STEP 5 — GENERATE EVENT NODES (OBSERVED)
    - One EVENT node per NormalizedEvent
    - Capture timestamp_source per §7.2
    - Denormalize key fields to evidence_snapshot JSONB

  STEP 6 — GENERATE CTI_MATCH NODES (OBSERVED)
    - One CTI_MATCH node per ThreatIntelResult where matched=True
    - Link to corresponding EVENT node via evidence_refs

  STEP 7 — GENERATE ENTITY NODES (OBSERVED)
    - One ENTITY node per unique entity_canonical_id

  STEP 8 — GENERATE TECHNIQUE NODES
    - One per unique (mitre_technique_id, incident_id)
    - Set mapping_type per §11.1

  STEP 9 — GENERATE TEMPORAL_NEXT EDGES (OBSERVED)
    - For each consecutive pair (event_i, event_{i+1})

  STEP 10 — GENERATE SAME_ENTITY EDGES (OBSERVED)
    - For each entity with >= 2 associated EVENT nodes
    - Limit: max 50 pairs per entity

  STEP 11 — GENERATE CORRELATED_WITH EDGES (OBSERVED)
    - Group IncidentEvent by correlation_rule_id (non-null)
    - Fully connected within each group; limit: max 100 pairs per group

  STEP 12 — GENERATE IOC_MATCH EDGES (OBSERVED)
    - For each CTI_MATCH node: match ioc_value to ENTITY canonical IDs

  STEP 13 — GENERATE TECHNIQUE_SUPPORT EDGES
    - For each EVENT node with mitre_technique_ids

  STEP 14 — GENERATE TACTIC_PROGRESSION EDGES (INFERRED)
    - Extract distinct tactic IDs from TECHNIQUE nodes
    - Apply ATT&CK ordering; create edges for consecutive pairs

  STEP 15 — GENERATE NETWORK_RELATION EDGES (INFERRED)
    - Index: ip → EVENT nodes where ip appears as src_ip or dst_ip
    - Create edges where E_i.dst_ip = E_j.src_ip

  STEP 16 — COMPUTE CONFIDENCE (see §12.1 and §12.2)

  STEP 17 — ASSIGN CHAIN VERSION
    - chain_canonical_id = sha256(
          "<incident_id>|<evidence_version>|<sorted node canonical IDs>"
      )[:64]
    - chain_version = per-incident sequential integer

  STEP 18 — PERSIST
    - Write AttackChainVersion record
    - Upsert AttackChainNode records (by node_canonical_id)
    - Upsert AttackChainEdge records (by edge_canonical_id)
    - Update attack_chains stub summary
    - Write AuditLog record

  STEP 19 — RETURN ChainResult
```

### 12.1 Node Confidence Formula

```
node_confidence =
    base_weight(provenance)
  x quality_weight(source)
  x volume_discount(corroborating_event_count)
```

| Component | Value | Rationale |
|-----------|-------|-----------|
| `base_weight(OBSERVED)` | 1.0 | Directly seen in telemetry |
| `base_weight(INFERRED)` | 0.6 | Derived from deterministic rules |
| `base_weight(UNKNOWN)` | 0.0 | Insufficient evidence |
| `quality_weight(direct_event)` | 1.0 | Raw Wazuh telemetry |
| `quality_weight(cti_matched)` | 0.9 | CTI-confirmed IOC |
| `quality_weight(cti_unmatched)` | 0.5 | CTI lookup with no match |
| `quality_weight(rule_inferred)` | 0.7 | Derived from correlation rule |
| `volume_discount(n >= 3)` | 1.0 | Three or more corroborating events |
| `volume_discount(n = 2)` | 0.9 | Two events |
| `volume_discount(n = 1)` | 0.8 | Single event |

**Bounds:** confidence in [0.0, 1.0]. A DB CHECK constraint enforces this.
Chain confidence is completely independent of risk-v1 and Phase 6 ML score.

### 12.2 Edge Confidence Formula

```
edge_confidence = min(src.confidence, dst.confidence) x edge_type_weight
```

| Edge Type | weight |
|-----------|--------|
| `TEMPORAL_NEXT` | 1.00 |
| `SAME_ENTITY` | 1.00 |
| `SAME_AGENT` | 1.00 |
| `CORRELATED_WITH` | 0.90 |
| `TECHNIQUE_SUPPORT` | 0.90 |
| `IOC_MATCH` | 0.95 |
| `TACTIC_PROGRESSION` | 0.70 |
| `NETWORK_RELATION` | 0.75 |
| `PROCESS_RELATION` | 0.65 |

---

## 13. Evidence Provenance

Every node and edge is auditable through an explicit evidence chain:

```
AttackChainNode / AttackChainEdge
  └── evidence_refs: [{table: "normalized_events", id: "<uuid>"},
                       {table: "threat_intel_results", id: "<uuid>"}]
      └── NormalizedEvent
            └── raw_alert_id -> RawAlert.raw_json  (complete Wazuh JSON)
      └── ThreatIntelResult
            └── raw_response_text  (complete CTI API response)
```

### 13.1 Orphaned References

If a referenced evidence row is deleted after chain construction:
- The node/edge is preserved with `evidence_deleted = True`
- `provenance` is downgraded to `UNKNOWN`
- A warning is added to `reconstruction_warnings`
- The chain is NOT invalidated — it represents a historical reconstruction

---

## 14. Evidence Versioning

Phase 7 extends the Phase 5 evidence-version concept to chain versioning.

| Field | Meaning |
|-------|---------|
| `chain_version.evidence_version` | `Incident.evidence_version` at reconstruction time |
| `chain_version.evidence_as_of` | `Incident.risk_evidence_as_of` at reconstruction time |
| `chain_version.generated_at` | Wall-clock when reconstruction ran (audit only) |
| `chain_version.chain_version` | Per-incident sequential integer |

**Staleness check:**
```
is_stale = (incident.evidence_version > latest_chain_version.evidence_version)
```

---

## 15. Late-Arriving Evidence

1. When `Incident.evidence_version` is incremented, chain is marked stale.
2. Next reconstruction loads the full current evidence snapshot including the late event.
3. Late event's `event_timestamp` determines its position in chronological order.
4. All edges are recomputed from scratch.
5. Previous chain version is preserved in `attack_chain_versions`.
6. `reconstruction_warnings` records:
   `{"type": "late_event", "event_id": "<uuid>", "lag_seconds": <int>}`
   where `lag_seconds = added_at - event_timestamp` (from `IncidentEvent.added_at`).

---

## 16. Idempotency

Given a fixed `(incident_id, evidence_version)`:
- The algorithm always produces the same set of nodes and edges.
- Node and edge canonical IDs are deterministic.
- Chain canonical ID is deterministic.
- Upsert semantics on `node_canonical_id` and `edge_canonical_id` prevent duplicates.
- Concurrent reconstruction calls produce identical results; the second is a no-op.

---

## 17. Conflict Handling

| Conflict | Handling |
|---------|---------|
| Equal `event_timestamp` | Tiebreak by `normalized_event_id` ASC (byte order) |
| Two hostnames for same `agent_id` | Both HOST entities created; `SAME_AGENT` edge links them |
| Multiple CTI verdicts for same IOC from different sources | All CTI_MATCH nodes preserved; highest confidence used for summary |
| Same IOC in different incidents | Each incident has its own CTI_MATCH nodes; no cross-incident contamination |
| Same technique ID from multiple events | One TECHNIQUE node; all events emit `TECHNIQUE_SUPPORT` edges |
| Conflicting technique mappings (direct vs. inferred) | Both included; `DIRECT_MAPPING` takes precedence for `mitre_mapping_type` |
| NULL `event_timestamp` | Fallback per §7.2; node created with warning in `reconstruction_warnings` |
| Evidence deleted after construction | Node preserved with `evidence_deleted=True`; provenance → UNKNOWN |
| Contradictory CTI verdicts | Both CTI_MATCH nodes created; conflict recorded in `reconstruction_warnings` |

---

## 18. API Design

All endpoints are **additive**. No existing endpoint is modified.

### 18.1 `GET /attack-chain/incident/{incident_id}`

Returns the current (latest) reconstructed chain for an incident.

**Response:**
```json
{
  "incident_id": "uuid",
  "chain_version": 3,
  "evidence_version": 7,
  "evidence_as_of": "ISO-8601",
  "generated_at": "ISO-8601",
  "is_stale": false,
  "node_count": 12,
  "edge_count": 18,
  "highest_tactic": "TA0006",
  "technique_count": 3,
  "attck_catalog_version": "14.1",
  "reconstruction_warnings": [],
  "nodes": [ <AttackChainNodeResponse> ],
  "edges": [ <AttackChainEdgeResponse> ]
}
```

**Errors:** `404` if no chain exists; `422` if `incident_id` is not a valid UUID.

### 18.2 `GET /attack-chain/incident/{incident_id}/history`

Returns all historical chain versions (summaries only — no nodes/edges).
Paginated: `page` (default 1), `page_size` (default 20, max 100).

### 18.3 `GET /attack-chain/{chain_id}`

Returns a specific chain version by UUID (useful for historical comparison).

### 18.4 `POST /attack-chain/incident/{incident_id}/reconstruct`

Triggers synchronous reconstruction for the specified incident.

- Reads current `Incident.evidence_version` and reconstructs against it.
- If `evidence_version` has not changed since last reconstruction, returns existing
  chain with `{"reconstructed": false, "message": "chain is current"}`.
- Authorization: same `X-Admin-Key` mechanism as existing API.
- Idempotent: safe to call multiple times.
- Timeout: 30 seconds; chain truncated at 500 EVENT nodes if exceeded.

### 18.5 `GET /attack-chain/incident/{incident_id}/timeline`

Returns only ordered EVENT nodes (chronological timeline without full graph).
Optimized for analyst timeline view.

### 18.6 AttackChainNodeResponse Schema

```json
{
  "node_id": "uuid",
  "node_canonical_id": "64-char-hex",
  "node_type": "EVENT|CTI_MATCH|ENTITY|TECHNIQUE",
  "provenance": "OBSERVED|INFERRED|UNKNOWN",
  "confidence": 0.80,
  "sequence_index": 3,
  "event_timestamp": "ISO-8601",
  "timestamp_source": "event_timestamp|wazuh_timestamp|ingestion_fallback",
  "normalized_event_id": "uuid or null",
  "threat_intel_result_id": "uuid or null",
  "entity_canonical_id": "string or null",
  "mitre_technique_id": "T1059 or null",
  "mitre_tactic_id": "TA0002 or null",
  "mitre_technique_name": "Command and Scripting Interpreter or null",
  "mitre_tactic_name": "Execution or null",
  "mitre_mapping_type": "DIRECT_MAPPING|INFERRED_MAPPING|UNKNOWN or null",
  "evidence_refs": [{"table": "normalized_events", "id": "uuid"}],
  "forensic_available": true
}
```

Note: `RawAlert.raw_json` and `ThreatIntelResult.raw_response_text` are NOT returned
in the API response. They are indicated by `forensic_available: true`.

### 18.7 AttackChainEdgeResponse Schema

```json
{
  "edge_id": "uuid",
  "edge_canonical_id": "64-char-hex",
  "edge_type": "TEMPORAL_NEXT",
  "src_node_id": "uuid",
  "dst_node_id": "uuid",
  "provenance": "OBSERVED|INFERRED|UNKNOWN",
  "confidence": 0.72,
  "evidence_refs": [{"table": "incident_events", "id": "uuid"}]
}
```

### 18.8 Chain Size Limits

| Limit | Value |
|-------|-------|
| Max EVENT nodes per chain | 500 |
| Max SAME_ENTITY edge pairs per entity | 50 |
| Max CORRELATED_WITH pairs per rule group | 100 |
| Max total edges per chain | 2000 |
| Reconstruction timeout | 30 seconds |

When a limit is exceeded, reconstruction proceeds with truncation and records:
`{"type": "limit_exceeded", "limit": "<name>", "actual": <count>}`

---

## 19. Storage Design

### 19.1 New Tables

Three new tables are required. The existing `attack_chains` stub is reused as a
materialized summary row.

### 19.2 `attack_chain_versions` DDL

```sql
CREATE TABLE attack_chain_versions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id             UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    chain_canonical_id      VARCHAR(128) NOT NULL,
    chain_version           INTEGER NOT NULL,
    evidence_version        BIGINT NOT NULL,
    evidence_as_of          TIMESTAMPTZ,
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    node_count              INTEGER NOT NULL DEFAULT 0,
    edge_count              INTEGER NOT NULL DEFAULT 0,
    technique_count         INTEGER NOT NULL DEFAULT 0,
    highest_tactic          VARCHAR(32),
    reconstruction_warnings JSONB NOT NULL DEFAULT '[]',
    attck_catalog_version   VARCHAR(16) NOT NULL
);
CREATE UNIQUE INDEX uq_acv_incident_version
    ON attack_chain_versions(incident_id, chain_version);
CREATE INDEX ix_acv_incident_evidence
    ON attack_chain_versions(incident_id, evidence_version DESC);
```

### 19.3 `attack_chain_nodes` DDL

```sql
CREATE TABLE attack_chain_nodes (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_version_id        UUID NOT NULL REFERENCES attack_chain_versions(id) ON DELETE CASCADE,
    node_canonical_id       VARCHAR(128) NOT NULL,
    node_type               VARCHAR(32) NOT NULL,
    normalized_event_id     UUID REFERENCES normalized_events(id) ON DELETE SET NULL,
    threat_intel_result_id  UUID REFERENCES threat_intel_results(id) ON DELETE SET NULL,
    entity_canonical_id     VARCHAR(256),
    mitre_technique_id      VARCHAR(32),
    mitre_tactic_id         VARCHAR(32),
    mitre_mapping_type      VARCHAR(32),
    event_timestamp         TIMESTAMPTZ,
    timestamp_source        VARCHAR(32),
    provenance              VARCHAR(16) NOT NULL,
    confidence              FLOAT NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    sequence_index          INTEGER,
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    evidence_snapshot       JSONB NOT NULL DEFAULT '{}',
    evidence_deleted        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_acn_chain_canonical
    ON attack_chain_nodes(chain_version_id, node_canonical_id);
CREATE INDEX ix_acn_event ON attack_chain_nodes(normalized_event_id);
CREATE INDEX ix_acn_chain_type ON attack_chain_nodes(chain_version_id, node_type);
CREATE INDEX ix_acn_entity ON attack_chain_nodes(entity_canonical_id);
```

### 19.4 `attack_chain_edges` DDL

```sql
CREATE TABLE attack_chain_edges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_version_id        UUID NOT NULL REFERENCES attack_chain_versions(id) ON DELETE CASCADE,
    edge_canonical_id       VARCHAR(128) NOT NULL,
    src_node_id             UUID NOT NULL REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    dst_node_id             UUID NOT NULL REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    edge_type               VARCHAR(32) NOT NULL,
    provenance              VARCHAR(16) NOT NULL,
    confidence              FLOAT NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_ace_chain_canonical
    ON attack_chain_edges(chain_version_id, edge_canonical_id);
CREATE INDEX ix_ace_src ON attack_chain_edges(src_node_id);
CREATE INDEX ix_ace_dst ON attack_chain_edges(dst_node_id);
CREATE INDEX ix_ace_chain_type ON attack_chain_edges(chain_version_id, edge_type);
```

### 19.5 Migration Strategy

- One new Alembic migration: `<timestamp>_phase_7_attack_chain_schema.py`
- DDL-only; no data migration required.
- The existing `attack_chains` table receives additive columns only
  (`chain_version_id` FK, `evidence_version`).
- No columns in Phase 0–6 tables are dropped or modified.

---

## 20. Security

| Control | Implementation |
|---------|---------------|
| Authorization | `X-Admin-Key` (Phase 0 mechanism); no new auth in Phase 7 |
| Input validation | `incident_id` must be a valid UUID; reject with HTTP 422 otherwise |
| Evidence reference validation | Referenced UUIDs validated against DB before reconstruction |
| Resource limits | Hard node/edge limits per §18.8 prevent unbounded memory/CPU use |
| Graph injection protection | All nodes/edges generated from verified DB records; no external graph input accepted |
| Canonical ID protection | SHA-256 over sanitized internal data; user input never flows into canonical IDs |
| Sensitive data in API response | `raw_json` and `raw_response_text` omitted from API responses; indicated by `forensic_available: true` |
| Audit trail | Every reconstruction → AuditLog row with `action="attack_chain.reconstruct"` |
| SQL injection | SQLAlchemy ORM parameterized queries exclusively |

---

## 21. Performance Methodology

### 21.1 Design Targets (not yet measured)

| Metric | Target | Method |
|--------|--------|--------|
| Reconstruction latency (50 events) | < 2 s | pytest-benchmark |
| Reconstruction latency (200 events) | < 10 s | pytest-benchmark |
| Reconstruction latency (500 events) | < 30 s | pytest-benchmark |
| Memory (500-event chain) | < 256 MB | memory_profiler |

> No performance claim is made until the implementation is benchmarked.

### 21.2 Benchmark Dataset

Controlled synthetic datasets (not from production Wazuh database):
- 50 events, 5 CTI matches — small chain
- 200 events, 20 CTI matches — medium chain
- 500 events, 50 CTI matches — large chain at limit

Generated deterministically from fixed seeds for reproducibility.

---

## 22. Testing Strategy

All Phase 0–6 tests (243 passing, 2 skipped) must remain green.
Phase 7 adds `tests/attack_chain/`.

### 22.1 Unit Tests

| Test | What it verifies |
|------|-----------------|
| `test_entity_canonicalization` | All entity types; null fields excluded |
| `test_node_canonical_id_determinism` | Same inputs → same ID |
| `test_edge_canonical_id_determinism` | Same inputs → same ID |
| `test_temporal_ordering` | Events ordered by event_timestamp ASC, id tiebreak |
| `test_equal_timestamp_tiebreak` | Equal timestamps: id byte-order tiebreak |
| `test_timestamp_fallback_chain` | NULL event_timestamp → wazuh_timestamp → ingestion_fallback |
| `test_technique_deduplication` | Same technique from two events → one TECHNIQUE node |
| `test_cti_deduplication` | Duplicate CTI records deduplicated correctly |
| `test_mitre_direct_vs_inferred` | Direct mapping vs. rule-inherited mapping |
| `test_provenance_event_observed` | EVENT nodes always OBSERVED |
| `test_provenance_tactic_progression_inferred` | TACTIC_PROGRESSION edges always INFERRED |
| `test_confidence_formula` | Values match §12.1 and §12.2 formulas |
| `test_confidence_bounds` | confidence always in [0.0, 1.0] |
| `test_chain_canonical_id_determinism` | Same evidence_version → same chain_canonical_id |
| `test_entity_conflict_two_hostnames` | Two hostnames for same agent → two HOST nodes + SAME_AGENT edge |
| `test_contradictory_cti` | Two CTI verdicts both preserved |
| `test_null_entity_fields_skipped` | NULL field → no entity extracted |
| `test_orphaned_evidence_reference` | Deleted evidence → node preserved, provenance=UNKNOWN |

### 22.2 Integration Tests

| Test | What it verifies |
|------|-----------------|
| `test_reconstruct_single_event` | 1-event incident → minimal valid chain |
| `test_reconstruct_multi_event` | N events → all TEMPORAL_NEXT edges present |
| `test_reconstruct_with_cti` | CTI match → CTI_MATCH node + IOC_MATCH edge |
| `test_reconstruct_idempotency` | Reconstruct twice, same evidence_version → identical result |
| `test_reconstruct_after_evidence_change` | New evidence_version → new chain_version |
| `test_late_event_position` | Late event placed at correct chronological position |
| `test_stale_chain_detection` | `is_stale` correct for evidence_version comparison |
| `test_chain_size_limit_truncation` | 600-event incident → truncated at 500, warning present |
| `test_api_get_chain` | GET endpoint returns correct structure |
| `test_api_get_history` | History endpoint returns all versions |
| `test_api_reconstruct_idempotent` | POST twice → second is no-op with `reconstructed=false` |
| `test_api_reconstruct_new_version` | After evidence change → `reconstructed=true` |
| `test_api_get_chain_404` | No chain → HTTP 404 |
| `test_api_invalid_uuid` | Non-UUID incident_id → HTTP 422 |
| `test_audit_log_written` | Every reconstruction → AuditLog record exists |

### 22.3 Determinism Regression Tests

N=10 repeated reconstructions of the same incident (same `evidence_version`) must
produce:
- Equal `node_count`
- Equal set of `node_canonical_id` values
- Equal `edge_count`
- Equal set of `edge_canonical_id` values
- Equal `chain_canonical_id`

---

## 23. Research Evaluation Methodology

### 23.1 Limitation

> The current production Wazuh database contains no incident-level labeled attack-chain
> ground truth. There is no dataset of known attack sequences for quantitative validation.

This is the same structural limitation as Phase 6 (`DATASET_STATUS = INSUFFICIENT`).

### 23.2 Proposed Evaluation Dataset

To enable future quantitative evaluation:

**Method:** Replay a known attack simulation (e.g., Atomic Red Team, CALDERA campaign)
against a Wazuh-monitored test host, capturing the resulting Wazuh telemetry.

**Ground truth:** Pre-defined sequence of ATT&CK techniques executed in a known order.

**Measurement:** Does the reconstructed chain recover the known sequence?

This dataset must be obtained from real Wazuh telemetry of controlled executions —
not fabricated synthetically.

### 23.3 Evaluation Metrics (once dataset is available)

| Metric | Formula |
|--------|---------|
| Chain Completeness | `observed_techniques / ground_truth_techniques` |
| Temporal Ordering Accuracy | Kendall tau between reconstructed order and ground-truth order |
| Evidence Coverage | `events_in_chain / total_incident_events` |
| Observed Ratio | `OBSERVED_nodes / total_nodes` |
| Duplicate Node Rate | `duplicates_before_dedup / nodes_after_dedup` |
| Orphan Edge Rate | `edges_with_deleted_endpoint / total_edges` |
| Deterministic Reproducibility | 1.0 if N reconstructions produce identical `chain_canonical_id` |
| Reconstruction Latency | p50 / p95 / p99 in milliseconds |

---

## 24. Failure Modes

| Failure | Behavior |
|---------|---------|
| Incident not found | HTTP 404 |
| Incident has no events | Empty chain with `node_count=0`; warning `{"type": "no_events"}` |
| All events have NULL timestamps | Reconstruct with fallback timestamps; warn for each |
| ATT&CK catalog bundle missing | Reconstruction proceeds; technique names = null; warning logged |
| Chain stale at read time | Return chain with `is_stale=true`; do not auto-reconstruct |
| Reconstruction timeout (>30s) | HTTP 503; partial state rolled back |
| Circular edge detected | Edge dropped silently; warning `{"type": "circular_edge_dropped"}` |
| DB write failure | Reconstruction result discarded; previous version preserved; HTTP 500 |
| Duplicate `chain_version` race | UNIQUE constraint violation → retry with next sequential version (up to 3 retries) |

---

## 25. Observability

| Signal | Type | Labels |
|--------|------|--------|
| `attack_chain_reconstruction_total` | Counter | `status`: success/error/timeout |
| `attack_chain_reconstruction_duration_seconds` | Histogram | — |
| `attack_chain_node_count` | Histogram | — |
| `attack_chain_edge_count` | Histogram | — |
| `attack_chain_stale_total` | Counter | — |
| `attack_chain_late_evidence_total` | Counter | — |
| `attack_chain_warnings_total` | Counter | `warning_type` |
| `attack_chain_api_requests_total` | Counter | `endpoint`, `status_code` |

Prometheus stubs (no-op when prometheus_client unavailable), consistent with the
Phase 6 `ml/observability.py` pattern.

---

## 26. Phase Boundaries

### In Scope — Phase 7

- `attack_chain/` package (reconstruction engine)
- `attack_chain_versions`, `attack_chain_nodes`, `attack_chain_edges` tables
- Alembic DDL migration
- Entity canonicalization
- Temporal ordering and tiebreaking
- 9 edge types
- MITRE technique/tactic mapping and ATT&CK ordering
- Provenance (OBSERVED/INFERRED/UNKNOWN) on every node and edge
- Evidence-based confidence formula
- Chain versioning keyed on `evidence_version`
- Late-arriving evidence handling
- Idempotent reconstruction
- 5 additive REST API endpoints
- AuditLog integration
- Prometheus observability stubs
- Unit and integration tests

### Out of Scope — Phase 7

| Feature | Phase |
|---------|-------|
| Automated containment (firewall, isolation, process kill) | Phase 8 |
| SOAR integration | Phase 8 |
| Wazuh Active Response (already exists; not duplicated) | Phase 8 |
| Frontend / dashboard visualization | Phase 9+ |
| LLM-based reasoning or narrative generation | Phase 9+ |
| Multi-tenancy | Phase 9+ |
| Live TAXII/STIX ATT&CK feed | Phase 9+ |
| Autonomous response decisions | Phase 9+ |

---

## 27. Implementation Sequence

| Step | Task | Dependency |
|------|------|-----------|
| 1 | Alembic DDL migration (3 new tables + attack_chains additive columns) | None |
| 2 | `attack_chain/constants.py` — enums, limits, edge weights | None |
| 3 | `attack_chain/entity.py` — entity extraction and canonicalization | constants |
| 4 | `attack_chain/mitre.py` — catalog loader, tactic ordering | None |
| 5 | `attack_chain/data/attck_catalog.json` — bundled catalog | mitre.py |
| 6 | `attack_chain/confidence.py` — node and edge confidence formulas | constants |
| 7 | `attack_chain/algorithm.py` — reconstruction steps 1–17 | entity, mitre, confidence |
| 8 | `attack_chain/models.py` — Phase 7 SQLAlchemy ORM models | Migration |
| 9 | `attack_chain/service.py` — orchestration, persistence, staleness | algorithm, models |
| 10 | `attack_chain/observability.py` — Prometheus stubs | None |
| 11 | API endpoints in `main.py` (additive) | service.py |
| 12 | `tests/attack_chain/__init__.py` | |
| 13 | `tests/attack_chain/test_entity.py` | entity.py |
| 14 | `tests/attack_chain/test_algorithm.py` | algorithm.py |
| 15 | `tests/attack_chain/test_api.py` — integration tests | API |
| 16 | Run full test suite — all Phase 0–6 + Phase 7 tests must pass | All |
| 17 | Phase 7 git checkpoint and tag | Tests green |

---

## 28. Acceptance Criteria

| Criterion | Verification |
|-----------|-------------|
| Reconstruction is deterministic (N=10 runs, same evidence_version) | Determinism test suite |
| All EVENT nodes have OBSERVED provenance | Unit test |
| All TACTIC_PROGRESSION edges have INFERRED provenance | Unit test |
| Confidence in [0.0, 1.0] for all nodes and edges | DB CHECK constraint + unit test |
| Evidence refs trace to valid DB records | Integration test |
| Late evidence handled without chain corruption | Integration test |
| All Phase 0–6 tests (243+2) continue to pass | CI run |
| Phase 7 test coverage >= 90% of `attack_chain/` | pytest-cov |
| API returns 404 for unknown incident | Integration test |
| API returns 422 for invalid UUID | Integration test |
| Chain size limits enforced | Unit test |
| AuditLog record written for every reconstruction | Integration test |
| No Phase 0–6 source files modified | `git diff phase-6-complete..HEAD --name-only` |
| No secrets in committed files | Secret scan |

---

## 29. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `attack_chain/` package naming conflicts with `backend/app/models/attack_chain.py` | Low | Low | Distinct namespaces; package = logic, models file = ORM |
| `SAME_ENTITY` edge explosion for high-frequency shared IPs (e.g., DNS server) | Medium | High | Per-entity pair limit of 50; warn and truncate |
| ATT&CK catalog bundle version drift | Medium | Low | Record `attck_catalog_version` in chain_version |
| MITRE technique IDs absent from most NormalizedEvents | High | Medium | Chain reconstructs without technique nodes; `technique_count=0` is a valid result |
| Reconstruction latency exceeds 30s for large incidents | Low | Medium | Hard 500-node limit + graceful truncation |
| No labeled ground-truth dataset for quantitative research evaluation | High | Medium | Explicit limitation documented; controlled simulation evaluation dataset proposed |
| `entity_context` on Incident not in normalized format | Medium | Low | Extract from individual events; treat `entity_context` as informational supplement |
| risk-v1 or ML score accidentally referenced in chain confidence | Low | High | Explicit formula in §12; independent implementation; code review gate |

---

## 30. Final Manual-Review Checklist

Before authorizing implementation, verify:

- [ ] Existing `attack_chains` stub assessment is understood; the Phase 7 extension plan (richer tables + stub as materialized summary) is approved
- [ ] Three new table designs (§19.2–19.4) are approved
- [ ] Confidence formula (§12.1 and §12.2) and all weights are approved
- [ ] Edge type set (§10.2) is approved — specifically: PROCESS_RELATION uses string containment matching which may produce false positives; NETWORK_RELATION uses `dst_ip = src_ip` cross-event matching as an INFERRED edge
- [ ] ATT&CK catalog bundling strategy (local JSON, version recorded in chain_version) is approved
- [ ] Chain size limits (500 nodes, 2000 edges) are approved
- [ ] API timeout (30 seconds) is approved
- [ ] Research evaluation limitation (no labeled dataset) is acknowledged
- [ ] `attack_chain/` package naming convention is approved (no conflict with `backend/app/models/attack_chain.py`)
- [ ] Phase 8 scope (automated response, SOAR) is explicitly excluded from Phase 7
- [ ] Wazuh Active Response (existing capability; not duplicated in Phase 7) is acknowledged
- [ ] All Phase 0–6 immutability constraints are acknowledged
- [ ] Implementation authorization will be given as a separate explicit message

---

**PLAN REVISION 1 — AWAITING MANUAL REVIEW**
