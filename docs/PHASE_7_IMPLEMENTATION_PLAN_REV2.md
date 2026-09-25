# PHASE 7 IMPLEMENTATION PLAN — REVISION 2
## Attack Chain / Incident Reconstruction Engine

**Document status:** PLAN REVISION 2 — AWAITING MANUAL REVIEW
**Created:** 2026-09-25
**Supersedes:** docs/PHASE_7_IMPLEMENTATION_PLAN_REV1.md
**Preceding checkpoints:**
- `phase-5-complete` → `a51c369d7e5d8363a8a3a7891faea0e804f33b1`
- `phase-6-complete` → `9b447c5b20c9182844d0ba5ae585f97f6fdd4e7d`

---

## Revision 2 — Summary of Corrections from Revision 1

| # | Correction |
|---|-----------|
| 1 | `TACTIC_PROGRESSION` edge type **removed**. ATT&CK tactic ordering must not create causal or temporal graph edges. |
| 2 | `TEMPORAL_NEXT` renamed to `CHRONOLOGICAL_NEXT` and reclassified as **INFERRED** (chronological adjacency is derived, not causal). |
| 3 | `CORRELATED_WITH` reclassified as **INFERRED** (correlation is an analytical product, not a directly-observed event relationship). |
| 4 | `confidence` renamed to `evidence_strength` throughout. Explicitly documented as a deterministic ordinal engineering score — not a probability. |
| 5 | `chain_evidence_as_of` introduced as a Phase 7-owned field derived from the eligible evidence set. Dependency on Phase 5 `risk_evidence_as_of` removed. |
| 6 | Logical node identity (`logical_node_id`) separated from chain-version membership (`chain_version_id`) and database row identity (`id`). |
| 7 | `PROCESS_RELATION` removed from Phase 7 V1. Insufficient evidence for process lineage from command-line string containment. |
| 8 | CTI evidence history preserved. No historical CTI record discarded. Current-vs-historical interpretation separated. |
| 9 | Provenance semantics tightened. OBSERVED reserved for directly extracted evidence; INFERRED for derived relationships. |
| 10 | Dedicated "Causality and Inference Boundary" section added. |
| 11 | ATT&CK catalog retained but tactic ordering removed as inference mechanism. |
| 12 | Final authoritative edge type set documented with 7 types (no TACTIC_PROGRESSION, no PROCESS_RELATION). |
| 13 | Evidence-strength formulas rewritten, non-probabilistic framing applied throughout. |
| 14 | Research questions updated to remove causal-discovery framing. |
| 15 | Evaluation metrics updated to measure reconstruction, not attacker-intent prediction. |

---

## 1. Executive Summary

Phase 7 delivers a deterministic, evidence-backed **Attack Chain Reconstruction Engine**
that assembles a directed evidence graph for security incidents from the evidence produced
by Phases 1–6. It does not modify any upstream Phase 0–6 contract.

Every graph element carries explicit **provenance** (OBSERVED / INFERRED / UNKNOWN) and
a transparent **evidence-strength** score that is a deterministic ordinal engineering
heuristic — not a probability.

The system answers:

- *What evidence exists?* — the complete set of correlated events and CTI results
- *In what order did events occur?* — deterministic chronological ordering by `event_timestamp`
- *Which entities appear in the evidence?* — canonicalized host/user/IP/file/process entities
- *Which ATT&CK techniques are supported by evidence?* — directly mapped or rule-inherited
- *Which relationships are directly extracted vs. analytically derived?* — explicit provenance on every edge
- *How does the graph change when late evidence arrives?* — versioned reconstruction keyed on `evidence_version`

**The engine does NOT:**
- claim attacker intent
- prove causality between events
- infer missing attack steps from tactic taxonomy
- perform automated containment, SOAR integration, LLM reasoning, or any response action

---

## 2. Causality and Inference Boundary

> **This section is normative. Every design decision in Phase 7 must be consistent with it.**

Phase 7 reconstructs **evidence relationships** from available telemetry. It does NOT prove:

- attacker intent or motivations
- causality between events (Event A caused Event B)
- process parent-child lineage without explicit telemetry
- lateral movement without supporting source/destination evidence
- attack step ordering beyond what timestamps show
- missing attack steps that are not in the evidence
- successful attacker objectives
- the actual attack path taken

The reconstructed graph is an **evidence reconstruction**, not a forensic proof of attacker
behavior.

**Language guidelines:**

| Prohibited | Preferred |
|-----------|-----------|
| "The attacker performed X" | "Evidence supports technique X" |
| "Event A caused Event B" | "Event A precedes Event B chronologically" |
| "The attacker moved laterally" | "A network relationship is observed between events E1 and E2" |
| "Phase 7 infers the attack path" | "Phase 7 reconstructs the evidence graph" |

Chronological adjacency (CHRONOLOGICAL_NEXT edge) establishes that Event A was observed
before Event B. It does **not** establish that A caused B.

Correlation-derived relationships (CORRELATED_WITH edge) establish that two events were
analytically grouped by the correlation engine. They do **not** prove those events were
caused by the same actor.

---

## 3. Research Objective

Produce a reproducible, deterministic evidence graph for security incidents from
heterogeneous Wazuh/CTI/correlation evidence. The output is suitable for:

1. Analyst review during incident investigation
2. Research evaluation of evidence coverage, graph completeness, and temporal ordering
3. Academic reporting in the capstone research paper

---

## 4. Research Questions

| ID  | Question |
|-----|----------|
| RQ1 | Can deterministic evidence reconstruction produce reproducible attack-chain graphs from heterogeneous Wazuh/CTI/correlation evidence? |
| RQ2 | How accurately does the reconstructed timeline preserve the temporal ordering of events in known controlled attack scenarios? |
| RQ3 | How does late-arriving evidence affect chain completeness, node/edge counts, and graph structure? |
| RQ4 | What proportion of graph relationships are directly observed (OBSERVED provenance) versus deterministically inferred (INFERRED provenance)? |
| RQ5 | Which MITRE ATT&CK techniques can be recovered from the current Wazuh/CTI telemetry schema, and which require future enrichment? |

**Explicitly excluded from Phase 7 RQs:**
- "Can the system infer attacker intent?" — out of scope
- "Can the system discover the actual attack path?" — no ground truth to validate this
- "Does the ATT&CK tactic sequence match the reconstructed order?" — Phase 7 does not infer tactic sequences

---

## 5. Existing Architecture Integration

Phase 7 is **additive only**. The following Phase 0–6 contracts are frozen:

| Component | Status |
|-----------|--------|
| RawAlert ingestion semantics | Frozen — Phase 1 |
| NormalizedEvent schema | Frozen — Phase 2 |
| Correlation engine, IncidentEvent, CorrelationRule | Frozen — Phase 3 |
| ThreatIntelResult, CTI providers, cache | Frozen — Phase 4 |
| risk-v1 formula, weights, decay, concurrency, PriorityBand | Frozen — Phase 5 |
| IncidentRiskScore temporal concepts | Frozen — Phase 5 |
| ML pipeline, DATASET_STATUS, inference disabled-by-default | Frozen — Phase 6 |

Phase 7 **reads** from existing tables. It **writes** only to Phase 7-specific tables.

**Phase 5 independence:** Phase 7 does NOT require the Phase 5 risk engine to have
executed. Phase 7 constructs its own evidence horizon (`chain_evidence_as_of`).
Risk scores may be read as optional contextual metadata but must not determine chain
provenance, evidence horizon, or graph structure.

---

## 6. Repository Inspection Findings (from Revision 1, confirmed)

### 6.1 Existing `AttackChain` Model (`backend/app/models/attack_chain.py`)

Phase 0 stub. Currently: `chain_steps` JSONB (flat), `confidence` scalar (no formula),
`last_calculated_at` (wall-clock), no `evidence_version`, no node/edge identity.

**Decision (unchanged from Rev1):** The stub is preserved as a materialized summary row.
Three richer tables introduced for the full graph. The stub's `chain_steps` JSONB is
back-filled from Phase 7 EVENT nodes for backward compatibility.

### 6.2 `attack_chain/` Package

Exists at project root — **completely empty**. No implementation.

### 6.3 No Attack-Chain API Routes

`backend/app/main.py` (1,302 lines) contains no `/attack-chain*` routes.

### 6.4 MITRE Data

MITRE IDs stored as plain strings in:
- `NormalizedEvent.mitre_technique_ids` — ARRAY(String), nullable
- `NormalizedEvent.mitre_tactic_ids` — ARRAY(String), nullable
- `Incident.mitre_techniques` / `mitre_tactics` — JSONB lists
- `CorrelationRule.mitre_technique_id` / `mitre_tactic_id` — single String, nullable

No ATT&CK name-resolution table exists. A bundled catalog JSON file is required.

### 6.5 CTI Data

`ThreatIntelResult` is append-only at the service layer (Phase 4 semantics).
Historical records are never updated or deleted by normal workflows.
Multiple records may exist for the same `(ioc_value, source)` over time —
this history must be preserved.

### 6.6 Phase 5 Temporal Fields Available (read-only, optional)

`Incident.risk_evidence_as_of`, `Incident.risk_calculated_at` — available as
contextual metadata but must NOT be required by Phase 7.

---

## 7. Input Evidence Model

Phase 7 reads from the following tables (read-only):

```
incidents
  ├── incident_events           — junction: incident <-> normalized_event
  │     └── normalized_events  — event occurrence, entity fields, MITRE
  │           └── raw_alerts   — original Wazuh JSON (forensic references only)
  ├── threat_intel_results      — CTI verdicts linked to event or incident
  │                               (ALL historical records, not just newest)
  ├── correlation_rules         — rule type, technique/tactic mappings
  └── incident_risk_scores      — Phase 5 risk context (OPTIONAL, contextual only)
```

`Incident.ml_priority_score` (Phase 6) is available as optional contextual metadata.
It is **never used** for chain provenance, evidence horizon, or evidence strength.

---

## 8. Timestamp Semantics

Phase 7 uses seven distinct timestamp concepts. These must never be conflated:

| Concept | Source | Meaning | Use in Chain |
|---------|--------|---------|-------------|
| **Event occurrence** | `NormalizedEvent.event_timestamp` | When the security event occurred | Primary chronological ordering |
| **Wazuh alert time** | `RawAlert.wazuh_timestamp` | When Wazuh generated the alert | Fallback timestamp (tier 2) |
| **Event ingestion** | `NormalizedEvent.created_at` | When the event entered the pipeline | Lag measurement only; NOT used for ordering |
| **CTI queried** | `ThreatIntelResult.queried_at` | When the IOC was looked up | CTI temporal eligibility gate |
| **Incident span** | `Incident.first_seen` / `Incident.last_seen` | Chronological bounds of incident | Chain timeline display |
| **Evidence snapshot version** | `Incident.evidence_version` | Monotonic counter — incremented when new evidence is correlated | Primary concurrency key for chain versioning |
| **Chain generated at** | `chain_version.generated_at` | Wall-clock time when reconstruction ran | **AUDIT METADATA ONLY** — does NOT determine evidence freshness |

### 8.1 Phase 7-Owned Evidence Horizon: `chain_evidence_as_of`

Phase 7 calculates its own evidence horizon independently of Phase 5.

```
chain_evidence_as_of = max(
    max(eligible_event.event_timestamp),
    max(eligible_cti.queried_at)
)
```

Where:
- `eligible_event` = all `NormalizedEvent` records associated with the incident
- `eligible_cti` = all `ThreatIntelResult` records eligible for this reconstruction
  (see §8.3)

If no events exist: `chain_evidence_as_of` = `Incident.created_at`.

Phase 5 `risk_evidence_as_of` is NOT used to set this value.
Phase 5 execution is NOT required.

### 8.2 Primary Chronological Ordering Rule

Events are ordered by `(event_timestamp ASC, normalized_event_id ASC)`.

`normalized_event_id` (UUID compared as byte sequences) is the deterministic tiebreaker
for equal `event_timestamp`. This guarantees a total ordering with no ambiguity.

### 8.3 CTI Temporal Eligibility

A `ThreatIntelResult` record is eligible for inclusion in a chain reconstruction if:

```
queried_at <= T_reconstruction
```

Where `T_reconstruction` is determined at the start of the reconstruction call as the
current snapshot boundary (see §14). This prevents CTI lookups performed after the
snapshot boundary from influencing the reconstruction.

**All eligible CTI records are included in the evidence set.** No deduplication
discards historical records (see §9.5).

### 8.4 Timestamp Fallback for Missing Values

If `NormalizedEvent.event_timestamp` is NULL (schema says `nullable=False`; handled
defensively):
1. Tier 2: `RawAlert.wazuh_timestamp` (via `raw_alert_id` join)
2. Tier 3: `NormalizedEvent.created_at` (ingestion time)
3. Record `timestamp_source` field accordingly in the node
4. Add reconstruction warning: `{"type": "timestamp_fallback", "tier": 2 or 3, "event_id": "..."}`

### 8.5 Late Evidence

Late evidence arrives after an evidence snapshot has already been processed.
Identified by:

```
is_stale = (incident.evidence_version > latest_chain_version.evidence_version)
```

Late events are positioned by their `event_timestamp`, not by `added_at` or
`created_at`. `IncidentEvent.added_at` is used only to compute and report
ingestion lag in `reconstruction_warnings`.

---

## 9. Entity Model

Entities are **canonicalized actors** directly extracted from normalized event fields.
Only entities extractable from existing schema columns are defined.

### 9.1 Supported Entity Types

| Type | Source Field(s) | Canonical ID Formula |
|------|----------------|---------------------|
| `HOST` | `NormalizedEvent.hostname` | `host:<lowercase(hostname)>` |
| `USER` | `NormalizedEvent.user` | `user:<lowercase(user)>` |
| `AGENT` | `NormalizedEvent.agent_id` | `agent:<agent_id>` |
| `IP` | `NormalizedEvent.src_ip` or `dst_ip` | `ip:<ip_address>` |
| `DOMAIN` | `NormalizedEvent.domain` | `domain:<lowercase(domain)>` |
| `URL` | `NormalizedEvent.url` | `url:<sha256_of_normalized_url>` |
| `PROCESS` | `NormalizedEvent.process_name` + `process_pid` | `process:<hostname>:<pid>:<process_name>` |
| `FILE` | `NormalizedEvent.file_hash_sha256` or `file_path` | `file:<sha256>` if hash present; else `file:<sha256_of_path>` |
| `FILE_HASH_MD5` | `NormalizedEvent.file_hash_md5` | `hash_md5:<md5>` |
| `FILE_HASH_SHA256` | `NormalizedEvent.file_hash_sha256` | `hash_sha256:<sha256>` |
| `IOC` | `ThreatIntelResult.ioc_value` + `ioc_type` | `ioc:<ioc_type>:<ioc_value>` |

**Not supported in Phase 7** (no schema columns): email, ASN, geolocation, certificate,
registry key, named pipe, mutex. These require future telemetry enrichment.

### 9.2 Canonicalization Rules

1. Strip leading/trailing whitespace from all string values.
2. Lowercase hostnames, domains.
3. IP addresses stored as-is (IPv4 dotted-decimal / IPv6 compressed).
4. URLs: strip fragment (`#...`), lowercase scheme, sort query params by key,
   compute SHA-256 of the resulting normalized string.
5. Processes without a PID: use `pid=0` in the canonical ID.
6. Files prefer `file_hash_sha256` over `file_path` for canonical ID.
7. NULL or empty string → entity type not extracted for that event.

### 9.3 Missing / Ambiguous Entities

- NULL component in the canonical ID formula → entity type skipped for that event.
- `hostname=NULL` but `agent_id` non-null → extract `AGENT` entity only.
- Two different hostnames for the same `agent_id` across events → two `HOST` entities;
  a `SAME_AGENT` edge links them.

### 9.4 Provenance of ENTITY Nodes

`ENTITY` nodes always have `provenance = OBSERVED` when directly extracted from a
non-null schema field. The entity node represents a claim extracted from evidence, not
an analytical derivation.

### 9.5 CTI Evidence: Historical Preservation

**All eligible `ThreatIntelResult` records are included as evidence.**
No historical CTI record is discarded.

For the current graph, Phase 7 distinguishes:

- **Complete CTI evidence history:** every eligible record in `threat_intel_results`
  for this incident/event, regardless of verdict or timestamp
- **Current-interpretation view:** for graph display/summary, the most recent
  eligible record per `(ioc_value, source)` is used as the "current" state

If a historical record shows `MALICIOUS` at 10:00 and a later record shows `BENIGN`
at 12:00, both are preserved in the evidence set. The reconstruction warns via
`reconstruction_warnings`:
```json
{"type": "cti_verdict_changed", "ioc_value": "...", "source": "...",
 "from_verdict": "MALICIOUS", "to_verdict": "BENIGN",
 "from_queried_at": "...", "to_queried_at": "..."}
```

The graph contains one `CTI_MATCH` node per `ThreatIntelResult.id` (not per
`(ioc_value, source)` pair). Multiple `CTI_MATCH` nodes for the same IOC and source
are all included with their own evidence references.

---

## 10. Logical Node Identity vs. Chain-Version Membership vs. Database Row Identity

Revision 1 incorporated `evidence_version` into the `node_canonical_id`, causing the
same underlying event to receive a different identity every time `evidence_version`
changes. Revision 2 separates three distinct concepts:

### 10.1 Logical Node Identity (`logical_node_id`)

Represents the underlying evidence-backed object, independent of any chain version.

```
logical_node_id = sha256("<node_type>|<primary_evidence_id>")[:64]
```

Where `primary_evidence_id` is:
- `EVENT` → `str(normalized_event_id)`
- `CTI_MATCH` → `str(threat_intel_result_id)`
- `ENTITY` → `entity_canonical_id`
- `TECHNIQUE` → `<mitre_technique_id>:<str(incident_id)>`

A given `NormalizedEvent` always produces the same `logical_node_id` regardless of
which chain version is being built. This enables chain-version comparison and
late-evidence diffing.

### 10.2 Chain-Version Membership (`chain_version_id`)

Identifies which specific graph snapshot (reconstruction run) a node belongs to.
The combination `(chain_version_id, logical_node_id)` uniquely identifies a node
within a graph version.

### 10.3 Database Row Identity (`id`)

A UUID surrogate primary key for the specific row in `attack_chain_nodes`.
May differ between chain versions even for the same logical node.

### 10.4 Determinism

The `logical_node_id` is deterministic: same underlying evidence → same ID.
The `chain_canonical_id` is a deterministic hash of all logical node IDs in a
snapshot:

```
chain_canonical_id = sha256(
    "<incident_id>|<evidence_version>|<sorted logical_node_ids>"
)[:64]
```

Re-running reconstruction with the same `(incident_id, evidence_version)` and the
same eligible evidence set always produces the same `chain_canonical_id`.

---

## 11. Node Model

### 11.1 Node Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Database row PK (surrogate) |
| `chain_version_id` | UUID FK | Parent chain version |
| `logical_node_id` | String(128) | Deterministic logical identity (§10.1) |
| `node_type` | Enum | `EVENT` / `CTI_MATCH` / `ENTITY` / `TECHNIQUE` |
| `normalized_event_id` | UUID FK | nullable — source event |
| `threat_intel_result_id` | UUID FK | nullable — source CTI record |
| `entity_canonical_id` | String(256) | nullable |
| `mitre_technique_id` | String(32) | nullable |
| `mitre_tactic_id` | String(32) | nullable |
| `mitre_technique_name` | String(255) | nullable — resolved from bundled catalog |
| `mitre_tactic_name` | String(128) | nullable — resolved from bundled catalog |
| `mitre_mapping_type` | Enum | `DIRECT_MAPPING` / `INFERRED_MAPPING` / `UNKNOWN` |
| `event_timestamp` | DateTime | canonical occurrence time |
| `timestamp_source` | String(32) | `event_timestamp` / `wazuh_timestamp` / `ingestion_fallback` |
| `provenance` | Enum | `OBSERVED` / `INFERRED` / `UNKNOWN` |
| `evidence_strength` | Float | deterministic ordinal score in [0.0, 1.0] (see §13) |
| `sequence_index` | Integer | 0-based chronological position within EVENT nodes |
| `evidence_refs` | JSONB | list of `{"table": str, "id": str}` |
| `evidence_snapshot` | JSONB | denormalized key fields for auditability |
| `evidence_deleted` | Boolean | True if a referenced evidence row was subsequently deleted |
| `created_at` | DateTime | wall-clock row generation time |

### 11.2 Node Types and Provenance

| Type | Created When | Provenance |
|------|-------------|-----------|
| `EVENT` | One per `NormalizedEvent` in the incident | `OBSERVED` — the event record is directly present in the evidence |
| `CTI_MATCH` | One per `ThreatIntelResult` with `matched=True` (all historical) | `OBSERVED` — the CTI result record is directly present |
| `ENTITY` | One per unique `entity_canonical_id` | `OBSERVED` — extracted directly from non-null schema fields |
| `TECHNIQUE` | One per unique `(mitre_technique_id, incident_id)` | `DIRECT_MAPPING` if from `NormalizedEvent.mitre_technique_ids`; `INFERRED_MAPPING` if from rule only |

---

## 12. Edge Model

An `AttackChainEdge` is a directed relationship between two nodes. Every edge has an
explicit creation condition, required evidence, and provenance declaration.

### 12.1 Edge Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Database row PK (surrogate) |
| `chain_version_id` | UUID FK | Parent chain version |
| `logical_edge_id` | String(128) | Deterministic logical identity (§12.2) |
| `src_node_logical_id` | String(128) | `logical_node_id` of source node |
| `dst_node_logical_id` | String(128) | `logical_node_id` of destination node |
| `src_node_id` | UUID FK | Database row FK of source node |
| `dst_node_id` | UUID FK | Database row FK of destination node |
| `edge_type` | Enum | See §12.3 |
| `provenance` | Enum | `OBSERVED` / `INFERRED` / `UNKNOWN` |
| `implies_causality` | Boolean | Always `False` in Phase 7 |
| `evidence_strength` | Float | deterministic ordinal score in [0.0, 1.0] |
| `evidence_refs` | JSONB | list of `{"table": str, "id": str}` |
| `created_at` | DateTime | wall-clock |

### 12.2 Deterministic `logical_edge_id`

```
logical_edge_id = sha256(
    "<edge_type>|<src_node_logical_id>|<dst_node_logical_id>"
)[:64]
```

Note: unlike Revision 1, `evidence_version` is NOT incorporated into the edge logical
ID. The same evidence relationship between the same two logical nodes always has the
same logical edge ID, enabling cross-version comparison.

### 12.3 Authoritative Phase 7 Edge Type Table

**Total: 7 edge types. TACTIC_PROGRESSION does not exist. PROCESS_RELATION does not exist.**

---

**`CHRONOLOGICAL_NEXT`** *(replaces Revision 1 `TEMPORAL_NEXT`)*

| Attribute | Value |
|-----------|-------|
| Creation condition | EVENT node E_i is the chronologically preceding event to EVENT node E_{i+1} in the ordered incident timeline |
| Required evidence | Both events in `incident_events`; both have `event_timestamp` (or valid fallback) |
| Provenance | **INFERRED** — chronological adjacency is deterministically derived from timestamps; it does NOT observe causality |
| Implies causality | **False** |
| Evidence refs | `incident_events` rows for both events |
| Limit | One per consecutive pair (no combinatorial expansion) |

**Design decision (Revision 2 correction):** `CHRONOLOGICAL_NEXT` is INFERRED because:
- The occurrence of each event is observed (`EVENT` nodes are OBSERVED)
- The chronological ordering is deterministic (based on timestamps)
- The adjacency relationship is **derived** by the reconstruction algorithm, not
  directly recorded in any evidence record
- Adjacency does NOT imply causality

---

**`SAME_ENTITY`**

| Attribute | Value |
|-----------|-------|
| Creation condition | Two EVENT nodes share the same `entity_canonical_id` |
| Required evidence | Entity extraction from both event records |
| Provenance | **OBSERVED** — entity field values are directly in the evidence records |
| Implies causality | **False** |
| Evidence refs | Both `normalized_events` rows |
| Limit | max 50 pairs per entity_canonical_id |

---

**`CORRELATED_WITH`** *(Revision 2 correction: reclassified from OBSERVED to INFERRED)*

| Attribute | Value |
|-----------|-------|
| Creation condition | Two events share the same non-null `correlation_rule_id` in `incident_events` |
| Required evidence | `IncidentEvent.correlation_rule_id` non-null and equal for both events; `CorrelationRule` record exists |
| Provenance | **INFERRED** — the correlation rule membership is an analytical product of the Phase 3 engine; while the underlying event records are observed, the relationship between them is a derived conclusion |
| Implies causality | **False** |
| Evidence refs | Both `incident_events` rows + `correlation_rules` row |
| Limit | max 100 pairs per rule group |

**Design decision (Revision 2 correction):** The facts observed are:
(a) Event A is a member of the incident.
(b) Event B is a member of the incident.
(c) Both have the same `correlation_rule_id`.
The **relationship** between A and B — that they are analytically grouped — is produced
by the correlation engine and must be classified as INFERRED.

---

**`IOC_MATCH`**

| Attribute | Value |
|-----------|-------|
| Creation condition | An EVENT or ENTITY node's canonical IP/domain/URL/hash value equals a CTI_MATCH node's `ioc_value` |
| Required evidence | `ThreatIntelResult.matched=True`; matching `ioc_value` field in event |
| Provenance | **OBSERVED** — both the event field and the CTI result are directly in the evidence |
| Implies causality | **False** |
| Evidence refs | `normalized_events` row + `threat_intel_results` row |
| Limit | No hard limit per edge; limits on CTI_MATCH nodes (one per ThreatIntelResult) |

---

**`TECHNIQUE_SUPPORT`**

| Attribute | Value |
|-----------|-------|
| Creation condition | An EVENT node carries a MITRE technique ID in `mitre_technique_ids` |
| Required evidence | `NormalizedEvent.mitre_technique_ids` non-empty (DIRECT_MAPPING); or `CorrelationRule.mitre_technique_id` when event has no technique IDs (INFERRED_MAPPING) |
| Provenance | **OBSERVED** if technique comes from `NormalizedEvent.mitre_technique_ids` (direct); **INFERRED** if technique is inherited from `CorrelationRule.mitre_technique_id` |
| Implies causality | **False** |
| Evidence refs | `normalized_events` row; optionally `correlation_rules` row |
| Limit | No hard limit |

---

**`SAME_AGENT`**

| Attribute | Value |
|-----------|-------|
| Creation condition | Two HOST or PROCESS entities share the same `agent_id` value |
| Required evidence | `NormalizedEvent.agent_id` equality across two events |
| Provenance | **OBSERVED** — `agent_id` is a directly recorded field |
| Implies causality | **False** |
| Evidence refs | Both `normalized_events` rows |
| Limit | max 50 pairs |

---

**`NETWORK_RELATION`**

| Attribute | Value |
|-----------|-------|
| Creation condition | EVENT node E_i has `dst_ip` equal to `src_ip` of EVENT node E_j, both in the same incident |
| Required evidence | `NormalizedEvent.dst_ip` of E_i equals `NormalizedEvent.src_ip` of E_j |
| Provenance | **INFERRED** — while the IP field values are observed, the directional network relationship between the two events is derived by the algorithm |
| Implies causality | **False** — this indicates a potential network path, not confirmed communication or attacker action |
| Evidence refs | Both `normalized_events` rows |
| Limit | max 200 NETWORK_RELATION edges per chain |

---

### 12.4 Explicitly Excluded Edge Types

| Type | Status | Reason |
|------|--------|--------|
| `TACTIC_PROGRESSION` | **REMOVED** | ATT&CK tactic taxonomy must not create causal or temporal graph edges. Tactic IDs are metadata on TECHNIQUE nodes, not inference triggers. |
| `PROCESS_RELATION` | **REMOVED** | String containment of `process_name` in `process_command_line` is insufficient evidence for process lineage. No parent-child process telemetry exists in the current schema. |

---

## 13. Evidence Strength

> **Terminology note:** Revision 1 used the term "confidence." Revision 2 uses
> **`evidence_strength`** throughout Phase 7.

### 13.1 Non-Probabilistic Declaration

`evidence_strength` is an **ordinal deterministic engineering score** in [0.0, 1.0].

It is:
- **Not** a probability
- **Not** a calibrated statistical estimate
- **Not** a claim that a value of 0.6 means 60% likelihood
- A design parameter representing relative evidence quality and provenance tier

These weights are engineering heuristics chosen for tractability and explainability.
They are subject to empirical validation in future research.

The database field is named `evidence_strength`. The API response field is named
`evidence_strength`. The existing `attack_chains` stub column (`confidence`) is
retained as-is to avoid modifying the frozen Phase 0 schema; its docstring is updated
to state: "ordinal deterministic evidence-strength score, not a probability."

### 13.2 Node Evidence-Strength Formula

```
node_evidence_strength =
    base_tier(provenance)
  × source_quality(source_type)
  × support_discount(corroborating_count)
```

Clipped to [0.0, 1.0] after multiplication.

**base_tier:**

| Provenance | Value | Rationale |
|-----------|-------|-----------|
| `OBSERVED` | 1.0 | Directly extracted from evidence records |
| `INFERRED` | 0.6 | Derived via deterministic algorithm |
| `UNKNOWN` | 0.0 | Insufficient or deleted evidence |

**source_quality:**

| Source Type | Value | Rationale |
|------------|-------|-----------|
| Direct Wazuh event | 1.0 | Raw telemetry |
| CTI matched | 0.9 | CTI-confirmed IOC |
| CTI unmatched | 0.5 | CTI lookup with no match |
| Rule-inferred technique | 0.7 | Inherited from correlation rule |

**support_discount:**

| Corroborating event count | Multiplier | Rationale |
|--------------------------|-----------|-----------|
| n >= 3 | 1.0 | Three or more supporting events — no discount |
| n = 2 | 0.9 | Two events |
| n = 1 | 0.8 | Single event — single-source discount |

### 13.3 Edge Evidence-Strength Formula

```
edge_evidence_strength =
    min(src_node.evidence_strength, dst_node.evidence_strength)
  × edge_type_weight
```

Clipped to [0.0, 1.0].

**edge_type_weight:**

| Edge Type | Weight | Rationale |
|-----------|--------|-----------|
| `SAME_ENTITY` | 1.00 | Entity equality is directly extractable |
| `SAME_AGENT` | 1.00 | Agent ID equality is directly extractable |
| `IOC_MATCH` | 0.95 | CTI match is a strong evidence relationship |
| `CORRELATED_WITH` | 0.85 | Analytical relationship via correlation engine |
| `TECHNIQUE_SUPPORT` | 0.90 | Technique directly on event vs. rule-inherited (formula applies) |
| `CHRONOLOGICAL_NEXT` | 0.70 | Chronological adjacency only; no causal claim |
| `NETWORK_RELATION` | 0.75 | IP field equality; directional network path inferred |

### 13.4 Evidence-Strength Invariants

- evidence_strength ∈ [0.0, 1.0] — enforced by DB CHECK constraint and unit tests
- Evidence-strength is independent of Phase 5 risk_score and Phase 6 ml_score
- Evidence-strength must not be interpreted as a probability
- The formula is deterministic: same inputs → same output

---

## 14. ATT&CK Catalog and Technique Representation

### 14.1 Catalog Design

Phase 7 bundles a static ATT&CK technique/tactic name lookup table as
`attack_chain/data/attck_catalog.json`. This enables:
- Resolving technique IDs (e.g., `T1059`) to names (`Command and Scripting Interpreter`)
- Resolving tactic IDs (e.g., `TA0002`) to names (`Execution`)
- Recording the catalog version in every chain version record

**The catalog does NOT encode tactic ordering as a graph inference mechanism.**
The static tactic ordering list from Revision 1 is **removed**.

### 14.2 Catalog Schema

Each catalog entry:
```json
{
  "id": "T1059",
  "name": "Command and Scripting Interpreter",
  "tactic_ids": ["TA0002"],
  "tactic_names": ["Execution"],
  "type": "technique"
}
```

Unknown IDs → `name = null`, reconstruction warning added if a technique/tactic ID
appears in the evidence but is not in the catalog.

### 14.3 MITRE Mapping Types

| Type | Source | Semantics |
|------|--------|-----------|
| `DIRECT_MAPPING` | `NormalizedEvent.mitre_technique_ids` non-empty | Wazuh rule or normalizer explicitly mapped this event |
| `INFERRED_MAPPING` | `CorrelationRule.mitre_technique_id` non-null and event has no technique IDs | Technique inherited from correlation rule |
| `UNKNOWN` | No technique data available | Technique node is not generated |

### 14.4 Technique Deduplication

Multiple events supporting the same `mitre_technique_id` produce **one** TECHNIQUE node
per technique per incident. All supporting EVENT nodes emit `TECHNIQUE_SUPPORT` edges
to that node.

### 14.5 Tactic as Metadata Only

Tactic IDs on TECHNIQUE nodes are **descriptive metadata**. They may be:
- Displayed in the API response
- Used to group or filter nodes in the timeline
- Resolved to human-readable names via the catalog

They must NOT create causal or temporal edges between nodes.
No TACTIC_PROGRESSION edge exists in Phase 7.

---

## 15. Reconstruction Algorithm

Deterministic for a fixed `(incident_id, evidence_version)`. Re-running with the same
eligible evidence set produces an identical graph.

```
function reconstruct(incident_id, evidence_version):

  STEP 1 — VALIDATE AND LOCK SNAPSHOT
    a. Load Incident; verify evidence_version matches parameter
    b. Record T_reconstruction = now() [wall-clock, audit only]

  STEP 2 — LOAD EVIDENCE SNAPSHOT
    a. Load all IncidentEvent records for incident_id
    b. Load all NormalizedEvent records via IncidentEvent join
    c. Load ALL ThreatIntelResult records where:
         (incident_id = X OR normalized_event_id IN event_ids)
         AND queried_at <= T_reconstruction
       Preserve all historical records — do NOT deduplicate
    d. Load CorrelationRule records referenced by IncidentEvent records

  STEP 3 — COMPUTE chain_evidence_as_of
    chain_evidence_as_of = max(
        max(event.event_timestamp) for all events,
        max(cti.queried_at) for all eligible CTI records
    )
    [See §8.1. Does NOT depend on Phase 5 execution.]

  STEP 4 — ORDER EVENTS
    Sort NormalizedEvents by (event_timestamp ASC, id ASC)
    Assign sequence_index 0, 1, 2, ..., N-1
    Resolve timestamp fallbacks per §8.4

  STEP 5 — CANONICALIZE ENTITIES
    For each NormalizedEvent: extract all non-null entity fields
    Apply canonicalization rules (§9.2)
    Build index: entity_canonical_id -> set of normalized_event_ids

  STEP 6 — GENERATE EVENT NODES [provenance = OBSERVED]
    One EVENT node per NormalizedEvent
    Compute logical_node_id = sha256("EVENT|" + str(ne.id))[:64]
    Capture timestamp_source per §8.4
    Denormalize key fields to evidence_snapshot JSONB

  STEP 7 — GENERATE CTI_MATCH NODES [provenance = OBSERVED]
    One CTI_MATCH node per ThreatIntelResult where matched=True
    Preserve ALL matched records (multiple may exist per IOC+source)
    Compute logical_node_id = sha256("CTI_MATCH|" + str(ti.id))[:64]
    Detect verdict changes; add reconstruction_warnings entries

  STEP 8 — GENERATE ENTITY NODES [provenance = OBSERVED]
    One ENTITY node per unique entity_canonical_id
    Compute logical_node_id = sha256("ENTITY|" + entity_canonical_id)[:64]

  STEP 9 — GENERATE TECHNIQUE NODES
    One per unique (mitre_technique_id, incident_id)
    Set mitre_mapping_type per §14.3
    Compute logical_node_id = sha256("TECHNIQUE|" + technique_id + "|" + str(incident_id))[:64]
    Resolve technique/tactic names from bundled catalog

  STEP 10 — GENERATE CHRONOLOGICAL_NEXT EDGES [provenance = INFERRED]
    For each consecutive pair (event_i, event_{i+1}) in the ordered EVENT list
    [Note: chronological adjacency; does NOT imply causality]

  STEP 11 — GENERATE SAME_ENTITY EDGES [provenance = OBSERVED]
    For each entity_canonical_id with >= 2 associated EVENT nodes
    Create edges between all pairs; limit 50 pairs per entity

  STEP 12 — GENERATE CORRELATED_WITH EDGES [provenance = INFERRED]
    Group IncidentEvent by correlation_rule_id (non-null only)
    For each rule group with >= 2 events: create edges between all pairs
    Limit: max 100 pairs per rule group
    [Note: event membership is observed; the relationship is analytically derived]

  STEP 13 — GENERATE IOC_MATCH EDGES [provenance = OBSERVED]
    For each CTI_MATCH node: find ENTITY nodes whose entity_canonical_id
    matches ioc_value; create IOC_MATCH edges

  STEP 14 — GENERATE TECHNIQUE_SUPPORT EDGES
    For each EVENT node with mitre_technique_ids: create TECHNIQUE_SUPPORT
    edges to corresponding TECHNIQUE nodes
    [provenance = OBSERVED for DIRECT_MAPPING; INFERRED for INFERRED_MAPPING]

  STEP 15 — GENERATE SAME_AGENT EDGES [provenance = OBSERVED]
    For each agent_id with >= 2 associated entity_canonical_ids:
    create SAME_AGENT edges; limit 50 pairs

  STEP 16 — GENERATE NETWORK_RELATION EDGES [provenance = INFERRED]
    Build index: ip_address -> set of EVENT logical_node_ids
    For pairs (E_i, E_j) where E_i.dst_ip = E_j.src_ip: create NETWORK_RELATION edge
    Limit: max 200 NETWORK_RELATION edges per chain

  STEP 17 — COMPUTE EVIDENCE-STRENGTH
    For each node: evidence_strength per §13.2
    For each edge: evidence_strength per §13.3

  STEP 18 — APPLY SIZE LIMITS (see §18.7)
    Truncate and record reconstruction_warnings for each limit exceeded

  STEP 19 — ASSIGN CHAIN VERSION
    chain_canonical_id = sha256(
        "<incident_id>|<evidence_version>|<sorted logical_node_ids>"
    )[:64]
    chain_version = next sequential integer per incident

  STEP 20 — PERSIST
    Write AttackChainVersion record (with chain_evidence_as_of)
    Upsert AttackChainNode records (by: chain_version_id + logical_node_id)
    Upsert AttackChainEdge records (by: chain_version_id + logical_edge_id)
    Update attack_chains stub summary (backward compatibility)
    Write AuditLog record (action="attack_chain.reconstruct")

  STEP 21 — RETURN ChainResult
```

---

## 16. Evidence Provenance (Corrected Semantics)

### 16.1 Provenance Definitions

| Provenance | Definition | Examples |
|-----------|-----------|---------|
| `OBSERVED` | Directly present in and extracted from an evidence record. The claim is supported by a concrete row in the database. | NormalizedEvent exists in incident; CTI result exists with matched=True; entity field is non-null in event record; DIRECT_MAPPING technique ID is on the event |
| `INFERRED` | Derived via a deterministic algorithm from observed evidence. The underlying inputs are observed but the relationship or conclusion is produced analytically. | CHRONOLOGICAL_NEXT (adjacency from timestamps); CORRELATED_WITH (analytical grouping); NETWORK_RELATION (IP-address matching); INFERRED_MAPPING technique (inherited from rule); TACTIC node when technique comes from rule only |
| `UNKNOWN` | Evidence is unavailable, orphaned, or insufficient to classify the node. | Evidence row deleted; NULL timestamps without fallback; insufficient fields |

### 16.2 Critical Distinction

OBSERVED means: the evidence record directly asserts the fact.
INFERRED means: the fact is computed from evidence; the computation is transparent and deterministic, but the conclusion is not directly recorded anywhere.

"CORRELATED_WITH is INFERRED" because: the correlation engine's analytical grouping of
two events is a derived conclusion, even though both event records are themselves
OBSERVED. The relationship between the events — not the events themselves — is inferred.

### 16.3 Provenance Chain

```
AttackChainNode / AttackChainEdge
  └── provenance: OBSERVED | INFERRED | UNKNOWN
  └── evidence_refs: [{"table": "normalized_events", "id": "<uuid>"},
                       {"table": "threat_intel_results", "id": "<uuid>"}]
      └── NormalizedEvent
            └── raw_alert_id -> RawAlert.raw_json  [forensic reference; not returned in API]
      └── ThreatIntelResult
            └── raw_response_text  [forensic reference; not returned in API]
```

### 16.4 Orphaned Evidence References

If a referenced evidence row is deleted after chain construction:
- The node/edge row is preserved; `evidence_deleted = True`
- `provenance` is downgraded to `UNKNOWN`
- A reconstruction warning is recorded:
  `{"type": "orphaned_evidence", "table": "...", "id": "..."}`
- The chain is NOT automatically invalidated — it is a historical snapshot

---

## 17. Evidence Versioning

### 17.1 Chain Version Record Fields

| Field | Type | Meaning |
|-------|------|---------|
| `id` | UUID | PK |
| `incident_id` | UUID FK | |
| `chain_canonical_id` | String(128) | deterministic hash over sorted logical node IDs |
| `chain_version` | Integer | per-incident sequential counter |
| `evidence_version` | BigInteger | from `Incident.evidence_version` at reconstruction time |
| `chain_evidence_as_of` | DateTime | Phase 7-derived evidence horizon (see §8.1) |
| `generated_at` | DateTime | wall-clock when reconstruction ran (AUDIT ONLY) |
| `node_count` | Integer | |
| `edge_count` | Integer | |
| `technique_count` | Integer | |
| `highest_tactic` | String | tactic with most events (descriptive; not an ordering claim) |
| `reconstruction_warnings` | JSONB | non-fatal warnings list |
| `attck_catalog_version` | String | e.g. `"14.1"` |

**`chain_evidence_as_of` is the authoritative Phase 7 evidence horizon.**
`generated_at` is audit metadata only — it must NOT determine evidence freshness.

### 17.2 Staleness Check

```
is_stale = (incident.evidence_version > latest_chain_version.evidence_version)
```

### 17.3 Update Triggers

Reconstruction is triggered when:
1. An explicit `POST /attack-chain/incident/{id}/reconstruct` is made
2. A caller detects `is_stale = True` and requests reconstruction

---

## 18. API Design

All endpoints are **additive**. No existing endpoint is modified.

### 18.1 `GET /attack-chain/incident/{incident_id}`

Returns the current (latest) reconstructed chain.

**Response:**
```json
{
  "incident_id": "uuid",
  "chain_version": 3,
  "evidence_version": 7,
  "chain_evidence_as_of": "ISO-8601",
  "generated_at": "ISO-8601 [audit metadata only]",
  "is_stale": false,
  "node_count": 12,
  "edge_count": 18,
  "technique_count": 3,
  "highest_tactic": "TA0006 [descriptive metadata]",
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

Returns a specific chain version by UUID.

### 18.4 `POST /attack-chain/incident/{incident_id}/reconstruct`

Triggers synchronous reconstruction.

- Reads current `Incident.evidence_version`.
- If `evidence_version` has not changed since last reconstruction, returns existing
  chain with `{"reconstructed": false, "message": "chain is current"}`.
- Idempotent: safe to call multiple times.
- Timeout: 30 seconds.

### 18.5 `GET /attack-chain/incident/{incident_id}/timeline`

Returns only ordered EVENT nodes (chronological; no full graph).

### 18.6 AttackChainNodeResponse Schema

```json
{
  "node_id": "uuid",
  "logical_node_id": "64-char-hex",
  "node_type": "EVENT|CTI_MATCH|ENTITY|TECHNIQUE",
  "provenance": "OBSERVED|INFERRED|UNKNOWN",
  "evidence_strength": 0.80,
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
in API responses. Indicated by `forensic_available: true`.

### 18.7 AttackChainEdgeResponse Schema

```json
{
  "edge_id": "uuid",
  "logical_edge_id": "64-char-hex",
  "edge_type": "CHRONOLOGICAL_NEXT",
  "src_node_logical_id": "64-char-hex",
  "dst_node_logical_id": "64-char-hex",
  "provenance": "INFERRED",
  "implies_causality": false,
  "evidence_strength": 0.56,
  "evidence_refs": [{"table": "incident_events", "id": "uuid"}]
}
```

### 18.8 Chain Size Limits

| Limit | Value |
|-------|-------|
| Max EVENT nodes per chain | 500 |
| Max SAME_ENTITY edge pairs per entity | 50 |
| Max CORRELATED_WITH pairs per rule group | 100 |
| Max NETWORK_RELATION edges per chain | 200 |
| Max SAME_AGENT edge pairs | 50 |
| Max total edges per chain | 2000 |
| Reconstruction timeout | 30 seconds |

Limits exceeded → truncation + reconstruction_warning entry:
`{"type": "limit_exceeded", "limit": "<name>", "actual": <count>}`

---

## 19. Storage Design

### 19.1 New Tables

Three new tables. The existing `attack_chains` stub is reused as a materialized summary.

### 19.2 `attack_chain_versions` DDL

```sql
CREATE TABLE attack_chain_versions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id             UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    chain_canonical_id      VARCHAR(128) NOT NULL,
    chain_version           INTEGER NOT NULL,
    evidence_version        BIGINT NOT NULL,
    chain_evidence_as_of    TIMESTAMPTZ,      -- Phase 7-derived; NOT from Phase 5
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT now(), -- audit only
    node_count              INTEGER NOT NULL DEFAULT 0,
    edge_count              INTEGER NOT NULL DEFAULT 0,
    technique_count         INTEGER NOT NULL DEFAULT 0,
    highest_tactic          VARCHAR(32),      -- descriptive metadata
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
    logical_node_id         VARCHAR(128) NOT NULL,  -- deterministic logical identity
    node_type               VARCHAR(32) NOT NULL,
    normalized_event_id     UUID REFERENCES normalized_events(id) ON DELETE SET NULL,
    threat_intel_result_id  UUID REFERENCES threat_intel_results(id) ON DELETE SET NULL,
    entity_canonical_id     VARCHAR(256),
    mitre_technique_id      VARCHAR(32),
    mitre_tactic_id         VARCHAR(32),
    mitre_technique_name    VARCHAR(255),
    mitre_tactic_name       VARCHAR(128),
    mitre_mapping_type      VARCHAR(32),
    event_timestamp         TIMESTAMPTZ,
    timestamp_source        VARCHAR(32),
    provenance              VARCHAR(16) NOT NULL,
    evidence_strength       FLOAT NOT NULL CHECK (evidence_strength BETWEEN 0.0 AND 1.0),
    sequence_index          INTEGER,
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    evidence_snapshot       JSONB NOT NULL DEFAULT '{}',
    evidence_deleted        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Logical node identity within a chain version
CREATE UNIQUE INDEX uq_acn_chain_logical
    ON attack_chain_nodes(chain_version_id, logical_node_id);
CREATE INDEX ix_acn_event ON attack_chain_nodes(normalized_event_id);
CREATE INDEX ix_acn_chain_type ON attack_chain_nodes(chain_version_id, node_type);
CREATE INDEX ix_acn_entity ON attack_chain_nodes(entity_canonical_id);
```

**ON DELETE SET NULL on `normalized_event_id` and `threat_intel_result_id`:**
If a source evidence row is deleted, the node row is preserved with the FK set to NULL
and `evidence_deleted = True`. Historical chain versions remain auditable.

### 19.4 `attack_chain_edges` DDL

```sql
CREATE TABLE attack_chain_edges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_version_id        UUID NOT NULL REFERENCES attack_chain_versions(id) ON DELETE CASCADE,
    logical_edge_id         VARCHAR(128) NOT NULL,  -- deterministic logical identity
    src_node_logical_id     VARCHAR(128) NOT NULL,
    dst_node_logical_id     VARCHAR(128) NOT NULL,
    src_node_id             UUID NOT NULL REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    dst_node_id             UUID NOT NULL REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    edge_type               VARCHAR(32) NOT NULL,
    provenance              VARCHAR(16) NOT NULL,
    implies_causality       BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_strength       FLOAT NOT NULL CHECK (evidence_strength BETWEEN 0.0 AND 1.0),
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_ace_chain_logical
    ON attack_chain_edges(chain_version_id, logical_edge_id);
CREATE INDEX ix_ace_src ON attack_chain_edges(src_node_id);
CREATE INDEX ix_ace_dst ON attack_chain_edges(dst_node_id);
CREATE INDEX ix_ace_chain_type ON attack_chain_edges(chain_version_id, edge_type);
```

### 19.5 Existing `attack_chains` Stub Updates

The existing `attack_chains` table (Phase 0) receives additive columns only:
- `chain_version_id` UUID FK → `attack_chain_versions(id)` ON DELETE SET NULL
- `evidence_version` BIGINT (copy of latest chain_version.evidence_version)

No existing columns are dropped or modified. The stub continues to serve as a
one-row-per-incident summary for backward-compatible reads.

### 19.6 Migration Strategy

- One new Alembic DDL migration: `<timestamp>_phase_7_attack_chain_schema.py`
- DDL-only; no data migration
- No columns in Phase 0–6 tables are dropped or modified
- `attack_chains` receives additive columns only

---

## 20. Security

| Control | Implementation |
|---------|---------------|
| Authorization | `X-Admin-Key` (Phase 0 mechanism); no new auth in Phase 7 |
| Input validation | `incident_id` must be valid UUID; reject with HTTP 422 |
| Evidence reference validation | Referenced UUIDs validated against DB before reconstruction |
| Resource limits | Hard limits per §18.8 |
| Graph injection protection | Nodes/edges generated from verified DB records only; no external graph input |
| Canonical ID protection | SHA-256 over sanitized internal values; user input does not flow into logical IDs |
| Sensitive data in API | `raw_json` and `raw_response_text` omitted from API; indicated by `forensic_available: true` |
| Audit trail | Every reconstruction → AuditLog row (`action="attack_chain.reconstruct"`) |
| SQL injection | SQLAlchemy ORM parameterized queries exclusively |

---

## 21. Idempotency

For a fixed `(incident_id, evidence_version)` and the same eligible evidence set:

- Every `logical_node_id` is identical
- Every `logical_edge_id` is identical
- `chain_canonical_id` is identical
- All `evidence_strength` values are identical
- Upsert on `(chain_version_id, logical_node_id)` prevents duplicate node rows
- Upsert on `(chain_version_id, logical_edge_id)` prevents duplicate edge rows
- Concurrent reconstruction calls are safe; the second is a no-op

`generated_at` (wall-clock) will differ between runs but does not affect logical
graph identity.

---

## 22. Conflict Handling

| Conflict | Handling |
|---------|---------|
| Equal `event_timestamp` | Tiebreak by `normalized_event_id` byte order (deterministic) |
| Two hostnames for same `agent_id` | Both HOST entities created; `SAME_AGENT` edge links them |
| Multiple CTI records for same IOC+source | ALL preserved as separate CTI_MATCH nodes; verdict changes reported in reconstruction_warnings |
| Same IOC in different incidents | Each incident has its own CTI_MATCH nodes; no cross-incident contamination |
| Same technique ID from multiple events | One TECHNIQUE node; all supporting events emit `TECHNIQUE_SUPPORT` edges |
| Conflicting MITRE mappings (direct vs. rule-inferred) | Both included; `DIRECT_MAPPING` takes precedence for `mitre_mapping_type` on the TECHNIQUE node |
| NULL `event_timestamp` | Fallback per §8.4; node created with warning |
| Evidence deleted after construction | Node preserved with `evidence_deleted=True`; provenance → UNKNOWN; warning added |
| Contradictory CTI verdicts (historical) | Both CTI_MATCH nodes preserved; verdict_changed warning added |

---

## 23. Late-Arriving Evidence

1. Correlation engine increments `Incident.evidence_version`.
2. Chain is marked stale: `incident.evidence_version > chain_version.evidence_version`.
3. Next reconstruction loads the full current evidence set including the late event.
4. Late event positioned by `event_timestamp` (not `added_at` or `created_at`).
5. `IncidentEvent.added_at` used only to compute and report ingestion lag:
   `{"type": "late_event", "event_id": "...", "lag_seconds": <int>}`
6. Previous chain version preserved in `attack_chain_versions` for historical comparison.
7. All edges recomputed from scratch (full reconstruction, not incremental).

---

## 24. Failure Modes

| Failure | Behavior |
|---------|---------|
| Incident not found | HTTP 404 |
| No events for incident | Empty chain, `node_count=0`, warning `{"type": "no_events"}` |
| All events have NULL timestamps | Reconstruct using fallback timestamps; warn per event |
| ATT&CK catalog bundle missing | Reconstruct proceeds; technique/tactic names = null; warning logged |
| Chain stale at read time | Return chain with `is_stale=true`; do not auto-reconstruct |
| Reconstruction timeout (>30s) | HTTP 503; partial state rolled back |
| Circular edge detected (defensive) | Edge dropped; warning `{"type": "circular_edge_dropped"}` |
| DB write failure | Reconstruction discarded; previous version preserved; HTTP 500 |
| Duplicate `chain_version` race (concurrent callers) | UNIQUE constraint violation → retry next sequential version (max 3 retries) |

---

## 25. Performance Methodology

### 25.1 Design Targets (not measured results)

| Metric | Target | Method |
|--------|--------|--------|
| Reconstruction latency (50 events) | < 2 s | pytest-benchmark |
| Reconstruction latency (200 events) | < 10 s | pytest-benchmark |
| Reconstruction latency (500 events) | < 30 s | pytest-benchmark |
| Memory (500-event chain) | < 256 MB | memory_profiler |

> No target is claimed as achieved until the implementation is built and benchmarked.
> Actual results must be reported post-implementation.

### 25.2 Benchmark Dataset

Controlled synthetic datasets (not from production Wazuh database):
- 50 events, 5 CTI matches — small chain
- 200 events, 20 CTI matches — medium chain
- 500 events, 50 CTI matches — large chain at node limit

Generated with deterministic seeds for reproducibility.

---

## 26. Testing Strategy

All Phase 0–6 tests (243 passed, 2 skipped) must remain green. Phase 7 adds
`tests/attack_chain/`.

### 26.1 Unit Tests

| Test | What it verifies |
|------|-----------------|
| `test_entity_canonicalization_all_types` | All 11 entity types; null fields excluded |
| `test_logical_node_id_determinism` | Same evidence → same logical_node_id |
| `test_logical_edge_id_determinism` | Same evidence → same logical_edge_id |
| `test_chain_version_membership_separate_from_logical_id` | Different evidence_version → same logical_node_id |
| `test_temporal_ordering_asc` | Events ordered by event_timestamp ASC, id tiebreak |
| `test_equal_timestamp_tiebreak` | Equal timestamps: id byte-order tiebreak is stable |
| `test_timestamp_fallback_tier2` | NULL event_timestamp → wazuh_timestamp |
| `test_timestamp_fallback_tier3` | NULL event_timestamp AND wazuh_timestamp → ingestion_fallback |
| `test_cti_history_preserved_no_dedup` | Multiple CTI records for same IOC+source: all nodes created |
| `test_cti_verdict_change_warning` | Verdict change between historical records → reconstruction_warning |
| `test_current_cti_interpretation` | Latest eligible record used for current-state view |
| `test_technique_deduplication` | Same technique from two events → one TECHNIQUE node |
| `test_direct_vs_inferred_mitre_mapping` | DIRECT_MAPPING from event; INFERRED_MAPPING from rule |
| `test_provenance_event_observed` | EVENT nodes always OBSERVED |
| `test_provenance_cti_match_observed` | CTI_MATCH nodes always OBSERVED |
| `test_provenance_entity_observed` | ENTITY nodes always OBSERVED |
| `test_provenance_chronological_next_inferred` | CHRONOLOGICAL_NEXT always INFERRED |
| `test_provenance_correlated_with_inferred` | CORRELATED_WITH always INFERRED |
| `test_provenance_network_relation_inferred` | NETWORK_RELATION always INFERRED |
| `test_no_tactic_progression_edges` | No TACTIC_PROGRESSION edge type created under any input |
| `test_no_process_relation_edges` | No PROCESS_RELATION edge type created under any input |
| `test_implies_causality_always_false` | `implies_causality = False` on all edge types |
| `test_evidence_strength_formula_node` | Node values match §13.2 formula |
| `test_evidence_strength_formula_edge` | Edge values match §13.3 formula |
| `test_evidence_strength_bounds` | evidence_strength in [0.0, 1.0] for all nodes and edges |
| `test_evidence_strength_not_probability` | Formula produces deterministic ordinal scores; no statistical claim |
| `test_chain_canonical_id_determinism` | Same evidence_version + same nodes → same chain_canonical_id |
| `test_entity_conflict_two_hostnames` | Two hostnames, same agent_id → two HOST nodes + SAME_AGENT edge |
| `test_contradictory_cti_both_preserved` | Two contradictory CTI verdicts → both CTI_MATCH nodes |
| `test_null_entity_fields_skipped` | NULL field → no entity extracted for that type |
| `test_orphaned_evidence_reference` | Deleted evidence → node preserved, provenance=UNKNOWN |
| `test_chain_evidence_as_of_independent_of_phase5` | chain_evidence_as_of computed from event/CTI data; does not use risk_evidence_as_of |

### 26.2 Integration Tests

| Test | What it verifies |
|------|-----------------|
| `test_reconstruct_single_event` | 1-event incident → minimal valid chain |
| `test_reconstruct_multi_event` | N events → correct CHRONOLOGICAL_NEXT edges |
| `test_reconstruct_with_cti` | CTI match → CTI_MATCH node + IOC_MATCH edge |
| `test_reconstruct_no_phase5_required` | Reconstruct succeeds when risk_score and risk_evidence_as_of are NULL |
| `test_reconstruct_idempotency` | Reconstruct twice, same evidence_version → identical logical graph |
| `test_reconstruct_after_evidence_change` | New evidence_version → new chain_version; old preserved |
| `test_late_event_chronological_position` | Late event placed at correct position by event_timestamp |
| `test_stale_chain_detection` | is_stale correct |
| `test_chain_size_limit_truncation` | 600-event incident → truncated at 500, warning present |
| `test_api_get_chain_200` | GET returns correct structure |
| `test_api_get_chain_has_evidence_strength_not_confidence` | Response field is evidence_strength |
| `test_api_get_chain_has_chain_evidence_as_of` | Response field chain_evidence_as_of present |
| `test_api_get_chain_no_raw_json` | raw_json absent from response; forensic_available present |
| `test_api_history_all_versions` | History returns all versions |
| `test_api_reconstruct_idempotent` | POST twice same evidence_version → reconstructed=false |
| `test_api_reconstruct_new_version` | After evidence change → reconstructed=true |
| `test_api_get_chain_404` | No chain → HTTP 404 |
| `test_api_invalid_uuid` | Non-UUID incident_id → HTTP 422 |
| `test_audit_log_written` | Every reconstruction → AuditLog record |

### 26.3 Determinism Regression Tests (N=10)

Ten repeated reconstructions of the same incident (same `evidence_version`) must
produce for each run:
- Equal `node_count`
- Equal set of `logical_node_id` values
- Equal `edge_count`
- Equal set of `logical_edge_id` values
- Equal `chain_canonical_id`

`generated_at` (wall-clock) is expected to differ and is excluded from the comparison.

---

## 27. Research Evaluation Methodology

### 27.1 Confirmed Limitation

> The current production Wazuh database contains no incident-level labeled attack-chain
> ground truth. Quantitative validation of reconstruction accuracy against known attack
> sequences is not possible with the production dataset.

This mirrors the Phase 6 constraint (DATASET_STATUS = INSUFFICIENT for ML).

### 27.2 Proposed Evaluation Dataset (Future Work)

**Method:** Replay known attack simulations (e.g., Atomic Red Team, CALDERA campaign)
against a Wazuh-monitored test host. Capture the resulting Wazuh telemetry.

**Ground truth:** Pre-defined sequence of ATT&CK techniques executed in a known order.

**Measure:** Does the reconstructed chain recover evidence of those techniques?

This dataset must come from real Wazuh telemetry of controlled executions.
It must NOT be synthetically fabricated.

### 27.3 Evaluation Metrics

| Metric | Formula | Notes |
|--------|---------|-------|
| Chain Completeness | `technique_nodes_found / ground_truth_techniques` | Measures technique coverage |
| Temporal Ordering Accuracy | Kendall tau between reconstructed EVENT order and ground-truth execution order | Does not measure causality |
| Evidence Coverage | `events_in_chain / total_incident_events` | |
| Observed Relationship Ratio | `OBSERVED_edges / total_edges` | |
| Inferred Relationship Ratio | `INFERRED_edges / total_edges` | |
| Duplicate Node Rate | `pre_dedup_nodes / post_dedup_nodes - 1` | Should be 0 by design |
| Orphan Evidence Rate | `edges_with_deleted_endpoint / total_edges` | |
| Deterministic Reproducibility | `1.0` if N=10 runs produce identical chain_canonical_id | Must be 1.0 |
| Reconstruction Latency | p50, p95, p99 in ms | |
| Late-Evidence Graph Delta | `abs(new_node_count - old_node_count) / old_node_count` | |
| False Inference Rate | `incorrect_inferred_edges / ground_truth_edges` | **Only measurable with controlled ground-truth dataset** |

**All metrics measure reconstruction fidelity, not attacker-intent prediction.**

---

## 28. Observability

| Signal | Type | Labels |
|--------|------|--------|
| `attack_chain_reconstruction_total` | Counter | `status`: success/error/timeout |
| `attack_chain_reconstruction_duration_seconds` | Histogram | — |
| `attack_chain_node_count` | Histogram | `node_type` |
| `attack_chain_edge_count` | Histogram | `edge_type` |
| `attack_chain_stale_total` | Counter | — |
| `attack_chain_late_evidence_total` | Counter | — |
| `attack_chain_warnings_total` | Counter | `warning_type` |
| `attack_chain_api_requests_total` | Counter | `endpoint`, `status_code` |

Prometheus stubs (no-op when prometheus_client unavailable), consistent with
Phase 6 `ml/observability.py` pattern.

---

## 29. Phase Boundaries

### In Scope — Phase 7

- `attack_chain/` package (reconstruction engine)
- `attack_chain_versions`, `attack_chain_nodes`, `attack_chain_edges` tables + Alembic migration
- Entity canonicalization
- Chronological ordering with deterministic tiebreaking
- 7 edge types (CHRONOLOGICAL_NEXT, SAME_ENTITY, CORRELATED_WITH, IOC_MATCH, TECHNIQUE_SUPPORT, SAME_AGENT, NETWORK_RELATION)
- ATT&CK technique/tactic name resolution from bundled catalog (no tactic-ordering inference)
- Provenance (OBSERVED/INFERRED/UNKNOWN) on every node and edge
- Evidence-strength formula (deterministic ordinal; not probabilistic)
- `chain_evidence_as_of` (Phase 7-owned evidence horizon)
- Chain versioning keyed on `evidence_version`
- CTI historical preservation
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
| Wazuh Active Response | Phase 8 |
| Response recommendations | Phase 8 |
| Frontend / dashboard visualization | Phase 9+ |
| LLM-based reasoning or narrative generation | Phase 9+ |
| Multi-tenancy | Phase 9+ |
| Live TAXII/STIX ATT&CK feed | Phase 9+ |
| Autonomous response decisions | Phase 9+ |
| New external CTI providers | Phase 9+ |
| Production ML training | Not in any Phase 7 scope |

---

## 30. Implementation Sequence

| Step | Task | Dependency |
|------|------|-----------|
| 1 | Alembic DDL migration (3 new tables + attack_chains additive columns) | None |
| 2 | `attack_chain/constants.py` — enums, limits, edge weights, provenance definitions | None |
| 3 | `attack_chain/entity.py` — entity extraction and canonicalization | constants |
| 4 | `attack_chain/mitre.py` — catalog loader, name resolution (no tactic ordering) | None |
| 5 | `attack_chain/data/attck_catalog.json` — bundled ATT&CK catalog | mitre.py |
| 6 | `attack_chain/evidence_strength.py` — node and edge evidence-strength formulas | constants |
| 7 | `attack_chain/algorithm.py` — reconstruction steps 1–21 | entity, mitre, evidence_strength |
| 8 | `attack_chain/models.py` — Phase 7 SQLAlchemy ORM models | Migration |
| 9 | `attack_chain/service.py` — orchestration, persistence, staleness check | algorithm, models |
| 10 | `attack_chain/observability.py` — Prometheus stubs | None |
| 11 | API endpoints in `backend/app/main.py` (additive) | service.py |
| 12 | `tests/attack_chain/__init__.py`, `test_entity.py`, `test_algorithm.py` | entity, algorithm |
| 13 | `tests/attack_chain/test_evidence_strength.py` | evidence_strength |
| 14 | `tests/attack_chain/test_api.py` — integration tests | API |
| 15 | `tests/attack_chain/test_determinism.py` — N=10 regression | All |
| 16 | Run full test suite — all Phase 0–6 + Phase 7 must pass | All |
| 17 | Phase 7 git checkpoint and tag | Tests green |

---

## 31. Acceptance Criteria

| Criterion | Verification |
|-----------|-------------|
| No `TACTIC_PROGRESSION` edge type implemented | grep for TACTIC_PROGRESSION in `attack_chain/` — must be zero results |
| No `PROCESS_RELATION` edge type implemented | grep for PROCESS_RELATION in `attack_chain/` — must be zero results |
| `CHRONOLOGICAL_NEXT` classified as INFERRED | Unit test |
| `CORRELATED_WITH` classified as INFERRED | Unit test |
| `implies_causality = False` on all edges | DB constraint + unit test |
| `evidence_strength` used throughout (not `confidence`) | grep for confidence in Phase 7 models/API — zero non-stub references |
| `chain_evidence_as_of` computed independently of Phase 5 | Unit test: reconstruct succeeds with NULL `risk_evidence_as_of` |
| Logical node identity separable from chain-version identity | Unit test: same event → same logical_node_id across two chain versions |
| CTI historical records preserved (no dedup discard) | Unit test: multiple records for same IOC+source → multiple CTI_MATCH nodes |
| Reconstruction deterministic (N=10 same chain_canonical_id) | Determinism test suite |
| All Phase 0–6 tests (243+2) remain green | CI run |
| Phase 7 test coverage >= 90% of `attack_chain/` | pytest-cov |
| API returns 404 for unknown incident | Integration test |
| API returns 422 for invalid UUID | Integration test |
| `forensic_available` present; `raw_json` absent from response | Integration test |
| Chain size limits enforced | Unit test |
| AuditLog record written for every reconstruction | Integration test |
| No Phase 0–6 source files modified | `git diff phase-6-complete..HEAD --name-only` in Phase 7 boundary |
| No secrets committed | Secret scan |

---

## 32. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `SAME_ENTITY` edge explosion for high-frequency shared IPs | Medium | High | Per-entity pair limit of 50 |
| ATT&CK catalog bundle version drift | Medium | Low | Record `attck_catalog_version` in chain_version |
| MITRE technique IDs absent from most NormalizedEvents | High | Medium | Chain reconstructs without technique nodes; `technique_count=0` is a valid result |
| Reconstruction latency exceeds 30s for large incidents | Low | Medium | Hard 500-node limit + graceful truncation |
| No labeled ground-truth dataset for quantitative RQ validation | High | Medium | Explicitly documented; controlled simulation evaluation proposed |
| CTI historical records growing very large for high-traffic IOCs | Medium | Medium | CTI records are bounded per incident; `threat_intel_results` are append-only per Phase 4 semantics |
| Phase 5 risk calculation has not run for a new incident | Low | Low | Phase 7 is explicitly independent; chain_evidence_as_of computed from event/CTI data |
| Tactic ID in catalog differs from ID used by normalizer | Low | Low | Unknown IDs stored as-is with name=null and a reconstruction_warning |

---

## 33. Final Manual-Review Checklist

Before authorizing Phase 7 implementation:

- [ ] No ATT&CK tactic-progression inference — `TACTIC_PROGRESSION` edge type does not exist in Phase 7
- [ ] No causal claims from chronological adjacency — `CHRONOLOGICAL_NEXT` is INFERRED; `implies_causality = False`
- [ ] `CORRELATED_WITH` classified as INFERRED (correlation is analytical; event membership is observed)
- [ ] `evidence_strength` is explicitly non-probabilistic — ordinal deterministic engineering score only
- [ ] Phase 7 independent of Phase 5 execution — `chain_evidence_as_of` computed from event/CTI data only
- [ ] `chain_evidence_as_of` clearly defined and distinct from `risk_evidence_as_of`
- [ ] Logical node identity (`logical_node_id`) separated from chain-version membership (`chain_version_id`) and DB row identity (`id`)
- [ ] `PROCESS_RELATION` removed from Phase 7 V1
- [ ] CTI history preserved — no historical record discarded; current-vs-historical distinction documented
- [ ] Current CTI interpretation (latest eligible per IOC+source) separated from historical evidence
- [ ] Provenance semantics correct — OBSERVED = directly extracted; INFERRED = analytically derived
- [ ] Causality/inference boundary documented in dedicated §2
- [ ] ATT&CK catalog versioned and bundled; tactic ordering NOT used as inference mechanism
- [ ] No Phase 0–6 contract changes
- [ ] No production response logic (no containment, no Active Response, no SOAR)
- [ ] No LLM logic
- [ ] No dashboard/frontend logic
- [ ] No implementation performed in this revision
- [ ] No migration created in this revision
- [ ] No tests created in this revision
- [ ] No Git commit/tag/push performed in this revision

---

**PLAN REVISION 2 — AWAITING MANUAL REVIEW**
