# PHASE 7 IMPLEMENTATION PLAN — REVISION 4
## Attack Chain / Incident Reconstruction Engine

**Document status:** PLAN REVISION 4 — AWAITING MANUAL REVIEW
**Created:** 2026-09-25
**Supersedes:** docs/PHASE_7_IMPLEMENTATION_PLAN_REV3.md
**Preceding checkpoints:**
- `phase-5-complete` → `a51c369d7e5d8363a8a3a7891faea0e804f33b1`
- `phase-6-complete` → `9b447c5b20c9182844d0ba5ae585f97f6fdd4e7d`

---

## Revision 4 — Summary of Corrections from Revision 3

| # | Correction | Description |
|---|------------|-------------|
| C1 | `IOC_MATCH` edge reclassified as **`INFERRED`** | The underlying evidence records (`EVENT`/`ENTITY` and `ThreatIntelResult`) and IOC values are directly present in source evidence (`OBSERVED`), but the relationship connecting those records across evidence types is derived deterministically by Phase 7 (`INFERRED`). Does not imply causality. `CTI_MATCH` node remains `OBSERVED`. |
| C2 | Independent CTI-aware staleness defined | Current chain is considered stale if `incident.evidence_version > latest_chain.evidence_version` OR `current_cti_evidence_as_of > latest_chain.cti_evidence_as_of`. Explicit NULL-horizon comparison semantics are formalized: NULL vs. non-NULL → stale; both NULL → not stale; both non-NULL → compare timestamps. |
| C3 | CTI evidence history vs. `CTI_MATCH` graph node creation clarified | ALL Phase 4 `ThreatIntelResult` records are permanently preserved in underlying database history and contribute to `cti_evidence_as_of`; only `matched = True` records materialize as `CTI_MATCH` graph nodes because only they establish matches against incident observables. Unmatched CTI records never create graph nodes and are never deleted. |
| C4 | Exact source of `agent_id` for `SAME_AGENT` defined | `agent_id` is resolved from the source `NormalizedEvent` records associated with entity occurrences: `EVENT → source NormalizedEvent → agent_id → entity occurrence`. Grouped by non-null `agent_id`; marked `INFERRED`. |
| C5 | Network fields terminology corrected | `src_port`, `dst_port`, `network_protocol` described as *contextual network fields retained in the evidence snapshot for analyst inspection and future refinement*, not "corroborating fields". Relationship condition remains strictly `E_i.dst_ip == E_j.src_ip AND event_timestamp_i <= event_timestamp_j`. |
| C6 | Legacy `confidence` boundary clarified | Phase 7 canonical semantic field is `evidence_strength`. Legacy `attack_chains.confidence` is a compatibility mirror only (= summary evidence_strength). Zero semantic dependency on `confidence` in Phase 7 algorithms, models, or APIs. |

### Preserved from Revisions 2 and 3
All valid architectural decisions from Revisions 2 and 3 are preserved without alteration:
- No `TACTIC_PROGRESSION` or tactic-sequence inference;
- No `PROCESS_RELATION` or speculative process lineage;
- `CHRONOLOGICAL_NEXT`, `SAME_ENTITY`, `SAME_AGENT`, `CORRELATED_WITH`, `NETWORK_RELATION` all `INFERRED` and non-causal (`implies_causality = False`);
- `EVENT_ENTITY` is `OBSERVED`;
- Separate `provenance` (`OBSERVED`/`INFERRED`/`UNKNOWN`) and `mitre_mapping_type` (`DIRECT_MAPPING`/`INFERRED_MAPPING`/`UNKNOWN`);
- `chain_canonical_id` incorporates sorted node IDs, sorted edge IDs, algorithm version, and catalog version;
- Phase 7-owned independent evidence horizons (`event_evidence_as_of`, `cti_evidence_as_of`, `chain_evidence_as_of`);
- Evidence deletion preserves historical provenance (`evidence_available = False`, `verification_status = UNVERIFIABLE`);
- `ON DELETE RESTRICT` on `attack_chain_versions.incident_id`;
- Deterministic IP canonicalization via Python stdlib `ipaddress`;
- Event-scoped `PROCESS` identity with PID reuse caveat;
- Transaction-safe chain version allocation via `SELECT ... FOR UPDATE`;
- Frozen Phase 0–6 baseline (243 passed, 2 skipped).

---

## 1. Executive Summary

Phase 7 delivers a deterministic, evidence-backed **Attack Chain Reconstruction Engine**
that assembles a directed evidence graph for security incidents from the evidence produced
by Phases 1–6. It does not modify any upstream Phase 0–6 contract.

Every graph element carries explicit **provenance** (`OBSERVED` / `INFERRED` / `UNKNOWN`),
a separate **evidence availability state** (`VERIFIABLE` / `UNVERIFIABLE`) for the case
where source records are subsequently deleted, and a transparent **evidence-strength**
score that is a deterministic ordinal engineering heuristic — not a probability.

The system answers:
- *What evidence exists?* — complete set of correlated events and CTI results
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

- attacker intent or motivation
- causality between events ("Event A caused Event B")
- process parent-child lineage (no PPID/process-start telemetry in current schema)
- lateral movement without source/destination evidence
- attack step ordering beyond what timestamps show
- missing attack steps not present in evidence
- successful attacker objectives
- the actual attack path taken

The reconstructed graph is an **evidence reconstruction**, not a forensic proof of attacker behaviour.

**Prohibited language:**

| Prohibited | Preferred |
|-----------|-----------|
| "The attacker performed X" | "Evidence supports technique X" |
| "Event A caused Event B" | "Event A precedes Event B chronologically" |
| "The attacker moved laterally" | "A network relationship is observed between events E1 and E2" |
| "Phase 7 discovers the attack path" | "Phase 7 reconstructs the evidence graph" |
| "The chain implies intent" | "The chain represents observed and inferred evidence relationships" |

`CHRONOLOGICAL_NEXT` establishes that Event A was observed before Event B.
It does **not** establish that A caused B.

`CORRELATED_WITH` establishes that two events were analytically grouped by the
correlation engine. It does **not** prove a common actor.

`NETWORK_RELATION` establishes that IP addresses in two events match a src→dst pattern.
It does **not** establish network communication, lateral movement, or attacker action.

`IOC_MATCH` establishes that an event observable or entity value matches a CTI indicator value.
It is an **INFERRED** relationship (the individual telemetry records and IOC values are observed,
but the analytical cross-record link is derived by Phase 7). It does **not** prove malicious activity.

---

## 3. Research Objective

Produce a reproducible, deterministic evidence graph for security incidents from
heterogeneous Wazuh/CTI/correlation evidence, suitable for:

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
- Attacker-intent inference — no ground truth; out of scope
- Discovering the actual attack path — no ground truth available
- Inferring tactic sequence from taxonomy — Phase 7 does not use tactic ordering as inference

---

## 5. Existing Architecture Integration

Phase 7 is **additive only**. All Phase 0–6 contracts are frozen.

| Component | Status |
|-----------|--------|
| RawAlert ingestion semantics | Frozen — Phase 1 |
| NormalizedEvent schema | Frozen — Phase 2 |
| Correlation engine, IncidentEvent, CorrelationRule | Frozen — Phase 3 |
| ThreatIntelResult, CTI providers, cache | Frozen — Phase 4 |
| risk-v1 formula, PriorityBand | Frozen — Phase 5 |
| IncidentRiskScore temporal concepts | Frozen — Phase 5 |
| ML pipeline, DATASET_STATUS, inference disabled-by-default | Frozen — Phase 6 |

**Phase 5 independence (Correction C7, preserved from Rev2):**
Phase 7 does NOT require the Phase 5 risk engine to have executed. Phase 7 constructs
its own evidence horizon. Risk scores may be read as optional contextual metadata but
must NOT determine chain provenance, evidence eligibility, or evidence horizon.

**Legacy `confidence` boundary (Correction C6):**
```text
Phase 7 canonical semantic field:
    evidence_strength

Legacy compatibility field:
    attack_chains.confidence
```
The legacy `confidence` field must NOT be used by the Phase 7 reconstruction engine as its semantic evidence-strength field. Phase 7 algorithms, models, and APIs use `evidence_strength` exclusively. If Phase 7 writes `attack_chains.confidence` for backward compatibility, it serves solely as an exact compatibility mirror of the chain's summary `evidence_strength`.

---

## 6. Repository Inspection Findings

Confirmed from source inspection during Revision 3 planning.

### 6.1 NormalizedEvent Fields Available to Phase 7

```
event_timestamp         DateTime  NOT NULL     — primary temporal ordering
src_ip                  String(45) nullable    — network context
dst_ip                  String(45) nullable    — network context
src_port                Integer    nullable    — contextual network field retained in evidence snapshot
dst_port                Integer    nullable    — contextual network field retained in evidence snapshot
network_protocol        String(16) nullable    — contextual network field retained in evidence snapshot
user                    String(255) nullable
hostname                String(255) nullable
agent_id                String(64) nullable
agent_name              String(128) nullable
domain                  String(255) nullable
url                     Text nullable
process_name            String(255) nullable
process_pid             Integer nullable
process_command_line    Text nullable
file_path               Text nullable
file_hash_md5           String(32) nullable
file_hash_sha256        String(64) nullable
mitre_technique_ids     ARRAY(String) nullable
mitre_tactic_ids        ARRAY(String) nullable
```

**Confirmed absent:** `process_ppid`, `parent_pid`, `process_start_time`.
Process lineage edges therefore remain **out of scope for Phase 7**.

### 6.2 ThreatIntelResult Fields Available to Phase 7

```
id                      UUID PK
normalized_event_id     UUID FK nullable  (ON DELETE CASCADE from normalized_events)
incident_id             UUID FK nullable  (ON DELETE CASCADE from incidents)
ioc_type                Enum (IOCType)   NOT NULL
ioc_value               String(512)      NOT NULL
source                  Enum (CTISource) NOT NULL
matched                 Boolean          NOT NULL
queried_at              DateTime         NOT NULL
```

`ioc_type` and `ioc_value` are first-class columns — confirmed directly on the row.
No join required to expose them on `CTI_MATCH` nodes.
All historical CTI records are preserved in Phase 4 history and contribute to `cti_evidence_as_of`; only `matched = True` records materialize as `CTI_MATCH` graph nodes (Correction C3).

### 6.3 Existing ON DELETE Policies (confirmed by inspection)

| Relationship | Policy | Rationale |
|-------------|--------|-----------|
| `normalized_events.raw_alert_id` → `raw_alerts` | CASCADE | Raw alert deleted → event deleted |
| `incident_events.incident_id` → `incidents` | CASCADE | Incident deleted → junction rows deleted |
| `incident_events.normalized_event_id` → `normalized_events` | **RESTRICT** | Prevents silent event deletion with active incident membership |
| `threat_intel_results.normalized_event_id` → `normalized_events` | CASCADE | CTI deleted when event deleted |
| `threat_intel_results.incident_id` → `incidents` | CASCADE | CTI deleted when incident deleted |
| `incident_risk_scores.incident_id` → `incidents` | **RESTRICT** | Preserves risk audit trail (Phase 5 pattern) |
| `attack_chains.incident_id` → `incidents` | CASCADE (Phase 0 stub) | Stub only |

**Phase 7 deletion policy decision** (Correction C9): follows Phase 5 `RESTRICT` pattern
for audit-trail preservation. See §19.7.

### 6.4 attack_chain Package

`attack_chain/` directory exists — currently empty. `backend/app/main.py` contains
no `/attack-chain*` routes. Phase 7 is entirely additive.

---

## 7. Timestamp Semantics

Seven distinct timestamp concepts. Never conflate them.

| Concept | Source | Meaning | Phase 7 Use |
|---------|--------|---------|-------------|
| **Event occurrence** | `NormalizedEvent.event_timestamp` | When the security event occurred | **Primary chronological ordering** |
| **Wazuh alert time** | `RawAlert.wazuh_timestamp` | When Wazuh generated the alert | Fallback tier 2 |
| **Event ingestion** | `NormalizedEvent.created_at` | When event entered pipeline | Ingestion-lag measurement **only** |
| **CTI queried** | `ThreatIntelResult.queried_at` | When IOC was looked up | CTI eligibility gate |
| **Evidence association** | `IncidentEvent.added_at` | When event was linked to incident | Ingestion-lag measurement **only**; NOT ordering |
| **Evidence snapshot** | `Incident.evidence_version` | Monotonic counter incremented by correlation engine | Primary concurrency key |
| **Chain generated** | `chain_version.generated_at` | Wall-clock time reconstruction ran | **AUDIT METADATA ONLY** — not freshness |

### 7.1 Phase 7-Owned Evidence Horizons (Corrections C2, C7)

Phase 7 defines **two** independent evidence horizons and derives one snapshot boundary:

```
event_evidence_as_of =
    max(event.event_timestamp) for all eligible NormalizedEvent records

cti_evidence_as_of =
    max(cti.queried_at) for all eligible ThreatIntelResult records (including unmatched records)

chain_evidence_as_of =
    max(event_evidence_as_of, cti_evidence_as_of) if cti_evidence_as_of is not None else event_evidence_as_of
```

> `chain_evidence_as_of` is a reconstruction snapshot boundary. It does NOT mean that
> all evidence occurred at that timestamp. Events and CTI records are distributed
> across time; this value marks the latest temporal horizon of the eligible evidence set.

If no events exist: `event_evidence_as_of = Incident.created_at`.
If no CTI records exist: `cti_evidence_as_of = NULL`.
If both are NULL: `chain_evidence_as_of = Incident.created_at`.

**Phase 5 `risk_evidence_as_of` is NOT used.** Phase 5 execution is NOT required.

#### Explicit Distinction of Timestamp Fields (Global Audit)
The system strictly distinguishes between different temporal dimensions:

| Timestamp Field | Semantic Role | Participates in Graph Sequencing? | Participates in Staleness? |
|-----------------|---------------|-----------------------------------|----------------------------|
| `event_timestamp` | Telemetry event occurrence time | **Yes** (primary chronological order) | No (uses horizon) |
| `added_at` | Time event was associated with incident | **No** (ingestion lag metric only) | No |
| `queried_at` | Wall-clock time CTI provider lookup executed | **No** (CTI eligibility cutoff) | **Yes** (via `cti_evidence_as_of`) |
| `event_evidence_as_of` | Maximum eligible event occurrence time | No (snapshot boundary) | **Yes** (via `Incident.evidence_version`) |
| `cti_evidence_as_of` | Maximum eligible CTI queried_at | No (snapshot boundary) | **Yes** (independent staleness check) |
| `chain_evidence_as_of` | Derived overall evidence snapshot boundary | No (audit metadata) | No |
| `generated_at` | Reconstruction execution wall-clock time | **No** (audit metadata only) | **No** (MUST NOT determine freshness) |

### 7.2 Primary Chronological Ordering Rule

Events ordered by `(event_timestamp ASC, id ASC)`.
`normalized_event_id` (UUID, compared as byte sequences) is the deterministic
tiebreaker for equal `event_timestamp`. Guarantees a total ordering.

### 7.3 CTI Temporal Eligibility

A `ThreatIntelResult` is eligible if `queried_at <= T_reconstruction`.
`T_reconstruction` is the wall-clock time at which reconstruction begins (captured
once at step 1 of the algorithm; used as the CTI eligibility gate only).
All eligible CTI records are included — historical records are never discarded.

### 7.4 Timestamp Fallback

If `NormalizedEvent.event_timestamp` is NULL (defensive; schema declares NOT NULL):
1. Tier 2: `RawAlert.wazuh_timestamp` (via `raw_alert_id` join)
2. Tier 3: `NormalizedEvent.created_at` (ingestion time)
3. Record `timestamp_source` field on the node
4. Add warning: `{"type": "timestamp_fallback", "tier": 2|3, "event_id": "..."}`

### 7.5 Late Evidence

Late events are positioned by `NormalizedEvent.event_timestamp`.
`IncidentEvent.added_at` is used **only** to compute ingestion lag:
`{"type": "late_event", "event_id": "...", "lag_seconds": <int>}`

---

## 8. Entity Model

Entities are **canonicalized actors** directly extracted from NormalizedEvent fields.
Only types extractable from confirmed schema columns are defined.

### 8.1 Supported Entity Types

| Type | Source Field(s) | Canonical ID Formula |
|------|----------------|---------------------|
| `HOST` | `hostname` | `host:<lowercase(canonical_hostname)>` |
| `USER` | `user` | `user:<lowercase(user)>` |
| `AGENT` | `agent_id` | `agent:<agent_id>` |
| `IP` | `src_ip` or `dst_ip` | `ip:<canonical_ip>` (see §8.3) |
| `DOMAIN` | `domain` | `domain:<lowercase(domain)>` |
| `URL` | `url` | `url:<sha256(normalized_url)>` |
| `PROCESS` | `process_name` + `process_pid` | `process_obs:<sha256(str(event_id) + ":" + process_name + ":" + str(pid))>` (see §8.4) |
| `FILE` | `file_hash_sha256` ∨ `file_path` | `file_sha256:<sha256>` if hash present; else `file_path:<sha256(file_path)>` |
| `FILE_HASH_MD5` | `file_hash_md5` | `hash_md5:<md5>` |
| `IOC` | `ThreatIntelResult.ioc_value` + `ioc_type` | `ioc:<ioc_type>:<ioc_value>` |

Not supported in Phase 7: email, ASN, geolocation, certificate, registry key,
named pipe, mutex (no schema columns available).

### 8.2 Canonicalization Rules

1. Strip leading/trailing whitespace from all string values.
2. Lowercase: hostnames, domains, usernames.
3. IP addresses: canonical form per §8.3.
4. URLs: strip fragment, lowercase scheme and host, sort query parameters by key,
   compute SHA-256 of the resulting normalized string.
5. Processes: event-scoped identity per §8.4.
6. Files: prefer `file_hash_sha256` over `file_path`.
7. NULL or empty string → entity type is not extracted for that event.

### 8.3 IP Address Canonicalization (Correction C11)

IP addresses must be canonicalized using Python's `ipaddress` standard library
(no new dependency required):

```python
import ipaddress

def canonical_ip(raw: str) -> str:
    """
    Raises ValueError if not a valid IP address.
    IPv4 → dotted-decimal ('192.168.1.1')
    IPv6 → compressed form ('2001:db8::1')
    """
    return str(ipaddress.ip_address(raw.strip()))
```

- IPv4: dotted-decimal representation
- IPv6: compressed representation per RFC 5952
- Invalid strings → entity type skipped; reconstruction warning added
- Original raw value preserved in `evidence_snapshot` for forensic reference

The canonical form is used for: `entity_canonical_id`, IOC matching, `logical_node_id`.

Test requirement: two textually different IPv6 representations of the same address
(e.g., `"2001:0db8:0000:0000:0000:0000:0000:0001"` and `"2001:db8::1"`) must produce
the same `entity_canonical_id`.

### 8.4 Process Entity Semantics (Corrections C12, C13)

`PROCESS` entity represents a **process observation** extracted from telemetry.
It does NOT represent a globally stable process instance.

**PID reuse caveat:** PIDs are integers that the OS may reuse. Without `process_ppid`
or `process_start_time` (not present in the current schema), there is no reliable
way to determine whether two events with the same `hostname + pid + process_name`
refer to the same OS process instance.

**Therefore:** the `PROCESS` canonical identity is **event-scoped**:

```
process_obs:<sha256(str(normalized_event_id) + ":" + process_name + ":" + str(pid or 0))>
```

This means two different events with identical `hostname + process_name + pid` produce
two different `PROCESS` entity nodes. They are not automatically merged.

To detect potential same-process references across events, analysts may inspect
`process_name`, `process_pid`, `hostname`, and `event_timestamp` in the evidence
snapshot. Phase 7 does not merge these nodes automatically.

Do NOT infer: process parent-child lineage, process ancestry, or execution causality.

### 8.5 Missing / Ambiguous Entities

- NULL field → entity type not extracted for that event.
- `hostname = NULL` but `agent_id` non-null → extract `AGENT` entity only.
- Two different canonical hostnames, same `agent_id` → two `HOST` entities;
  `SAME_AGENT` edges link them (INFERRED).
- Invalid IP format → entity skipped; warning added.

### 8.6 CTI Evidence: Historical Preservation vs. Graph Node Materialization (Correction C3)

Revision 4 formalizes the conceptual distinction between underlying CTI evidence history and graph node materialization:

#### 1. CTI Evidence History (Underlying Evidence Layer)
- ALL Phase 4 `ThreatIntelResult` records remain permanently preserved in the underlying CTI evidence model.
- Phase 7 must **never** delete, overwrite, deduplicate, or collapse these historical records.
- Every eligible CTI query result contributes to the CTI evidence horizon (`cti_evidence_as_of`), regardless of whether `matched` is `True` or `False`.
- Complete auditability is preserved across all historical lookups.

#### 2. CTI_MATCH Graph Nodes (Graph Representation Layer)
- A `CTI_MATCH` graph node represents a CTI observation that actually establishes a match against an incident observable.
- Therefore, `CTI_MATCH` graph nodes are materialized **only** for eligible records where:
  ```text
  ThreatIntelResult.matched = True
  ```
- **Unmatched CTI observations** remain part of the Phase 4 auditable evidence history and contribute to `cti_evidence_as_of` where eligible, but they do **NOT** create `CTI_MATCH` graph nodes because no incident-observable match exists.
- Phase 7 does **not** invent a new node type for unmatched CTI, does **not** delete unmatched CTI, and does **not** collapse historical CTI observations.

#### 3. Multiple Historical Matches and Verdict Changes
- If multiple historical CTI records exist for the same `(ioc_value, source)` where `matched = True`, each is materialized as an individual `CTI_MATCH` node (one per `ThreatIntelResult.id`).
- For summary/display, the latest eligible record per `(ioc_value, source)` represents the current-interpretation view.
- Verdict changes between historical records generate `reconstruction_warnings`:
```json
{"type": "cti_verdict_changed", "ioc_value": "...", "source": "...",
 "from_verdict": "MALICIOUS", "to_verdict": "BENIGN",
 "from_queried_at": "...", "to_queried_at": "..."}
```

---

## 9. Logical Identity Architecture

Three distinct concepts (from Rev2, confirmed):

### 9.1 Logical Node Identity (`logical_node_id`)

Represents the underlying evidence-backed object, independent of chain version.

```
EVENT:         sha256("EVENT|" + str(normalized_event_id))[:64]
CTI_MATCH:     sha256("CTI_MATCH|" + str(threat_intel_result_id))[:64]
ENTITY:        sha256("ENTITY|" + entity_canonical_id)[:64]
TECHNIQUE:     sha256("TECHNIQUE|" + technique_id + "|" + str(incident_id))[:64]
```

Same underlying evidence → same `logical_node_id`, regardless of chain version.
Enables cross-version comparison and late-evidence diffing.

### 9.2 Logical Edge Identity (`logical_edge_id`)

```
logical_edge_id = sha256(
    edge_type + "|" + src_node_logical_id + "|" + dst_node_logical_id
)[:64]
```

`evidence_version` is NOT incorporated into edge or node logical IDs.

### 9.3 Chain Canonical ID (Correction C1)

The chain canonical ID must be sensitive to **both** node and edge composition,
**and** to the algorithm and catalog versions that produced it:

```
canonical_input = "|".join([
    str(incident_id),
    str(evidence_version),
    reconstruction_algorithm_version,
    attck_catalog_version,
    "N:" + ",".join(sorted(logical_node_ids)),
    "E:" + ",".join(sorted(logical_edge_ids)),
])
chain_canonical_id = sha256(canonical_input.encode("utf-8"))[:64]
```

**Properties:**
- Deterministic for identical `(incident, evidence, algorithm, catalog, nodes, edges)`
- Sensitive to edge changes: same nodes + different edges → different `chain_canonical_id`
- Sensitive to algorithm/catalog version changes
- Independent of database-generated UUID primary keys
- Stable across restarts and concurrent runs

**Test requirements:**
1. Same evidence + same algorithm/catalog → identical `chain_canonical_id`
2. Same nodes + one edge added/removed → different `chain_canonical_id`
3. Same evidence + different `reconstruction_algorithm_version` → different `chain_canonical_id`
4. Same evidence + different `attck_catalog_version` → different `chain_canonical_id`

### 9.4 Database Row Identity (`id`)

UUID surrogate primary key for the specific database row.
May differ between chain versions even for the same logical node.
Must NOT participate in logical identity.

---

## 10. Provenance Model

### 10.1 Provenance Definitions (Correction C1)

| Provenance | Definition | Permitted On |
|------------|------------|--------------|
| `OBSERVED` | Directly present in and extracted from a source evidence record. The claim is supported by a concrete database row. | Nodes: `EVENT`, `ENTITY`, `CTI_MATCH`. Edges: `EVENT_ENTITY`, `TECHNIQUE_SUPPORT` (DIRECT_MAPPING only) |
| `INFERRED` | Produced by deterministic analytical logic from observed evidence. The underlying inputs are observed, but the relationship or conclusion is an analytical derivation. | Edges: `CHRONOLOGICAL_NEXT`, `SAME_ENTITY`, `SAME_AGENT`, `CORRELATED_WITH`, `IOC_MATCH`, `NETWORK_RELATION`, `TECHNIQUE_SUPPORT` (INFERRED_MAPPING). Nodes: `TECHNIQUE` (when rule-derived) |
| `UNKNOWN` | Evidence cannot currently be established — insufficient or missing data. | Rare fallback |

> **Evidence deletion does NOT change provenance** (Correction C8).
> Provenance describes how the relationship was established at reconstruction time.
> Subsequent deletion of a source record does not retroactively change `OBSERVED` to
> `UNKNOWN`. Use `evidence_available` and `verification_status` for current availability.

### 10.2 Evidence Availability (Correction C8)

Separate from provenance, each node and edge carries:

| Field | Type | Values | Meaning |
|-------|------|--------|---------|
| `evidence_available` | Boolean | `True` / `False` | Whether all referenced source records currently exist |
| `verification_status` | Enum | `VERIFIABLE` / `UNVERIFIABLE` | Whether the claim can currently be independently verified from source records |

When a source evidence record is deleted after chain construction:
- `provenance` remains **unchanged** (e.g., still `OBSERVED`)
- `evidence_available` → `False`
- `verification_status` → `UNVERIFIABLE`
- `evidence_refs` preserved (FK fields set to NULL by DB `ON DELETE SET NULL`; UUIDs stored in `evidence_refs` JSONB remain)
- Reconstruction warning added: `{"type": "orphaned_evidence", "table": "...", "id": "..."}`
- The chain snapshot is preserved for historical auditability

### 10.3 Canonical Provenance Assignments (Correction C1)

**OBSERVED:**
- `NormalizedEvent` record exists in incident → EVENT node
- Non-null entity field directly extracted from event → ENTITY node
- EVENT → ENTITY relationship (entity directly extracted from event field) → EVENT_ENTITY edge
- `ThreatIntelResult.matched = True` → CTI_MATCH node
- `NormalizedEvent.mitre_technique_ids` non-empty → TECHNIQUE node (DIRECT mapping)
- Direct technique mapping present on event → TECHNIQUE_SUPPORT edge (DIRECT_MAPPING)

**INFERRED:**
- Chronological adjacency between events → CHRONOLOGICAL_NEXT edge
- Shared entity canonical ID across two events → SAME_ENTITY edge
- Shared agent ID across two events/entities (resolved via source NormalizedEvent) → SAME_AGENT edge
- Correlation rule groups two events → CORRELATED_WITH edge
- IOC matching between event/entity observable and CTI result → IOC_MATCH edge (source records and IOC values are OBSERVED, but the matching relationship connecting them across records is derived deterministically by Phase 7; implies causality = False)
- IP address pair matching across two events → NETWORK_RELATION edge
- Technique inherited from CorrelationRule (no direct event technique IDs) → INFERRED mapping type; TECHNIQUE_SUPPORT edge provenance = INFERRED

**UNKNOWN:**
- Timestamps all NULL with no fallback
- Evidence record could not be loaded during reconstruction
- Insufficient information to establish the node or relationship

---

## 11. Authoritative Node Table

### 11.1 Node Type Definitions

**`EVENT`**
| Attribute | Value |
|-----------|-------|
| Source evidence | `NormalizedEvent` record in `incident_events` |
| Logical identity | `sha256("EVENT|" + str(ne.id))[:64]` |
| Provenance | `OBSERVED` |
| Evidence-strength | `base_tier(OBSERVED) × source_quality(direct_event) × support_discount(1)` = 0.80 |
| MITRE data | From `NormalizedEvent.mitre_technique_ids` and `mitre_tactic_ids` |
| Deletion behavior | Node preserved; `evidence_available = False`; `verification_status = UNVERIFIABLE` |
| API exposure | Full fields; no raw Wazuh JSON |

**`ENTITY`**
| Attribute | Value |
|-----------|-------|
| Source evidence | Non-null field in `NormalizedEvent` |
| Logical identity | `sha256("ENTITY|" + entity_canonical_id)[:64]` |
| Provenance | `OBSERVED` (entity field is directly in evidence record) |
| Evidence-strength | `base_tier(OBSERVED) × source_quality(direct_event) × support_discount(n_events)` |
| Deletion behavior | Node preserved; `evidence_available = False` if all source events deleted |
| Notes | One node per unique `entity_canonical_id` within the chain; linked to events via EVENT_ENTITY edges |

**`CTI_MATCH`**
| Attribute | Value |
|-----------|-------|
| Source evidence | One per eligible `ThreatIntelResult` record where `matched = True` |
| Logical identity | `sha256("CTI_MATCH|" + str(ti.id))[:64]` |
| Provenance | `OBSERVED` (directly backed by a source ThreatIntelResult record) |
| Evidence-strength | `base_tier(OBSERVED) × source_quality(cti_matched)` = 0.90 |
| Fields exposed | `ioc_type`, `ioc_value`, `source`, `matched`, `queried_at`, `threat_intel_result_id` |
| Deletion behavior | Node preserved; `evidence_available = False`; `verification_status = UNVERIFIABLE` |
| Notes | Materialized ONLY for records where `matched = True`. Unmatched CTI records remain in Phase 4 history and contribute to `cti_evidence_as_of`, but do NOT create graph nodes. Multiple nodes per `(ioc_value, source)` if multiple historical matched records exist; verdict-change warnings generated |

**`TECHNIQUE`**
| Attribute | Value |
|-----------|-------|
| Source evidence | `NormalizedEvent.mitre_technique_ids` (DIRECT) or `CorrelationRule.mitre_technique_id` (INFERRED) |
| Logical identity | `sha256("TECHNIQUE|" + technique_id + "|" + str(incident_id))[:64]` |
| Provenance | `OBSERVED` for DIRECT_MAPPING; `INFERRED` for INFERRED_MAPPING |
| Mapping type | Separate field: `DIRECT_MAPPING` / `INFERRED_MAPPING` / `UNKNOWN` |
| Evidence-strength | `OBSERVED→DIRECT`: 1.0 × 0.90 = 0.90; `INFERRED→RULE`: 0.6 × 0.70 = 0.42 |
| Deletion behavior | Technique node preserved; evidence refs marked unavailable if source events deleted |
| Notes | One per `(technique_id, incident_id)`; multiple events link via TECHNIQUE_SUPPORT edges |

### 11.2 Node Database Fields

```sql
attack_chain_nodes:
  id                      UUID PK
  chain_version_id        UUID FK → attack_chain_versions(id) ON DELETE CASCADE
  logical_node_id         VARCHAR(128) NOT NULL
  node_type               VARCHAR(32) NOT NULL
  normalized_event_id     UUID → normalized_events(id) ON DELETE SET NULL  [nullable]
  threat_intel_result_id  UUID → threat_intel_results(id) ON DELETE SET NULL  [nullable]
  entity_canonical_id     VARCHAR(256)  [nullable]
  entity_type             VARCHAR(32)   [nullable]
  ioc_type                VARCHAR(32)   [nullable — populated for CTI_MATCH nodes]
  ioc_value               VARCHAR(512)  [nullable — populated for CTI_MATCH nodes]
  mitre_technique_id      VARCHAR(32)   [nullable]
  mitre_tactic_ids        JSONB         [nullable — array of tactic IDs]
  mitre_technique_name    VARCHAR(255)  [nullable]
  mitre_tactic_names      JSONB         [nullable — map tactic_id → name]
  mitre_mapping_type      VARCHAR(32)   [nullable]
  provenance              VARCHAR(16) NOT NULL
  evidence_available      BOOLEAN NOT NULL DEFAULT TRUE
  verification_status     VARCHAR(16) NOT NULL DEFAULT 'VERIFIABLE'
  evidence_strength       FLOAT NOT NULL CHECK (evidence_strength BETWEEN 0.0 AND 1.0)
  event_timestamp         TIMESTAMPTZ  [nullable]
  timestamp_source        VARCHAR(32)  [nullable]
  sequence_index          INTEGER      [nullable — only EVENT nodes]
  evidence_refs           JSONB NOT NULL DEFAULT '[]'
  evidence_snapshot       JSONB NOT NULL DEFAULT '{}'
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
```

---

## 12. Authoritative Edge Table

**Total: 8 edge types.**
`TACTIC_PROGRESSION` does not exist.
`PROCESS_RELATION` does not exist.

### Master Edge Summary Table (Revision 4 Authoritative)

| Edge Type | Source Node | Destination Node | Direction | Creation Condition | Required Evidence | Provenance | Implies Causality | Deterministic Canonical ID Inputs |
|-----------|-------------|------------------|-----------|--------------------|-------------------|------------|-------------------|-----------------------------------|
| `EVENT_ENTITY` | `EVENT` | `ENTITY` | `EVENT → ENTITY` | Entity extracted from event field | Non-null field in `normalized_events` | **OBSERVED** | **False** | `"EVENT_ENTITY\|" + event_logical_id + "\|" + entity_logical_id` |
| `CHRONOLOGICAL_NEXT` | `EVENT` | `EVENT` | `EVENT_i → EVENT_{i+1}` | Consecutive in chronological ordering | Events in `incident_events` with resolved timestamps | **INFERRED** | **False** | `"CHRONOLOGICAL_NEXT\|" + ei_logical_id + "\|" + ei1_logical_id` |
| `SAME_ENTITY` | `EVENT` | `EVENT` | Bidirectional | Two events share same `entity_canonical_id` | Both events carry same canonical entity ID | **INFERRED** | **False** | `"SAME_ENTITY\|" + sorted(e1_logical_id, e2_logical_id)` |
| `CORRELATED_WITH` | `EVENT` | `EVENT` | Undirected | Shared non-null `correlation_rule_id` | `IncidentEvent.correlation_rule_id` equal and non-null | **INFERRED** | **False** | `"CORRELATED_WITH\|" + sorted(e1_logical_id, e2_logical_id)` |
| `IOC_MATCH` | `ENTITY` or `EVENT` | `CTI_MATCH` | `Src → CTI_MATCH` | Observable matches canonical `ioc_value` | Observable value equals `ThreatIntelResult.ioc_value` (`matched=True`) | **INFERRED** | **False** | `"IOC_MATCH\|" + src_logical_id + "\|" + cti_logical_id` |
| `TECHNIQUE_SUPPORT` | `EVENT` | `TECHNIQUE` | `EVENT → TECHNIQUE` | Event carries technique ID | `NormalizedEvent.mitre_technique_ids` (DIRECT) or `CorrelationRule` (INFERRED) | **OBSERVED** (DIRECT) / **INFERRED** (RULE) | **False** | `"TECHNIQUE_SUPPORT\|" + event_logical_id + "\|" + technique_logical_id` |
| `SAME_AGENT` | `ENTITY` | `ENTITY` | Undirected | Entities share same `agent_id` from source events | Source events carry equal non-null `agent_id` | **INFERRED** | **False** | `"SAME_AGENT\|" + sorted(entity1_logical_id, entity2_logical_id)` |
| `NETWORK_RELATION` | `EVENT` | `EVENT` | `EVENT_i → EVENT_j` | `dst_ip == canonical(src_ip)` AND `ts_i <= ts_j` | Matching IP addresses and temporal ordering | **INFERRED** | **False** | `"NETWORK_RELATION\|" + ei_logical_id + "\|" + ej_logical_id` |

---

### `EVENT_ENTITY` *(from Revision 3, preserved)*

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `ENTITY` |
| Direction | EVENT → ENTITY |
| Creation condition | An entity is directly extracted from a non-null field of the NormalizedEvent |
| Required evidence | Non-null field in `normalized_events` |
| Provenance | **OBSERVED** — entity field is directly in the evidence record |
| Implies causality | **False** |
| Evidence refs | `normalized_events` row |
| Evidence-strength | `min(event.evidence_strength, entity.evidence_strength) × 1.00` |
| Canonical ID inputs | `"EVENT_ENTITY|" + event_logical_id + "|" + entity_logical_id` |

> This edge represents direct evidence linkage: the event record contains the entity field.
> It is the primary observed relationship between events and entities.

---

### `SAME_ENTITY` *(reclassified INFERRED — Correction C2)*

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `EVENT` |
| Direction | Bidirectional (implementation creates one directed edge; visualisation may show undirected) |
| Creation condition | Two EVENT nodes share the same `entity_canonical_id` |
| Required evidence | `entity_canonical_id` extracted from both event records; entity node exists |
| Provenance | **INFERRED** — entity occurrence in each event is OBSERVED; the cross-event relationship through shared entity identity is an analytical derivation |
| Implies causality | **False** |
| Evidence refs | Both `normalized_events` rows; `entity_canonical_id` |
| Evidence-strength | `min(e1.evidence_strength, e2.evidence_strength) × 0.85` |
| Canonical ID inputs | `"SAME_ENTITY|" + sorted(e1_logical_id, e2_logical_id)` |
| Limit | max 50 pairs per entity_canonical_id |

> The entity occurrence in each event is OBSERVED. The cross-event relationship derived
> from shared entity identity is INFERRED. SAME_ENTITY does not imply causality.

---

### `CORRELATED_WITH`

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `EVENT` |
| Direction | Undirected (implementation symmetric) |
| Creation condition | Two events share the same non-null `correlation_rule_id` in `incident_events` |
| Required evidence | `IncidentEvent.correlation_rule_id` non-null and equal; `CorrelationRule` record exists |
| Provenance | **INFERRED** — the correlation grouping is an analytical product of the Phase 3 engine; event membership is observed, but the relationship is derived |
| Implies causality | **False** |
| Evidence refs | Both `incident_events` rows + `correlation_rules` row |
| Evidence-strength | `min(e1.evidence_strength, e2.evidence_strength) × 0.85` |
| Canonical ID inputs | `"CORRELATED_WITH|" + sorted(e1_logical_id, e2_logical_id)` |
| Limit | max 100 pairs per rule group |

---

### `IOC_MATCH` *(reclassified INFERRED — Correction C1)*

| Attribute | Value |
|-----------|-------|
| Source node type | `ENTITY` or `EVENT` |
| Destination node type | `CTI_MATCH` |
| Direction | ENTITY/EVENT → CTI_MATCH |
| Creation condition | An ENTITY node's `entity_canonical_id` matches the canonical form of `CTI_MATCH.ioc_value`; or an EVENT node's direct field matches |
| Required evidence | `ThreatIntelResult.matched = True`; matching `ioc_value` field in event/entity |
| Provenance | **INFERRED** — the individual evidence records (`EVENT`/`ENTITY` and `ThreatIntelResult`) and IOC values are directly present in source evidence (`OBSERVED`), but the relationship connecting those records across evidence types is derived deterministically by Phase 7 (`INFERRED`) |
| Implies causality | **False** |
| Evidence refs | Source event/entity + `threat_intel_results` row |
| Evidence-strength | `min(src.evidence_strength, cti.evidence_strength) × 0.95` |
| Canonical ID inputs | `"IOC_MATCH|" + src_logical_id + "|" + cti_logical_id` |

> `CTI_MATCH` node provenance remains `OBSERVED`. The `IOC_MATCH` edge connecting an event
> or entity to that CTI match is `INFERRED`. `IOC_MATCH` does not imply causality.

---

### `TECHNIQUE_SUPPORT`

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `TECHNIQUE` |
| Direction | EVENT → TECHNIQUE |
| Creation condition | EVENT node carries a MITRE technique ID |
| Required evidence | `NormalizedEvent.mitre_technique_ids` non-empty (DIRECT); or `CorrelationRule.mitre_technique_id` non-null when event has no technique IDs (INFERRED) |
| Provenance | **OBSERVED** for DIRECT_MAPPING; **INFERRED** for INFERRED_MAPPING from rule |
| Implies causality | **False** |
| Evidence refs | `normalized_events` row; optionally `correlation_rules` row |
| Evidence-strength | OBSERVED: `event.evidence_strength × 0.90`; INFERRED: `event.evidence_strength × 0.70` |
| Canonical ID inputs | `"TECHNIQUE_SUPPORT|" + event_logical_id + "|" + technique_logical_id` |

---

### `SAME_AGENT` *(reclassified INFERRED — Corrections C3, C4)*

| Attribute | Value |
|-----------|-------|
| Source node type | `ENTITY` |
| Destination node type | `ENTITY` |
| Direction | Undirected |
| Creation condition | Two ENTITY nodes (HOST or AGENT type) share the same `agent_id` value, resolved from their source event occurrences |
| Required evidence | `NormalizedEvent.agent_id` equality across the source events generating the entities |
| Provenance | **INFERRED** — agent membership in each event is OBSERVED; the cross-entity relationship through shared agent ID is analytically derived |
| Implies causality | **False** |
| Evidence refs | Both `normalized_events` rows |
| Evidence-strength | `min(e1.evidence_strength, e2.evidence_strength) × 0.90` |
| Canonical ID inputs | `"SAME_AGENT|" + sorted(entity1_logical_id, entity2_logical_id)` |
| Limit | max 50 pairs |

#### Exact Resolution of `agent_id` (Correction C4)
The `agent_id` is resolved directly from the source `NormalizedEvent` records associated with the entity occurrences:
```text
EVENT
  ↓
source NormalizedEvent
  ↓
agent_id
  ↓
entity occurrence
```
The reconstruction algorithm maintains this evidence linkage through the following deterministic process:
1. Identify entity occurrences extracted from NormalizedEvents.
2. Resolve each occurrence's `agent_id` directly from its source `NormalizedEvent`.
3. Group entity occurrences by non-null `agent_id` (occurrences with null `agent_id` are strictly excluded).
4. Create `SAME_AGENT` relationships between ENTITY nodes only where the relationship is supported by shared agent identity.
5. Mark the edge provenance as `INFERRED`.
6. Preserve the source event references in `evidence_refs`.

> `agent_id` equality is observed telemetry; the cross-entity relationship derived from that
> equality is inferred. Does NOT claim that `SAME_AGENT` proves the entities belong to the
> same physical system beyond what the Wazuh agent identity supports.

---

### `NETWORK_RELATION` *(strengthened — Correction C10)*

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `EVENT` |
| Direction | EVENT_i → EVENT_j |
| Creation condition | `event_i.dst_ip = canonical(event_j.src_ip)` AND `event_i.event_timestamp <= event_j.event_timestamp`; both events in the same incident |
| Required evidence | Non-null `dst_ip` on E_i; non-null `src_ip` on E_j; both canonically equal; temporal ordering confirmed |
| Contextual network fields | `src_port`, `dst_port`, `network_protocol` retained in `evidence_snapshot` for analyst inspection and future refinement (not part of V1 creation condition) |
| Provenance | **INFERRED** — IP field values are OBSERVED; the directional network relationship between events is analytically derived |
| Implies causality | **False** — matches network addresses; does NOT establish communication, lateral movement, or attacker action |
| Evidence refs | Both `normalized_events` rows |
| Evidence-strength | `min(e1.evidence_strength, e2.evidence_strength) × 0.75` |
| Canonical ID inputs | `"NETWORK_RELATION|" + ei_logical_id + "|" + ej_logical_id` |
| Limit | max 200 per chain |

> Matching network addresses alone does not establish attacker movement, communication
> direction, causality, or lateral movement. The temporal constraint prevents backwards
> network relationships that would be analytically meaningless. Contextual fields (ports,
> protocol) are retained in the evidence snapshot for analyst reference; they do not currently
> establish the relationship and do not increase evidence strength merely by being present.

---

### `CHRONOLOGICAL_NEXT` *(Correction C17)*

| Attribute | Value |
|-----------|-------|
| Source node type | `EVENT` |
| Destination node type | `EVENT` |
| Direction | EVENT_i → EVENT_{i+1} (chronological predecessor → successor) |
| Creation condition | EVENT node E_i is the immediately preceding event to EVENT node E_{i+1} in the deterministic chronological ordering |
| Required evidence | Both events in `incident_events`; both have resolved `event_timestamp` |
| Provenance | **INFERRED** — event occurrence is OBSERVED; chronological ordering is deterministic; adjacency is derived by the algorithm |
| Implies causality | **False** |
| Evidence refs | `incident_events` rows for both events |
| Evidence-strength | `min(e1.evidence_strength, e2.evidence_strength) × 0.70` |
| Canonical ID inputs | `"CHRONOLOGICAL_NEXT|" + ei_logical_id + "|" + ei1_logical_id` |
| Limit | N-1 edges for N events |

**Design decision (retained from Rev2, clarified):**
`CHRONOLOGICAL_NEXT` edges are **retained** for timeline visualization purposes.
The `sequence_index` field on EVENT nodes provides an alternative traversal mechanism
for analysts who prefer not to follow edges. Both representations are provided.

`CHRONOLOGICAL_NEXT` MUST NOT be described or interpreted as:
- `caused_by`, `led_to`, `attacker_progressed_to`
- attacker action sequence
- causal chain

It represents: "these two consecutive evidence-backed events are adjacent in the
deterministic chronological ordering." Nothing more.

---

### Explicitly Excluded Edge Types

| Type | Status | Reason |
|------|--------|--------|
| `TACTIC_PROGRESSION` | **REMOVED** | ATT&CK tactic taxonomy must not create causal or temporal graph edges. Tactics are metadata on TECHNIQUE nodes only. |
| `PROCESS_RELATION` | **REMOVED** | No PPID/process-start-time telemetry in current schema. String containment of `process_name` in `process_command_line` is insufficient evidence for process lineage. |

---

## 13. MITRE ATT&CK: Mapping Type vs. Provenance (Correction C5)

Mapping type and provenance are **distinct, orthogonal dimensions**.

### 13.1 Mapping Type (`mitre_mapping_type`)

Describes how the MITRE technique was associated with the event:

| Value | Source | Meaning |
|-------|--------|---------|
| `DIRECT_MAPPING` | `NormalizedEvent.mitre_technique_ids` non-empty | Wazuh rule or normalizer explicitly mapped this event to the technique |
| `INFERRED_MAPPING` | `CorrelationRule.mitre_technique_id` non-null; event has no technique IDs | Technique inherited from the correlation rule |
| `UNKNOWN` | No technique data available | No mapping; TECHNIQUE node is not generated |

### 13.2 Provenance (`provenance`)

Describes the reliability tier of the evidence supporting the node/edge:

| Value | When used for TECHNIQUE nodes |
|-------|-------------------------------|
| `OBSERVED` | Technique directly on the event record (`DIRECT_MAPPING`) |
| `INFERRED` | Technique derived from rule inheritance (`INFERRED_MAPPING`) |

### 13.3 Combinations

| `mitre_mapping_type` | `provenance` | Meaning |
|----------------------|-------------|---------|
| `DIRECT_MAPPING` | `OBSERVED` | Technique explicitly mapped in event; directly evidenced |
| `INFERRED_MAPPING` | `INFERRED` | Technique inherited from correlation rule; not directly on event |

These two fields are always set independently. Do not use `DIRECT_MAPPING` as a
substitute for `provenance = OBSERVED`.

### 13.4 ATT&CK Catalog

Bundled as `attack_chain/data/attck_catalog.json`. Provides:
- `technique_id`, `technique_name`, `tactic_ids`, `tactic_names`, `catalog_version`

Tactic ordering is NOT used as graph inference. Tactics are descriptive metadata on
TECHNIQUE nodes.

Unknown IDs → `name = null`; reconstruction warning added.
No live internet access required.

---

## 14. Evidence Strength

### 14.1 Non-Probabilistic Declaration and Legacy Confidence Boundary (Correction C6)

`evidence_strength` is an **ordinal deterministic engineering score** in [0.0, 1.0].

It is:
- **Not** a probability
- **Not** a calibrated statistical estimate
- **Not** a claim that 0.6 means 60% probability or likelihood
- An engineering heuristic representing relative evidence quality and provenance tier

`0.6 does NOT mean 60% probability.`

These weights are design parameters chosen for tractability and explainability.
They are subject to empirical calibration in future research — any such calibration
must be explicitly documented and must not be claimed without measurement.

#### Legacy `confidence` Boundary (Correction C6)
```text
Phase 7 canonical semantic field:
    evidence_strength

Legacy compatibility field:
    attack_chains.confidence
```
- **Canonical field (`evidence_strength`):** Every node, edge, and summary carries `evidence_strength` in `[0.0, 1.0]`. All Phase 7 reconstruction algorithms, models, and APIs use this field exclusively.
- **Legacy compatibility field (`attack_chains.confidence`):** The pre-existing column `attack_chains.confidence` is preserved strictly as a backward-compatibility mirror representing the chain's summary evidence strength:
  ```text
  attack_chains.confidence = summary evidence_strength
  ```
- **Strict Boundary:** The Phase 7 reconstruction engine has **zero semantic dependency** on `confidence`. The only permitted reference to `confidence` in Phase 7 is the documented legacy mirror column on `attack_chains`.

### 14.2 Node Evidence-Strength Formula

```
node_evidence_strength =
    clamp(
        base_tier(provenance) × source_quality(source_type) × support_discount(n),
        0.0, 1.0
    )
```

**base_tier:**

| Provenance | Value |
|-----------|-------|
| `OBSERVED` | 1.0 |
| `INFERRED` | 0.6 |
| `UNKNOWN` | 0.0 |

**source_quality:**

| Source Type | Value | Notes |
|------------|-------|-------|
| Direct Wazuh event | 1.0 | Event occurrence observed |
| CTI matched | 0.9 | Backed by `ThreatIntelResult.matched = True` |
| Rule-inferred technique | 0.7 | Derived from correlation rule |

**support_discount (n = corroborating events referencing this node):**

| n | Multiplier |
|---|-----------|
| n ≥ 3 | 1.0 |
| n = 2 | 0.9 |
| n = 1 | 0.8 |

### 14.3 Edge Evidence-Strength Formula

```
edge_evidence_strength =
    clamp(
        min(src_node.evidence_strength, dst_node.evidence_strength) × edge_type_weight,
        0.0, 1.0
    )
```

**edge_type_weight:**

| Edge Type | Weight |
|-----------|--------|
| `EVENT_ENTITY` | 1.00 |
| `IOC_MATCH` | 0.95 |
| `TECHNIQUE_SUPPORT` (DIRECT) | 0.90 |
| `SAME_AGENT` | 0.90 |
| `TECHNIQUE_SUPPORT` (INFERRED) | 0.70 |
| `CORRELATED_WITH` | 0.85 |
| `SAME_ENTITY` | 0.85 |
| `NETWORK_RELATION` | 0.75 |
| `CHRONOLOGICAL_NEXT` | 0.70 |

### 14.4 Evidence-Strength Invariants

- `evidence_strength ∈ [0.0, 1.0]` enforced by DB CHECK constraint and unit tests
- Independent of Phase 5 `risk_score` and Phase 6 `ml_score`
- Deterministic: same inputs → same output
- Not a probability; not calibrated

---

## 15. Reconstruction Algorithm

Deterministic for a fixed `(incident_id, evidence_version)` and the same eligible
evidence set. Re-running with identical inputs produces an identical graph.

```
function reconstruct(incident_id, evidence_version):

  STEP 1 — VALIDATE AND ACQUIRE LOCK
    a. BEGIN TRANSACTION
    b. SELECT ... FROM incidents WHERE id = incident_id FOR UPDATE
       [Row-level lock — prevents concurrent version-allocation races; see §18]
    c. Verify Incident.evidence_version == requested evidence_version
    d. Capture T_reconstruction = now() [wall-clock; used only for CTI eligibility gate and audit]

  STEP 2 — CHECK IDEMPOTENCY (Corrections C2, C5)
    a. Look up latest chain version for incident_id
    b. Determine current eligible CTI horizon: current_cti_evidence_as_of = max(queried_at)
    c. If latest chain exists, matches evidence_version, matches cti_evidence_as_of (with explicit NULL handling),
       and uses matching algorithm/catalog versions:
       RETURN existing chain (idempotent; no duplicate reconstruction)

  STEP 3 — LOAD EVIDENCE SNAPSHOT
    a. Load all IncidentEvent records for incident_id
    b. Load all NormalizedEvent records via IncidentEvent join
    c. Load ALL eligible ThreatIntelResult records:
         (incident_id = X OR normalized_event_id IN event_ids)
         AND queried_at <= T_reconstruction
       [All historical records preserved — no deduplication]
    d. Load CorrelationRule records referenced by IncidentEvent.correlation_rule_id (non-null)

  STEP 4 — COMPUTE EVIDENCE HORIZONS
    event_evidence_as_of = max(event.event_timestamp) or Incident.created_at
    cti_evidence_as_of   = max(cti.queried_at) or NULL
    chain_evidence_as_of = max(event_evidence_as_of, cti_evidence_as_of or event_evidence_as_of)

  STEP 5 — ORDER EVENTS
    Sort NormalizedEvents by (event_timestamp ASC, id ASC)
    Assign sequence_index 0 .. N-1
    Resolve timestamp fallbacks per §7.4

  STEP 6 — CANONICALIZE ENTITIES
    For each NormalizedEvent: extract all entity types from non-null fields
    Apply canonicalization rules per §8
    Build index: entity_canonical_id → set of (normalized_event_id, entity_type)

  STEP 7 — DETECT CTI VERDICT CHANGES
    For each (ioc_value, source) group with multiple records, ordered by queried_at:
      If verdicts differ → add reconstruction_warning {"type": "cti_verdict_changed", ...}

  STEP 8 — GENERATE EVENT NODES [provenance = OBSERVED]
    One per NormalizedEvent
    logical_node_id = sha256("EVENT|" + str(ne.id))[:64]
    Populate timestamp_source, sequence_index, evidence_snapshot

  STEP 9 — GENERATE CTI_MATCH NODES [provenance = OBSERVED] (Correction C3)
    One per eligible ThreatIntelResult where matched=True
    logical_node_id = sha256("CTI_MATCH|" + str(ti.id))[:64]
    Populate ioc_type, ioc_value (directly from ThreatIntelResult columns)
    Note: Unmatched CTI records remain in Phase 4 history and contribute to cti_evidence_as_of,
    but do NOT create CTI_MATCH graph nodes.

  STEP 10 — GENERATE ENTITY NODES [provenance = OBSERVED]
    One per unique entity_canonical_id
    logical_node_id = sha256("ENTITY|" + entity_canonical_id)[:64]

  STEP 11 — GENERATE TECHNIQUE NODES
    One per unique (mitre_technique_id, incident_id)
    DIRECT_MAPPING: technique on NormalizedEvent.mitre_technique_ids
      → provenance = OBSERVED; mitre_mapping_type = DIRECT_MAPPING
    INFERRED_MAPPING: technique from CorrelationRule only (event has no technique IDs)
      → provenance = INFERRED; mitre_mapping_type = INFERRED_MAPPING
    Resolve names from bundled ATT&CK catalog

  STEP 12 — GENERATE EVENT_ENTITY EDGES [provenance = OBSERVED]
    For each (normalized_event_id, entity_canonical_id) pair extracted in Step 6

  STEP 13 — GENERATE CHRONOLOGICAL_NEXT EDGES [provenance = INFERRED]
    For each consecutive pair (event_i, event_{i+1}) in Step 5 ordering
    [Chronological adjacency; does NOT imply causality]

  STEP 14 — GENERATE SAME_ENTITY EDGES [provenance = INFERRED]
    For each entity_canonical_id with >= 2 associated EVENT nodes
    Pairs between EVENT nodes sharing that entity; limit 50 pairs per entity

  STEP 15 — GENERATE CORRELATED_WITH EDGES [provenance = INFERRED]
    Group IncidentEvent by correlation_rule_id (non-null)
    Pairs within each rule group; limit 100 pairs per group

  STEP 16 — GENERATE IOC_MATCH EDGES [provenance = INFERRED] (Correction C1)
    For each CTI_MATCH node: find ENTITY nodes whose canonical ID matches ioc_value
    (after canonical IP normalization for IP-type IOCs)
    Mark edge provenance = INFERRED (underlying records OBSERVED; cross-record match derived)

  STEP 17 — GENERATE TECHNIQUE_SUPPORT EDGES
    EVENT → TECHNIQUE for each (event, technique) pair
    provenance = OBSERVED if DIRECT_MAPPING; INFERRED if INFERRED_MAPPING

  STEP 18 — GENERATE SAME_AGENT EDGES [provenance = INFERRED] (Correction C4)
    Resolve agent_id from source NormalizedEvent telemetry for each entity occurrence
    Group entity occurrences by non-null agent_id
    Create SAME_AGENT edges between ENTITY nodes sharing agent_id; limit 50 pairs
    Mark provenance = INFERRED; store source event references in evidence_refs

  STEP 19 — GENERATE NETWORK_RELATION EDGES [provenance = INFERRED] (Correction C5)
    E_i.dst_ip = canonical(E_j.src_ip)
    AND E_i.event_timestamp <= E_j.event_timestamp
    Limit 200 per chain
    Store contextual network fields (src_port, dst_port, network_protocol) in evidence_snapshot for analyst review

  STEP 20 — COMPUTE EVIDENCE-STRENGTH
    All nodes: per §14.2
    All edges: per §14.3

  STEP 21 — APPLY SIZE LIMITS
    Truncate per §19.8; add reconstruction_warnings; set truncated=True on chain version

  STEP 22 — COMPUTE chain_canonical_id
    Per §9.3 (includes sorted node IDs, sorted edge IDs, algorithm version, catalog version)

  STEP 23 — ALLOCATE chain_version
    Within the locked transaction:
      SELECT COALESCE(MAX(chain_version), 0) + 1
      FROM attack_chain_versions
      WHERE incident_id = X
      [Safe under row lock from Step 1; see §18 for concurrency details]

  STEP 24 — PERSIST
    INSERT attack_chain_versions (with event_evidence_as_of, cti_evidence_as_of, chain_evidence_as_of)
    UPSERT attack_chain_nodes (on conflict: chain_version_id + logical_node_id)
    UPSERT attack_chain_edges (on conflict: chain_version_id + logical_edge_id)
    UPDATE attack_chains stub (additive backward-compat columns)
    INSERT AuditLog row (action="attack_chain.reconstruct")
    COMMIT

  STEP 25 — RETURN ChainResult
```

---

## 16. Chain Version Concurrency (Correction C14)

### 16.1 Race Condition

Two concurrent reconstruction requests for the same incident must not produce:
- Two chain versions with the same `chain_version` number
- Ambiguous ordering of chain versions

### 16.2 Transaction-Safe Version Allocation

The incident row is locked in STEP 1:
```sql
SELECT id, evidence_version FROM incidents
WHERE id = :incident_id
FOR UPDATE;
```

Within the same transaction:
- Idempotency check (STEP 2): if a chain for this `evidence_version` AND matching `cti_evidence_as_of`
  already exists (and algorithm/catalog versions match), return it without creating a new version
- Version number allocation (STEP 23):
  ```sql
  SELECT COALESCE(MAX(chain_version), 0) + 1
  FROM attack_chain_versions
  WHERE incident_id = :incident_id;
  ```
  This is safe because the `FOR UPDATE` lock on the incident row serializes
  concurrent callers. The second caller blocks at STEP 1 until the first commits.

### 16.3 Retry Behavior

If a `UNIQUE` constraint violation occurs on `(incident_id, chain_version)` despite
the lock (defensive retry path):
- Retry STEP 23 allocation up to 3 times
- If all retries fail → raise internal error; ROLLBACK

### 16.4 Failed Transaction

If any step fails after the transaction begins:
- Full ROLLBACK
- No chain version row persisted
- No partial graph persisted
- Previous chain version remains the authoritative current version
- AuditLog row written with `status="error"` outside the main transaction

### 16.5 Evidence Version Linkage

The `chain_version.evidence_version` exactly matches `Incident.evidence_version` as
read under the `FOR UPDATE` lock. This guarantees the chain is linked to the exact
evidence snapshot that was loaded.

---

## 17. Evidence Versioning

### 17.1 Chain Version Record Fields (updated for Corrections C7, C15, C16)

| Field | Type | Meaning |
|-------|------|---------|
| `id` | UUID PK | Surrogate key |
| `incident_id` | UUID FK | → incidents(id) ON DELETE RESTRICT |
| `chain_canonical_id` | VARCHAR(128) | Deterministic hash (§9.3); includes nodes, edges, algorithm, catalog |
| `chain_version` | Integer | Per-incident sequential counter |
| `evidence_version` | BigInteger | From `Incident.evidence_version` at reconstruction time |
| `event_evidence_as_of` | TIMESTAMPTZ | Max eligible event_timestamp |
| `cti_evidence_as_of` | TIMESTAMPTZ nullable | Max eligible CTI queried_at (NULL if no CTI) |
| `chain_evidence_as_of` | TIMESTAMPTZ | Snapshot boundary = max(event, cti) |
| `generated_at` | TIMESTAMPTZ | Wall-clock reconstruction time — **AUDIT ONLY** |
| `node_count` | Integer | |
| `edge_count` | Integer | |
| `technique_count` | Integer | |
| `tactic_ids_present` | JSONB | Array of distinct tactic IDs found (replaces `highest_tactic`) |
| `reconstruction_warnings` | JSONB | Non-fatal warnings |
| `attck_catalog_version` | VARCHAR(16) | e.g. `"14.1"` |
| `reconstruction_algorithm_version` | VARCHAR(16) | e.g. `"7.0.0"` |
| `truncated` | Boolean | True if any size limit was applied |
| `complete` | Boolean | True if chain is untruncated |

**`tactic_ids_present`** (Correction C16): replaces the removed `highest_tactic` field.
Contains all distinct ATT&CK tactic IDs found across TECHNIQUE nodes in this chain.
Example: `["TA0002", "TA0005", "TA0006"]`
No ordering semantics; no implication of attack progression.

`generated_at` is audit metadata only. It MUST NOT be used to determine evidence
freshness or chain currency.

### 17.2 Staleness Check (Correction C2)

A chain version is considered stale if upstream evidence has advanced beyond the snapshot used during reconstruction. Because Phase 7 independently consumes both normalized events (tracked by `Incident.evidence_version`) and CTI query observations (tracked by `ThreatIntelResult.queried_at`), staleness must be evaluated against **both** independent evidence horizons:

```python
# 1. Determine current eligible CTI horizon across all eligible ThreatIntelResult records
current_cti_evidence_as_of = (
    max(cti.queried_at for cti in eligible_cti_records)
    if eligible_cti_records else None
)

# 2. Evaluate CTI staleness with explicit NULL-horizon comparison logic
if latest_chain_version.cti_evidence_as_of is None and current_cti_evidence_as_of is not None:
    # Latest chain had no CTI, but new CTI evidence has arrived
    cti_stale = True
elif latest_chain_version.cti_evidence_as_of is not None and current_cti_evidence_as_of is not None:
    # Both have CTI horizons: compare timestamps
    cti_stale = (current_cti_evidence_as_of > latest_chain_version.cti_evidence_as_of)
else:
    # Both are NULL, or current is NULL while chain had CTI (no new CTI)
    cti_stale = False

# 3. Evaluate Event staleness via Incident evidence_version
event_stale = (incident.evidence_version > latest_chain_version.evidence_version)

# 4. Final staleness decision
is_stale = event_stale or cti_stale
```

**Key properties:**
- `is_stale` becomes `True` if new events are correlated (`event_stale = True`) **OR** if new CTI observations arrive (`cti_stale = True`), even when `incident.evidence_version` has not changed.
- Does NOT introduce any dependency on Phase 5 risk execution.
- NULL-horizon semantics are explicitly defined without assuming database NULL ordering.

### 17.3 Update Triggers

Reconstruction triggered by:
1. Explicit `POST /attack-chain/incident/{id}/reconstruct`
2. Caller detecting `is_stale = True` (due to event evidence_version increment OR new CTI arrival)

---

## 18. Storage Design

### 18.1 `attack_chain_versions` DDL

```sql
CREATE TABLE attack_chain_versions (
    id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id                    UUID NOT NULL,
    chain_canonical_id             VARCHAR(128) NOT NULL,
    chain_version                  INTEGER NOT NULL,
    evidence_version               BIGINT NOT NULL,
    event_evidence_as_of           TIMESTAMPTZ,
    cti_evidence_as_of             TIMESTAMPTZ,
    chain_evidence_as_of           TIMESTAMPTZ,
    generated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    node_count                     INTEGER NOT NULL DEFAULT 0,
    edge_count                     INTEGER NOT NULL DEFAULT 0,
    technique_count                INTEGER NOT NULL DEFAULT 0,
    tactic_ids_present             JSONB NOT NULL DEFAULT '[]',
    reconstruction_warnings        JSONB NOT NULL DEFAULT '[]',
    attck_catalog_version          VARCHAR(16) NOT NULL,
    reconstruction_algorithm_version VARCHAR(16) NOT NULL,
    truncated                      BOOLEAN NOT NULL DEFAULT FALSE,
    complete                       BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT fk_acv_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
        ON DELETE RESTRICT,   -- prevents silent destruction of historical chain audit trail
    CONSTRAINT uq_acv_incident_version
        UNIQUE (incident_id, chain_version)
);
CREATE INDEX ix_acv_incident_evidence
    ON attack_chain_versions(incident_id, evidence_version DESC);
CREATE INDEX ix_acv_canonical
    ON attack_chain_versions(chain_canonical_id);
```

### 18.2 `attack_chain_nodes` DDL

```sql
CREATE TABLE attack_chain_nodes (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_version_id        UUID NOT NULL
        REFERENCES attack_chain_versions(id) ON DELETE CASCADE,
    logical_node_id         VARCHAR(128) NOT NULL,
    node_type               VARCHAR(32) NOT NULL,
    normalized_event_id     UUID
        REFERENCES normalized_events(id) ON DELETE SET NULL,
    threat_intel_result_id  UUID
        REFERENCES threat_intel_results(id) ON DELETE SET NULL,
    entity_canonical_id     VARCHAR(256),
    entity_type             VARCHAR(32),
    ioc_type                VARCHAR(32),
    ioc_value               VARCHAR(512),
    mitre_technique_id      VARCHAR(32),
    mitre_tactic_ids        JSONB,
    mitre_technique_name    VARCHAR(255),
    mitre_tactic_names      JSONB,
    mitre_mapping_type      VARCHAR(32),
    provenance              VARCHAR(16) NOT NULL,
    evidence_available      BOOLEAN NOT NULL DEFAULT TRUE,
    verification_status     VARCHAR(16) NOT NULL DEFAULT 'VERIFIABLE',
    evidence_strength       FLOAT NOT NULL
        CHECK (evidence_strength BETWEEN 0.0 AND 1.0),
    event_timestamp         TIMESTAMPTZ,
    timestamp_source        VARCHAR(32),
    sequence_index          INTEGER,
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    evidence_snapshot       JSONB NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_acn_chain_logical
        UNIQUE (chain_version_id, logical_node_id)
);
CREATE INDEX ix_acn_event ON attack_chain_nodes(normalized_event_id);
CREATE INDEX ix_acn_chain_type ON attack_chain_nodes(chain_version_id, node_type);
CREATE INDEX ix_acn_entity ON attack_chain_nodes(entity_canonical_id);
CREATE INDEX ix_acn_logical ON attack_chain_nodes(logical_node_id);
```

**ON DELETE SET NULL** on `normalized_event_id` and `threat_intel_result_id`:
Source evidence deletion nullifies the FK but preserves the node row.
`evidence_available` → `False`; `verification_status` → `UNVERIFIABLE`.
UUID values are also captured in `evidence_refs` JSONB for forensic reference
even after the FK is nullified.

### 18.3 `attack_chain_edges` DDL

```sql
CREATE TABLE attack_chain_edges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_version_id        UUID NOT NULL
        REFERENCES attack_chain_versions(id) ON DELETE CASCADE,
    logical_edge_id         VARCHAR(128) NOT NULL,
    src_node_logical_id     VARCHAR(128) NOT NULL,
    dst_node_logical_id     VARCHAR(128) NOT NULL,
    src_node_id             UUID NOT NULL
        REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    dst_node_id             UUID NOT NULL
        REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    edge_type               VARCHAR(32) NOT NULL,
    provenance              VARCHAR(16) NOT NULL,
    implies_causality       BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_available      BOOLEAN NOT NULL DEFAULT TRUE,
    verification_status     VARCHAR(16) NOT NULL DEFAULT 'VERIFIABLE',
    evidence_strength       FLOAT NOT NULL
        CHECK (evidence_strength BETWEEN 0.0 AND 1.0),
    evidence_refs           JSONB NOT NULL DEFAULT '[]',
    evidence_snapshot       JSONB NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ace_chain_logical
        UNIQUE (chain_version_id, logical_edge_id)
);
CREATE INDEX ix_ace_src ON attack_chain_edges(src_node_id);
CREATE INDEX ix_ace_dst ON attack_chain_edges(dst_node_id);
CREATE INDEX ix_ace_chain_type ON attack_chain_edges(chain_version_id, edge_type);
CREATE INDEX ix_ace_chain_logical ON attack_chain_edges(chain_version_id, logical_edge_id);
```

### 18.4 Existing `attack_chains` Stub (Additive & Legacy Confidence Boundary)

Additive columns only — no existing column dropped or modified:

```sql
ALTER TABLE attack_chains
    ADD COLUMN chain_version_id UUID
        REFERENCES attack_chain_versions(id) ON DELETE SET NULL,
    ADD COLUMN evidence_version BIGINT;

COMMENT ON COLUMN attack_chains.confidence IS
    'Legacy compatibility mirror only: ordinal deterministic summary evidence-strength score [0.0, 1.0]; not a probability.';
```

**Legacy `confidence` boundary (Correction C6):**
- Phase 7 canonical semantic field is `evidence_strength` across all node, edge, and version records.
- The pre-existing column `attack_chains.confidence` serves strictly as a backward-compatibility mirror representing the chain's summary evidence strength.
- The Phase 7 reconstruction engine, models, and APIs have **zero semantic dependency** on `confidence`.

### 18.5 Migration Strategy

One new Alembic DDL migration: `<timestamp>_phase_7_attack_chain_schema.py`
DDL only; no data migration.
No Phase 0–6 columns dropped or semantics changed.

### 18.6 Deletion Policy (Correction C9)

| Table | `incident_id` FK | Rationale |
|-------|-----------------|-----------|
| `attack_chain_versions` | `ON DELETE RESTRICT` | Preserves historical chain audit trail; consistent with Phase 5 `incident_risk_scores` pattern |
| `attack_chain_nodes` | `ON DELETE CASCADE` from `attack_chain_versions` | Node is meaningless without its chain version |
| `attack_chain_edges` | `ON DELETE CASCADE` from `attack_chain_versions` | Edge is meaningless without its chain version |

**Consequence:** Deleting an `incident` row is RESTRICTED if any `attack_chain_versions`
record exists for it. Incident deletion requires explicit prior deletion of chain versions,
which requires explicit prior deletion of dependent node/edge rows.

This is intentional: it prevents accidental destruction of historical reconstruction
audit trails. If an explicit incident archival policy is implemented in the future, that
policy must include an explicit chain-version archival step.

**Source-evidence deletion behavior:**
- `normalized_events` row deleted → `attack_chain_nodes.normalized_event_id` SET NULL;
  `evidence_available = False`; `verification_status = UNVERIFIABLE`; `provenance` UNCHANGED
- `threat_intel_results` row deleted → same pattern for `threat_intel_result_id`
- Chain version rows are NOT deleted when source evidence is deleted
- Historical chain versions remain queryable and auditable

### 18.7 Chain Size Limits

| Limit | Value |
|-------|-------|
| Max EVENT nodes per chain | 500 |
| Max SAME_ENTITY edge pairs per entity | 50 |
| Max CORRELATED_WITH pairs per rule group | 100 |
| Max NETWORK_RELATION edges per chain | 200 |
| Max SAME_AGENT edge pairs | 50 |
| Max total edges per chain | 2000 |
| Reconstruction timeout | 30 seconds |

Limits exceeded → truncation + `reconstruction_warnings` entry:
```json
{"type": "limit_exceeded", "limit": "<name>", "actual": <count>}
```
`truncated = True`, `complete = False` set on `attack_chain_versions`.

---

## 19. API Design

All endpoints additive. No existing endpoint is modified.

### 19.1 `GET /attack-chain/incident/{incident_id}`

Returns the current (latest) reconstructed chain.

**Response:**
```json
{
  "incident_id": "uuid",
  "chain_version": 3,
  "evidence_version": 7,
  "event_evidence_as_of": "ISO-8601",
  "cti_evidence_as_of": "ISO-8601 or null",
  "chain_evidence_as_of": "ISO-8601",
  "generated_at": "ISO-8601 [audit metadata only — does not indicate freshness]",
  "is_stale": false,
  "complete": true,
  "truncated": false,
  "node_count": 12,
  "edge_count": 18,
  "technique_count": 3,
  "tactic_ids_present": ["TA0002", "TA0005"],
  "attck_catalog_version": "14.1",
  "reconstruction_algorithm_version": "7.0.0",
  "reconstruction_warnings": [],
  "nodes": [ <AttackChainNodeResponse> ],
  "edges": [ <AttackChainEdgeResponse> ]
}
```

**Errors:** `404` if no chain exists; `422` if `incident_id` is not a valid UUID.

### 19.2 `GET /attack-chain/incident/{incident_id}/history`

All historical chain version summaries (no nodes/edges).
Paginated: `page` (default 1), `page_size` (default 20, max 100).

### 19.3 `GET /attack-chain/{chain_id}`

Specific chain version by UUID.

### 19.4 `POST /attack-chain/incident/{incident_id}/reconstruct`

Triggers synchronous reconstruction (timeout 30 s).
- Idempotent if evidence snapshot is unchanged across `(incident_id, evidence_version, cti_evidence_as_of, algorithm_version, catalog_version)`:
  returns `{"reconstructed": false, "message": "chain is current"}`
- Returns new chain if reconstruction occurred (new events OR advanced CTI horizon): `{"reconstructed": true, ...}`

### 19.5 `GET /attack-chain/incident/{incident_id}/timeline`

Ordered EVENT nodes only (chronological; no full graph).
Includes `event_evidence_as_of`, `cti_evidence_as_of`, `chain_evidence_as_of`.

### 19.6 `AttackChainNodeResponse`

```json
{
  "node_id": "uuid",
  "logical_node_id": "64-char-hex",
  "node_type": "EVENT|CTI_MATCH|ENTITY|TECHNIQUE",
  "provenance": "OBSERVED|INFERRED|UNKNOWN",
  "evidence_available": true,
  "verification_status": "VERIFIABLE|UNVERIFIABLE",
  "evidence_strength": 0.80,
  "sequence_index": 3,
  "event_timestamp": "ISO-8601 or null",
  "timestamp_source": "event_timestamp|wazuh_timestamp|ingestion_fallback",
  "normalized_event_id": "uuid or null",
  "threat_intel_result_id": "uuid or null",
  "entity_canonical_id": "string or null",
  "entity_type": "HOST|USER|IP|... or null",
  "ioc_type": "ip|domain|url|hash|... or null",
  "ioc_value": "string or null",
  "mitre_technique_id": "T1059 or null",
  "mitre_tactic_ids": ["TA0002"] ,
  "mitre_technique_name": "Command and Scripting Interpreter or null",
  "mitre_tactic_names": {"TA0002": "Execution"},
  "mitre_mapping_type": "DIRECT_MAPPING|INFERRED_MAPPING|UNKNOWN or null",
  "evidence_refs": [{"table": "normalized_events", "id": "uuid"}],
  "forensic_available": true
}
```

`RawAlert.raw_json` and `ThreatIntelResult.raw_response_text` are NOT returned.
Indicated by `forensic_available: true/false`.

### 19.7 `AttackChainEdgeResponse`

```json
{
  "edge_id": "uuid",
  "logical_edge_id": "64-char-hex",
  "edge_type": "CHRONOLOGICAL_NEXT",
  "src_node_logical_id": "64-char-hex",
  "dst_node_logical_id": "64-char-hex",
  "provenance": "INFERRED",
  "implies_causality": false,
  "evidence_available": true,
  "verification_status": "VERIFIABLE",
  "evidence_strength": 0.56,
  "evidence_refs": [{"table": "incident_events", "id": "uuid"}]
}
```

### 19.8 Truncation Transparency

If `truncated = True`, the API MUST expose this explicitly:
```json
{
  "complete": false,
  "truncated": true,
  "reconstruction_warnings": [
    {"type": "limit_exceeded", "limit": "max_event_nodes", "actual": 712}
  ]
}
```

A partial graph must NEVER be silently presented as a complete reconstruction.

---

## 20. Security

| Control | Implementation |
|---------|---------------|
| Authorization | `X-Admin-Key` (Phase 0 mechanism); no new auth in Phase 7 |
| Input validation | `incident_id` must be valid UUID; reject with HTTP 422 |
| Evidence validation | Referenced UUIDs validated before reconstruction |
| Resource limits | Hard limits per §18.7 |
| Graph injection protection | Nodes/edges from verified DB records only |
| Canonical ID protection | SHA-256 over sanitized internal values; user input does not flow into logical IDs |
| Sensitive data | `raw_json` and `raw_response_text` omitted from API; `forensic_available` flag |
| Audit trail | Every reconstruction → AuditLog row (`action="attack_chain.reconstruct"`) |
| SQL injection | SQLAlchemy ORM parameterized queries |
| Concurrency | Incident row-level lock during version allocation |

---

## 21. Idempotency (Correction C2)

A reconstruction request is idempotent and returns the existing chain version when the evidence snapshot is unchanged across all five dimensions:

1. `incident_id`
2. `event evidence version` (`Incident.evidence_version`)
3. `eligible CTI evidence horizon` (`cti_evidence_as_of`)
4. `reconstruction_algorithm_version`
5. `attck_catalog_version`

For an identical evidence snapshot:
- Every `logical_node_id` is identical
- Every `logical_edge_id` is identical
- `chain_canonical_id` is identical
- All `evidence_strength` values are identical
- Second call to `POST /attack-chain/incident/{id}/reconstruct` with unchanged snapshot returns existing chain version without DB write
- Row-level lock on `incidents` row prevents concurrent duplicate allocations

If either `Incident.evidence_version` has incremented OR `current_cti_evidence_as_of > latest_chain.cti_evidence_as_of`, idempotency does not hold: the existing chain is recognized as stale and a new chain version is generated.

`generated_at` (wall-clock) differs between runs but does not affect logical identity or freshness.

---

## 22. Late-Arriving Evidence (Corrections C2, C3)

Phase 7 explicitly distinguishes late-arriving event evidence from late-arriving CTI evidence:

### 22.1 Late-Arriving Events

```
New event arrives & correlated
    ↓
Incident.evidence_version increments
    ↓
is_stale becomes True (event_stale = True)
    ↓
POST /attack-chain/incident/{id}/reconstruct
    ↓
Full evidence snapshot loaded (including late event)
    ↓
Late events positioned by event_timestamp (NOT added_at or created_at)
    ↓
added_at used ONLY to compute ingestion lag (reconstruction_warnings)
    ↓
All edges recomputed from scratch
    ↓
New chain_version persisted; previous chain_version preserved in attack_chain_versions
```

- Events ordered by `event_timestamp`. A late event whose `event_timestamp` falls between earlier events is inserted in its correct chronological position.
- Ingestion lag measured by `added_at - event_timestamp`.

### 22.2 Late-Arriving CTI Evidence

```
New CTI observation query completes
    ↓
ThreatIntelResult written with queried_at
    ↓
Incident.evidence_version remains unchanged
    ↓
current_cti_evidence_as_of advances
    ↓
is_stale becomes True (cti_stale = True)
    ↓
POST /attack-chain/incident/{id}/reconstruct
    ↓
Reconstruction loads updated CTI evidence set
    ↓
New CTI_MATCH nodes (if matched=True) and INFERRED IOC_MATCH edges generated
    ↓
New chain version persisted with updated cti_evidence_as_of and chain_evidence_as_of
    ↓
Previous chain version preserved in attack_chain_versions
```

- CTI arrival does **NOT** require modifying Phase 3's `incident.evidence_version`.
- Phase 7 detects CTI freshness independently via `cti_evidence_as_of`.
- Neither horizon is substituted for the other.

---

## 23. Conflict Resolution

| Conflict | Resolution |
|---------|-----------|
| Equal `event_timestamp` | Tiebreak by `normalized_event_id` byte order (deterministic) |
| Two hostnames, same `agent_id` | Two HOST entities; SAME_AGENT edge links them |
| Multiple CTI records for same IOC+source | All preserved as separate CTI_MATCH nodes; verdict-change warning |
| Same technique from multiple events | One TECHNIQUE node; multiple TECHNIQUE_SUPPORT edges |
| Conflicting MITRE mappings (direct vs. rule) | DIRECT_MAPPING takes precedence on TECHNIQUE node; INFERRED also included via separate edge if rule-inherited |
| NULL `event_timestamp` | Fallback per §7.4; warning added |
| Evidence deleted post-construction | Node/edge preserved; `evidence_available = False`; `verification_status = UNVERIFIABLE`; provenance UNCHANGED |
| Contradictory CTI verdicts | Both CTI_MATCH nodes preserved; verdict-changed warning |
| Invalid IP format | Entity skipped; warning added |
| Chain version race | Row-level lock serializes; idempotency check prevents double reconstruction |

---

## 24. Failure Modes

| Failure | Behavior |
|---------|---------|
| Incident not found | HTTP 404 |
| No events for incident | Empty chain, `node_count=0`, warning `{"type": "no_events"}` |
| All events NULL timestamps | Reconstruct using fallback timestamps; warn per event |
| ATT&CK catalog missing | Reconstruct proceeds; names = null; catalog_version = "UNKNOWN"; warning logged |
| Chain stale at read time | Return chain with `is_stale=true`; do not auto-reconstruct |
| Reconstruction timeout (>30s) | HTTP 503; ROLLBACK; previous version preserved |
| DB write failure | ROLLBACK; previous version preserved; HTTP 500 |
| Concurrent lock wait timeout | HTTP 503 after timeout; no partial state committed |
| Invalid IP address in event | Entity type skipped; warning added; reconstruction continues |

---

## 25. Performance Methodology

### 25.1 Design Targets (not measured results — not yet implemented)

| Metric | Target | Method |
|--------|--------|--------|
| Reconstruction latency (50 events) | < 2 s | pytest-benchmark |
| Reconstruction latency (200 events) | < 10 s | pytest-benchmark |
| Reconstruction latency (500 events) | < 30 s | pytest-benchmark |
| Memory (500-event chain) | < 256 MB | memory_profiler |

> Targets are design parameters. No target is claimed as achieved until the
> implementation is built and benchmarked. Actual results must be reported
> post-implementation.

### 25.2 Benchmark Datasets

Controlled deterministic datasets (not from production):
- 50 events, 5 CTI matches — small
- 200 events, 20 CTI matches — medium
- 500 events, 50 CTI matches — large (at node limit)

Generated with deterministic seeds. Benchmarks report:
- Graph construction latency (algorithm only)
- Persistence latency (DB writes)
- Memory usage
- Node count
- Edge count

---

## 26. Testing Strategy

Frozen baseline: **243 passed, 2 skipped** (Phase 0–6). Must remain green.
Phase 7 adds `tests/attack_chain/`.

### 26.1 Identity Tests

| Test | Requirement |
|------|-------------|
| `test_logical_node_id_determinism` | Same evidence → same logical_node_id |
| `test_logical_edge_id_determinism` | Same edge type + endpoints → same logical_edge_id |
| `test_chain_canonical_id_includes_edges` | Same nodes + different edges → different chain_canonical_id |
| `test_chain_canonical_id_includes_algorithm_version` | Different algorithm version → different chain_canonical_id |
| `test_chain_canonical_id_includes_catalog_version` | Different catalog version → different chain_canonical_id |
| `test_chain_canonical_id_full_determinism` | Same evidence + same versions → identical chain_canonical_id |
| `test_logical_node_id_stable_across_chain_versions` | Same event → same logical_node_id in chain v1 and v2 |

### 26.2 Provenance Tests

| Test | Requirement |
|------|-------------|
| `test_provenance_event_observed` | EVENT nodes always OBSERVED |
| `test_provenance_entity_observed` | ENTITY nodes always OBSERVED |
| `test_provenance_cti_match_observed` | CTI_MATCH nodes always OBSERVED |
| `test_provenance_event_entity_observed` | EVENT_ENTITY edges always OBSERVED |
| `test_provenance_ioc_match_inferred` | IOC_MATCH edges always INFERRED |
| `test_provenance_same_entity_inferred` | SAME_ENTITY edges always INFERRED |
| `test_provenance_same_agent_inferred` | SAME_AGENT edges always INFERRED |
| `test_provenance_correlated_with_inferred` | CORRELATED_WITH edges always INFERRED |
| `test_provenance_network_relation_inferred` | NETWORK_RELATION edges always INFERRED |
| `test_provenance_chronological_next_inferred` | CHRONOLOGICAL_NEXT edges always INFERRED |
| `test_provenance_technique_direct_observed` | TECHNIQUE_SUPPORT OBSERVED for DIRECT_MAPPING |
| `test_provenance_technique_rule_inferred` | TECHNIQUE_SUPPORT INFERRED for INFERRED_MAPPING |
| `test_mitre_mapping_type_separate_from_provenance` | Both fields independently set |

### 26.3 CTI Tests

| Test | Requirement |
|------|-------------|
| `test_unmatched_cti_preserved_in_phase4_history` | Unmatched CTI records remain in Phase 4 history |
| `test_unmatched_cti_does_not_create_cti_match_node` | Unmatched CTI records do not create CTI_MATCH nodes in graph |
| `test_cti_horizon_includes_eligible_cti_records` | cti_evidence_as_of includes all eligible CTI records regardless of match status |
| `test_matched_cti_creates_cti_match_node` | ThreatIntelResult with matched=True creates CTI_MATCH node |
| `test_cti_history_preserved_no_dedup` | Multiple records for same IOC+source → multiple CTI_MATCH nodes |
| `test_cti_verdict_change_warning` | MALICIOUS then BENIGN → reconstruction_warning |
| `test_cti_current_interpretation_latest` | Latest eligible record used for current-state summary |
| `test_cti_ioc_type_ioc_value_on_node` | CTI_MATCH node exposes ioc_type and ioc_value |
| `test_cti_temporal_eligibility` | Records with queried_at > T_reconstruction excluded |
| `test_ioc_match_edge_linkage` | CTI node IOC value matches entity canonical form |

### 26.4 Evidence Deletion Tests

| Test | Requirement |
|------|-------------|
| `test_node_preserved_after_source_deleted` | Node row exists; `evidence_available = False` |
| `test_edge_preserved_after_source_deleted` | Edge row exists; `evidence_available = False` |
| `test_provenance_unchanged_after_deletion` | `provenance` unchanged (OBSERVED stays OBSERVED) |
| `test_verification_status_unverifiable` | `verification_status = UNVERIFIABLE` after deletion |
| `test_evidence_refs_preserved_in_jsonb` | UUID still in `evidence_refs` JSONB after FK nullified |
| `test_orphaned_evidence_warning` | `reconstruction_warning` added |

### 26.5 Temporal Tests

| Test | Requirement |
|------|-------------|
| `test_temporal_ordering_asc` | Events ordered by event_timestamp ASC, id tiebreak |
| `test_equal_timestamp_uuid_tiebreak` | Equal timestamps → deterministic UUID byte-order tiebreak |
| `test_timestamp_fallback_tier2` | NULL event_timestamp → wazuh_timestamp |
| `test_timestamp_fallback_tier3` | NULL event_timestamp AND wazuh_timestamp → ingestion_fallback |
| `test_late_event_positioned_by_event_timestamp` | Late event at correct chronological position |
| `test_ingestion_lag_uses_added_at_not_ordering` | `added_at` used only for lag measurement |
| `test_cti_queried_at_eligibility` | CTI after T_reconstruction excluded |
| `test_event_evidence_as_of` | `event_evidence_as_of` = max(event_timestamp) |
| `test_cti_evidence_as_of` | `cti_evidence_as_of` = max(queried_at) of eligible CTI |
| `test_chain_evidence_as_of_no_phase5` | Reconstruct succeeds when `risk_evidence_as_of` is NULL |

### 26.6 Graph Structure Tests

| Test | Requirement |
|------|-------------|
| `test_event_entity_edges_created` | EVENT_ENTITY edges for each extracted entity |
| `test_technique_deduplication` | Same technique from two events → one TECHNIQUE node |
| `test_no_tactic_progression_edges` | No TACTIC_PROGRESSION edge type under any input |
| `test_no_process_relation_edges` | No PROCESS_RELATION edge type under any input |
| `test_implies_causality_always_false` | `implies_causality = False` on all edges |
| `test_network_relation_temporal_constraint` | E_i.timestamp > E_j.timestamp → no NETWORK_RELATION(i→j) |
| `test_network_relation_ip_canonicalization` | Matching IPs in different textual forms create edge |
| `test_same_entity_between_events` | Two events sharing entity → SAME_ENTITY edge |
| `test_same_agent_between_entities` | Two entities sharing agent_id → SAME_AGENT edge |
| `test_chronological_next_non_causal_documented` | Edge `implies_causality = False` |

### 26.7 Entity and IP Tests

| Test | Requirement |
|------|-------------|
| `test_entity_canonicalization_all_types` | All 10 entity types; NULL fields excluded |
| `test_ip_canonicalization_ipv4` | `192.168.001.001` → `192.168.1.1` |
| `test_ip_canonicalization_ipv6_compressed` | `2001:0db8:0000::0001` → `2001:db8::1` |
| `test_ip_canonicalization_ipv6_equivalent` | Two textual forms of same address → same entity |
| `test_ip_invalid_skipped_with_warning` | Invalid IP string → entity skipped + warning |
| `test_process_entity_event_scoped` | Same process_name + pid in two events → two PROCESS nodes |
| `test_process_entity_no_lineage_inference` | No parent-child PROCESS edges |
| `test_url_normalization` | URL fragment stripped; query params sorted |
| `test_null_entity_fields_skipped` | NULL field → no entity extracted |
| `test_hostname_lowercased` | `Host.Name` → `host.name` |
| `test_same_agent_source_event_resolution` | SAME_AGENT resolves agent_id from source NormalizedEvent telemetry |
| `test_same_agent_inferred_provenance` | SAME_AGENT edges are always INFERRED |
| `test_same_agent_null_agent_excluded` | Entities with null agent_id excluded from SAME_AGENT grouping |

### 26.8 Concurrency and Staleness Tests

| Test | Requirement |
|------|-------------|
| `test_concurrent_reconstruct_unique_versions` | Two simultaneous requests → distinct chain_version numbers |
| `test_idempotent_same_evidence_version` | Reconstruct twice, same evidence_version → second is no-op |
| `test_failed_transaction_no_partial_state` | DB failure mid-reconstruction → ROLLBACK; previous version current |
| `test_stale_detection` | `is_stale` correct after evidence_version increment |
| `test_new_cti_marks_chain_stale_without_event_version_change` | New CTI record advances cti_evidence_as_of, setting is_stale=True without event_version change |
| `test_cti_horizon_participates_in_currentness` | cti_evidence_as_of participates in chain currentness evaluation |
| `test_no_cti_to_cti_present_does_not_mark_stale` | If both chain and current CTI horizons are NULL, CTI does not mark chain stale |
| `test_same_event_version_and_same_cti_horizon_is_idempotent` | Reconstruct with unchanged event_version and cti_evidence_as_of returns existing version |

### 26.9 Evidence-Strength Tests

| Test | Requirement |
|------|-------------|
| `test_evidence_strength_node_formula` | Values match §14.2 formula |
| `test_evidence_strength_edge_formula` | Values match §14.3 formula |
| `test_evidence_strength_bounds` | All values in [0.0, 1.0] |
| `test_evidence_strength_not_probability` | Deterministic ordinal; no statistical claim |
| `test_evidence_strength_inferred_less_than_observed` | INFERRED base < OBSERVED base (0.6 < 1.0) |

### 26.10 Determinism Regression (N=10)

Ten repeated reconstructions of the same `(incident_id, evidence_version)`:
- Equal `node_count`
- Equal set of `logical_node_id` values
- Equal `edge_count`
- Equal set of `logical_edge_id` values
- Equal `chain_canonical_id`

`generated_at` expected to differ; excluded from comparison.

### 26.11 API Contract Tests

| Test | Requirement |
|------|-------------|
| `test_api_get_chain_200` | Returns correct structure |
| `test_api_response_has_evidence_strength_not_confidence` | Field named `evidence_strength` |
| `test_no_phase7_semantic_dependency_on_confidence` | Grep check confirms zero non-stub semantic references to confidence in Phase 7 |
| `test_api_response_has_three_evidence_horizons` | `event_evidence_as_of`, `cti_evidence_as_of`, `chain_evidence_as_of` all present |
| `test_api_response_has_tactic_ids_present` | `tactic_ids_present` array present; `highest_tactic` absent |
| `test_api_response_no_raw_json` | `raw_json` absent; `forensic_available` present |
| `test_api_response_complete_true_when_untruncated` | `complete = True`, `truncated = False` |
| `test_api_response_truncated_explicit` | `complete = False`, `truncated = True` when limit exceeded |
| `test_api_history` | Returns all chain versions |
| `test_api_reconstruct_idempotent` | Same evidence_version → `reconstructed = false` |
| `test_api_reconstruct_new_version` | After evidence change → `reconstructed = true` |
| `test_api_get_chain_404` | No chain → HTTP 404 |
| `test_api_invalid_uuid` | Non-UUID incident_id → HTTP 422 |
| `test_api_implies_causality_false` | All edge objects have `implies_causality = false` |
| `test_api_audit_log_written` | Every reconstruction → AuditLog record |

---

## 27. Research Evaluation Methodology

### 27.1 Current Dataset Status

> The current production Wazuh database contains no incident-level labeled attack-chain
> ground truth. Quantitative validation of reconstruction accuracy against known attack
> sequences is not possible with the production dataset.
>
> This mirrors the Phase 6 constraint (DATASET_STATUS = INSUFFICIENT for ML).
> No fabricated evaluation results will be reported.

### 27.2 Proposed Evaluation Dataset (Future Work)

**Method:** Replay known attack simulations (Atomic Red Team, CALDERA) against a
Wazuh-monitored test host. Capture resulting Wazuh telemetry. Ground truth = pre-defined
ATT&CK technique sequence in known execution order.

**Measure:** Does the reconstructed chain recover evidence of those techniques?
Does the reconstructed `event_timestamp` order match known execution order?

Dataset must come from real Wazuh telemetry of controlled executions.
Must NOT be synthetically fabricated.

### 27.3 Evaluation Metrics

| Metric | Formula | Notes |
|--------|---------|-------|
| Chain Completeness | `technique_nodes_found / ground_truth_techniques` | Technique coverage only |
| Temporal Ordering Accuracy | Kendall tau: reconstructed EVENT order vs. ground-truth execution order | Does not measure causality |
| Evidence Coverage | `events_in_chain / total_incident_events` | |
| Observed Relationship Ratio | `OBSERVED_edges / total_edges` | |
| Inferred Relationship Ratio | `INFERRED_edges / total_edges` | |
| Duplicate Node Rate | `pre_dedup_nodes / post_dedup_nodes - 1` | Should be 0 by design |
| Orphan Evidence Rate | `nodes_with_evidence_available_false / total_nodes` | |
| Deterministic Reproducibility | `1.0` if N=10 runs produce identical `chain_canonical_id` | Must be 1.0 |
| Reconstruction Latency | p50, p95, p99 in ms | |
| Late-Evidence Graph Delta | `abs(new_node_count - old_node_count) / old_node_count` | |
| False Inference Rate | `incorrect_inferred_edges / ground_truth_edges` | Only measurable with controlled ground-truth dataset |

All metrics measure reconstruction fidelity. None measure attacker-intent prediction.

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
| `attack_chain_truncated_total` | Counter | `limit_type` |

Prometheus stubs (no-op when `prometheus_client` unavailable), consistent with
Phase 6 `ml/observability.py` pattern.

---

## 29. Phase Boundaries

### In Scope — Phase 7

- `attack_chain/` package (reconstruction engine)
- Three new graph tables + Alembic DDL migration
- Entity canonicalization (10 entity types)
- Deterministic IP canonicalization using Python `ipaddress` stdlib
- Chronological ordering with deterministic tiebreaking
- 8 edge types (EVENT_ENTITY, CHRONOLOGICAL_NEXT, SAME_ENTITY, CORRELATED_WITH,
  IOC_MATCH, TECHNIQUE_SUPPORT, SAME_AGENT, NETWORK_RELATION)
- ATT&CK technique/tactic name resolution from bundled catalog (no tactic-ordering inference)
- Provenance (OBSERVED/INFERRED/UNKNOWN) on every node and edge
- Evidence availability state (VERIFIABLE/UNVERIFIABLE) separate from provenance
- Evidence-strength formula (deterministic ordinal; not probabilistic)
- Three evidence horizon fields (event_evidence_as_of, cti_evidence_as_of, chain_evidence_as_of)
- Chain canonical ID incorporating nodes, edges, algorithm version, catalog version
- Chain versioning keyed on `evidence_version`
- CTI historical preservation
- Late-arriving evidence handling
- Idempotent reconstruction with transaction-safe version allocation
- 5 additive REST API endpoints
- AuditLog integration
- Prometheus observability stubs
- Unit and integration tests

### Out of Scope — Phase 7

| Feature | Phase |
|---------|-------|
| Automated containment (firewall, isolation, kill) | Phase 8 |
| SOAR integration | Phase 8 |
| Active Response | Phase 8 |
| Response recommendations | Phase 8 |
| Frontend / dashboard | Phase 9+ |
| LLM reasoning / narrative generation | Phase 9+ |
| Multi-tenancy | Phase 9+ |
| Live TAXII/STIX ATT&CK feed | Phase 9+ |
| Autonomous response decisions | Phase 9+ |
| Production ML training | Not in Phase 7 scope |
| New external CTI providers | Phase 9+ |

---

## 30. Implementation Sequence

| Step | Task | Dependency |
|------|------|-----------|
| 1 | Read Phase 7 Rev3 plan in full; document any unresolved ambiguity before coding | None |
| 2 | `attack_chain/constants.py` — enums, limits, edge weights, provenance, algorithm version | None |
| 3 | `attack_chain/ip_utils.py` — deterministic IP canonicalization using `ipaddress` stdlib | constants |
| 4 | `attack_chain/entity.py` — entity extraction, canonicalization for all 10 entity types | constants, ip_utils |
| 5 | `attack_chain/mitre.py` — catalog loader, name resolution (no tactic-ordering logic) | None |
| 6 | `attack_chain/data/attck_catalog.json` — bundled ATT&CK technique+tactic catalog | mitre.py |
| 7 | `attack_chain/evidence_strength.py` — node and edge evidence-strength formulas | constants |
| 8 | Alembic DDL migration — 3 new tables + attack_chains additive columns | None |
| 9 | `attack_chain/models.py` — SQLAlchemy ORM for attack_chain_versions/nodes/edges | Migration |
| 10 | `attack_chain/algorithm.py` — reconstruction steps 1–25 per §15 | entity, mitre, evidence_strength, models |
| 11 | `attack_chain/service.py` — orchestration, transaction management, lock, persistence | algorithm, models |
| 12 | `attack_chain/observability.py` — Prometheus stubs | constants |
| 13 | API endpoints in `backend/app/main.py` (additive) | service.py |
| 14 | `tests/attack_chain/test_entity.py` | entity, ip_utils |
| 15 | `tests/attack_chain/test_evidence_strength.py` | evidence_strength |
| 16 | `tests/attack_chain/test_algorithm.py` | algorithm |
| 17 | `tests/attack_chain/test_api.py` | API |
| 18 | `tests/attack_chain/test_determinism.py` — N=10 regression | All |
| 19 | Run full test suite — all Phase 0–6 (243+2) + Phase 7 must pass | All |
| 20 | Phase 7 git checkpoint and tag | Tests green |

---

## 31. Acceptance Criteria

| Criterion | Verification |
|-----------|-------------|
| No `TACTIC_PROGRESSION` edge type | `grep -r TACTIC_PROGRESSION attack_chain/` → 0 results |
| No `PROCESS_RELATION` edge type | `grep -r PROCESS_RELATION attack_chain/` → 0 results |
| `CHRONOLOGICAL_NEXT` is INFERRED | Unit test |
| `CORRELATED_WITH` is INFERRED | Unit test |
| `SAME_ENTITY` is INFERRED | Unit test |
| `SAME_AGENT` is INFERRED | Unit test |
| `SAME_AGENT` resolves `agent_id` from source `NormalizedEvent` | Unit test |
| `IOC_MATCH` is INFERRED | Unit test |
| `EVENT_ENTITY` is OBSERVED | Unit test |
| New CTI evidence makes chain stale without `evidence_version` changing | Integration test |
| CTI horizon participates in currentness and idempotency | Unit/integration test |
| Unmatched CTI does not create `CTI_MATCH` nodes | Unit test |
| Historical CTI records remain preserved in Phase 4 database | Integration test |
| Network port/protocol fields are contextual in evidence snapshot | Schema review / unit test |
| Legacy `confidence` has compatibility-only semantics | Unit test: mirror only |
| No Phase 7 semantic dependency on legacy `confidence` | `grep -r confidence attack_chain/` → zero non-stub references |
| `implies_causality = False` on all edges | DB constraint + unit test |
| `evidence_strength` used (not `confidence`) | `grep confidence attack_chain/` → zero non-stub references |
| `chain_canonical_id` includes both nodes AND edges | Unit test: same nodes + different edges → different ID |
| `reconstruction_algorithm_version` stored and in canonical ID | Unit test |
| `attck_catalog_version` stored and in canonical ID | Unit test |
| `chain_evidence_as_of` independent of Phase 5 | Unit test: reconstruct with NULL `risk_evidence_as_of` succeeds |
| `event_evidence_as_of` and `cti_evidence_as_of` both present | Integration test |
| Evidence deletion preserves provenance | Unit test: provenance unchanged after deletion |
| `evidence_available = False` after source deleted | Unit test |
| `verification_status = UNVERIFIABLE` after source deleted | Unit test |
| `attack_chain_versions.incident_id` ON DELETE RESTRICT | DDL inspection |
| `tactic_ids_present` present; `highest_tactic` absent | Integration test |
| IP canonicalization deterministic for IPv6 | Unit test: equivalent textual forms → same entity |
| `PROCESS` entity is event-scoped | Unit test: two events same process → two PROCESS nodes |
| Chain version allocation transaction-safe | Concurrency test |
| Truncated chain explicitly marked | Integration test: `complete=False`, `truncated=True` |
| All Phase 0–6 tests (243+2) remain green | CI run |
| Phase 7 coverage ≥ 90% of `attack_chain/` | pytest-cov |
| No Phase 0–6 source files modified | `git diff phase-6-complete..HEAD --name-only` |
| No secrets committed | Secret scan |
| AuditLog written per reconstruction | Integration test |

---

## 32. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `SAME_ENTITY` edge explosion for shared IPs (e.g., gateway) | High | High | 50-pair limit per entity_canonical_id |
| `NETWORK_RELATION` still too permissive despite temporal constraint | Medium | Medium | Explicit non-causal documentation; 200-edge limit; remove from V1 if low research value |
| ATT&CK catalog version drift from live registry | Medium | Low | `attck_catalog_version` recorded; no live internet access required |
| MITRE technique IDs absent from most events | High | Medium | Chain reconstructs without TECHNIQUE nodes; valid result |
| Reconstruction > 30s for large incident | Low | Medium | 500-node hard limit + graceful truncation |
| No labeled ground-truth dataset | High | Medium | Explicitly documented; controlled simulation evaluation proposed |
| Concurrent lock wait timeout under high load | Low | Low | Timeout → HTTP 503; no partial state |
| IPv6 representation diversity in raw Wazuh data | Low | Medium | `ipaddress` stdlib handles all RFC-compliant forms |
| PID reuse causing incorrect process merging | High | Low | Event-scoped PROCESS identity eliminates merging problem |
| CTI historical records growing large for high-traffic IOCs | Medium | Low | Bounded per incident; no deduplication removes records |

---

## 33. Final Manual-Review Checklist

- [ ] Revision 3 content preserved unless explicitly corrected
- [ ] `TACTIC_PROGRESSION` does not exist
- [ ] ATT&CK tactic ordering is not used for graph inference
- [ ] `PROCESS_RELATION` is removed
- [ ] `SAME_ENTITY` provenance is INFERRED
- [ ] `SAME_AGENT` provenance is INFERRED
- [ ] `SAME_AGENT` resolves agent_id from source NormalizedEvent evidence
- [ ] `IOC_MATCH` provenance is INFERRED
- [ ] CTI node provenance remains OBSERVED
- [ ] `EVENT_ENTITY` direct evidence edge exists (OBSERVED, EVENT → ENTITY)
- [ ] MITRE mapping type is a separate dimension from graph provenance
- [ ] `CTI_MATCH` nodes explicitly expose `ioc_type` and `ioc_value`
- [ ] CTI historical records are never discarded
- [ ] Unmatched CTI records do not become CTI_MATCH nodes
- [ ] Matched CTI records become CTI_MATCH nodes
- [ ] `chain_evidence_as_of` does not depend on Phase 5
- [ ] `event_evidence_as_of` and `cti_evidence_as_of` explicitly distinguished
- [ ] Event and CTI evidence horizons remain independent
- [ ] New CTI evidence can make a chain stale without changing Incident.evidence_version
- [ ] `cti_evidence_as_of` participates in chain currentness
- [ ] CTI NULL-horizon comparison semantics are explicit
- [ ] All staleness definitions include the independent CTI horizon
- [ ] Generated wall-clock time does not determine freshness
- [ ] Evidence deletion does NOT rewrite historical provenance
- [ ] `evidence_available` and `verification_status` fields separate from provenance
- [ ] Node and edge deletion behavior is documented
- [ ] Historical chain versions protected by `ON DELETE RESTRICT` on `attack_chain_versions.incident_id`
- [ ] `NETWORK_RELATION` requires temporal ordering constraint (`timestamp_i <= timestamp_j`)
- [ ] `NETWORK_RELATION` explicitly non-causal; docs state it does not establish lateral movement
- [ ] Network ports/protocol are explicitly contextual fields in V1 (not inference requirements)
- [ ] IP canonicalization uses Python `ipaddress` stdlib deterministically
- [ ] `PROCESS` entity is event-scoped; PID reuse caveat documented
- [ ] Chain version allocation uses `SELECT ... FOR UPDATE` row lock
- [ ] `chain_canonical_id` includes both sorted node IDs AND sorted edge IDs
- [ ] `chain_canonical_id` includes `reconstruction_algorithm_version`
- [ ] `chain_canonical_id` includes `attck_catalog_version`
- [ ] `highest_tactic` removed; replaced by `tactic_ids_present` array
- [ ] `CHRONOLOGICAL_NEXT` is explicitly non-causal; `implies_causality = False`
- [ ] Evidence strength is explicitly non-probabilistic
- [ ] Legacy `confidence` is compatibility-only
- [ ] No Phase 7 algorithm uses `confidence` semantically
- [ ] N=10 determinism testing specified
- [ ] Same nodes + different edges → different `chain_canonical_id` test required
- [ ] API response exposes `event_evidence_as_of`, `cti_evidence_as_of`, `chain_evidence_as_of`
- [ ] Truncated reconstructions explicitly marked (`complete = False`, `truncated = True`)
- [ ] Phase 0–6 frozen baseline 243 passed, 2 skipped
- [ ] No implementation performed in this revision
- [ ] No migration created in this revision
- [ ] No tests executed in this revision
- [ ] No Git commit/tag/push performed in this revision

---

**PLAN REVISION 4 COMPLETE — AWAITING MANUAL REVIEW**
