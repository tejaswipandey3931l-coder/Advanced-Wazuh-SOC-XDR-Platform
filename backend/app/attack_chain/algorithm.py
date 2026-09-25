import hashlib
import uuid
import json
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict

from app.attack_chain.constants import (
    Provenance, EdgeType, NodeType, ALGORITHM_VERSION, LIMITS
)
from app.attack_chain.entity import extract_entities_from_event, EntityInfo
from app.attack_chain.ip_utils import canonical_ip
from app.attack_chain.mitre import MitreCatalog
from app.attack_chain.evidence_strength import calculate_node_evidence_strength, calculate_edge_evidence_strength

from app.models.incident import Incident
from app.models.normalized_event import NormalizedEvent
from app.models.incident_event import IncidentEvent
from app.models.threat_intel_result import ThreatIntelResult
from app.models.correlation_rule import CorrelationRule
from app.attack_chain.models import AttackChainVersion, AttackChainNode, AttackChainEdge

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

class AttackChainBuilder:
    def __init__(
        self,
        incident_id: uuid.UUID,
        evidence_version: int,
        events: List[NormalizedEvent],
        incident_events: List[IncidentEvent],
        cti_results: List[ThreatIntelResult],
        rules: List[CorrelationRule],
        mitre_catalog: MitreCatalog
    ):
        self.incident_id = incident_id
        self.evidence_version = evidence_version
        
        # Sort events chronologically (Step 5)
        self.events = sorted(events, key=lambda e: (e.event_timestamp or datetime.min, e.id))
        self.incident_events = incident_events
        self.cti_results = cti_results  # Assumed to be correctly ordered and filtered
        self.rules = {r.id: r for r in rules}
        self.mitre = mitre_catalog
        
        self.nodes: Dict[str, dict] = {}
        self.edges: Dict[str, dict] = {}
        self.warnings: List[dict] = []
        self.truncated = False
        
        self.entity_index: Dict[str, Set[Tuple[uuid.UUID, str]]] = defaultdict(set) # canonical_id -> set((event_id, entity_type))
        self.event_to_entities: Dict[uuid.UUID, List[EntityInfo]] = defaultdict(list)
        self.event_nodes: Dict[uuid.UUID, str] = {} # event_id -> logical_node_id
        self.entity_nodes: Dict[str, str] = {} # canonical_id -> logical_node_id
        self.cti_nodes: Dict[uuid.UUID, str] = {} # cti_id -> logical_node_id
        self.technique_nodes: Dict[str, str] = {} # technique_id -> logical_node_id

    def build(self) -> Tuple[List[dict], List[dict], List[dict], bool]:
        """
        Executes Steps 6-22 of the reconstruction algorithm.
        Returns (nodes, edges, warnings, truncated_flag).
        """
        self._step6_canonicalize_entities()
        self._step7_detect_cti_verdict_changes()
        self._step8_generate_event_nodes()
        self._step9_generate_cti_match_nodes()
        self._step10_generate_entity_nodes()
        self._step11_generate_technique_nodes()
        self._step12_generate_event_entity_edges()
        self._step13_generate_chronological_next_edges()
        self._step14_generate_same_entity_edges()
        self._step15_generate_correlated_with_edges()
        self._step16_generate_ioc_match_edges()
        self._step17_generate_technique_support_edges()
        self._step18_generate_same_agent_edges()
        self._step19_generate_network_relation_edges()
        self._step20_compute_evidence_strength()
        self._step21_apply_size_limits()
        
        return list(self.nodes.values()), list(self.edges.values()), self.warnings, self.truncated

    def _step6_canonicalize_entities(self):
        for event in self.events:
            entities = extract_entities_from_event(event, self.warnings.append)
            self.event_to_entities[event.id] = entities
            for ent in entities:
                self.entity_index[ent.canonical_id].add((event.id, ent.entity_type))

    def _step7_detect_cti_verdict_changes(self):
        groups = defaultdict(list)
        for cti in self.cti_results:
            groups[(cti.ioc_value, cti.source)].append(cti)
            
        for (ioc, src), records in groups.items():
            if len(records) > 1:
                verdicts = {r.verdict for r in records}
                if len(verdicts) > 1:
                    self.warnings.append({
                        "type": "cti_verdict_changed",
                        "ioc_value": ioc,
                        "source": src,
                        "records": [str(r.id) for r in records],
                        "verdicts": list(verdicts)
                    })

    def _step8_generate_event_nodes(self):
        for i, event in enumerate(self.events):
            logical_id = sha256_hash(f"EVENT|{event.id}")[:64]
            self.event_nodes[event.id] = logical_id
            
            self.nodes[logical_id] = {
                "logical_node_id": logical_id,
                "node_type": NodeType.EVENT.value,
                "normalized_event_id": event.id,
                "provenance": Provenance.OBSERVED.value,
                "event_timestamp": event.event_timestamp,
                "sequence_index": i,
                "source_type": "DIRECT_EVENT",
                "evidence_refs": [str(event.id)]
            }

    def _step9_generate_cti_match_nodes(self):
        for cti in self.cti_results:
            if not cti.matched:
                continue
                
            logical_id = sha256_hash(f"CTI_MATCH|{cti.id}")[:64]
            self.cti_nodes[cti.id] = logical_id
            
            self.nodes[logical_id] = {
                "logical_node_id": logical_id,
                "node_type": NodeType.CTI_MATCH.value,
                "threat_intel_result_id": cti.id,
                "ioc_type": cti.ioc_type,
                "ioc_value": cti.ioc_value,
                "provenance": Provenance.OBSERVED.value,
                "source_type": "CTI_MATCHED",
                "evidence_refs": [str(cti.id)]
            }

    def _step10_generate_entity_nodes(self):
        for canonical_id, occs in self.entity_index.items():
            logical_id = sha256_hash(f"ENTITY|{canonical_id}")[:64]
            self.entity_nodes[canonical_id] = logical_id
            
            # Use the most common entity type among occurrences
            type_counts = defaultdict(int)
            for _, etype in occs:
                type_counts[etype] += 1
            primary_type = max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else None
            
            self.nodes[logical_id] = {
                "logical_node_id": logical_id,
                "node_type": NodeType.ENTITY.value,
                "entity_canonical_id": canonical_id,
                "entity_type": primary_type,
                "provenance": Provenance.OBSERVED.value,
                "source_type": "DIRECT_EVENT",
                "evidence_refs": [str(eid) for eid, _ in occs]
            }

    def _step11_generate_technique_nodes(self):
        # Gather all techniques
        event_techniques = defaultdict(set) # technique_id -> set of event_ids
        for event in self.events:
            if event.mitre_technique_ids:
                for tech_id in event.mitre_technique_ids:
                    event_techniques[tech_id].add(event.id)
                    
        rule_techniques = defaultdict(set) # technique_id -> set of rule_ids
        for ie in self.incident_events:
            if ie.correlation_rule_id and ie.correlation_rule_id in self.rules:
                rule = self.rules[ie.correlation_rule_id]
                if rule.mitre_technique_ids:
                    for tech_id in rule.mitre_technique_ids:
                        rule_techniques[tech_id].add(rule.id)
                        
        all_techniques = set(event_techniques.keys()) | set(rule_techniques.keys())
        
        for tech_id in all_techniques:
            logical_id = sha256_hash(f"TECHNIQUE|{self.incident_id}|{tech_id}")[:64]
            self.technique_nodes[tech_id] = logical_id
            
            name, tactics = self.mitre.get_technique_info(tech_id)
            tactic_names = [self.mitre.get_tactic_name(t) for t in tactics]
            
            # If directly mapped on event -> OBSERVED, else INFERRED
            if tech_id in event_techniques:
                prov = Provenance.OBSERVED.value
                mapping = "DIRECT_MAPPING"
                refs = [str(eid) for eid in event_techniques[tech_id]]
            else:
                prov = Provenance.INFERRED.value
                mapping = "INFERRED_MAPPING"
                refs = [str(rid) for rid in rule_techniques[tech_id]]
                
            self.nodes[logical_id] = {
                "logical_node_id": logical_id,
                "node_type": NodeType.TECHNIQUE.value,
                "mitre_technique_id": tech_id,
                "mitre_tactic_ids": tactics,
                "mitre_technique_name": name,
                "mitre_tactic_names": tactic_names,
                "mitre_mapping_type": mapping,
                "provenance": prov,
                "source_type": "RULE_INFERRED" if mapping == "INFERRED_MAPPING" else "DIRECT_EVENT",
                "evidence_refs": refs
            }

    def _step12_generate_event_entity_edges(self):
        for event_id, entities in self.event_to_entities.items():
            src_logical = self.event_nodes[event_id]
            for ent in entities:
                dst_logical = self.entity_nodes[ent.canonical_id]
                logical_id = sha256_hash(f"EVENT_ENTITY|{src_logical}|{dst_logical}")[:64]
                
                self.edges[logical_id] = {
                    "logical_edge_id": logical_id,
                    "src_node_logical_id": src_logical,
                    "dst_node_logical_id": dst_logical,
                    "edge_type": EdgeType.EVENT_ENTITY.value,
                    "provenance": Provenance.OBSERVED.value,
                    "evidence_refs": [str(event_id)]
                }

    def _step13_generate_chronological_next_edges(self):
        for i in range(len(self.events) - 1):
            src_event = self.events[i]
            dst_event = self.events[i+1]
            src_logical = self.event_nodes[src_event.id]
            dst_logical = self.event_nodes[dst_event.id]
            
            logical_id = sha256_hash(f"CHRONOLOGICAL_NEXT|{src_logical}|{dst_logical}")[:64]
            self.edges[logical_id] = {
                "logical_edge_id": logical_id,
                "src_node_logical_id": src_logical,
                "dst_node_logical_id": dst_logical,
                "edge_type": EdgeType.CHRONOLOGICAL_NEXT.value,
                "provenance": Provenance.INFERRED.value,
                "evidence_refs": [str(src_event.id), str(dst_event.id)]
            }

    def _step14_generate_same_entity_edges(self):
        for canonical_id, occs in self.entity_index.items():
            event_ids = sorted(list({eid for eid, _ in occs}))
            if len(event_ids) < 2:
                continue
                
            pairs_created = 0
            for i in range(len(event_ids)):
                for j in range(i + 1, len(event_ids)):
                    if pairs_created >= LIMITS["MAX_SAME_ENTITY_EDGE_PAIRS_PER_ENTITY"]:
                        break
                        
                    src_logical = self.event_nodes[event_ids[i]]
                    dst_logical = self.event_nodes[event_ids[j]]
                    logical_id = sha256_hash(f"SAME_ENTITY|{src_logical}|{dst_logical}|{canonical_id}")[:64]
                    
                    self.edges[logical_id] = {
                        "logical_edge_id": logical_id,
                        "src_node_logical_id": src_logical,
                        "dst_node_logical_id": dst_logical,
                        "edge_type": EdgeType.SAME_ENTITY.value,
                        "provenance": Provenance.INFERRED.value,
                        "evidence_refs": [str(event_ids[i]), str(event_ids[j]), canonical_id]
                    }
                    pairs_created += 1

    def _step15_generate_correlated_with_edges(self):
        rule_groups = defaultdict(list)
        for ie in self.incident_events:
            if ie.correlation_rule_id:
                rule_groups[ie.correlation_rule_id].append(ie.normalized_event_id)
                
        for rule_id, event_ids in rule_groups.items():
            event_ids = sorted(list(set(event_ids)))
            if len(event_ids) < 2:
                continue
                
            pairs_created = 0
            for i in range(len(event_ids)):
                for j in range(i + 1, len(event_ids)):
                    if pairs_created >= LIMITS["MAX_CORRELATED_WITH_PAIRS_PER_RULE_GROUP"]:
                        break
                        
                    src_logical = self.event_nodes[event_ids[i]]
                    dst_logical = self.event_nodes[event_ids[j]]
                    logical_id = sha256_hash(f"CORRELATED_WITH|{src_logical}|{dst_logical}|{rule_id}")[:64]
                    
                    self.edges[logical_id] = {
                        "logical_edge_id": logical_id,
                        "src_node_logical_id": src_logical,
                        "dst_node_logical_id": dst_logical,
                        "edge_type": EdgeType.CORRELATED_WITH.value,
                        "provenance": Provenance.INFERRED.value,
                        "evidence_refs": [str(event_ids[i]), str(event_ids[j]), str(rule_id)]
                    }
                    pairs_created += 1

    def _step16_generate_ioc_match_edges(self):
        for cti in self.cti_results:
            if not cti.matched:
                continue
                
            cti_logical = self.cti_nodes[cti.id]
            if cti.ioc_value in self.entity_nodes:
                ent_logical = self.entity_nodes[cti.ioc_value]
                logical_id = sha256_hash(f"IOC_MATCH|{cti_logical}|{ent_logical}")[:64]
                
                self.edges[logical_id] = {
                    "logical_edge_id": logical_id,
                    "src_node_logical_id": cti_logical,
                    "dst_node_logical_id": ent_logical,
                    "edge_type": EdgeType.IOC_MATCH.value,
                    "provenance": Provenance.INFERRED.value,
                    "evidence_refs": [str(cti.id), cti.ioc_value]
                }

    def _step17_generate_technique_support_edges(self):
        for event in self.events:
            if event.mitre_technique_ids:
                src_logical = self.event_nodes[event.id]
                for tech_id in event.mitre_technique_ids:
                    dst_logical = self.technique_nodes[tech_id]
                    logical_id = sha256_hash(f"TECHNIQUE_SUPPORT|{src_logical}|{dst_logical}")[:64]
                    
                    self.edges[logical_id] = {
                        "logical_edge_id": logical_id,
                        "src_node_logical_id": src_logical,
                        "dst_node_logical_id": dst_logical,
                        "edge_type": EdgeType.TECHNIQUE_SUPPORT.value,
                        "provenance": Provenance.OBSERVED.value,
                        "is_inferred_mapping": False,
                        "evidence_refs": [str(event.id)]
                    }
                    
        for ie in self.incident_events:
            if ie.correlation_rule_id and ie.correlation_rule_id in self.rules:
                rule = self.rules[ie.correlation_rule_id]
                if rule.mitre_technique_ids:
                    src_logical = self.event_nodes[ie.normalized_event_id]
                    for tech_id in rule.mitre_technique_ids:
                        dst_logical = self.technique_nodes[tech_id]
                        logical_id = sha256_hash(f"TECHNIQUE_SUPPORT|{src_logical}|{dst_logical}")[:64]
                        if logical_id not in self.edges:
                            self.edges[logical_id] = {
                                "logical_edge_id": logical_id,
                                "src_node_logical_id": src_logical,
                                "dst_node_logical_id": dst_logical,
                                "edge_type": EdgeType.TECHNIQUE_SUPPORT.value,
                                "provenance": Provenance.INFERRED.value,
                                "is_inferred_mapping": True,
                                "evidence_refs": [str(ie.normalized_event_id), str(rule.id)]
                            }

    def _step18_generate_same_agent_edges(self):
        # Resolve agent_id from source telemetry for each entity occurrence
        agent_entities = defaultdict(list)
        for event in self.events:
            if not event.agent_id:
                continue
            for ent in self.event_to_entities[event.id]:
                agent_entities[event.agent_id].append(ent.canonical_id)
                
        for agent_id, canonical_ids in agent_entities.items():
            unique_ids = sorted(list(set(canonical_ids)))
            if len(unique_ids) < 2:
                continue
                
            pairs_created = 0
            for i in range(len(unique_ids)):
                for j in range(i + 1, len(unique_ids)):
                    if pairs_created >= LIMITS["MAX_SAME_AGENT_EDGE_PAIRS"]:
                        break
                        
                    src_logical = self.entity_nodes[unique_ids[i]]
                    dst_logical = self.entity_nodes[unique_ids[j]]
                    logical_id = sha256_hash(f"SAME_AGENT|{src_logical}|{dst_logical}|{agent_id}")[:64]
                    
                    self.edges[logical_id] = {
                        "logical_edge_id": logical_id,
                        "src_node_logical_id": src_logical,
                        "dst_node_logical_id": dst_logical,
                        "edge_type": EdgeType.SAME_AGENT.value,
                        "provenance": Provenance.INFERRED.value,
                        "evidence_refs": [unique_ids[i], unique_ids[j], agent_id]
                    }
                    pairs_created += 1

    def _step19_generate_network_relation_edges(self):
        pairs_created = 0
        for i in range(len(self.events)):
            for j in range(len(self.events)):
                if pairs_created >= LIMITS["MAX_NETWORK_RELATION_EDGES_PER_CHAIN"]:
                    break
                ei = self.events[i]
                ej = self.events[j]
                
                # E_i.dst_ip = canonical(E_j.src_ip) AND E_i.event_timestamp <= E_j.event_timestamp
                if ei.dst_ip and ej.src_ip:
                    try:
                        ei_dst = canonical_ip(ei.dst_ip)
                        ej_src = canonical_ip(ej.src_ip)
                        if ei_dst == ej_src:
                            ti = ei.event_timestamp or datetime.min
                            tj = ej.event_timestamp or datetime.min
                            if ti <= tj:
                                src_logical = self.event_nodes[ei.id]
                                dst_logical = self.event_nodes[ej.id]
                                logical_id = sha256_hash(f"NETWORK_RELATION|{src_logical}|{dst_logical}")[:64]
                                
                                self.edges[logical_id] = {
                                    "logical_edge_id": logical_id,
                                    "src_node_logical_id": src_logical,
                                    "dst_node_logical_id": dst_logical,
                                    "edge_type": EdgeType.NETWORK_RELATION.value,
                                    "provenance": Provenance.INFERRED.value,
                                    "evidence_refs": [str(ei.id), str(ej.id)],
                                    "evidence_snapshot": {
                                        "src_port": ei.src_port or ej.src_port,
                                        "dst_port": ei.dst_port or ej.dst_port,
                                        "network_protocol": ei.network_protocol or ej.network_protocol
                                    }
                                }
                                pairs_created += 1
                    except ValueError:
                        pass # Ignore canonicalization errors here, already logged elsewhere

    def _step20_compute_evidence_strength(self):
        # Node strengths
        for node in self.nodes.values():
            n_events = len(node.get("evidence_refs", []))
            prov = Provenance(node["provenance"])
            source_type = node.get("source_type", "DIRECT_EVENT")
            
            strength = calculate_node_evidence_strength(prov, source_type, n_events)
            node["evidence_strength"] = strength
            node["verification_status"] = "VERIFIABLE"
            node["evidence_available"] = True
            
        # Edge strengths
        for edge in self.edges.values():
            src_node = self.nodes.get(edge["src_node_logical_id"])
            dst_node = self.nodes.get(edge["dst_node_logical_id"])
            if src_node and dst_node:
                src_strength = src_node.get("evidence_strength", 0.0)
                dst_strength = dst_node.get("evidence_strength", 0.0)
                edge_type = EdgeType(edge["edge_type"])
                is_inferred = edge.get("is_inferred_mapping", False)
                
                strength = calculate_edge_evidence_strength(src_strength, dst_strength, edge_type, is_inferred)
                edge["evidence_strength"] = strength
                edge["verification_status"] = "VERIFIABLE"
                edge["evidence_available"] = True

    def _step21_apply_size_limits(self):
        # Truncate edges first, since they are derived from nodes
        limit_edges = LIMITS["MAX_TOTAL_EDGES_PER_CHAIN"]
        if len(self.edges) > limit_edges:
            # Sort edges by evidence_strength DESC, then logical_edge_id ASC
            sorted_edges = sorted(self.edges.values(), key=lambda e: (-e.get("evidence_strength", 0.0), e["logical_edge_id"]))
            self.edges = {e["logical_edge_id"]: e for e in sorted_edges[:limit_edges]}
            self.warnings.append({"type": "edge_truncation", "limit": limit_edges})
            self.truncated = True
            
        limit_nodes = LIMITS["MAX_EVENT_NODES_PER_CHAIN"]
        if len(self.nodes) > limit_nodes:
            sorted_nodes = sorted(self.nodes.values(), key=lambda n: (-n.get("evidence_strength", 0.0), n["logical_node_id"]))
            self.nodes = {n["logical_node_id"]: n for n in sorted_nodes[:limit_nodes]}
            self.warnings.append({"type": "node_truncation", "limit": limit_nodes})
            self.truncated = True
            
            # Remove any edges that reference deleted nodes
            edges_to_delete = []
            for logical_id, edge in self.edges.items():
                if edge["src_node_logical_id"] not in self.nodes or edge["dst_node_logical_id"] not in self.nodes:
                    edges_to_delete.append(logical_id)
            for logical_id in edges_to_delete:
                del self.edges[logical_id]
