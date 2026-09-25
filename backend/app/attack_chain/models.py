import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

class AttackChainVersion(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_chain_versions"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("incidents.id", ondelete="RESTRICT"), 
        nullable=False
    )
    chain_canonical_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    chain_version: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_version: Mapped[int] = mapped_column(Integer, nullable=False)
    event_evidence_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cti_evidence_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chain_evidence_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cti_evidence_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    technique_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    tactic_ids_present: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reconstruction_warnings: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    
    attck_catalog_version: Mapped[str] = mapped_column(String(16), nullable=False)
    reconstruction_algorithm_version: Mapped[str] = mapped_column(String(16), nullable=False)
    
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("incident_id", "chain_version", name="uq_acv_incident_version"),
        # Index on (incident_id, evidence_version DESC) to be created via Alembic
    )
    
    nodes: Mapped[list["AttackChainNode"]] = relationship(
        "AttackChainNode", back_populates="chain_version_rel", cascade="all, delete-orphan"
    )
    edges: Mapped[list["AttackChainEdge"]] = relationship(
        "AttackChainEdge", back_populates="chain_version_rel", cascade="all, delete-orphan"
    )

class AttackChainNode(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_chain_nodes"

    chain_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("attack_chain_versions.id", ondelete="CASCADE"), 
        nullable=False
    )
    logical_node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    
    normalized_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("normalized_events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    threat_intel_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_intel_results.id", ondelete="SET NULL"), nullable=True
    )
    
    entity_canonical_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ioc_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ioc_value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_tactic_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre_tactic_names: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_mapping_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    
    provenance: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIABLE")
    evidence_strength: Mapped[float] = mapped_column(Float, nullable=False)
    
    event_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sequence_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("chain_version_id", "logical_node_id", name="uq_acn_chain_logical"),
    )
    
    chain_version_rel: Mapped["AttackChainVersion"] = relationship("AttackChainVersion", back_populates="nodes")

class AttackChainEdge(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_chain_edges"

    chain_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("attack_chain_versions.id", ondelete="CASCADE"), 
        nullable=False
    )
    logical_edge_id: Mapped[str] = mapped_column(String(128), nullable=False)
    src_node_logical_id: Mapped[str] = mapped_column(String(128), nullable=False)
    dst_node_logical_id: Mapped[str] = mapped_column(String(128), nullable=False)
    
    src_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_chain_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dst_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_chain_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False)
    provenance: Mapped[str] = mapped_column(String(16), nullable=False)
    implies_causality: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    
    evidence_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIABLE")
    evidence_strength: Mapped[float] = mapped_column(Float, nullable=False)
    
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("chain_version_id", "logical_edge_id", name="uq_ace_chain_logical"),
    )

    chain_version_rel: Mapped["AttackChainVersion"] = relationship("AttackChainVersion", back_populates="edges")
