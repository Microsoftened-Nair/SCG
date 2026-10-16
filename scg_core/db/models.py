"""SQLAlchemy 2.0 Async Relational Data Model for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (P7-01, P7-07).
Defines the PostgreSQL 16 relational data model with multi-tenant isolation,
global component deduplication, soft deletion safeguards, and cascade restrictions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """Declarative Base class for all SCG relational models."""

    type_annotation_map = {
        dict: JSONB,
        list: JSONB,
    }


def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)


class Principal(Base):
    """API Principal representing authenticated clients in a multi-tenant environment (P7-01)."""

    __tablename__ = "principals"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class Repository(Base):
    """Monitored source code repository scoped to a tenant (P7-01, P7-07).

    Enforces soft deletion to preserve audit and compliance trail.
    """

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("tenant_id", "url", name="uq_tenant_repo_url"),
        Index("ix_repositories_tenant_deleted", "tenant_id", "is_deleted"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    default_branch: Mapped[str] = mapped_column(
        String(128), default="main", nullable=False
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    scans: Mapped[List["ScanRun"]] = relationship(
        "ScanRun", back_populates="repository"
    )


class ScanRun(Base):
    """Execution record for an automated supply chain security scan (P7-01).

    Enforces RESTRICT on repository deletion to protect audit integrity.
    """

    __tablename__ = "scan_runs"
    __table_args__ = (
        Index("ix_scan_runs_repo_created", "repository_id", "created_at"),
        Index("ix_scan_runs_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="RESTRICT"), nullable=False
    )
    commit_sha: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="QUEUED", nullable=False)

    overall_trust_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mean_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    vulnerability_facet: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    hygiene_facet: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    behavior_facet: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    total_dependencies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerable_dependencies: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    analysis_completeness: Mapped[str] = mapped_column(
        String(32), default="FULL", nullable=False
    )

    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    repository: Mapped["Repository"] = relationship(
        "Repository", back_populates="scans"
    )
    scan_components: Mapped[List["ScanComponent"]] = relationship(
        "ScanComponent", back_populates="scan", cascade="all, delete-orphan"
    )
    remediations: Mapped[List["RemediationPR"]] = relationship(
        "RemediationPR", back_populates="scan", cascade="all, delete-orphan"
    )


class Component(Base):
    """Software package component globally deduplicated across all tenants (P7-07)."""

    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    purl: Mapped[str] = mapped_column(
        String(512), unique=True, index=True, nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    package_name: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)

    maintainer_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    weekly_downloads: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    has_install_scripts: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    openssf_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_registry_activity: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    vulnerabilities: Mapped[List["ComponentVulnerability"]] = relationship(
        "ComponentVulnerability",
        back_populates="component",
        cascade="all, delete-orphan",
    )
    scan_components: Mapped[List["ScanComponent"]] = relationship(
        "ScanComponent", back_populates="component"
    )


class ScanComponent(Base):
    """Component evaluated within a specific scan run, capturing point-in-time metrics."""

    __tablename__ = "scan_components"
    __table_args__ = (
        UniqueConstraint("scan_id", "component_id", name="uq_scan_component"),
        Index("ix_scan_components_scan", "scan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("components.id", ondelete="RESTRICT"), nullable=False
    )
    graph_depth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_direct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reachability_status: Mapped[str] = mapped_column(String(32), nullable=False)
    exposure_factor: Mapped[float] = mapped_column(Float, nullable=False)
    symbol_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    composite_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    score_deductions: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )

    # Relationships
    scan: Mapped["ScanRun"] = relationship("ScanRun", back_populates="scan_components")
    component: Mapped["Component"] = relationship(
        "Component", back_populates="scan_components"
    )


class Vulnerability(Base):
    """Vulnerability advisory canonical record (OSV/CVE/GHSA)."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    aliases: Mapped[List[str]] = mapped_column(JSONB, default=list, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_source: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    fixed_versions: Mapped[List[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    vulnerable_symbols: Mapped[List[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )

    # Relationships
    components: Mapped[List["ComponentVulnerability"]] = relationship(
        "ComponentVulnerability", back_populates="vulnerability"
    )


class ComponentVulnerability(Base):
    """Association table mapping components to known vulnerabilities."""

    __tablename__ = "component_vulnerabilities"
    __table_args__ = (
        Index("ix_component_vulns_vuln", "vulnerability_id"),
    )

    component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("components.id", ondelete="CASCADE"), primary_key=True
    )
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), primary_key=True
    )

    # Relationships
    component: Mapped["Component"] = relationship(
        "Component", back_populates="vulnerabilities"
    )
    vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability", back_populates="components"
    )


class RemediationPR(Base):
    """Autonomous remediation Pull Request tracking record."""

    __tablename__ = "remediation_prs"
    __table_args__ = (
        Index(
            "ix_remediation_prs_key",
            "scan_id",
            "package_name",
            "target_version",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False
    )
    package_name: Mapped[str] = mapped_column(String(256), nullable=False)
    target_version: Mapped[str] = mapped_column(String(128), nullable=False)
    branch_name: Mapped[str] = mapped_column(String(256), nullable=False)
    pr_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pr_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="OPENED", nullable=False)
    score_delta: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    scan: Mapped["ScanRun"] = relationship("ScanRun", back_populates="remediations")


if __name__ == "__main__":
    print("Executing verification harness for scg_core/db/models.py (REQ-P7-03)...")

    # 1. Assert all declared tables exist in Base.metadata.tables
    expected_tables = {
        "principals",
        "repositories",
        "scan_runs",
        "components",
        "scan_components",
        "vulnerabilities",
        "component_vulnerabilities",
        "remediation_prs",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(
        actual_tables
    ), f"Missing tables: {expected_tables - actual_tables}"
    print(f"✓ All {len(expected_tables)} declared tables exist in Base.metadata.tables.")

    # 2. Verify foreign key definitions and ondelete rules
    tables = Base.metadata.tables

    # scan_runs.repository_id -> repositories.id (RESTRICT)
    scan_runs_tbl = tables["scan_runs"]
    sr_fks = {fk.target_fullname: fk for fk in scan_runs_tbl.foreign_keys}
    assert "repositories.id" in sr_fks, "scan_runs missing FK to repositories.id"
    assert (
        sr_fks["repositories.id"].ondelete == "RESTRICT"
    ), f"Expected RESTRICT ondelete for repositories.id, got {sr_fks['repositories.id'].ondelete}"

    # scan_components.scan_id -> scan_runs.id (CASCADE)
    # scan_components.component_id -> components.id (RESTRICT)
    sc_tbl = tables["scan_components"]
    sc_fks = {fk.target_fullname: fk for fk in sc_tbl.foreign_keys}
    assert "scan_runs.id" in sc_fks, "scan_components missing FK to scan_runs.id"
    assert (
        sc_fks["scan_runs.id"].ondelete == "CASCADE"
    ), f"Expected CASCADE ondelete for scan_runs.id, got {sc_fks['scan_runs.id'].ondelete}"
    assert "components.id" in sc_fks, "scan_components missing FK to components.id"
    assert (
        sc_fks["components.id"].ondelete == "RESTRICT"
    ), f"Expected RESTRICT ondelete for components.id, got {sc_fks['components.id'].ondelete}"

    # component_vulnerabilities.component_id -> components.id (CASCADE)
    # component_vulnerabilities.vulnerability_id -> vulnerabilities.id (RESTRICT)
    cv_tbl = tables["component_vulnerabilities"]
    cv_fks = {fk.target_fullname: fk for fk in cv_tbl.foreign_keys}
    assert "components.id" in cv_fks, "component_vulnerabilities missing FK to components.id"
    assert (
        cv_fks["components.id"].ondelete == "CASCADE"
    ), f"Expected CASCADE ondelete for components.id, got {cv_fks['components.id'].ondelete}"
    assert (
        "vulnerabilities.id" in cv_fks
    ), "component_vulnerabilities missing FK to vulnerabilities.id"
    assert (
        cv_fks["vulnerabilities.id"].ondelete == "RESTRICT"
    ), f"Expected RESTRICT ondelete for vulnerabilities.id, got {cv_fks['vulnerabilities.id'].ondelete}"

    # remediation_prs.scan_id -> scan_runs.id (CASCADE)
    rem_tbl = tables["remediation_prs"]
    rem_fks = {fk.target_fullname: fk for fk in rem_tbl.foreign_keys}
    assert "scan_runs.id" in rem_fks, "remediation_prs missing FK to scan_runs.id"
    assert (
        rem_fks["scan_runs.id"].ondelete == "CASCADE"
    ), f"Expected CASCADE ondelete for scan_runs.id, got {rem_fks['scan_runs.id'].ondelete}"
    print("✓ All Foreign Key definitions and ondelete behaviors verified.")

    # 3. Verify unique constraint names
    repo_uq_names = {
        c.name for c in tables["repositories"].constraints if isinstance(c, UniqueConstraint)
    }
    assert (
        "uq_tenant_repo_url" in repo_uq_names
    ), f"repositories missing uq_tenant_repo_url: {repo_uq_names}"

    sc_uq_names = {
        c.name for c in tables["scan_components"].constraints if isinstance(c, UniqueConstraint)
    }
    assert (
        "uq_scan_component" in sc_uq_names
    ), f"scan_components missing uq_scan_component: {sc_uq_names}"
    print("✓ Unique constraint names ('uq_tenant_repo_url', 'uq_scan_component') verified.")

    # 4. Verify index names
    all_indices = set()
    for t in tables.values():
        for idx in t.indexes:
            all_indices.add(idx.name)

    expected_indices = {
        "ix_repositories_tenant_deleted",
        "ix_scan_runs_repo_created",
        "ix_scan_runs_tenant_status",
        "ix_scan_components_scan",
        "ix_component_vulns_vuln",
        "ix_remediation_prs_key",
    }
    assert expected_indices.issubset(
        all_indices
    ), f"Missing indices: {expected_indices - all_indices}"
    print(f"✓ All specified indices exist: {expected_indices}.")

    print("PHASE 7 DATABASE MODELS VALIDATION: SUCCESS")
