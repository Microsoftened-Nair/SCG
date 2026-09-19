"""Canonical base schemas and data contracts for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-1-2026-REV-2.1.
Governs all serialization contracts across FastAPI, Redis, PostgreSQL, and Celery,
incorporating security, multi-tenancy, and advanced vulnerability intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
import re
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)


def _require_aware_utc(v: datetime) -> datetime:
    """Enforces that datetime instances must be timezone-aware (UTC).

    Args:
        v: Candidate datetime object.

    Returns:
        Timezone-aware datetime converted to UTC.

    Raises:
        ValueError: If candidate datetime is naive (missing tzinfo or utcoffset).
    """
    if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
        raise ValueError("datetime must be timezone-aware (UTC)")
    return v.astimezone(timezone.utc)


AwareUTC = Annotated[datetime, AfterValidator(_require_aware_utc)]

# Strict Semantic Versioning 2.0.0 specification regex (https://semver.org/)
SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def validate_semver(v: str) -> str:
    """Validates that a string conforms to the Semantic Versioning 2.0.0 specification.

    Args:
        v: String representation of a version.

    Returns:
        The validated version string.

    Raises:
        ValueError: If the string fails SemVer 2.0.0 regex compliance.
    """
    if not SEMVER_REGEX.match(v):
        raise ValueError(f"Value '{v}' does not adhere to Semantic Versioning 2.0.0 specification.")
    return v


SemVerString = Annotated[str, AfterValidator(validate_semver)]


def _round_to_two_decimals(value: float) -> float:
    """Rounds a floating-point score to a maximum of two decimal places using standard numeric evaluation."""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


class Ecosystem(str, Enum):
    """Target software package registry and ecosystem."""

    NPM = "npm"
    PYPI = "pypi"


class ReachabilityStatus(str, Enum):
    """Static AST call-graph reachability classification for dependencies."""

    DIRECT_IMPORTED = "DIRECT_IMPORTED"
    TRANSITIVE_REQUIRED = "TRANSITIVE_REQUIRED"
    UNREFERENCED_LATENT = "UNREFERENCED_LATENT"
    DEV_DEPENDENCY = "DEV_DEPENDENCY"


class SeverityLevel(str, Enum):
    """Qualitative severity classification aligned with CVSS mapping."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class CvssSource(str, Enum):
    """Origin of the recorded CVSS score and vector."""

    PUBLISHED_VECTOR = "PUBLISHED_VECTOR"
    PUBLISHED_SCORE = "PUBLISHED_SCORE"
    INFERRED_FROM_SEVERITY = "INFERRED_FROM_SEVERITY"
    ABSENT = "ABSENT"


class VersionParseStatus(str, Enum):
    """Classification status of package version resolution parsing."""

    PARSED = "PARSED"
    UNPARSEABLE = "UNPARSEABLE"


class VulnerabilityRecord(BaseModel):
    """Vulnerability advisory record with CVSS, EPSS, CISA KEV, and symbol impact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Canonical vulnerability identifier (e.g. CVE-2023-1234, GHSA-xxxx-xxxx-xxxx).",
    )
    aliases: List[str] = Field(
        default_factory=list,
        description="Alternative vulnerability identifiers referencing the same flaw.",
    )
    summary: str = Field(
        ...,
        max_length=500,
        description="Brief summary or description of the vulnerability advisory.",
    )
    cvss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Common Vulnerability Scoring System (CVSS) base score (0.0 to 10.0).",
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="Standard CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).",
    )
    cvss_source: CvssSource = Field(
        default=CvssSource.ABSENT,
        description="Provenance of the assigned CVSS score.",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Categorical severity rating.",
    )
    epss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Exploit Prediction Scoring System (EPSS) probability score between 0.0 and 1.0.",
    )
    epss_percentile: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="EPSS relative percentile rank between 0.0 and 1.0.",
    )
    is_known_exploited: bool = Field(
        default=False,
        description="True if cataloged in CISA Known Exploited Vulnerabilities (KEV).",
    )
    published: Optional[AwareUTC] = Field(
        default=None,
        description="Publication timestamp of the vulnerability advisory in UTC.",
    )
    withdrawn: Optional[AwareUTC] = Field(
        default=None,
        description="Timestamp when advisory was officially withdrawn or retracted in UTC.",
    )
    fixed_versions: List[str] = Field(
        default_factory=list,
        description="List of package versions containing fixes for this vulnerability.",
    )
    vulnerable_version_ranges: List[str] = Field(
        default_factory=list,
        description="Version range constraints affected by this vulnerability.",
    )
    vulnerable_symbols: List[str] = Field(
        default_factory=list,
        description="List of vulnerable classes, methods, or function symbols identified in the package.",
    )

    @field_validator("cvss_score", mode="after")
    @classmethod
    def round_cvss_score(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        return _round_to_two_decimals(v)


class PackageHealthData(BaseModel):
    """Aggregated health, maintenance, and registry metrics for a package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    published_date: AwareUTC = Field(
        ...,
        description="Release timestamp of the resolved version in ISO 8601 UTC.",
    )
    last_registry_activity: AwareUTC = Field(
        ...,
        description="Timestamp of the most recent activity or release on the registry in UTC.",
    )
    maintainer_count: int = Field(
        ...,
        ge=1,
        description="Count of active maintainers registered for the package.",
    )
    weekly_downloads: int = Field(
        ...,
        ge=0,
        description="Average weekly download count from the registry.",
    )
    has_install_scripts: bool = Field(
        ...,
        description="Indicates whether the package specifies pre/post install lifecycle scripts.",
    )
    openssf_scorecard_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="OpenSSF Scorecard evaluation score between 0.0 and 10.0, if available.",
    )
    is_deprecated: bool = Field(
        default=False,
        description="Flag indicating if the package or version is formally deprecated upstream.",
    )

    @field_validator("openssf_scorecard_score", mode="after")
    @classmethod
    def round_openssf_score(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        return _round_to_two_decimals(v)


class DependencyNode(BaseModel):
    """Canonical representation of an evaluated package node within the dependency graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Canonical name of the package as published on the package registry.",
    )
    ecosystem: Ecosystem = Field(
        ...,
        description="Target software ecosystem (npm or pypi).",
    )
    resolved_version: str = Field(
        ...,
        max_length=128,
        description="Pinned resolution version string.",
    )
    version_parse_status: VersionParseStatus = Field(
        default=VersionParseStatus.PARSED,
        description="Indicates whether resolved_version successfully adhered to SemVer specifications.",
    )
    is_direct: bool = Field(
        ...,
        description="Boolean indicating if the package is declared directly in project root manifests.",
    )
    graph_depth: Optional[int] = Field(
        default=None,
        ge=1,
        le=64,
        description="Topological depth from root manifest (1 for direct). None indicates unreachable.",
    )
    declared_range: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Raw version requirement string from manifest (e.g., ^1.2.0, >=2.0.0).",
    )
    reachability: ReachabilityStatus = Field(
        default=ReachabilityStatus.UNREFERENCED_LATENT,
        description="Static AST call-graph reachability status.",
    )
    vulnerabilities: List[VulnerabilityRecord] = Field(
        default_factory=list,
        description="List of security vulnerabilities affecting this specific package resolution.",
    )
    health: PackageHealthData = Field(
        ...,
        description="Repository and registry health metrics for this dependency.",
    )


class TrustScoreBreakdown(BaseModel):
    """Comprehensive facet scoring breakdown and deduction ledger."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerability_facet: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Security facet score based on vulnerability severity, EPSS, KEV, and reachability.",
    )
    hygiene_facet: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Ecosystem hygiene and maintenance facet score.",
    )
    behavior_facet: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Behavioral and structural risk facet score.",
    )
    composite_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall weighted composite trust score (0.0 to 100.0).",
    )
    deductions: Dict[str, float] = Field(
        default_factory=dict,
        description="Transparent deduction ledger mapping rule identifiers to score penalties.",
    )

    @field_validator(
        "vulnerability_facet",
        "hygiene_facet",
        "behavior_facet",
        "composite_score",
        mode="after",
    )
    @classmethod
    def round_facet_scores(cls, v: float) -> float:
        return _round_to_two_decimals(v)

    @field_validator("deductions", mode="after")
    @classmethod
    def round_deductions(cls, v: Dict[str, float]) -> Dict[str, float]:
        return {k: _round_to_two_decimals(val) for k, val in v.items()}


class RepositoryScanReport(BaseModel):
    """Top-level scan output report summarizing findings and scores for a repository."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str = Field(
        ...,
        description="Universally unique identifier for the scan job (UUIDv4).",
    )
    tenant_id: str = Field(
        ...,
        max_length=64,
        description="Tenant identifier establishing multi-tenancy isolation boundary.",
    )
    repository_url: str = Field(
        ...,
        description="Remote source control repository URL scanned.",
    )
    commit_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{40}$",
        description="40-character lowercase hexadecimal SHA-1 commit hash analyzed.",
    )
    scanned_at: AwareUTC = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the repository scan completed in UTC.",
    )
    overall_trust_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall composite supply chain trust score for the repository.",
    )
    dependency_count: int = Field(
        ...,
        ge=0,
        description="Total number of resolved dependencies identified.",
    )
    vulnerable_dependency_count: int = Field(
        ...,
        ge=0,
        description="Count of unique dependencies having one or more unresolved vulnerabilities.",
    )
    dependencies: List[DependencyNode] = Field(
        ...,
        description="Enumeration of all evaluated dependency nodes.",
    )
    summary_breakdown: TrustScoreBreakdown = Field(
        ...,
        description="Detailed trust score facets and itemized deduction ledger.",
    )

    @field_validator("overall_trust_score", mode="after")
    @classmethod
    def round_overall_trust_score(cls, v: float) -> float:
        return _round_to_two_decimals(v)


if __name__ == "__main__":
    from uuid import uuid4

    print("Executing verification harness for scg_core/schemas/base.py (SRS Rev 2.1)...")

    # 1. Asserts a naive datetime passed to AwareUTC raises ValidationError
    class _TimestampModel(BaseModel):
        ts: AwareUTC

    try:
        naive_dt = datetime(2024, 1, 15, 10, 30, 0)  # Naive datetime (tzinfo=None)
        _TimestampModel(ts=naive_dt)
        raise AssertionError("Failed to raise ValidationError for naive datetime")
    except ValidationError:
        print("✓ [1/6] Naive datetime successfully rejected with ValidationError.")

    # 2. Asserts a valid UTC datetime passes
    valid_utc_dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    model_instance = _TimestampModel(ts=valid_utc_dt)
    assert model_instance.ts.tzinfo is not None, "Timezone awareness must be retained"
    print("✓ [2/6] Timezone-aware UTC datetime accepted successfully.")

    # 3. Validates that DependencyNode allows graph_depth=None and rejects graph_depth=0 (bounds 1 to 64)
    dummy_health = PackageHealthData(
        published_date=datetime(2024, 1, 10, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2024, 2, 1, 12, 0, 0, tzinfo=timezone.utc),
        maintainer_count=3,
        weekly_downloads=50000,
        has_install_scripts=False,
        openssf_scorecard_score=8.5,
        is_deprecated=False,
    )

    # 3a. Valid graph_depth=None (unreachable node)
    node_unreachable = DependencyNode(
        package_name="latent-lib",
        ecosystem=Ecosystem.PYPI,
        resolved_version="2.0.1",
        version_parse_status=VersionParseStatus.PARSED,
        is_direct=False,
        graph_depth=None,
        declared_range=None,
        reachability=ReachabilityStatus.UNREFERENCED_LATENT,
        vulnerabilities=[],
        health=dummy_health,
    )
    assert node_unreachable.graph_depth is None, "graph_depth=None must be supported"

    # 3b. Invalid graph_depth=0 rejected (bounds are ge=1, le=64)
    try:
        DependencyNode(
            package_name="invalid-depth-pkg",
            ecosystem=Ecosystem.NPM,
            resolved_version="1.0.0",
            version_parse_status=VersionParseStatus.PARSED,
            is_direct=True,
            graph_depth=0,
            health=dummy_health,
        )
        raise AssertionError("Failed to raise ValidationError for graph_depth=0")
    except ValidationError:
        print("✓ [3/6] DependencyNode bounds validated (graph_depth=None allowed, graph_depth=0 rejected).")

    # 4. Validates that RepositoryScanReport serializes with model_dump_json() and round-trips via model_validate_json()
    vuln_dummy = VulnerabilityRecord(
        id="GHSA-test-rev21-abcd",
        aliases=["CVE-2024-1234"],
        summary="Remote code execution via prototype pollution",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_source=CvssSource.PUBLISHED_VECTOR,
        severity=SeverityLevel.CRITICAL,
        epss_score=0.85432,
        epss_percentile=0.97123,
        is_known_exploited=True,
        published=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        withdrawn=None,
        fixed_versions=["1.2.4"],
        vulnerable_version_ranges=["< 1.2.4"],
        vulnerable_symbols=["executeCommand"],
    )

    node_direct = DependencyNode(
        package_name="critical-dep",
        ecosystem=Ecosystem.NPM,
        resolved_version="1.2.3",
        version_parse_status=VersionParseStatus.PARSED,
        is_direct=True,
        graph_depth=1,
        declared_range="^1.2.0",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerabilities=[vuln_dummy],
        health=dummy_health,
    )

    breakdown_dummy = TrustScoreBreakdown(
        vulnerability_facet=45.5,
        hygiene_facet=85.0,
        behavior_facet=90.0,
        composite_score=68.25,
        deductions={"CRITICAL_KNOWN_EXPLOITED": -40.0},
    )

    report = RepositoryScanReport(
        scan_id=str(uuid4()),
        tenant_id="tenant-enterprise-001",
        repository_url="https://github.com/supply-chain-guardian/test-target",
        commit_hash="abcdef0123456789abcdef0123456789abcdef01",
        scanned_at=datetime(2024, 3, 1, 15, 45, 0, tzinfo=timezone.utc),
        overall_trust_score=68.25,
        dependency_count=2,
        vulnerable_dependency_count=1,
        dependencies=[node_direct, node_unreachable],
        summary_breakdown=breakdown_dummy,
    )

    report_json = report.model_dump_json()
    report_restored = RepositoryScanReport.model_validate_json(report_json)
    assert report_restored == report, "RepositoryScanReport round-trip serialization failed"
    print("✓ [4/6] RepositoryScanReport model_dump_json() and model_validate_json() round-trip verified.")

    # 5. Asserts VersionParseStatus.UNPARSEABLE is valid for non-SemVer packages
    non_semver_node = DependencyNode(
        package_name="legacy-custom-pkg",
        ecosystem=Ecosystem.PYPI,
        resolved_version="2024.01-custom-build",
        version_parse_status=VersionParseStatus.UNPARSEABLE,
        is_direct=False,
        graph_depth=2,
        declared_range="*",
        reachability=ReachabilityStatus.TRANSITIVE_REQUIRED,
        vulnerabilities=[],
        health=dummy_health,
    )
    assert non_semver_node.version_parse_status == VersionParseStatus.UNPARSEABLE
    assert non_semver_node.resolved_version == "2024.01-custom-build"
    print("✓ [5/6] Non-SemVer package with VersionParseStatus.UNPARSEABLE accepted successfully.")

    # 6. Final success indicator
    print("PHASE 1 REV 2.1 CONTRACT VALIDATION: SUCCESS")
