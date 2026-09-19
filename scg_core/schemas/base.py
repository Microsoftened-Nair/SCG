"""Canonical base schemas and data contracts for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-1-2026-REV-2.0.
Governs all serialization contracts across FastAPI, Redis, PostgreSQL, and Celery.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    GetJsonSchemaHandler,
    HttpUrl,
    ValidationError,
    field_serializer,
    field_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema


def _round_to_two_decimals(value: float) -> float:
    """Rounds a floating-point score to a maximum of two decimal places using standard numeric evaluation."""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


# Strict Semantic Versioning 2.0.0 specification regex (https://semver.org/)
SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


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


class SemVerString(str):
    """Custom Pydantic v2 type validating Semantic Versioning 2.0.0 compliance."""

    @classmethod
    def _validate(cls, value: Any) -> "SemVerString":
        if not isinstance(value, str):
            raise TypeError("SemVerString must be a valid string.")
        if not SEMVER_REGEX.match(value):
            raise ValueError(f"Value '{value}' does not adhere to Semantic Versioning 2.0.0 specification.")
        return cls(value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.str_schema(),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        json_schema = handler(_core_schema)
        json_schema = handler.resolve_ref_schema(json_schema)
        json_schema.update(
            type="string",
            pattern=SEMVER_REGEX.pattern,
            examples=["1.0.0", "2.1.3-beta.1", "0.9.4+build.2026"],
            description="Strict Semantic Versioning 2.0.0 formatted version string.",
        )
        return json_schema


class VulnerabilityRecord(BaseModel):
    """Vulnerability advisory record with severity, CVSS score, and symbol impact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Canonical vulnerability identifier (e.g. CVE-2023-1234, GHSA-xxxx-xxxx-xxxx).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Categorical severity rating.",
    )
    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Common Vulnerability Scoring System (CVSS) v3 base score (0.0 to 10.0).",
    )
    fixed_versions: List[str] = Field(
        default_factory=list,
        description="List of package versions containing fixes for this vulnerability.",
    )
    vulnerable_symbols: List[str] = Field(
        default_factory=list,
        description="List of vulnerable classes, methods, or function symbols identified in the package.",
    )

    @field_validator("cvss_score", mode="after")
    @classmethod
    def round_cvss_score(cls, v: float) -> float:
        return _round_to_two_decimals(v)


class PackageHealthData(BaseModel):
    """Aggregated health, maintenance, and registry metrics for a package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    published_date: datetime = Field(
        ...,
        description="Release timestamp of the resolved version in ISO 8601 UTC.",
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

    @field_validator("published_date", mode="after")
    @classmethod
    def validate_utc_date(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_serializer("published_date", when_used="json")
    def serialize_published_date(self, dt: datetime) -> str:
        return dt.isoformat()

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
    resolved_version: SemVerString = Field(
        ...,
        description="Strict SemVer 2.0.0 string representing the pinned resolution version.",
    )
    is_direct: bool = Field(
        ...,
        description="Boolean indicating if the package is declared directly in project root manifests.",
    )
    graph_depth: int = Field(
        ...,
        ge=0,
        description="Shortest topological path distance from the root project manifest (0 for direct).",
    )
    declared_range: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Raw version requirement string from manifest (e.g., ^1.2.0, >=2.0.0).",
    )
    reachability: ReachabilityStatus = Field(
        ...,
        description="Static AST call-graph reachability status.",
    )
    vulnerabilities: List[VulnerabilityRecord] = Field(
        default_factory=list,
        description="List of security vulnerabilities affecting this specific package resolution.",
    )
    health: Optional[PackageHealthData] = Field(
        default=None,
        description="Repository and registry health metrics for this dependency.",
    )


class TrustScoreBreakdown(BaseModel):
    """Comprehensive facet scoring breakdown and deduction ledger."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerability_facet: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Security facet score based on vulnerability severity and reachability.",
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

    scan_id: UUID = Field(
        ...,
        description="Universally unique identifier for the scan job.",
    )
    repository_url: HttpUrl = Field(
        ...,
        description="Remote source control repository URL scanned.",
    )
    commit_hash: str = Field(
        ...,
        pattern=r"^[0-9a-fA-F]{40}$",
        description="40-character hexadecimal SHA-1 commit hash analyzed.",
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
        default_factory=list,
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

    # 1. Instantiation of valid dummy instances
    health_dummy = PackageHealthData(
        published_date=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        maintainer_count=4,
        weekly_downloads=1250000,
        has_install_scripts=False,
        openssf_scorecard_score=8.567,  # Rounds to 8.57
    )
    assert health_dummy.openssf_scorecard_score == 8.57

    vuln_dummy = VulnerabilityRecord(
        id="GHSA-test-1234-abcd",
        severity=SeverityLevel.HIGH,
        cvss_score=8.456,  # Rounds to 8.46
        fixed_versions=["1.2.4"],
        vulnerable_symbols=["parsePayload", "decodeHeader"],
    )
    assert vuln_dummy.cvss_score == 8.46

    dep_dummy = DependencyNode(
        package_name="fast-jwt",
        ecosystem=Ecosystem.NPM,
        resolved_version=SemVerString("1.2.3-beta.1"),
        is_direct=True,
        graph_depth=0,
        declared_range="^1.2.0",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerabilities=[vuln_dummy],
        health=health_dummy,
    )
    assert dep_dummy.package_name == "fast-jwt"
    assert dep_dummy.resolved_version == "1.2.3-beta.1"

    breakdown_dummy = TrustScoreBreakdown(
        vulnerability_facet=72.333,  # Rounds to 72.33
        hygiene_facet=88.555,        # Rounds to 88.56
        behavior_facet=95.0,
        composite_score=81.256,      # Rounds to 81.26
        deductions={"HIGH_SEVERITY_DIRECT_DEP": -15.555},  # Rounds to -15.56
    )
    assert breakdown_dummy.vulnerability_facet == 72.33
    assert breakdown_dummy.hygiene_facet == 88.56
    assert breakdown_dummy.composite_score == 81.26
    assert breakdown_dummy.deductions["HIGH_SEVERITY_DIRECT_DEP"] == -15.56

    report_id = uuid4()
    report_dummy = RepositoryScanReport(
        scan_id=report_id,
        repository_url=HttpUrl("https://github.com/supply-chain-guardian/scg-core"),
        commit_hash="a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d",
        overall_trust_score=81.256,  # Rounds to 81.26
        dependency_count=1,
        vulnerable_dependency_count=1,
        dependencies=[dep_dummy],
        summary_breakdown=breakdown_dummy,
    )
    assert report_dummy.overall_trust_score == 81.26

    # 2. Assert symmetrical serialization and deserialization
    dep_json = dep_dummy.model_dump_json()
    dep_restored = DependencyNode.model_validate_json(dep_json)
    assert dep_restored == dep_dummy, "DependencyNode serialization symmetry violated."

    report_json = report_dummy.model_dump_json()
    report_restored = RepositoryScanReport.model_validate_json(report_json)
    assert report_restored == report_dummy, "RepositoryScanReport serialization symmetry violated."

    # 3. Test boundary validations
    # Test 3a: cvss_score > 10.0 raises ValidationError
    try:
        VulnerabilityRecord(
            id="CVE-2024-0001",
            severity=SeverityLevel.CRITICAL,
            cvss_score=10.01,
            fixed_versions=["2.0.0"],
            vulnerable_symbols=[],
        )
        raise AssertionError("Validation did not fail for cvss_score > 10.0")
    except ValidationError:
        pass

    # Test 3b: graph_depth < 0 raises ValidationError
    try:
        DependencyNode(
            package_name="malformed-depth-pkg",
            ecosystem=Ecosystem.PYPI,
            resolved_version=SemVerString("1.0.0"),
            is_direct=False,
            graph_depth=-1,
            declared_range="==1.0.0",
            reachability=ReachabilityStatus.TRANSITIVE_REQUIRED,
        )
        raise AssertionError("Validation did not fail for graph_depth < 0")
    except ValidationError:
        pass

    # Test 3c: Invalid SemVer string raises ValidationError
    try:
        DependencyNode(
            package_name="invalid-semver-pkg",
            ecosystem=Ecosystem.NPM,
            resolved_version=SemVerString("1.0"),  # Invalid: 2 parts instead of 3
            is_direct=True,
            graph_depth=0,
            declared_range="1.0",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
        )
        raise AssertionError("Validation did not fail for invalid SemVerString")
    except ValidationError:
        pass

    # 4. Success sentinel output
    print("PHASE 1 CONTRACT VALIDATION: SUCCESS")
