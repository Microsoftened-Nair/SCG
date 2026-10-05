"""Data contracts and schemas for Supply Chain Guardian (SCG) Phase 3 Track B.

Conforms to IEEE Std 830-1998, RFC 2119, and SCG Phase 3 Specification.
Defines data structures for external vulnerability intelligence, package registry metadata,
OpenSSF Scorecards, and aggregated enrichment results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

import sys
from pathlib import Path

# Ensure repository root is in sys.path for direct script execution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scg_core.schemas.base import (
    AwareUTC,
    Ecosystem,
    PackageHealthData,
    VulnerabilityRecord,
)


def _round_to_two_decimals(value: float) -> float:
    """Rounds a floating-point score to a maximum of two decimal places."""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


class SignalSource(str, Enum):
    """Provenance and availability status of external enrichment signals."""

    REGISTRY = "REGISTRY"
    SCORECARD = "SCORECARD"
    CACHED = "CACHED"
    UNAVAILABLE_404 = "UNAVAILABLE_404"
    UNAVAILABLE_ERROR = "UNAVAILABLE_ERROR"
    UNAVAILABLE_RATE_LIMITED = "UNAVAILABLE_RATE_LIMITED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ScorecardCheckDetail(BaseModel):
    """Evaluation result for an individual OpenSSF Scorecard check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(
        ...,
        min_length=1,
        description="Name of the evaluated OpenSSF Scorecard check.",
    )
    score: int = Field(
        ...,
        ge=-1,
        le=10,
        description="Score assigned to the check, from -1 (inconclusive/not applicable) to 10.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Optional diagnostic reason or explanation provided by Scorecard.",
    )


class ScorecardReport(BaseModel):
    """Aggregated OpenSSF Scorecard report for an upstream repository."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    aggregate_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Composite OpenSSF Scorecard rating between 0.0 and 10.0.",
    )
    repo_url: str = Field(
        ...,
        description="Target VCS repository URL assessed by OpenSSF Scorecard.",
    )
    checks: Dict[str, int] = Field(
        ...,
        description="Mapping of check names to their assigned integer scores.",
    )
    date: Optional[str] = Field(
        default=None,
        description="Timestamp or date string of the Scorecard assessment run.",
    )

    @field_validator("aggregate_score", mode="after")
    @classmethod
    def round_aggregate_score(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        return _round_to_two_decimals(v)


class RegistryMetadataResponse(BaseModel):
    """Normalized metadata response payload returned from package registry APIs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Canonical package identifier on the upstream package registry.",
    )
    ecosystem: Ecosystem = Field(
        ...,
        description="Package ecosystem (npm or pypi).",
    )
    version: str = Field(
        ...,
        max_length=128,
        description="Specific package version represented by this metadata.",
    )
    published_date: Optional[AwareUTC] = Field(
        default=None,
        description="Release publication timestamp in UTC ISO-8601 format.",
    )
    last_registry_activity: Optional[AwareUTC] = Field(
        default=None,
        description="Timestamp of the most recent activity or release on the registry in UTC.",
    )
    maintainer_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Count of registered package maintainers.",
    )
    weekly_downloads: Optional[int] = Field(
        default=None,
        ge=0,
        description="Average weekly download count from registry telemetry.",
    )
    has_install_scripts: Optional[bool] = Field(
        default=None,
        description="Indicates whether the package specifies pre/post install lifecycle scripts.",
    )
    vcs_url: Optional[str] = Field(
        default=None,
        description="Source code VCS repository URL.",
    )
    is_deprecated: Optional[bool] = Field(
        default=None,
        description="Flag indicating if the package or version is formally deprecated upstream.",
    )
    signal_sources: Dict[str, SignalSource] = Field(
        default_factory=dict,
        description="Provenance of each ingested metadata signal.",
    )


class EnrichmentStageResult(BaseModel):
    """Aggregate result output produced by the vulnerability enrichment pipeline stage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerabilities: Dict[str, List[VulnerabilityRecord]] = Field(
        default_factory=dict,
        description="Mapping of package identifiers/PURLs to detected security vulnerability advisories.",
    )
    health: Dict[str, PackageHealthData] = Field(
        default_factory=dict,
        description="Mapping of package identifiers/PURLs to package health and maintenance metrics.",
    )
    enrichment_coverage: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Ratio of successfully enriched packages to total dependencies (0.0 to 1.0).",
    )
    cache_healthy: bool = Field(
        default=True,
        description="Flag indicating whether the multi-tier caching layer operated in healthy status.",
    )
    degraded_signals: List[str] = Field(
        default_factory=list,
        description="List of signal sources currently operating in degraded fallback mode.",
    )

    @field_validator("enrichment_coverage", mode="after")
    @classmethod
    def round_coverage(cls, v: float) -> float:
        return _round_to_two_decimals(v)


__all__ = [
    "EnrichmentStageResult",
    "PackageHealthData",
    "RegistryMetadataResponse",
    "ScorecardCheckDetail",
    "ScorecardReport",
    "SignalSource",
]


if __name__ == "__main__":
    print("Executing verification harness for scg_core/schemas/enrichment.py...")

    # 1. SignalSource Enum check
    expected_signals = {
        "REGISTRY",
        "SCORECARD",
        "CACHED",
        "UNAVAILABLE_404",
        "UNAVAILABLE_ERROR",
        "UNAVAILABLE_RATE_LIMITED",
        "NOT_APPLICABLE",
    }
    actual_signals = {s.value for s in SignalSource}
    assert expected_signals == actual_signals, f"SignalSource mismatch: {actual_signals} != {expected_signals}"
    print("[1/5] SignalSource enum verified with all 7 required values.")

    # 2. ScorecardCheckDetail validation & bounds (-1 <= score <= 10)
    valid_detail = ScorecardCheckDetail(name="Binary-Artifacts", score=10, reason="No binaries present")
    assert valid_detail.score == 10
    assert valid_detail.reason == "No binaries present"

    inconclusive_detail = ScorecardCheckDetail(name="Branch-Protection", score=-1)
    assert inconclusive_detail.score == -1
    assert inconclusive_detail.reason is None

    try:
        ScorecardCheckDetail(name="Invalid-Low", score=-2)
        raise AssertionError("Failed to reject score < -1")
    except ValidationError:
        pass

    try:
        ScorecardCheckDetail(name="Invalid-High", score=11)
        raise AssertionError("Failed to reject score > 10")
    except ValidationError:
        pass

    # Extra forbid check
    try:
        ScorecardCheckDetail(name="Test", score=5, extra_field="forbidden")  # type: ignore[call-arg]
        raise AssertionError("Failed to forbid extra fields in ScorecardCheckDetail")
    except ValidationError:
        pass
    print("[2/5] ScorecardCheckDetail bounds (-1 to 10) and extra='forbid' verified.")

    # 3. ScorecardReport validation
    report = ScorecardReport(
        aggregate_score=8.756,
        repo_url="https://github.com/lodash/lodash",
        checks={"Binary-Artifacts": 10, "Code-Review": 8, "Vulnerabilities": 9},
        date="2024-03-01",
    )
    assert report.aggregate_score == 8.76, "aggregate_score must round to two decimals"
    assert report.checks["Binary-Artifacts"] == 10

    report_json = report.model_dump_json()
    restored_report = ScorecardReport.model_validate_json(report_json)
    assert restored_report == report
    print("[3/5] ScorecardReport rounding and round-trip serialization verified.")

    # 4. RegistryMetadataResponse validation
    now_utc = datetime.now(timezone.utc)
    reg_meta = RegistryMetadataResponse(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        version="4.17.21",
        published_date=now_utc,
        last_registry_activity=now_utc,
        maintainer_count=2,
        weekly_downloads=45000000,
        has_install_scripts=False,
        vcs_url="https://github.com/lodash/lodash",
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY,
            "scorecard": SignalSource.SCORECARD,
        },
    )
    assert reg_meta.ecosystem == Ecosystem.NPM
    assert reg_meta.signal_sources["weekly_downloads"] == SignalSource.REGISTRY
    print("[4/5] RegistryMetadataResponse validated with AwareUTC and signal_sources.")

    # 5. EnrichmentStageResult validation
    dummy_health = PackageHealthData(
        published_date=now_utc,
        last_registry_activity=now_utc,
        maintainer_count=2,
        weekly_downloads=45000000,
        has_install_scripts=False,
        openssf_scorecard_score=8.5,
        is_deprecated=False,
        signal_sources={"scorecard": SignalSource.SCORECARD},
    )

    stage_result = EnrichmentStageResult(
        vulnerabilities={"pkg:npm/lodash@4.17.21": []},
        health={"pkg:npm/lodash@4.17.21": dummy_health},
        enrichment_coverage=1.0,
        cache_healthy=True,
        degraded_signals=["OSV_FALLBACK"],
    )
    assert stage_result.enrichment_coverage == 1.0
    assert stage_result.cache_healthy is True
    assert stage_result.degraded_signals == ["OSV_FALLBACK"]

    res_json = stage_result.model_dump_json()
    restored_res = EnrichmentStageResult.model_validate_json(res_json)
    assert restored_res == stage_result
    print("[5/5] EnrichmentStageResult and PackageHealthData integration verified.")

    print("\nSUCCESS: scg_core/schemas/enrichment.py verified.")
