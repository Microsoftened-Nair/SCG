"""Unit tests for Phase 3 Track B enrichment schemas."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from scg_core.schemas.base import Ecosystem, PackageHealthData
from scg_core.schemas.enrichment import (
    EnrichmentStageResult,
    RegistryMetadataResponse,
    ScorecardCheckDetail,
    ScorecardReport,
    SignalSource,
)


def test_signal_source_enum_values():
    """Validates that SignalSource contains all required Phase 3 enum variants."""
    expected = {
        "REGISTRY",
        "SCORECARD",
        "CACHED",
        "UNAVAILABLE_404",
        "UNAVAILABLE_ERROR",
        "UNAVAILABLE_RATE_LIMITED",
        "NOT_APPLICABLE",
    }
    actual = {s.value for s in SignalSource}
    assert actual == expected


def test_scorecard_check_detail_valid():
    """Validates ScorecardCheckDetail instantiation, valid score bounds, and optional reason."""
    detail_max = ScorecardCheckDetail(name="Maintained", score=10, reason="Active commits")
    assert detail_max.name == "Maintained"
    assert detail_max.score == 10
    assert detail_max.reason == "Active commits"

    detail_min = ScorecardCheckDetail(name="Fuzzing", score=-1)
    assert detail_min.score == -1
    assert detail_min.reason is None


def test_scorecard_check_detail_bounds():
    """Validates that ScorecardCheckDetail rejects scores outside [-1, 10]."""
    with pytest.raises(ValidationError):
        ScorecardCheckDetail(name="Test", score=-2)

    with pytest.raises(ValidationError):
        ScorecardCheckDetail(name="Test", score=11)


def test_scorecard_check_detail_frozen_and_forbid():
    """Validates that ScorecardCheckDetail is immutable and forbids extra attributes."""
    detail = ScorecardCheckDetail(name="Signed-Releases", score=8)
    with pytest.raises(ValidationError):
        detail.score = 9  # type: ignore[misc]

    with pytest.raises(ValidationError):
        ScorecardCheckDetail(name="Signed-Releases", score=8, unexpected_field="bad")  # type: ignore[call-arg]


def test_scorecard_report_serialization():
    """Validates ScorecardReport rounding, bounds, and JSON round-trip."""
    report = ScorecardReport(
        aggregate_score=7.456,
        repo_url="https://github.com/expressjs/express",
        checks={"Binary-Artifacts": 10, "Code-Review": 9, "Vulnerabilities": 8},
        date="2024-03-01",
    )
    assert report.aggregate_score == 7.46
    assert report.checks["Code-Review"] == 9

    # Round trip
    json_data = report.model_dump_json()
    restored = ScorecardReport.model_validate_json(json_data)
    assert restored == report

    # Out of bounds
    with pytest.raises(ValidationError):
        ScorecardReport(
            aggregate_score=-0.1,
            repo_url="https://github.com/foo/bar",
            checks={},
        )

    with pytest.raises(ValidationError):
        ScorecardReport(
            aggregate_score=10.1,
            repo_url="https://github.com/foo/bar",
            checks={},
        )


def test_registry_metadata_response():
    """Validates RegistryMetadataResponse field types, UTC validation, and signal sources."""
    now_utc = datetime.now(timezone.utc)
    meta = RegistryMetadataResponse(
        package_name="express",
        ecosystem=Ecosystem.NPM,
        version="4.18.2",
        published_date=now_utc,
        last_registry_activity=now_utc,
        maintainer_count=5,
        weekly_downloads=30000000,
        has_install_scripts=False,
        vcs_url="https://github.com/expressjs/express",
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY,
            "maintainer_count": SignalSource.REGISTRY,
            "scorecard": SignalSource.SCORECARD,
        },
    )
    assert meta.package_name == "express"
    assert meta.ecosystem == Ecosystem.NPM
    assert meta.maintainer_count == 5
    assert meta.signal_sources["scorecard"] == SignalSource.SCORECARD

    # Rejection of naive datetime
    with pytest.raises(ValidationError):
        RegistryMetadataResponse(
            package_name="express",
            ecosystem=Ecosystem.NPM,
            version="4.18.2",
            published_date=datetime(2024, 1, 1, 0, 0, 0),  # naive
            signal_sources={},
        )


def test_enrichment_stage_result():
    """Validates EnrichmentStageResult schema, coverage bounds, and degraded signals defaults."""
    now_utc = datetime.now(timezone.utc)
    health = PackageHealthData(
        published_date=now_utc,
        last_registry_activity=now_utc,
        maintainer_count=2,
        weekly_downloads=50000,
        has_install_scripts=False,
        openssf_scorecard_score=8.0,
        is_deprecated=False,
        signal_sources={"scorecard": SignalSource.SCORECARD},
    )

    result = EnrichmentStageResult(
        vulnerabilities={},
        health={"pkg:npm/express@4.18.2": health},
        enrichment_coverage=0.95,
        cache_healthy=True,
        degraded_signals=[],
    )
    assert result.enrichment_coverage == 0.95
    assert result.cache_healthy is True
    assert result.degraded_signals == []

    # Coverage out of range
    with pytest.raises(ValidationError):
        EnrichmentStageResult(
            vulnerabilities={},
            health={},
            enrichment_coverage=1.5,
        )

    with pytest.raises(ValidationError):
        EnrichmentStageResult(
            vulnerabilities={},
            health={},
            enrichment_coverage=-0.1,
        )
