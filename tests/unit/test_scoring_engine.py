"""Unit tests for Track D TrustScoringEngine (SCG Phase 5)."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from scg_core.schemas.base import (
    CvssSource,
    DependencyNode,
    Ecosystem,
    PackageHealthData,
    ReachabilityStatus,
    SeverityLevel,
    VulnerabilityRecord,
)
from scg_core.schemas.reachability import ReachabilityEvaluationResult
from scg_core.schemas.scoring import (
    DependencyScoreResult,
    FacetName,
    PolicyWeights,
    SCGPolicyConfig,
    TWO_PLACES,
)
from scg_core.scoring.engine import TrustScoringEngine, VETTED_BUILD_TOOLS


def _make_health(
    published_days_ago: int = 30,
    activity_days_ago: int = 30,
    maintainer_count: int | None = 3,
    weekly_downloads: int | None = 50_000,
    has_install_scripts: bool = False,
    scorecard: float | None = 8.0,
    is_deprecated: bool = False,
) -> PackageHealthData:
    now = datetime.now(timezone.utc)
    return PackageHealthData(
        published_date=now - timedelta(days=published_days_ago),
        last_registry_activity=now - timedelta(days=activity_days_ago),
        maintainer_count=maintainer_count,
        weekly_downloads=weekly_downloads,
        has_install_scripts=has_install_scripts,
        openssf_scorecard_score=scorecard,
        is_deprecated=is_deprecated,
    )


def _make_node(
    name: str = "example-pkg",
    version: str = "1.0.0",
    health: PackageHealthData | None = None,
    vulnerabilities: list[VulnerabilityRecord] | None = None,
) -> DependencyNode:
    return DependencyNode(
        package_name=name,
        ecosystem=Ecosystem.NPM,
        resolved_version=version,
        is_direct=True,
        health=health or _make_health(),
        vulnerabilities=vulnerabilities or [],
    )


def _make_reach(
    name: str = "example-pkg",
    version: str = "1.0.0",
    status: ReachabilityStatus = ReachabilityStatus.DIRECT_IMPORTED,
    exposure: float = 1.0,
    symbol_confirmed: bool = False,
) -> ReachabilityEvaluationResult:
    return ReachabilityEvaluationResult(
        package_name=name,
        ecosystem=Ecosystem.NPM,
        resolved_version=version,
        reachability=status,
        exposure_factor=exposure,
        effective_exposure_factor=exposure,
        symbol_confirmed_reachable=symbol_confirmed,
    )


def test_repository_rollup_prevents_clean_dependency_dilution():
    """Reproduces SCORE-TC-01: Verifies 1,000 clean dependencies cannot raise a critical repo above 35.00."""
    engine = TrustScoringEngine()

    scores_map: dict[str, DependencyScoreResult] = {}

    # 1 critical vulnerable dependency
    critical_dsr = DependencyScoreResult(
        package_name="vulnerable-core",
        purl="pkg:npm/vulnerable-core@1.0.0",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerability_facet=Decimal("0.00"),
        hygiene_facet=Decimal("100.00"),
        behavior_facet=Decimal("100.00"),
        composite_score=Decimal("50.00"),
        confidence=Decimal("1.00"),
        effective_exposure_factor=Decimal("1.00"),
        has_reachable_critical=True,
        has_reachable_high=False,
        has_known_exploited=False,
    )
    scores_map[critical_dsr.purl] = critical_dsr

    # 1,000 clean dependencies with score 100.00
    for i in range(1000):
        purl = f"pkg:npm/clean-dep-{i}@1.0.0"
        scores_map[purl] = DependencyScoreResult(
            package_name=f"clean-dep-{i}",
            purl=purl,
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            vulnerability_facet=Decimal("100.00"),
            hygiene_facet=Decimal("100.00"),
            behavior_facet=Decimal("100.00"),
            composite_score=Decimal("100.00"),
            confidence=Decimal("1.00"),
            effective_exposure_factor=Decimal("1.00"),
            has_reachable_critical=False,
            has_reachable_high=False,
            has_known_exploited=False,
        )

    report = engine.aggregate_project_report(scan_id="scan-dilution-test", dependency_scores=scores_map)

    # Must be bounded by critical safety ceiling <= 35.00
    assert report.total_components_evaluated == 1001
    assert report.considered_components_count == 1001
    assert report.overall_trust_score <= Decimal("35.00")
    assert report.passed_policy_threshold is False


def test_missing_scorecard_decrements_confidence_without_penalty():
    """Reproduces SCORE-TC-02: Verifies untracked Scorecard packages get 100.00 hygiene with confidence < 1.0."""
    engine = TrustScoringEngine()

    # Health data missing scorecard score (None)
    health = _make_health(
        published_days_ago=30,
        activity_days_ago=30,
        maintainer_count=2,
        weekly_downloads=50_000,
        has_install_scripts=False,
        scorecard=None,  # Missing scorecard
        is_deprecated=False,
    )
    node = _make_node(health=health)
    reach = _make_reach()

    hygiene_res = engine._compute_hygiene_facet(node)

    assert hygiene_res.score == Decimal("100.00")
    assert hygiene_res.confidence < Decimal("1.00")
    assert hygiene_res.confidence == Decimal("0.70")  # 46.0 / 66.0 = 0.6969... -> 0.70
    assert "openssf_scorecard_score" in hygiene_res.unavailable_signals


def test_vulnerability_facet_non_saturating():
    """Asserts adding 20 medium vulnerabilities does not saturate score to 0.00."""
    engine = TrustScoringEngine()

    vulns: list[VulnerabilityRecord] = []
    for i in range(20):
        vulns.append(
            VulnerabilityRecord(
                id=f"GHSA-med-{i}",
                summary=f"Medium advisory #{i}",
                cvss_score=5.0,
                cvss_source=CvssSource.PUBLISHED_SCORE,
                severity=SeverityLevel.MEDIUM,
                epss_score=0.01,
            )
        )

    node = _make_node(vulnerabilities=vulns)
    reach = _make_reach(exposure=1.0)

    vuln_res = engine._compute_vulnerability_facet(node, reach)

    assert vuln_res.score > Decimal("0.00")
    assert vuln_res.score >= Decimal("50.00")  # Due to exponential decay tail attenuation
    assert len(vuln_res.deductions) == 20


def test_reputation_bypass_esbuild():
    """Asserts build utilities like esbuild bypass install script penalties."""
    engine = TrustScoringEngine()

    health = _make_health(
        has_install_scripts=True,
        weekly_downloads=5_000,  # Below 10k modifier threshold
        published_days_ago=2,    # New release (<= 7 days)
        scorecard=4.0,           # Below 6.0
    )
    node = _make_node(name="esbuild", health=health)
    reach = _make_reach(name="esbuild")

    dsr = engine.evaluate_dependency(node, reach)

    assert dsr.reputation_bypass_applied is True
    assert dsr.behavior_facet == Decimal("100.00")
    vetted_deductions = [d for d in dsr.deductions if d.rule_id == "BEH.INSTALL_SCRIPT_VETTED"]
    assert len(vetted_deductions) == 1
    assert vetted_deductions[0].points == Decimal("0.00")


def test_unvetted_install_script_penalties():
    """Validates full penalties and modifiers for untrusted package with install scripts."""
    engine = TrustScoringEngine()

    health = _make_health(
        has_install_scripts=True,
        weekly_downloads=5_000,  # < 10,000 (+15 pts)
        published_days_ago=3,    # <= 7 days (+10 pts)
        scorecard=3.0,           # < 6.0
    )
    node = _make_node(name="untrusted-pkg", health=health)
    reach = _make_reach(name="untrusted-pkg")

    dsr = engine.evaluate_dependency(node, reach)

    assert dsr.reputation_bypass_applied is False
    # Base 15 + Low dl 15 + New release 10 = 40 pts penalty -> 60.00 score
    assert dsr.behavior_facet == Decimal("60.00")
    rule_ids = {d.rule_id for d in dsr.deductions}
    assert "BEH.UNVETTED_INSTALL_SCRIPT" in rule_ids
    assert "BEH.LOW_DOWNLOADS_INSTALL_SCRIPT" in rule_ids
    assert "BEH.NEW_RELEASE_INSTALL_SCRIPT" in rule_ids


def test_safety_ceiling_known_exploited():
    """Validates ceiling gate <= 20.00 for known exploited vulnerabilities."""
    engine = TrustScoringEngine()

    scores_map = {
        "pkg:npm/kev-pkg@1.0.0": DependencyScoreResult(
            package_name="kev-pkg",
            purl="pkg:npm/kev-pkg@1.0.0",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            vulnerability_facet=Decimal("10.00"),
            hygiene_facet=Decimal("100.00"),
            behavior_facet=Decimal("100.00"),
            composite_score=Decimal("80.00"),
            confidence=Decimal("1.00"),
            effective_exposure_factor=Decimal("1.00"),
            has_reachable_critical=False,
            has_reachable_high=False,
            has_known_exploited=True,
        )
    }

    report = engine.aggregate_project_report("scan-kev", scores_map)
    assert report.overall_trust_score <= Decimal("20.00")


def test_latent_nodes_excluded_from_considered_rollup():
    """Validates that ReachabilityStatus.UNREFERENCED_LATENT nodes are filtered out."""
    engine = TrustScoringEngine()

    scores_map = {
        "pkg:npm/direct-good@1.0.0": DependencyScoreResult(
            package_name="direct-good",
            purl="pkg:npm/direct-good@1.0.0",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            vulnerability_facet=Decimal("100.00"),
            hygiene_facet=Decimal("100.00"),
            behavior_facet=Decimal("100.00"),
            composite_score=Decimal("100.00"),
            confidence=Decimal("1.00"),
            effective_exposure_factor=Decimal("1.00"),
        ),
        "pkg:npm/latent-bad@1.0.0": DependencyScoreResult(
            package_name="latent-bad",
            purl="pkg:npm/latent-bad@1.0.0",
            reachability=ReachabilityStatus.UNREFERENCED_LATENT,
            vulnerability_facet=Decimal("0.00"),
            hygiene_facet=Decimal("0.00"),
            behavior_facet=Decimal("0.00"),
            composite_score=Decimal("0.00"),
            confidence=Decimal("1.00"),
            effective_exposure_factor=Decimal("0.10"),
            has_reachable_critical=False,
        ),
    }

    report = engine.aggregate_project_report("scan-latent", scores_map)
    assert report.total_components_evaluated == 2
    assert report.considered_components_count == 1
    assert report.overall_trust_score == Decimal("100.00")
