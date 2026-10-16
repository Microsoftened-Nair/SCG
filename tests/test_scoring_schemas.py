"""Unit tests for Phase 5 Track D Scoring schemas and precision utilities."""

from datetime import datetime, timezone
from decimal import Decimal
import pytest
from pydantic import HttpUrl, ValidationError

from scg_core.schemas.base import AwareUTC, ReachabilityStatus, SeverityLevel
from scg_core.schemas.scoring import (
    FOUR_PLACES,
    SEVERITY_WEIGHTS,
    TWO_PLACES,
    Deduction,
    DependencyScoreResult,
    Evidence,
    EvidenceKind,
    FacetName,
    FacetResult,
    PolicyWeights,
    ProjectTrustReport,
    SCGPolicyConfig,
    Suppression,
    SuppressionScope,
    quantize,
)


def test_quantize_round_half_up():
    """Validates REQ-P5-01: quantize precision utility using ROUND_HALF_UP."""
    assert quantize(Decimal("1.255")) == Decimal("1.26")
    assert quantize(Decimal("1.254")) == Decimal("1.25")
    assert quantize(1.255) == Decimal("1.26")
    assert quantize(1.254) == Decimal("1.25")
    assert quantize("2.5") == Decimal("2.50")
    assert quantize(5) == Decimal("5.00")
    assert quantize(Decimal("0.005")) == Decimal("0.01")
    assert quantize(Decimal("0.004")) == Decimal("0.00")
    assert TWO_PLACES == Decimal("0.01")
    assert FOUR_PLACES == Decimal("0.0001")


def test_enums():
    """Validates REQ-P5-03: exact enum definitions and values."""
    assert {f.value for f in FacetName} == {"VULNERABILITY", "HYGIENE", "BEHAVIOR"}
    assert {e.value for e in EvidenceKind} == {
        "SOURCE_LOCATION",
        "REGISTRY_FIELD",
        "SCORECARD_CHECK",
        "ADVISORY",
    }
    assert {s.value for s in SuppressionScope} == {"GLOBAL", "PACKAGE", "ADVISORY"}


def test_policy_weights_defaults_and_normalization():
    """Validates REQ-P5-04 & REQ-P5-05: PolicyWeights normalization and validation."""
    # 1. Defaults instantiate and sum to 1.0 (quantized to 4 decimal places)
    pw = PolicyWeights()
    assert pw.vuln == Decimal("0.5000")
    assert pw.hygiene == Decimal("0.3000")
    assert pw.behavior == Decimal("0.2000")
    assert pw.vuln + pw.hygiene + pw.behavior == Decimal("1.0")

    # 2. Non-normalized weights normalize to (0.6000, 0.2000, 0.2000)
    pw_custom = PolicyWeights(vuln=3, hygiene=1, behavior=1)  # type: ignore[arg-type]
    assert pw_custom.vuln == Decimal("0.6000")
    assert pw_custom.hygiene == Decimal("0.2000")
    assert pw_custom.behavior == Decimal("0.2000")
    assert pw_custom.vuln + pw_custom.hygiene + pw_custom.behavior == Decimal("1.0")

    # 3. All-zero or negative weights raise ValueError
    with pytest.raises(ValidationError) as exc_info:
        PolicyWeights(vuln=0, hygiene=0, behavior=0)  # type: ignore[arg-type]
    assert "Policy weights must sum to a strictly positive value" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        PolicyWeights(vuln=-1, hygiene=0, behavior=0)  # type: ignore[arg-type]
    assert "Policy weights must sum to a strictly positive value" in str(exc_info.value)


def test_policy_weights_frozen_and_forbid():
    """Validates immutability and rejection of extra fields."""
    pw = PolicyWeights()
    with pytest.raises(ValidationError):
        pw.vuln = Decimal("0.6000")  # type: ignore[misc]

    with pytest.raises(ValidationError):
        PolicyWeights(extra_field=1)  # type: ignore[call-arg]


def test_evidence_model():
    """Validates REQ-P5-04: Evidence model."""
    ev = Evidence(
        kind=EvidenceKind.SOURCE_LOCATION,
        file_path="src/index.js",
        line_number=42,
        excerpt="eval(payload)",
        url=HttpUrl("https://example.com/advisory/1"),
    )
    assert ev.kind == EvidenceKind.SOURCE_LOCATION
    assert ev.file_path == "src/index.js"
    assert ev.line_number == 42
    assert ev.excerpt == "eval(payload)"
    assert str(ev.url) == "https://example.com/advisory/1"

    # Frozen & extra forbid
    with pytest.raises(ValidationError):
        ev.file_path = "other.js"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.ADVISORY, unknown_key="val")  # type: ignore[call-arg]


def test_deduction_model():
    """Validates REQ-P5-04: Deduction model."""
    d = Deduction(
        rule_id="VULN-REACHABLE-CRIT",
        points=Decimal("30.00"),
        facet=FacetName.VULNERABILITY,
        title="Reachable Critical CVE",
        detail="High confidence AST callpath exists to vulnerable symbol",
    )
    assert d.rule_id == "VULN-REACHABLE-CRIT"
    assert d.points == Decimal("30.00")
    assert d.facet == FacetName.VULNERABILITY
    assert d.evidence == []
    assert d.inputs == {}
    assert d.subject_id is None
    assert d.suppressible is True
    assert d.confidence == Decimal("1.0")

    # Frozen & extra forbid
    with pytest.raises(ValidationError):
        d.points = Decimal("20.00")  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Deduction(  # type: ignore[call-arg]
            rule_id="R1",
            points=Decimal("10"),
            facet=FacetName.HYGIENE,
            title="T",
            detail="D",
            unexpected="fail",
        )


def test_suppression_model():
    """Validates REQ-P5-04: Suppression model with reason min_length and AwareUTC."""
    valid_time = datetime(2027, 1, 1, 12, 0, tzinfo=timezone.utc)
    s = Suppression(
        rule_id="VULN-REACHABLE-CRIT",
        scope=SuppressionScope.PACKAGE,
        target="pkg:npm/lodash@4.17.20",
        reason="Compensating control active in outer API gateway filter",
        approved_by="security-lead@company.internal",
        expires_at=valid_time,
    )
    assert s.reason == "Compensating control active in outer API gateway filter"
    assert s.expires_at == valid_time

    # Rejects reason < 20 chars
    with pytest.raises(ValidationError):
        Suppression(
            rule_id="VULN-REACHABLE-CRIT",
            scope=SuppressionScope.PACKAGE,
            reason="Too short reason",
            approved_by="sec",
            expires_at=valid_time,
        )

    # Rejects naive datetime
    with pytest.raises(ValidationError):
        Suppression(
            rule_id="VULN-REACHABLE-CRIT",
            scope=SuppressionScope.PACKAGE,
            reason="Compensating control active in outer API gateway filter",
            approved_by="sec",
            expires_at=datetime(2027, 1, 1, 12, 0),  # Naive
        )


def test_scg_policy_config():
    """Validates REQ-P5-04: SCGPolicyConfig schema and constraints."""
    config = SCGPolicyConfig()
    assert config.schema_version == "1.0"
    assert config.min_acceptable_score == Decimal("70.00")
    assert config.weights.vuln == Decimal("0.5000")
    assert config.allowed_install_scripts == []
    assert config.suppressions == []

    # Score bounds [0.0, 100.0]
    with pytest.raises(ValidationError):
        SCGPolicyConfig(min_acceptable_score=Decimal("-1.0"))
    with pytest.raises(ValidationError):
        SCGPolicyConfig(min_acceptable_score=Decimal("100.1"))


def test_facet_result():
    """Validates REQ-P5-04: FacetResult confidence bounds and structure."""
    fr = FacetResult(score=Decimal("85.50"), confidence=Decimal("0.95"))
    assert fr.score == Decimal("85.50")
    assert fr.confidence == Decimal("0.95")
    assert fr.deductions == []
    assert fr.unavailable_signals == []

    # Confidence must be in [0.0, 1.0]
    with pytest.raises(ValidationError):
        FacetResult(score=Decimal("85.50"), confidence=Decimal("1.05"))
    with pytest.raises(ValidationError):
        FacetResult(score=Decimal("85.50"), confidence=Decimal("-0.1"))


def test_dependency_score_result_and_severity_helper():
    """Validates REQ-P5-04 & REQ-P5-02: DependencyScoreResult and SeverityLevel helper."""
    dsr = DependencyScoreResult(
        package_name="lodash",
        purl="pkg:npm/lodash@4.17.21",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerability_facet=Decimal("100.00"),
        hygiene_facet=Decimal("90.00"),
        behavior_facet=Decimal("100.00"),
        composite_score=Decimal("97.00"),
        confidence=Decimal("0.95"),
        effective_exposure_factor=Decimal("1.00"),
        has_reachable_critical=False,
        has_reachable_high=True,
    )
    assert dsr.reachability == ReachabilityStatus.DIRECT_IMPORTED
    assert dsr.has_reachable_severity(SeverityLevel.HIGH) is True
    assert dsr.has_reachable_severity(SeverityLevel.CRITICAL) is False
    assert dsr.has_reachable_severity(SeverityLevel.LOW) is False
    assert SEVERITY_WEIGHTS[SeverityLevel.CRITICAL] == Decimal("1.00")


def test_project_trust_report():
    """Validates REQ-P5-04: ProjectTrustReport model structure."""
    policy = SCGPolicyConfig()
    dsr = DependencyScoreResult(
        package_name="lodash",
        purl="pkg:npm/lodash@4.17.21",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerability_facet=Decimal("100.00"),
        hygiene_facet=Decimal("90.00"),
        behavior_facet=Decimal("100.00"),
        composite_score=Decimal("97.00"),
        confidence=Decimal("0.95"),
        effective_exposure_factor=Decimal("1.00"),
    )
    report = ProjectTrustReport(
        scan_id="scan-12345",
        overall_trust_score=Decimal("97.00"),
        mean_confidence=Decimal("0.95"),
        policy_applied=policy,
        total_components_evaluated=1,
        considered_components_count=1,
        average_vuln_facet=Decimal("100.00"),
        average_hygiene_facet=Decimal("90.00"),
        average_behavior_facet=Decimal("100.00"),
        applied_suppressions=[],
        dependency_scores={"pkg:npm/lodash@4.17.21": dsr},
        passed_policy_threshold=True,
    )
    assert report.scan_id == "scan-12345"
    assert report.overall_trust_score == Decimal("97.00")
    assert report.passed_policy_threshold is True
    assert "pkg:npm/lodash@4.17.21" in report.dependency_scores
