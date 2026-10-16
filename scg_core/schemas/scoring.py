"""Deterministic mathematical scoring schemas and policy contracts for SCG Track D.

Defines all shared schemas, enums, evidence models, structured deductions,
policy configurations, and quantization functions adhering to IEEE Std 830-1998,
RFC 2119, and SCG Phase 5 Track D specifications using bit-exact Decimal arithmetic.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from scg_core.schemas.base import AwareUTC, ReachabilityStatus, SeverityLevel

# Precision constants
TWO_PLACES = Decimal("0.01")
FOUR_PLACES = Decimal("0.0001")


def quantize(val: Decimal | float | int | str) -> Decimal:
    """Quantizes numeric value to 2 decimal places using ROUND_HALF_UP.

    Args:
        val: Input numeric value represented as Decimal, float, int, or str.

    Returns:
        Exact Decimal quantized to 2 decimal places.
    """
    if isinstance(val, Decimal):
        d = val
    elif isinstance(val, float):
        d = Decimal(str(val))
    else:
        d = Decimal(val)
    return d.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)


class FacetName(str, Enum):
    """Scoring evaluation facets for software components."""

    VULNERABILITY = "VULNERABILITY"
    HYGIENE = "HYGIENE"
    BEHAVIOR = "BEHAVIOR"


class EvidenceKind(str, Enum):
    """Classification of forensic evidence supporting scoring deductions."""

    SOURCE_LOCATION = "SOURCE_LOCATION"
    REGISTRY_FIELD = "REGISTRY_FIELD"
    SCORECARD_CHECK = "SCORECARD_CHECK"
    ADVISORY = "ADVISORY"


class SuppressionScope(str, Enum):
    """Granularity scope of a policy suppression rule."""

    GLOBAL = "GLOBAL"
    PACKAGE = "PACKAGE"
    ADVISORY = "ADVISORY"


class Evidence(BaseModel):
    """Individual piece of forensic evidence backing a deduction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: EvidenceKind
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    excerpt: Optional[str] = None
    url: Optional[HttpUrl] = None


class Deduction(BaseModel):
    """Structured deduction penalty applied to a scoring facet."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    points: Decimal
    facet: FacetName
    title: str
    detail: str
    evidence: List[Evidence] = Field(default_factory=list)
    inputs: Dict[str, Any] = Field(default_factory=dict)
    subject_id: Optional[str] = None
    suppressible: bool = True
    confidence: Decimal = Decimal("1.0")


class PolicyWeights(BaseModel):
    """Weight distribution for composite score calculation across facets."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vuln: Decimal = Decimal("0.50")
    hygiene: Decimal = Decimal("0.30")
    behavior: Decimal = Decimal("0.20")

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        """Normalizes input weights so they sum to 1.0 (quantized to 4 decimal places).

        Raises:
            ValueError: If total <= 0 or any weight is negative.
        """
        if not isinstance(data, dict):
            return data

        def _to_decimal(v: Any) -> Decimal:
            if isinstance(v, Decimal):
                return v
            if isinstance(v, float):
                return Decimal(str(v))
            return Decimal(v)

        vuln_raw = data.get("vuln")
        hygiene_raw = data.get("hygiene")
        behavior_raw = data.get("behavior")

        vuln = _to_decimal(vuln_raw) if vuln_raw is not None else Decimal("0.50")
        hygiene = _to_decimal(hygiene_raw) if hygiene_raw is not None else Decimal("0.30")
        behavior = _to_decimal(behavior_raw) if behavior_raw is not None else Decimal("0.20")

        total = vuln + hygiene + behavior
        if total <= Decimal("0") or vuln < Decimal("0") or hygiene < Decimal("0") or behavior < Decimal("0"):
            raise ValueError("Policy weights must sum to a strictly positive value")

        v_norm = (vuln / total).quantize(FOUR_PLACES, rounding=ROUND_HALF_UP)
        h_norm = (hygiene / total).quantize(FOUR_PLACES, rounding=ROUND_HALF_UP)
        b_norm = (behavior / total).quantize(FOUR_PLACES, rounding=ROUND_HALF_UP)

        diff = Decimal("1.0000") - (v_norm + h_norm + b_norm)
        if diff != Decimal("0"):
            b_norm += diff

        return {
            **data,
            "vuln": v_norm,
            "hygiene": h_norm,
            "behavior": b_norm,
        }


class Suppression(BaseModel):
    """Audit-approved policy exception suppressing a scoring deduction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    scope: SuppressionScope
    target: Optional[str] = None
    reason: str = Field(..., min_length=20)
    approved_by: str
    expires_at: AwareUTC


class SCGPolicyConfig(BaseModel):
    """Configurable evaluation policy rules and thresholds."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    weights: PolicyWeights = Field(default_factory=PolicyWeights)
    allowed_install_scripts: List[str] = Field(default_factory=list)
    min_acceptable_score: Decimal = Field(
        default=Decimal("70.00"),
        ge=Decimal("0.0"),
        le=Decimal("100.0"),
    )
    suppressions: List[Suppression] = Field(default_factory=list)


class FacetResult(BaseModel):
    """Intermediate evaluation result for a single risk facet."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    score: Decimal
    confidence: Decimal = Field(..., ge=Decimal("0.0"), le=Decimal("1.0"))
    deductions: List[Deduction] = Field(default_factory=list)
    unavailable_signals: List[str] = Field(default_factory=list)


class DependencyScoreResult(BaseModel):
    """Comprehensive mathematical evaluation result for an individual package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    purl: str
    reachability: ReachabilityStatus
    vulnerability_facet: Decimal
    hygiene_facet: Decimal
    behavior_facet: Decimal
    composite_score: Decimal
    confidence: Decimal
    effective_exposure_factor: Decimal
    deductions: List[Deduction] = Field(default_factory=list)
    reputation_bypass_applied: bool = False
    has_reachable_critical: bool = False
    has_reachable_high: bool = False
    has_known_exploited: bool = False

    def has_reachable_severity(self, severity: SeverityLevel) -> bool:
        """Determines if this component has reachable vulnerabilities of the specified severity level."""
        if severity == SeverityLevel.CRITICAL:
            return self.has_reachable_critical
        if severity == SeverityLevel.HIGH:
            return self.has_reachable_high
        return False


class ProjectTrustReport(BaseModel):
    """Aggregated project-level supply chain risk and trust posture report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    overall_trust_score: Decimal
    mean_confidence: Decimal
    policy_applied: SCGPolicyConfig
    total_components_evaluated: int
    considered_components_count: int
    average_vuln_facet: Decimal
    average_hygiene_facet: Decimal
    average_behavior_facet: Decimal
    applied_suppressions: List[str] = Field(default_factory=list)
    dependency_scores: Dict[str, DependencyScoreResult]
    passed_policy_threshold: bool


# Severity weights mapping for domain risk calculations
SEVERITY_WEIGHTS: Dict[SeverityLevel, Decimal] = {
    SeverityLevel.CRITICAL: Decimal("1.00"),
    SeverityLevel.HIGH: Decimal("0.80"),
    SeverityLevel.MEDIUM: Decimal("0.50"),
    SeverityLevel.LOW: Decimal("0.20"),
    SeverityLevel.NONE: Decimal("0.00"),
}


__all__ = [
    "TWO_PLACES",
    "FOUR_PLACES",
    "quantize",
    "AwareUTC",
    "SeverityLevel",
    "ReachabilityStatus",
    "FacetName",
    "EvidenceKind",
    "SuppressionScope",
    "Evidence",
    "Deduction",
    "PolicyWeights",
    "Suppression",
    "SCGPolicyConfig",
    "FacetResult",
    "DependencyScoreResult",
    "ProjectTrustReport",
    "SEVERITY_WEIGHTS",
]


if __name__ == "__main__":
    print("Running self-test for scg_core.schemas.scoring...")

    # 1. Default PolicyWeights instantiate and sum to 1.0.
    default_pw = PolicyWeights()
    total_default = default_pw.vuln + default_pw.hygiene + default_pw.behavior
    assert total_default == Decimal("1.0"), f"Expected 1.0, got {total_default}"
    assert default_pw.vuln == Decimal("0.5000"), f"Expected 0.5000, got {default_pw.vuln}"
    assert default_pw.hygiene == Decimal("0.3000"), f"Expected 0.3000, got {default_pw.hygiene}"
    assert default_pw.behavior == Decimal("0.2000"), f"Expected 0.2000, got {default_pw.behavior}"
    print("✓ 1. Default PolicyWeights instantiate and sum to 1.0.")

    # 2. Non-normalized weights (e.g. vuln=3, hygiene=1, behavior=1) normalize to (0.6000, 0.2000, 0.2000).
    custom_pw = PolicyWeights(vuln=3, hygiene=1, behavior=1)  # type: ignore[arg-type]
    assert custom_pw.vuln == Decimal("0.6000"), f"Expected 0.6000, got {custom_pw.vuln}"
    assert custom_pw.hygiene == Decimal("0.2000"), f"Expected 0.2000, got {custom_pw.hygiene}"
    assert custom_pw.behavior == Decimal("0.2000"), f"Expected 0.2000, got {custom_pw.behavior}"
    assert (custom_pw.vuln + custom_pw.hygiene + custom_pw.behavior) == Decimal("1.0")
    print("✓ 2. Non-normalized weights normalize to (0.6000, 0.2000, 0.2000).")

    # 3. All-zero or negative weights raise ValueError.
    try:
        PolicyWeights(vuln=0, hygiene=0, behavior=0)  # type: ignore[arg-type]
        raise AssertionError("Failed to raise ValueError on all-zero weights")
    except ValueError as exc:
        assert "Policy weights must sum to a strictly positive value" in str(exc)
    print("✓ 3a. All-zero weights raise ValueError('Policy weights must sum to a strictly positive value').")

    try:
        PolicyWeights(vuln=-1, hygiene=0, behavior=0)  # type: ignore[arg-type]
        raise AssertionError("Failed to raise ValueError on negative weights")
    except ValueError as exc:
        assert "Policy weights must sum to a strictly positive value" in str(exc)
    print("✓ 3b. Negative weights raise ValueError.")

    # 4. quantize properly applies ROUND_HALF_UP to standard test values.
    assert quantize(Decimal("1.255")) == Decimal("1.26")
    assert quantize(Decimal("1.254")) == Decimal("1.25")
    assert quantize(1.255) == Decimal("1.26")
    assert quantize(1.254) == Decimal("1.25")
    assert quantize("2.5") == Decimal("2.50")
    assert quantize(5) == Decimal("5.00")
    assert quantize(Decimal("0.005")) == Decimal("0.01")
    assert quantize(Decimal("0.004")) == Decimal("0.00")
    print("✓ 4. quantize properly applies ROUND_HALF_UP to standard test values.")

    print("\nAll self-test assertions passed successfully!")
