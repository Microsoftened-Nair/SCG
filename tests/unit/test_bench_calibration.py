"""Unit tests for ScoreCalibrationValidator (CALIB-TC-01).

Verifies:
- Score distribution spread (std dev >= 10.0)
- Dynamic non-saturation bounds (<= 5% floor, <= 10% ceiling)
- Facet orthogonality (|r| < 0.70)
- Remediation monotonicity (delta >= 2.0 pts)
- Human ranking correlation (Spearman rho >= 0.60)
"""

from __future__ import annotations

from decimal import Decimal
import pytest

from tests.benchmarks.calibration import ScoreCalibrationValidator


def test_validate_score_distribution_success() -> None:
    """Verify passing score distribution with wide spread and no saturation."""
    validator = ScoreCalibrationValidator()
    # 20 scores ranging from 20 to 80, std ~ 19.3
    scores = [Decimal(str(x)) for x in range(20, 81, 3)]
    res = validator.validate_score_distribution(scores)

    assert res["passed"] is True
    assert res["std_dev"] >= 10.0
    assert res["floor_fraction"] <= 0.05
    assert res["ceiling_fraction"] <= 0.10


def test_validate_score_distribution_spread_failure() -> None:
    """Verify assertion error when spread std dev < 10.0."""
    validator = ScoreCalibrationValidator()
    # Clustered scores between 50 and 52 -> std ~ 0.8
    scores = [Decimal("50.0"), Decimal("50.5"), Decimal("51.0"), Decimal("51.5"), Decimal("52.0")]
    with pytest.raises(AssertionError, match="Score distribution spread failed"):
        validator.validate_score_distribution(scores)


def test_validate_score_distribution_floor_saturation_failure() -> None:
    """Verify assertion error when floor saturation exceeds 5%."""
    validator = ScoreCalibrationValidator()
    # 10 scores, 2 are < 5.0 -> 20% floor saturation (> 5%)
    scores = [Decimal("1.0"), Decimal("2.0")] + [Decimal(str(x)) for x in range(30, 90, 8)]
    with pytest.raises(AssertionError, match="Dynamic floor saturation exceeded"):
        validator.validate_score_distribution(scores)


def test_validate_score_distribution_ceiling_saturation_failure() -> None:
    """Verify assertion error when ceiling saturation exceeds 10%."""
    validator = ScoreCalibrationValidator()
    # 10 scores, 2 are > 95.0 -> 20% ceiling saturation (> 10%)
    scores = [Decimal("96.0"), Decimal("98.0")] + [Decimal(str(x)) for x in range(20, 80, 8)]
    with pytest.raises(AssertionError, match="Dynamic ceiling saturation exceeded"):
        validator.validate_score_distribution(scores)


def test_validate_facet_orthogonality_success() -> None:
    """Verify passing orthogonality with low pairwise correlation."""
    validator = ScoreCalibrationValidator()
    # Orthogonal components
    v = [15.0, 85.0, 45.0, 92.0, 30.0, 65.0, 78.0, 22.0, 90.0, 50.0, 35.0, 80.0]
    h = [70.0, 40.0, 80.0, 85.0, 60.0, 90.0, 45.0, 75.0, 35.0, 68.0, 82.0, 55.0]
    b = [85.0, 65.0, 30.0, 75.0, 90.0, 40.0, 60.0, 82.0, 70.0, 55.0, 48.0, 88.0]

    corrs = validator.validate_facet_orthogonality(v, h, b)
    assert abs(corrs["r_vuln_hyg"]) < 0.70
    assert abs(corrs["r_vuln_beh"]) < 0.70
    assert abs(corrs["r_hyg_beh"]) < 0.70


def test_validate_facet_orthogonality_failure() -> None:
    """Verify assertion error when any pairwise correlation >= 0.70."""
    validator = ScoreCalibrationValidator()
    # v and h are strongly collinear (r = 1.0)
    v = [10.0, 20.0, 30.0, 40.0, 50.0]
    h = [12.0, 22.0, 32.0, 42.0, 52.0]
    b = [50.0, 30.0, 40.0, 20.0, 10.0]

    with pytest.raises(AssertionError, match="Facet orthogonality violated"):
        validator.validate_facet_orthogonality(v, h, b)


def test_validate_remediation_monotonicity_success() -> None:
    """Verify passing monotonicity when all deltas >= 2.0 pts."""
    validator = ScoreCalibrationValidator()
    before = [Decimal("40.0"), Decimal("55.0"), Decimal("70.0")]
    after = [Decimal("42.0"), Decimal("58.5"), Decimal("75.0")]
    assert validator.validate_remediation_monotonicity(before, after) is True


def test_validate_remediation_monotonicity_failure() -> None:
    """Verify assertion error when any delta < 2.0 pts."""
    validator = ScoreCalibrationValidator()
    before = [Decimal("40.0"), Decimal("55.0")]
    after = [Decimal("42.0"), Decimal("56.5")]  # delta is 1.5 < 2.0
    with pytest.raises(AssertionError, match="Remediation monotonicity violated"):
        validator.validate_remediation_monotonicity(before, after)


def test_validate_human_ranking_correlation_success() -> None:
    """Verify passing human ranking correlation with rho >= 0.60."""
    validator = ScoreCalibrationValidator()
    tool_scores = [20.0, 40.0, 60.0, 80.0, 95.0]
    expert_ranks = [1, 2, 3, 4, 5]  # rho = 1.0
    rho = validator.validate_human_ranking_correlation(tool_scores, expert_ranks)
    assert rho >= 0.60


def test_validate_human_ranking_correlation_failure() -> None:
    """Verify assertion error when Spearman rho < 0.60."""
    validator = ScoreCalibrationValidator()
    tool_scores = [20.0, 40.0, 60.0, 80.0, 95.0]
    expert_ranks = [5, 4, 3, 2, 1]  # rho = -1.0 < 0.60
    with pytest.raises(AssertionError, match="Human ranking alignment violated"):
        validator.validate_human_ranking_correlation(tool_scores, expert_ranks)
