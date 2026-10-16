"""Score Calibration & Distribution Validator for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-8 (REQ-P8-07, P5-12, P8-10, P8-11, P8-13).
Validates statistical properties of composite scores across real-world benchmark corpora:
1. Score spread (std dev >= 10.0 pts across corpus).
2. Dynamic non-saturation (<= 5% at floor < 5.0, <= 10% at ceiling > 95.0).
3. Facet orthogonality (pairwise Pearson r < 0.70).
4. Strict monotonicity on remediation (patch bump delta >= 2.0 pts).
5. Ranking alignment against human consensus (Spearman rho >= 0.60).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Sequence, Union

import numpy as np
from scipy import stats


class ScoreCalibrationValidator:
    """Statistical validator for SCG scoring engine distribution and calibration."""

    @staticmethod
    def validate_score_distribution(
        scores: Sequence[Union[Decimal, float, int]],
    ) -> Dict[str, Any]:
        """Validate score distribution spread and non-saturation boundaries across corpus.

        Per P8-10 and P8-13:
        - Calculates standard deviation; asserts std >= 10.0.
        - Asserts fraction of scores < 5.0 is <= 0.05 (5%).
        - Asserts fraction of scores > 95.0 is <= 0.10 (10%).

        Args:
            scores: Sequence of composite trust scores (Decimal or numeric).

        Returns:
            Dict containing computed statistical metrics.

        Raises:
            AssertionError: If spread < 10.0, floor saturation > 5%, or ceiling saturation > 10%.
        """
        if not scores:
            raise ValueError("Score list cannot be empty for distribution validation.")

        float_scores = [float(s) for s in scores]
        n_scores = len(float_scores)

        # Standard deviation (using sample std dev if n > 1 else population)
        std_dev = float(np.std(float_scores, ddof=1 if n_scores > 1 else 0))

        # Saturation calculations
        floor_count = sum(1 for s in float_scores if s < 5.0)
        ceiling_count = sum(1 for s in float_scores if s > 95.0)

        floor_fraction = float(floor_count) / float(n_scores)
        ceiling_fraction = float(ceiling_count) / float(n_scores)

        # Invariant 1: Spread std >= 10.0
        if std_dev < 10.0:
            raise AssertionError(
                f"Score distribution spread failed: std dev {std_dev:.2f} < 10.0 (P8-10)"
            )

        # Invariant 2: Dynamic floor non-saturation <= 5%
        if floor_fraction > 0.05:
            raise AssertionError(
                f"Dynamic floor saturation exceeded: {floor_fraction:.2%} > 5.00% (P8-13)"
            )

        # Invariant 3: Dynamic ceiling non-saturation <= 10%
        if ceiling_fraction > 0.10:
            raise AssertionError(
                f"Dynamic ceiling saturation exceeded: {ceiling_fraction:.2%} > 10.00% (P8-13)"
            )

        return {
            "std_dev": std_dev,
            "floor_fraction": floor_fraction,
            "ceiling_fraction": ceiling_fraction,
            "total_scores": n_scores,
            "mean": float(np.mean(float_scores)),
            "passed": True,
        }

    @staticmethod
    def validate_facet_orthogonality(
        vuln_scores: Sequence[float],
        hyg_scores: Sequence[float],
        beh_scores: Sequence[float],
    ) -> Dict[str, float]:
        """Validate facet orthogonality across vulnerability, hygiene, and behavioral facets.

        Per P8-11:
        - Calculates pairwise Pearson correlation coefficients: r(V, H), r(V, B), r(H, B).
        - Asserts all pairwise |r| < 0.70.

        Args:
            vuln_scores: Vulnerability facet scores across packages.
            hyg_scores: Hygiene facet scores across packages.
            beh_scores: Behavioral / reputation facet scores across packages.

        Returns:
            Dict containing pairwise Pearson r values.

        Raises:
            AssertionError: If any pairwise |r| >= 0.70.
        """
        if not (len(vuln_scores) == len(hyg_scores) == len(beh_scores)):
            raise ValueError("All facet score arrays must have equal length.")
        if len(vuln_scores) < 3:
            raise ValueError("At least 3 samples required to evaluate Pearson correlation.")

        # Compute pairwise Pearson r
        res_vh = stats.pearsonr(vuln_scores, hyg_scores)
        res_vb = stats.pearsonr(vuln_scores, beh_scores)
        res_hb = stats.pearsonr(hyg_scores, beh_scores)

        r_vh = float(res_vh.statistic if hasattr(res_vh, "statistic") else res_vh[0])
        r_vb = float(res_vb.statistic if hasattr(res_vb, "statistic") else res_vb[0])
        r_hb = float(res_hb.statistic if hasattr(res_hb, "statistic") else res_hb[0])

        correlations = {
            "r_vuln_hyg": r_vh,
            "r_vuln_beh": r_vb,
            "r_hyg_beh": r_hb,
        }

        for pair_name, r_val in correlations.items():
            if abs(r_val) >= 0.70:
                raise AssertionError(
                    f"Facet orthogonality violated for {pair_name}: |{r_val:.4f}| >= 0.70 (P8-11)"
                )

        return correlations

    @staticmethod
    def validate_remediation_monotonicity(
        before_scores: Sequence[Union[Decimal, float, str]],
        after_scores: Sequence[Union[Decimal, float, str]],
    ) -> bool:
        """Validate strict monotonicity on successful vulnerability remediation.

        Per P5-12:
        - Asserts that for all pairs, (after_score - before_score) >= Decimal("2.00").

        Args:
            before_scores: Pre-remediation scores.
            after_scores: Post-remediation scores after applying verified patch bump.

        Returns:
            True if all remediation deltas strictly meet or exceed 2.00 pts.

        Raises:
            AssertionError: If any delta < 2.00 pts.
        """
        if len(before_scores) != len(after_scores):
            raise ValueError("Before and after score sequences must have identical lengths.")
        if not before_scores:
            raise ValueError("Score sequences cannot be empty.")

        min_required_delta = Decimal("2.00")

        for idx, (b, a) in enumerate(zip(before_scores, after_scores)):
            dec_b = Decimal(str(b))
            dec_a = Decimal(str(a))
            delta = dec_a - dec_b

            if delta < min_required_delta:
                raise AssertionError(
                    f"Remediation monotonicity violated at index {idx}: "
                    f"delta {delta} < {min_required_delta} (before={dec_b}, after={dec_a}) (P5-12)"
                )

        return True

    @staticmethod
    def validate_human_ranking_correlation(
        tool_scores: Sequence[float],
        expert_ranks: Sequence[int],
    ) -> float:
        """Validate ranking alignment against human expert consensus.

        Per P8-13:
        - Calculates Spearman rank correlation rho.
        - Asserts rho >= 0.60.

        Args:
            tool_scores: Automated SCG trust scores.
            expert_ranks: Human consensus rank ordering.

        Returns:
            Spearman rho correlation coefficient.

        Raises:
            AssertionError: If Spearman rho < 0.60.
        """
        if len(tool_scores) != len(expert_ranks):
            raise ValueError("Tool scores and expert ranks must have identical length.")
        if len(tool_scores) < 3:
            raise ValueError("At least 3 samples required to calculate Spearman rank correlation.")

        res = stats.spearmanr(tool_scores, expert_ranks)
        rho = float(res.statistic if hasattr(res, "statistic") else res[0])

        if rho < 0.60:
            raise AssertionError(
                f"Human ranking alignment violated: Spearman rho {rho:.4f} < 0.60 (P8-13)"
            )

        return rho
