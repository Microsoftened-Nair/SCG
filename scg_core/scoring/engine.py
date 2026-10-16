"""Core risk evaluation and mathematical trust scoring engine for SCG Track D.

Implements:
1. Convex, non-saturating Vulnerability Facet calculation (K=0.8, P5-01) with critical floor (P4-10).
2. Epistemic Hygiene Facet calculation with missing-data confidence isolation (P5-04, P5-05, P5-06).
3. Behavioral Facet with disjunctive reputation bypass and risk modifiers (P5-07).
4. Anti-dilution graph rollup with exposure weights, 5th-percentile tail blending, and hard safety ceilings (P5-02, P5-03, P5-08).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Set

from scg_core.schemas.base import (
    CvssSource,
    DependencyNode,
    ReachabilityStatus,
    SeverityLevel,
)
from scg_core.schemas.reachability import ReachabilityEvaluationResult
from scg_core.schemas.scoring import (
    Deduction,
    DependencyScoreResult,
    Evidence,
    EvidenceKind,
    FacetName,
    FacetResult,
    ProjectTrustReport,
    SCGPolicyConfig,
    SuppressionScope,
    quantize,
)

# Vetted ecosystem build tools exempt from install script penalties via reputation bypass
VETTED_BUILD_TOOLS: Set[str] = {
    "esbuild",
    "sharp",
    "bcrypt",
    "node-sass",
    "swc",
    "@swc/core",
    "prisma",
    "@prisma/client",
    "puppeteer",
    "playwright",
    "cypress",
}


def _compute_percentile(sorted_vals: List[Decimal], p: float) -> Decimal:
    """Computes p-th percentile (0 <= p <= 100) using linear interpolation."""
    if not sorted_vals:
        return Decimal("0.00")
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    rank = (p / 100.0) * (n - 1)
    low_idx = int(rank)
    high_idx = min(low_idx + 1, n - 1)
    fraction = Decimal(str(rank - low_idx))
    return sorted_vals[low_idx] + fraction * (sorted_vals[high_idx] - sorted_vals[low_idx])


class TrustScoringEngine:
    """Deterministic mathematical scoring engine evaluating packages and repository trust."""

    VETTED_BUILD_TOOLS = VETTED_BUILD_TOOLS

    def __init__(self, policy: Optional[SCGPolicyConfig] = None) -> None:
        """Initializes the scoring engine with an active policy configuration.

        Args:
            policy: Optional SCGPolicyConfig. If None, default policy is applied.
        """
        self.policy: SCGPolicyConfig = policy if policy is not None else SCGPolicyConfig()
        self._applied_suppressions: Set[str] = set()

    def _is_suppressed(
        self,
        rule_id: str,
        package_name: str,
        purl: str,
        subject_id: Optional[str] = None,
    ) -> Optional[str]:
        """Checks if a deduction rule matches an active policy suppression.

        Returns:
            The matched suppression rule_id if active, else None.
        """
        for supp in self.policy.suppressions:
            if supp.rule_id == rule_id:
                if supp.scope == SuppressionScope.GLOBAL:
                    return supp.rule_id
                if supp.scope == SuppressionScope.PACKAGE and supp.target in (package_name, purl):
                    return supp.rule_id
                if supp.scope == SuppressionScope.ADVISORY and subject_id and supp.target == subject_id:
                    return supp.rule_id
        return None

    def evaluate_dependency(
        self,
        node: DependencyNode,
        reachability: ReachabilityEvaluationResult,
    ) -> DependencyScoreResult:
        """Evaluates Vuln, Hygiene, and Behavior facets and computes composite score.

        Args:
            node: The evaluated dependency node.
            reachability: AST reachability evaluation result for this node.

        Returns:
            Bit-exact quantized DependencyScoreResult.
        """
        purl = f"pkg:{node.ecosystem.value}/{node.package_name}@{node.resolved_version}"

        # 1. Compute Facets
        vuln_res = self._compute_vulnerability_facet(node, reachability)
        hygiene_res = self._compute_hygiene_facet(node)
        behavior_res = self._compute_behavior_facet(node)

        # 2. Composite score using normalized policy weights
        w = self.policy.weights
        raw_composite = (
            w.vuln * vuln_res.score
            + w.hygiene * hygiene_res.score
            + w.behavior * behavior_res.score
        )
        composite_score = quantize(raw_composite)

        # 3. Overall confidence: mean of facet confidences
        overall_confidence = quantize(
            (vuln_res.confidence + hygiene_res.confidence + behavior_res.confidence)
            / Decimal("3.0")
        )

        # 4. Exposure reachability flags (where exposure >= 0.5)
        is_exposure_reachable = (
            reachability.exposure_factor >= 0.5
            or (
                reachability.effective_exposure_factor >= 0.5
                and reachability.reachability != ReachabilityStatus.UNREFERENCED_LATENT
            )
        )

        has_reachable_critical = is_exposure_reachable and any(
            v.severity == SeverityLevel.CRITICAL for v in node.vulnerabilities
        )
        has_reachable_high = is_exposure_reachable and any(
            v.severity == SeverityLevel.HIGH for v in node.vulnerabilities
        )
        has_known_exploited = is_exposure_reachable and any(
            v.is_known_exploited for v in node.vulnerabilities
        )

        # Check if reputation bypass was applied in behavior facet
        is_vetted = (
            node.package_name in self.policy.allowed_install_scripts
            or (node.health.weekly_downloads is not None and node.health.weekly_downloads >= 1_000_000)
            or (node.health.openssf_scorecard_score is not None and node.health.openssf_scorecard_score >= 6.0)
            or (node.package_name in self.VETTED_BUILD_TOOLS)
        )
        reputation_bypass_applied = bool(node.health.has_install_scripts and is_vetted)

        all_deductions = vuln_res.deductions + hygiene_res.deductions + behavior_res.deductions

        return DependencyScoreResult(
            package_name=node.package_name,
            purl=purl,
            reachability=reachability.reachability,
            vulnerability_facet=vuln_res.score,
            hygiene_facet=hygiene_res.score,
            behavior_facet=behavior_res.score,
            composite_score=composite_score,
            confidence=overall_confidence,
            effective_exposure_factor=quantize(reachability.effective_exposure_factor),
            deductions=all_deductions,
            reputation_bypass_applied=reputation_bypass_applied,
            has_reachable_critical=has_reachable_critical,
            has_reachable_high=has_reachable_high,
            has_known_exploited=has_known_exploited,
        )

    def _compute_vulnerability_facet(
        self,
        node: DependencyNode,
        reach: ReachabilityEvaluationResult,
    ) -> FacetResult:
        """Computes convex non-saturating vulnerability facet score."""
        purl = f"pkg:{node.ecosystem.value}/{node.package_name}@{node.resolved_version}"

        if not node.vulnerabilities:
            return FacetResult(
                score=Decimal("100.00"),
                confidence=Decimal("1.00"),
                deductions=[],
                unavailable_signals=[],
            )

        weights: List[float] = []
        deductions: List[Deduction] = []
        conf_list: List[float] = []

        for v in node.vulnerabilities:
            # P4-10 floor: If severity == CRITICAL or is_known_exploited: max(exposure, 0.60)
            if v.severity == SeverityLevel.CRITICAL or v.is_known_exploited:
                effective_exp = max(reach.exposure_factor, 0.60)
            else:
                effective_exp = reach.exposure_factor

            # Convex base = (cvss / 10.0)^2
            if v.cvss_score is not None:
                cvss = float(v.cvss_score)
            else:
                severity_map = {
                    SeverityLevel.CRITICAL: 9.0,
                    SeverityLevel.HIGH: 7.0,
                    SeverityLevel.MEDIUM: 5.0,
                    SeverityLevel.LOW: 2.0,
                    SeverityLevel.NONE: 0.0,
                }
                cvss = severity_map.get(v.severity, 0.0)
            base = (cvss / 10.0) ** 2

            # Confidence discount: 0.80 if cvss_source == INFERRED_FROM_SEVERITY else 1.00
            conf = 0.80 if v.cvss_source == CvssSource.INFERRED_FROM_SEVERITY else 1.00
            conf_list.append(conf)

            # Symbol multiplier = 1.25 if reach.symbol_confirmed_reachable else 1.00
            symbol_mult = 1.25 if reach.symbol_confirmed_reachable else 1.00

            # Threat boost = (1.0 + 1.5 * (epss_score or 0.0)) * (2.0 if is_known_exploited else 1.0)
            epss = float(v.epss_score) if v.epss_score is not None else 0.0
            threat = (1.0 + 1.5 * epss) * (2.0 if v.is_known_exploited else 1.0)

            # Weight w = base * exposure * symbol_mult * conf * threat
            w = base * effective_exp * symbol_mult * conf * threat

            # Check policy suppression
            matched_supp = self._is_suppressed(
                rule_id="VULN.ADVISORY_PRESENT",
                package_name=node.package_name,
                purl=purl,
                subject_id=v.id,
            )
            if matched_supp:
                self._applied_suppressions.add(matched_supp)
                w = 0.0

            weights.append(w)

            deductions.append(
                Deduction(
                    rule_id="VULN.ADVISORY_PRESENT",
                    points=quantize(Decimal(str(w))),
                    facet=FacetName.VULNERABILITY,
                    title=f"Advisory {v.id or 'VULN'}",
                    detail=(
                        f"Severity: {v.severity.value}, CVSS: {cvss:.1f}, "
                        f"Effective Exposure: {effective_exp:.2f}, Weight: {w:.4f}"
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.ADVISORY,
                            excerpt=v.summary,
                        )
                    ],
                    inputs={
                        "id": v.id,
                        "cvss": cvss,
                        "severity": v.severity.value,
                        "weight": float(w),
                        "is_known_exploited": v.is_known_exploited,
                    },
                    subject_id=v.id,
                    suppressible=True,
                    confidence=quantize(Decimal(str(conf))),
                )
            )

        # Sort weights descending: w_0 >= w_1 >= ...
        weights.sort(reverse=True)

        # Converging exponential tail attenuation: Aggregate = sum(w_i * (0.5)^i)
        aggregate = sum(w_i * (0.5 ** i) for i, w_i in enumerate(weights))

        # Soft-knee mapping: S_vuln = 100.00 * (0.80 / (0.80 + Aggregate))
        s_vuln = Decimal("100.00") * (
            Decimal("0.80") / (Decimal("0.80") + Decimal(str(aggregate)))
        )
        facet_score = quantize(s_vuln)

        avg_conf = sum(conf_list) / len(conf_list) if conf_list else 1.0
        facet_conf = quantize(Decimal(str(avg_conf)))

        return FacetResult(
            score=facet_score,
            confidence=facet_conf,
            deductions=deductions,
            unavailable_signals=[],
        )

    def _compute_hygiene_facet(self, node: DependencyNode) -> FacetResult:
        """Computes epistemic hygiene facet score with missing-signal isolation."""
        purl = f"pkg:{node.ecosystem.value}/{node.package_name}@{node.resolved_version}"

        total_rule_weights = 66.0
        observed_weights = 0.0
        accumulated_penalties = 0.0
        deductions: List[Deduction] = []
        unavailable_signals: List[str] = []

        now = datetime.now(timezone.utc)

        # 1. Staleness (Weight: 20.0)
        observed_weights += 20.0
        delta = now - node.health.last_registry_activity
        days = delta.days
        if days > 730:
            staleness_penalty = 20.0
        elif days >= 180:
            staleness_penalty = ((days - 180) / 550.0) * 15.0
        else:
            staleness_penalty = 0.0

        if staleness_penalty > 0:
            matched_supp = self._is_suppressed("HYG.STALENESS", node.package_name, purl)
            if matched_supp:
                self._applied_suppressions.add(matched_supp)
                staleness_penalty = 0.0
            else:
                accumulated_penalties += staleness_penalty
                deductions.append(
                    Deduction(
                        rule_id="HYG.STALENESS",
                        points=quantize(Decimal(str(staleness_penalty))),
                        facet=FacetName.HYGIENE,
                        title="Package Release Staleness",
                        detail=f"Last registry activity was {days} days ago",
                        inputs={"days_since_activity": days},
                    )
                )

        # 2. Scorecard (Weight: 20.0)
        if node.health.openssf_scorecard_score is None:
            unavailable_signals.append("openssf_scorecard_score")
        else:
            observed_weights += 20.0
            sc = float(node.health.openssf_scorecard_score)
            sc_penalty = min(20.0, max(0.0, (10.0 - sc) * 2.0))
            if sc_penalty > 0:
                matched_supp = self._is_suppressed("HYG.SCORECARD_LOW", node.package_name, purl)
                if matched_supp:
                    self._applied_suppressions.add(matched_supp)
                else:
                    accumulated_penalties += sc_penalty
                    deductions.append(
                        Deduction(
                            rule_id="HYG.SCORECARD_LOW",
                            points=quantize(Decimal(str(sc_penalty))),
                            facet=FacetName.HYGIENE,
                            title="Low OpenSSF Scorecard Rating",
                            detail=f"Scorecard rating is {sc:.1f}/10.0",
                            inputs={"scorecard_score": sc},
                        )
                    )

        # 3. Maintainer count (Weight: 6.0)
        if node.health.maintainer_count is None:
            unavailable_signals.append("maintainer_count")
        else:
            observed_weights += 6.0
            if node.health.maintainer_count == 1:
                m_penalty = 6.0
                matched_supp = self._is_suppressed("HYG.SINGLE_MAINTAINER", node.package_name, purl)
                if matched_supp:
                    self._applied_suppressions.add(matched_supp)
                else:
                    accumulated_penalties += m_penalty
                    deductions.append(
                        Deduction(
                            rule_id="HYG.SINGLE_MAINTAINER",
                            points=Decimal("6.00"),
                            facet=FacetName.HYGIENE,
                            title="Single Maintainer Risk",
                            detail="Package is maintained by a single author",
                            inputs={"maintainer_count": 1},
                        )
                    )

        # 4. Deprecation (Weight: 20.0)
        observed_weights += 20.0
        if node.health.is_deprecated:
            dep_penalty = 40.0
            matched_supp = self._is_suppressed("HYG.DEPRECATED", node.package_name, purl)
            if matched_supp:
                self._applied_suppressions.add(matched_supp)
            else:
                accumulated_penalties += dep_penalty
                deductions.append(
                    Deduction(
                        rule_id="HYG.DEPRECATED",
                        points=Decimal("40.00"),
                        facet=FacetName.HYGIENE,
                        title="Formally Deprecated Package",
                        detail="Package has been flagged as deprecated upstream",
                        inputs={"is_deprecated": True},
                    )
                )

        confidence = quantize(Decimal(str(observed_weights / total_rule_weights)))
        score = quantize(max(Decimal("0.00"), Decimal("100.00") - Decimal(str(accumulated_penalties))))

        return FacetResult(
            score=score,
            confidence=confidence,
            deductions=deductions,
            unavailable_signals=unavailable_signals,
        )

    def _compute_behavior_facet(self, node: DependencyNode) -> FacetResult:
        """Computes behavioral facet score with disjunctive reputation bypass."""
        purl = f"pkg:{node.ecosystem.value}/{node.package_name}@{node.resolved_version}"

        total_rule_weights = 40.0
        observed_weights = 30.0  # Base install scripts rule
        accumulated_penalties = 0.0
        deductions: List[Deduction] = []
        unavailable_signals: List[str] = []

        now = datetime.now(timezone.utc)

        # Observe weekly downloads signal weight
        if node.health.weekly_downloads is None:
            unavailable_signals.append("weekly_downloads")
        else:
            observed_weights += 10.0

        # Install scripts evaluation
        if node.health.has_install_scripts:
            # Disjunctive Reputation Bypass
            is_vetted = (
                node.package_name in self.policy.allowed_install_scripts
                or (node.health.weekly_downloads is not None and node.health.weekly_downloads >= 1_000_000)
                or (node.health.openssf_scorecard_score is not None and node.health.openssf_scorecard_score >= 6.0)
                or (node.package_name in self.VETTED_BUILD_TOOLS)
            )

            if is_vetted:
                deductions.append(
                    Deduction(
                        rule_id="BEH.INSTALL_SCRIPT_VETTED",
                        points=Decimal("0.00"),
                        facet=FacetName.BEHAVIOR,
                        title="Vetted Install Script",
                        detail="Install scripts permitted via reputation bypass or vetted status",
                        inputs={"package_name": node.package_name},
                    )
                )
            else:
                # Unvetted base penalty: 15.00 pts
                base_pen = 15.00
                matched_supp = self._is_suppressed("BEH.UNVETTED_INSTALL_SCRIPT", node.package_name, purl)
                if matched_supp:
                    self._applied_suppressions.add(matched_supp)
                else:
                    accumulated_penalties += base_pen
                    deductions.append(
                        Deduction(
                            rule_id="BEH.UNVETTED_INSTALL_SCRIPT",
                            points=Decimal("15.00"),
                            facet=FacetName.BEHAVIOR,
                            title="Unvetted Install Script Execution",
                            detail="Package executes install scripts without trusted reputation bypass",
                            inputs={"has_install_scripts": True},
                        )
                    )

                # High-risk modifier 1: downloads < 10,000 -> +15.00 pts
                if node.health.weekly_downloads is not None and node.health.weekly_downloads < 10_000:
                    matched_supp = self._is_suppressed("BEH.LOW_DOWNLOADS_INSTALL_SCRIPT", node.package_name, purl)
                    if matched_supp:
                        self._applied_suppressions.add(matched_supp)
                    else:
                        accumulated_penalties += 15.00
                        deductions.append(
                            Deduction(
                                rule_id="BEH.LOW_DOWNLOADS_INSTALL_SCRIPT",
                                points=Decimal("15.00"),
                                facet=FacetName.BEHAVIOR,
                                title="Low Download Install Script Risk",
                                detail=f"Weekly downloads ({node.health.weekly_downloads}) < 10,000",
                                inputs={"weekly_downloads": node.health.weekly_downloads},
                            )
                        )

                # High-risk modifier 2: release age <= 7 days -> +10.00 pts
                release_age_days = (now - node.health.published_date).days
                if release_age_days <= 7:
                    matched_supp = self._is_suppressed("BEH.NEW_RELEASE_INSTALL_SCRIPT", node.package_name, purl)
                    if matched_supp:
                        self._applied_suppressions.add(matched_supp)
                    else:
                        accumulated_penalties += 10.00
                        deductions.append(
                            Deduction(
                                rule_id="BEH.NEW_RELEASE_INSTALL_SCRIPT",
                                points=Decimal("10.00"),
                                facet=FacetName.BEHAVIOR,
                                title="New Release with Install Script",
                                detail=f"Release is {release_age_days} days old (<= 7 days)",
                                inputs={"release_age_days": release_age_days},
                            )
                        )

        # Low downloads penalty (< 50 weekly downloads -> +10.00 pts)
        if node.health.weekly_downloads is not None and node.health.weekly_downloads < 50:
            matched_supp = self._is_suppressed("BEH.VERY_LOW_DOWNLOADS", node.package_name, purl)
            if matched_supp:
                self._applied_suppressions.add(matched_supp)
            else:
                accumulated_penalties += 10.00
                deductions.append(
                    Deduction(
                        rule_id="BEH.VERY_LOW_DOWNLOADS",
                        points=Decimal("10.00"),
                        facet=FacetName.BEHAVIOR,
                        title="Very Low Download Activity",
                        detail=f"Weekly downloads ({node.health.weekly_downloads}) < 50",
                        inputs={"weekly_downloads": node.health.weekly_downloads},
                    )
                )

        confidence = quantize(Decimal(str(observed_weights / total_rule_weights)))
        score = quantize(max(Decimal("0.00"), Decimal("100.00") - Decimal(str(accumulated_penalties))))

        return FacetResult(
            score=score,
            confidence=confidence,
            deductions=deductions,
            unavailable_signals=unavailable_signals,
        )

    def aggregate_project_report(
        self,
        scan_id: str,
        dependency_scores: Dict[str, DependencyScoreResult],
    ) -> ProjectTrustReport:
        """Aggregates dependency scores into repository trust posture report with anti-dilution.

        Args:
            scan_id: Unique identifier for the scan.
            dependency_scores: Dictionary of purl to DependencyScoreResult.

        Returns:
            ProjectTrustReport adhering to Level 5 calibration criteria.
        """
        all_nodes = list(dependency_scores.values())
        total_components_evaluated = len(all_nodes)

        if not all_nodes:
            return ProjectTrustReport(
                scan_id=scan_id,
                overall_trust_score=Decimal("100.00"),
                mean_confidence=Decimal("1.00"),
                policy_applied=self.policy,
                total_components_evaluated=0,
                considered_components_count=0,
                average_vuln_facet=Decimal("100.00"),
                average_hygiene_facet=Decimal("100.00"),
                average_behavior_facet=Decimal("100.00"),
                applied_suppressions=sorted(self._applied_suppressions),
                dependency_scores={},
                passed_policy_threshold=True,
            )

        # Filter considered nodes: exclude ReachabilityStatus.UNREFERENCED_LATENT. If empty, include all.
        considered = [
            d for d in all_nodes if d.reachability != ReachabilityStatus.UNREFERENCED_LATENT
        ]
        if not considered:
            considered = list(all_nodes)

        # Sort considered nodes by canonical purl for bit-exact deterministic aggregation
        considered.sort(key=lambda d: d.purl)
        considered_components_count = len(considered)

        # Semantic exposure weighted mean: W(n) = n.effective_exposure_factor
        total_weight = sum(d.effective_exposure_factor for d in considered)
        if total_weight > Decimal("0.00"):
            weighted_sum = sum(d.effective_exposure_factor * d.composite_score for d in considered)
            weighted_mean = weighted_sum / total_weight
        else:
            weighted_mean = sum(d.composite_score for d in considered) / Decimal(str(len(considered)))

        # 5th-percentile worst-case term P05 of composite scores
        sorted_scores = sorted(d.composite_score for d in considered)
        p05 = _compute_percentile(sorted_scores, 5.0)

        # Blended score = 0.5 * weighted_mean + 0.5 * P05
        blended = Decimal("0.5") * weighted_mean + Decimal("0.5") * p05

        # Safety ceiling gates
        ceiling = Decimal("100.00")
        if any(d.has_known_exploited for d in considered):
            ceiling = min(ceiling, Decimal("20.00"))
        elif any(d.has_reachable_critical for d in considered):
            ceiling = min(ceiling, Decimal("35.00"))
        elif any(d.has_reachable_high for d in considered):
            ceiling = min(ceiling, Decimal("60.00"))

        final_score = quantize(min(blended, ceiling))

        mean_confidence = quantize(
            sum(d.confidence for d in considered) / Decimal(str(len(considered)))
        )
        avg_vuln = quantize(
            sum(d.vulnerability_facet for d in considered) / Decimal(str(len(considered)))
        )
        avg_hygiene = quantize(
            sum(d.hygiene_facet for d in considered) / Decimal(str(len(considered)))
        )
        avg_behavior = quantize(
            sum(d.behavior_facet for d in considered) / Decimal(str(len(considered)))
        )

        passed_threshold = final_score >= self.policy.min_acceptable_score

        return ProjectTrustReport(
            scan_id=scan_id,
            overall_trust_score=final_score,
            mean_confidence=mean_confidence,
            policy_applied=self.policy,
            total_components_evaluated=total_components_evaluated,
            considered_components_count=considered_components_count,
            average_vuln_facet=avg_vuln,
            average_hygiene_facet=avg_hygiene,
            average_behavior_facet=avg_behavior,
            applied_suppressions=sorted(self._applied_suppressions),
            dependency_scores=dependency_scores,
            passed_policy_threshold=passed_threshold,
        )
