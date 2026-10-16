"""Multi-ecosystem SemVer solver for Supply Chain Guardian Track E.

Provides version comparison, upgrade safety classification, and automated
fix selection across NPM (SemVer 2.0 with 0.x breaking dynamics) and
PyPI (PEP 440 with CalVer detection).
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, List, Optional, Tuple

# Ensure repository root is on sys.path when executed directly
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packaging.version import InvalidVersion, Version
import semver

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import UpgradeSafetyClassification


class SemVerSolver:
    """Multi-ecosystem semantic versioning solver and upgrade classifier."""

    @classmethod
    def classify_upgrade(
        cls,
        ecosystem: Ecosystem | str,
        current: str,
        target: str,
    ) -> UpgradeSafetyClassification:
        """Classify the safety level of upgrading from current to target version.

        Args:
            ecosystem: The package ecosystem (NPM or PYPI).
            current: Current installed or resolved version string.
            target: Proposed target version string.

        Returns:
            UpgradeSafetyClassification indicating safety level or conflict.
        """
        eco = str(ecosystem).lower()
        if eco in ("npm", "ecosystem.npm"):
            return cls._classify_npm(current, target)
        if eco in ("pypi", "ecosystem.pypi"):
            return cls._classify_pypi(current, target)

        return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

    @classmethod
    def _classify_npm(cls, current: str, target: str) -> UpgradeSafetyClassification:
        """Classify upgrade safety under NPM SemVer 2.0 rules with 0.x breaking dynamics."""
        try:
            curr_v = semver.Version.parse(current)
            target_v = semver.Version.parse(target)
        except (ValueError, TypeError):
            return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

        # Prerelease check: If target has prerelease tag and current doesn't, return REQUIRES_REVIEW (P6-05)
        if target_v.prerelease is not None and curr_v.prerelease is None:
            return UpgradeSafetyClassification.REQUIRES_REVIEW

        # 0.x.y Breaking Semantic Rule (P6-05):
        if curr_v.major == 0:
            if target_v.major != 0 or target_v.minor != curr_v.minor:
                return UpgradeSafetyClassification.MAJOR_BREAKING
            if target_v.patch > curr_v.patch:
                return UpgradeSafetyClassification.PATCH_FIX_SAFE
            return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

        # 1.x.y+ SemVer:
        if target_v.major > curr_v.major:
            return UpgradeSafetyClassification.MAJOR_BREAKING
        if target_v.major == curr_v.major and target_v.minor > curr_v.minor:
            return UpgradeSafetyClassification.MINOR_FEATURE_SAFE
        if target_v.major == curr_v.major and target_v.minor == curr_v.minor and target_v.patch > curr_v.patch:
            return UpgradeSafetyClassification.PATCH_FIX_SAFE

        return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

    @classmethod
    def _classify_pypi(cls, current: str, target: str) -> UpgradeSafetyClassification:
        """Classify upgrade safety under PyPI PEP 440 rules with CalVer detection."""
        try:
            curr_v = Version(current)
            target_v = Version(target)
        except InvalidVersion:
            return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

        # Prerelease check: If target.is_prerelease and not current.is_prerelease: return REQUIRES_REVIEW
        if target_v.is_prerelease and not curr_v.is_prerelease:
            return UpgradeSafetyClassification.REQUIRES_REVIEW

        # CalVer Detection: If current.release and current.release[0] >= 2000: return REQUIRES_REVIEW
        if (curr_v.release and curr_v.release[0] >= 2000) or (target_v.release and target_v.release[0] >= 2000):
            return UpgradeSafetyClassification.REQUIRES_REVIEW

        # Normal PEP 440: compare release segments.
        if target_v.major > curr_v.major:
            return UpgradeSafetyClassification.MAJOR_BREAKING
        if target_v.major == curr_v.major and target_v.minor > curr_v.minor:
            return UpgradeSafetyClassification.MINOR_FEATURE_SAFE
        if target_v.major == curr_v.major and target_v.minor == curr_v.minor and target_v.release > curr_v.release:
            return UpgradeSafetyClassification.PATCH_FIX_SAFE

        return UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT

    @classmethod
    def select_best_fix(
        cls,
        ecosystem: Ecosystem | str,
        current_version: str,
        fixed_versions: List[str],
    ) -> Optional[Tuple[str, UpgradeSafetyClassification]]:
        """Evaluate candidate versions and select the minimal safe fix.

        Picks in priority order:
        1. PATCH_FIX_SAFE (minimal safe patch)
        2. MINOR_FEATURE_SAFE (minimal safe minor feature)
        3. MAJOR_BREAKING (minimal breaking jump, flagged for review)
        4. REQUIRES_REVIEW (e.g., CalVer or prerelease fix)

        Returns None if fixed_versions is empty or all candidates are unresolvable conflicts.

        Args:
            ecosystem: The package ecosystem (NPM or PYPI).
            current_version: Currently installed version string.
            fixed_versions: List of version strings that resolve the vulnerability.

        Returns:
            Tuple of (selected_version, classification) or None.
        """
        if not fixed_versions:
            return None

        eco = str(ecosystem).lower()
        is_npm = eco in ("npm", "ecosystem.npm")

        def _sort_key(v_str: str) -> Any:
            if is_npm:
                try:
                    return (0, semver.Version.parse(v_str))
                except (ValueError, TypeError):
                    return (1, v_str)
            else:
                try:
                    return (0, Version(v_str))
                except InvalidVersion:
                    return (1, v_str)

        classified: List[Tuple[str, UpgradeSafetyClassification]] = []
        for v in fixed_versions:
            classification = cls.classify_upgrade(ecosystem, current_version, v)
            if classification != UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT:
                classified.append((v, classification))

        if not classified:
            return None

        # Priority order for minimal safe fix selection
        tier_order = [
            UpgradeSafetyClassification.PATCH_FIX_SAFE,
            UpgradeSafetyClassification.MINOR_FEATURE_SAFE,
            UpgradeSafetyClassification.MAJOR_BREAKING,
            UpgradeSafetyClassification.REQUIRES_REVIEW,
        ]

        for tier in tier_order:
            tier_candidates = [c for c in classified if c[1] == tier]
            if tier_candidates:
                # Pick the minimal version within the preferred tier
                best = min(tier_candidates, key=lambda c: _sort_key(c[0]))
                return best

        return None


if __name__ == "__main__":
    # REQ-P6-03 Executable self-tests
    # Assert 0.2.3 -> 0.3.0 is MAJOR_BREAKING
    c1 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.3.0")
    assert c1 == UpgradeSafetyClassification.MAJOR_BREAKING, f"Expected MAJOR_BREAKING, got {c1}"

    # Assert 0.2.3 -> 0.2.4 is PATCH_FIX_SAFE
    c2 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.2.4")
    assert c2 == UpgradeSafetyClassification.PATCH_FIX_SAFE, f"Expected PATCH_FIX_SAFE, got {c2}"

    # Assert 1.2.0 -> 1.3.0 is MINOR_FEATURE_SAFE
    c3_npm = SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "1.3.0")
    assert c3_npm == UpgradeSafetyClassification.MINOR_FEATURE_SAFE, f"Expected MINOR_FEATURE_SAFE, got {c3_npm}"

    c3_pypi = SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "1.3.0")
    assert c3_pypi == UpgradeSafetyClassification.MINOR_FEATURE_SAFE, f"Expected MINOR_FEATURE_SAFE, got {c3_pypi}"

    # Assert 2021.3.17 -> 2021.4.1 is REQUIRES_REVIEW
    c4 = SemVerSolver.classify_upgrade(Ecosystem.PYPI, "2021.3.17", "2021.4.1")
    assert c4 == UpgradeSafetyClassification.REQUIRES_REVIEW, f"Expected REQUIRES_REVIEW, got {c4}"

    # Assert 1.0.0 -> 1.0.1-rc1 is REQUIRES_REVIEW
    c5 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.0.0", "1.0.1-rc1")
    assert c5 == UpgradeSafetyClassification.REQUIRES_REVIEW, f"Expected REQUIRES_REVIEW, got {c5}"

    # Test select_best_fix
    best_fix = SemVerSolver.select_best_fix(
        Ecosystem.NPM, "1.2.0", ["2.0.0", "1.2.2", "1.2.1", "1.3.0"]
    )
    assert best_fix == ("1.2.1", UpgradeSafetyClassification.PATCH_FIX_SAFE), f"Unexpected best fix: {best_fix}"

    print("All SemVerSolver self-tests passed successfully!")
