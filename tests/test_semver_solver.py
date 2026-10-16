"""Unit tests for SemVerSolver multi-ecosystem upgrade solver."""

import pytest

from scg_core.remediation.semver_solver import SemVerSolver
from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import UpgradeSafetyClassification


def test_npm_0x_breaking_rule():
    """Asserts 0.x.y Breaking Semantic Rule for NPM."""
    # 0.2.3 -> 0.3.0 is MAJOR_BREAKING
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.3.0")
        == UpgradeSafetyClassification.MAJOR_BREAKING
    )
    # 0.2.3 -> 1.0.0 is MAJOR_BREAKING
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "1.0.0")
        == UpgradeSafetyClassification.MAJOR_BREAKING
    )
    # 0.2.3 -> 0.2.4 is PATCH_FIX_SAFE
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.2.4")
        == UpgradeSafetyClassification.PATCH_FIX_SAFE
    )
    # 0.2.3 -> 0.2.3 is UNRESOLVABLE_CONFLICT (same version)
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.2.3")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )
    # 0.2.3 -> 0.2.1 is UNRESOLVABLE_CONFLICT (downgrade)
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.2.1")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )


def test_npm_standard_semver():
    """Asserts standard 1.x.y+ SemVer upgrade classification for NPM."""
    # 1.2.0 -> 1.3.0 is MINOR_FEATURE_SAFE
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "1.3.0")
        == UpgradeSafetyClassification.MINOR_FEATURE_SAFE
    )
    # 1.2.0 -> 1.2.5 is PATCH_FIX_SAFE
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "1.2.5")
        == UpgradeSafetyClassification.PATCH_FIX_SAFE
    )
    # 1.2.0 -> 2.0.0 is MAJOR_BREAKING
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "2.0.0")
        == UpgradeSafetyClassification.MAJOR_BREAKING
    )
    # Downgrades / equal versions
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "1.2.0")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "2.0.0", "1.9.0")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )


def test_npm_prerelease():
    """Asserts NPM prerelease upgrade requires review."""
    # 1.0.0 -> 1.0.1-rc1 is REQUIRES_REVIEW
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.0.0", "1.0.1-rc1")
        == UpgradeSafetyClassification.REQUIRES_REVIEW
    )
    # Both prereleases -> normal semver rules
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.0.0-rc1", "1.0.0-rc2")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )


def test_npm_invalid_semver():
    """Asserts invalid SemVer strings return UNRESOLVABLE_CONFLICT."""
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "invalid", "1.0.0")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.0.0", "not-a-version")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )


def test_pypi_calver_detection():
    """Asserts CalVer detection returns REQUIRES_REVIEW for PyPI."""
    # 2021.3.17 -> 2021.4.1 is REQUIRES_REVIEW
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "2021.3.17", "2021.4.1")
        == UpgradeSafetyClassification.REQUIRES_REVIEW
    )
    # Switch from semver to calver
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "2024.1.0")
        == UpgradeSafetyClassification.REQUIRES_REVIEW
    )


def test_pypi_pep440():
    """Asserts PEP 440 upgrade classification for PyPI."""
    # Major jump
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "2.0.0")
        == UpgradeSafetyClassification.MAJOR_BREAKING
    )
    # Minor jump
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "1.3.0")
        == UpgradeSafetyClassification.MINOR_FEATURE_SAFE
    )
    # Patch jump
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "1.2.1")
        == UpgradeSafetyClassification.PATCH_FIX_SAFE
    )
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.2.0", "1.2.0.1")
        == UpgradeSafetyClassification.PATCH_FIX_SAFE
    )
    # Prerelease jump
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.0.0", "1.0.1a1")
        == UpgradeSafetyClassification.REQUIRES_REVIEW
    )
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "1.0.0", "1.0.1-rc1")
        == UpgradeSafetyClassification.REQUIRES_REVIEW
    )
    # Invalid version
    assert (
        SemVerSolver.classify_upgrade(Ecosystem.PYPI, "bad_ver", "1.0.0")
        == UpgradeSafetyClassification.UNRESOLVABLE_CONFLICT
    )


def test_select_best_fix_priority():
    """Asserts select_best_fix evaluates priority order and picks minimal safe fix."""
    # When PATCH_FIX_SAFE candidates exist, choose minimal patch
    fix = SemVerSolver.select_best_fix(
        Ecosystem.NPM,
        "1.2.0",
        ["2.0.0", "1.2.5", "1.2.1", "1.3.0", "1.2.2"],
    )
    assert fix == ("1.2.1", UpgradeSafetyClassification.PATCH_FIX_SAFE)

    # When no patch exists, choose minimal minor feature
    fix_minor = SemVerSolver.select_best_fix(
        Ecosystem.NPM,
        "1.2.0",
        ["2.0.0", "1.4.0", "1.3.0"],
    )
    assert fix_minor == ("1.3.0", UpgradeSafetyClassification.MINOR_FEATURE_SAFE)

    # When only major break exists, fallback to minimal major
    fix_major = SemVerSolver.select_best_fix(
        Ecosystem.NPM,
        "1.2.0",
        ["3.0.0", "2.1.0", "2.0.0"],
    )
    assert fix_major == ("2.0.0", UpgradeSafetyClassification.MAJOR_BREAKING)

    # When only CalVer/prerelease exists, fallback to REQUIRES_REVIEW
    fix_review = SemVerSolver.select_best_fix(
        Ecosystem.PYPI,
        "2021.3.17",
        ["2021.4.2", "2021.4.1"],
    )
    assert fix_review == ("2021.4.1", UpgradeSafetyClassification.REQUIRES_REVIEW)

    # Empty list
    assert SemVerSolver.select_best_fix(Ecosystem.NPM, "1.2.0", []) is None

    # All unresolvable conflicts (downgrades / same version)
    assert (
        SemVerSolver.select_best_fix(
            Ecosystem.NPM, "1.2.0", ["1.1.0", "1.2.0", "0.9.0"]
        )
        is None
    )


def test_select_best_fix_string_ecosystem():
    """Asserts select_best_fix works with string ecosystem identifiers."""
    fix = SemVerSolver.select_best_fix("npm", "1.2.0", ["1.2.1"])
    assert fix == ("1.2.1", UpgradeSafetyClassification.PATCH_FIX_SAFE)

    fix_pypi = SemVerSolver.select_best_fix("pypi", "1.2.0", ["1.2.1"])
    assert fix_pypi == ("1.2.1", UpgradeSafetyClassification.PATCH_FIX_SAFE)
