"""Unit tests for Phase 6 Track E Remediation schemas and models."""

from decimal import Decimal
import pytest
from pydantic import ValidationError

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import (
    ManifestUpdateMode,
    PullRequestResult,
    RemediationCandidate,
    RemediationOutcome,
    RemediationStrategy,
    RemediationVerification,
    SandboxExecutionResult,
    ScoreComputationMode,
    UpgradeSafetyClassification,
    VersionChange,
)


def test_remediation_enums():
    """Validates REQ-P6-01: exact enum definitions and values."""
    assert {e.value for e in UpgradeSafetyClassification} == {
        "PATCH_FIX_SAFE",
        "MINOR_FEATURE_SAFE",
        "MAJOR_BREAKING",
        "REQUIRES_REVIEW",
        "UNRESOLVABLE_CONFLICT",
    }
    assert {m.value for m in ManifestUpdateMode} == {
        "LOCKFILE_ONLY",
        "RAISE_FLOOR",
        "WIDEN_RANGE",
    }
    assert {s.value for s in RemediationStrategy} == {
        "DIRECT_BUMP",
        "PARENT_BUMP",
        "SCOPED_OVERRIDE",
        "GLOBAL_OVERRIDE",
        "PIN_TRANSITIVE",
        "NOT_AVAILABLE",
    }
    assert {o.value for o in RemediationOutcome} == {
        "LOCKFILE_UPDATED",
        "MANIFEST_ONLY_FALLBACK",
        "VERIFICATION_FAILED",
        "SANDBOX_ERROR",
        "NOT_ATTEMPTED",
        "SUPPRESSED_BY_PRIOR_REJECTION",
    }
    assert {c.value for c in ScoreComputationMode} == {
        "RECOMPUTED",
        "ESTIMATED",
    }


def test_version_change_frozen_and_extra_forbidden():
    """Validates VersionChange immutability and strict field validation."""
    vc = VersionChange(
        package_name="requests",
        from_version="2.31.0",
        to_version="2.32.0",
        is_intended_target=True,
    )
    assert vc.package_name == "requests"
    assert vc.from_version == "2.31.0"
    assert vc.to_version == "2.32.0"
    assert vc.is_intended_target is True

    # Check frozen
    with pytest.raises(ValidationError):
        vc.package_name = "urllib3"  # type: ignore

    # Check extra forbid
    with pytest.raises(ValidationError):
        VersionChange(
            package_name="requests",
            from_version="2.31.0",
            to_version="2.32.0",
            is_intended_target=True,
            extra_field="disallowed",  # type: ignore
        )


def test_remediation_verification_model():
    """Validates RemediationVerification fields and verdict validation."""
    rv = RemediationVerification(
        target_version_resolved=True,
        advisory_still_matches=False,
        lockfile_parses=True,
        unexpected_version_changes=[],
        verdict="VERIFIED",
    )
    assert rv.verdict == "VERIFIED"
    assert rv.unexpected_version_changes == []

    # Test invalid verdict
    with pytest.raises(ValidationError):
        RemediationVerification(
            target_version_resolved=True,
            advisory_still_matches=False,
            lockfile_parses=True,
            verdict="INVALID_VERDICT",  # type: ignore
        )


def test_remediation_candidate_model():
    """Validates RemediationCandidate model structure and constraints."""
    candidate = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.20",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=True,
        manifest_path="package.json",
        lockfile_path="package-lock.json",
        parent_package=None,
    )
    assert candidate.package_name == "lodash"
    assert candidate.ecosystem == Ecosystem.NPM
    assert candidate.classification == UpgradeSafetyClassification.PATCH_FIX_SAFE

    # Check frozen
    with pytest.raises(ValidationError):
        candidate.target_version = "4.17.22"  # type: ignore


def test_sandbox_execution_result_model():
    """Validates SandboxExecutionResult stderr excerpt truncation limit."""
    res = SandboxExecutionResult(
        outcome=RemediationOutcome.LOCKFILE_UPDATED,
        exit_code=0,
        modified_files=["package-lock.json"],
        stderr_excerpt="Warning: something minor",
        duration_seconds=1.45,
    )
    assert res.outcome == RemediationOutcome.LOCKFILE_UPDATED
    assert res.exit_code == 0
    assert res.duration_seconds == 1.45

    # Check stderr_excerpt max_length constraint
    with pytest.raises(ValidationError):
        SandboxExecutionResult(
            outcome=RemediationOutcome.SANDBOX_ERROR,
            exit_code=1,
            stderr_excerpt="x" * 8193,
            duration_seconds=0.5,
        )


def test_pull_request_result_model():
    """Validates PullRequestResult fields, types, and score quantization."""
    pr = PullRequestResult(
        pr_created=True,
        pr_number=42,
        pr_url="https://github.com/org/repo/pull/42",
        branch_name="scg/fix-lodash-4.17.21",
        skipped_reason=None,
        score_before=Decimal("65.50"),
        score_after=Decimal("82.00"),
        score_computation=ScoreComputationMode.RECOMPUTED,
    )
    assert pr.pr_created is True
    assert pr.pr_number == 42
    assert pr.score_before == Decimal("65.50")
    assert pr.score_after == Decimal("82.00")
    assert pr.score_computation == ScoreComputationMode.RECOMPUTED
